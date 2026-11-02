import hmac
import logging
import secrets
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import (
    blacklist_token,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_admin_user,
    get_current_user,
    hash_password,
    is_token_blacklisted,
    verify_password,
)
from app.database import get_db
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    LogoutRequest,
    PasswordChangeRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
    UserSettingsPatch,
    UserUpdateRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/registration-status")
async def registration_status(db: AsyncSession = Depends(get_db)):
    """Public pre-login configuration: whether self-registration is enabled, if an invite code is required,
    and whether anonymous visitors may browse read-only (public read-only mode)."""
    from app.services.system_settings import get_setting

    enabled = await get_setting("registration_enabled", db)
    invite_code = await get_setting("registration_invite_code", db)
    public_read_only = await get_setting("public_read_only_enabled", db)
    return {
        "registration_enabled": enabled is not False,
        "invite_code_required": bool(invite_code),
        "public_read_only_enabled": bool(public_read_only),
    }


@router.get("/invite-code")
async def get_invite_code(
    _admin: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the configured registration invite code, or null when none is set. Admin only."""
    from app.services.system_settings import get_setting

    code = await get_setting("registration_invite_code", db)
    return {"invite_code": code if code else None}


async def _gate_registration_after_first_admin(db: AsyncSession) -> None:
    """Put an invite code on registration the moment the first admin exists.

    Registration has to be open for the very first account, but an install
    reachable from the internet should not stay open to strangers after that.
    The code is shown to the admin under Settings → Users, where it can be
    changed or cleared to reopen registration. An operator who set a code
    before the first login (env or DB) keeps theirs.
    """
    from app.services.system_settings import get_setting, update_settings

    if await get_setting("registration_invite_code", db):
        return
    try:
        await update_settings(db, {"registration_invite_code": secrets.token_urlsafe(9)})
    except ValueError as exc:
        # The code is a secret, so it is stored encrypted; a dev box still on
        # the placeholder ENCRYPTION_KEY cannot encrypt. Registration must not
        # fail over that — the admin can set a code once the key is real.
        logger.warning("registration left open: could not store an invite code (%s)", exc)


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(request: RegisterRequest, db: AsyncSession = Depends(get_db)):
    """Create a new user account and return an access/refresh token pair.

    The first human account becomes the admin, and an invite code is generated
    right after it so later sign-ups need the code (Settings → Users shows it).
    Fails with 403 when registration is disabled or the invite code is invalid,
    and 409 when the username is already taken.
    """
    from app.services.system_settings import get_setting

    registration_enabled = await get_setting("registration_enabled", db)
    if registration_enabled is False:
        raise AppError(code="forbidden", message="Account registration is currently disabled", status_code=403)

    # Validate invite code if one is configured
    required_code = await get_setting("registration_invite_code", db)
    if required_code:
        submitted = (request.invite_code or "").encode("utf-8")
        expected = required_code.encode("utf-8")
        if not hmac.compare_digest(submitted, expected):
            raise AppError(code="forbidden", message="Invalid invite code", status_code=403)

    # Serialize sign-ups until this transaction ends: two at once on a fresh
    # install would otherwise both see no user and both become admin.
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtext('intelfeed:register'))"))

    # Check if username already exists
    result = await db.execute(select(User).where(User.username == request.username))
    if result.scalar_one_or_none():
        raise AppError(code="conflict", message="Username already taken", status_code=409)

    # The first HUMAN account on a fresh install becomes the admin — the
    # migration-seeded `system` service account must not count.
    any_user = await db.execute(select(User.id).where(User.role != "system").limit(1))
    is_first_user = any_user.scalar_one_or_none() is None

    user = User(
        username=request.username,
        password_hash=hash_password(request.password),
        last_login=datetime.now(UTC),
        role="admin" if is_first_user else "user",
    )
    db.add(user)
    await db.flush()

    if is_first_user:
        await _gate_registration_after_first_admin(db)

    # Seed the newcomer with the instance's default feed list (the earliest
    # admin's subscriptions). Done regardless of the per-user-subscriptions
    # flag so the table stays consistent for a later flip.
    from app.services.feed_visibility import seed_subscriptions_for_new_user

    await seed_subscriptions_for_new_user(db, user.id)

    return TokenResponse(
        access_token=create_access_token(user.id, user.role, user.username),
        refresh_token=create_refresh_token(user.id),
    )


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Authenticate with username and password, returning an access/refresh token pair. Updates last_login."""
    result = await db.execute(select(User).where(User.username == request.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(request.password, user.password_hash):
        raise AppError(code="unauthorized", message="Invalid username or password", status_code=401)

    if not user.is_active:
        raise AppError(code="forbidden", message="Account is disabled", status_code=403)

    user.last_login = datetime.now(UTC)
    db.add(user)
    await db.flush()

    return TokenResponse(
        access_token=create_access_token(user.id, user.role, user.username),
        refresh_token=create_refresh_token(user.id),
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(request: RefreshRequest, db: AsyncSession = Depends(get_db)):
    """Exchange a valid refresh token for a new access/refresh token pair.

    Tokens are rotated: the presented refresh token is blacklisted and a new one issued.
    """
    payload = decode_token(request.refresh_token)
    if payload.get("type") != "refresh":
        raise AppError(code="unauthorized", message="Invalid refresh token", status_code=401)

    jti = payload.get("jti")
    if jti and await is_token_blacklisted(jti):
        raise AppError(code="unauthorized", message="Refresh token has been revoked", status_code=401)

    user_id = payload.get("sub")
    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise AppError(code="unauthorized", message="User not found or inactive", status_code=401)

    # Rotate: blacklist the old refresh token, issue new pair
    if jti:
        exp = datetime.fromtimestamp(payload["exp"], tz=UTC)
        await blacklist_token(jti, exp)

    return TokenResponse(
        access_token=create_access_token(user.id, user.role, user.username),
        refresh_token=create_refresh_token(user.id),
    )


@router.post("/logout")
async def logout(
    request: LogoutRequest,
    credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
):
    """Revoke both the current access token and the provided refresh token."""
    # Blacklist the access token
    access_payload = decode_token(credentials.credentials)
    access_jti = access_payload.get("jti")
    if access_jti:
        exp = datetime.fromtimestamp(access_payload["exp"], tz=UTC)
        await blacklist_token(access_jti, exp)

    # Blacklist the refresh token
    if request.refresh_token:
        try:
            refresh_payload = decode_token(request.refresh_token)
            refresh_jti = refresh_payload.get("jti")
            if refresh_jti and refresh_payload.get("type") == "refresh":
                exp = datetime.fromtimestamp(refresh_payload["exp"], tz=UTC)
                await blacklist_token(refresh_jti, exp)
        except HTTPException:
            pass  # Refresh token already expired — no need to blacklist

    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserResponse)
async def get_me(user: User = Depends(get_current_user)):
    """Return the authenticated user's profile."""
    return user


@router.put("/me", response_model=UserResponse)
async def update_me(
    request: UserUpdateRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update the authenticated user's settings blob. A null settings field leaves it unchanged."""
    if request.settings is not None:
        user.settings = request.settings
    db.add(user)
    await db.flush()
    return user


@router.patch("/me/settings", response_model=UserResponse)
async def patch_my_settings(
    request: UserSettingsPatch,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Shallow-merge top-level keys into the authenticated user's settings blob.

    Unlike `PUT /me`, which replaces the whole blob, this only touches the keys
    present in the request — so independent client-side auto-savers (triage
    view, table layouts, ...) can't clobber each other's writes with a stale
    snapshot of the rest of the settings.
    """
    user.settings = {**(user.settings or {}), **request.settings}
    db.add(user)
    await db.flush()
    return user


@router.put("/me/password")
async def change_password(
    request: PasswordChangeRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Change the authenticated user's password after verifying the current password."""
    if not verify_password(request.current_password, user.password_hash):
        raise AppError(code="unauthorized", message="Current password is incorrect", status_code=401)

    user.password_hash = hash_password(request.new_password)
    db.add(user)
    await db.flush()
    return {"message": "Password updated"}
