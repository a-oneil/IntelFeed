import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Query, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.public_access import set_viewer_anonymous
from app.database import get_db
from app.models.user import User

security_scheme = HTTPBearer()

ALGORITHM = "HS256"
TOKEN_BLACKLIST_PREFIX = "token_blacklist:"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


def create_access_token(user_id: uuid.UUID, role: str, username: str | None = None) -> str:
    expire = datetime.now(UTC) + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": expire,
        "iat": datetime.now(UTC),
        "type": "access",
        "jti": str(uuid.uuid4()),
    }
    if username:
        payload["username"] = username
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def create_refresh_token(user_id: uuid.UUID) -> str:
    expire = datetime.now(UTC) + timedelta(days=settings.refresh_token_expire_days)
    payload = {
        "sub": str(user_id),
        "exp": expire,
        "iat": datetime.now(UTC),
        "type": "refresh",
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


# A credential for an AI agent acting for a user: the Claude CLI's IntelFeed MCP
# server holds one for the length of one run. It is its own token type, so
# get_current_user (and with it every ordinary route) refuses it; only the tool
# endpoints accept it, through get_tool_caller: a ``read`` token runs read-only
# tools, a ``propose`` token also stages writes for the user to confirm.
AGENT_TOKEN_TYPE = "agent"
AGENT_SCOPE_READ = "read"
AGENT_SCOPE_PROPOSE = "propose"


def create_agent_token(user_id: uuid.UUID, ttl_seconds: float, *, conversation_id: uuid.UUID | None = None) -> str:
    """A short-lived token for one agent run on ``user_id``'s behalf.

    Read-only by default. With ``conversation_id`` it is a ``propose`` token:
    a write it asks for is staged on that copilot conversation for the user to
    confirm, never run (see app.tools.gate).
    """
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "exp": now + timedelta(seconds=max(60.0, ttl_seconds)),
        "iat": now,
        "type": AGENT_TOKEN_TYPE,
        "scope": AGENT_SCOPE_PROPOSE if conversation_id else AGENT_SCOPE_READ,
        "jti": str(uuid.uuid4()),
    }
    if conversation_id:
        payload["conversation_id"] = str(conversation_id)
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        ) from e


async def blacklist_token(jti: str, exp: datetime) -> None:
    """Add a token's JTI to the Redis blacklist until it would naturally expire."""
    from app.services.redis_client import get_redis

    redis = await get_redis()
    ttl = int((exp - datetime.now(UTC)).total_seconds())
    if ttl > 0:
        await redis.setex(f"{TOKEN_BLACKLIST_PREFIX}{jti}", ttl, "1")


async def is_token_blacklisted(jti: str) -> bool:
    """Check if a token's JTI is in the Redis blacklist."""
    from app.services.redis_client import get_redis

    redis = await get_redis()
    return await redis.exists(f"{TOKEN_BLACKLIST_PREFIX}{jti}") > 0


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    payload = decode_token(credentials.credentials)
    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
    set_viewer_anonymous(False)
    return await _user_from_payload(payload, db)


# ── Public read-only mode ─────────────────────────────────────────────
#
# With the admin switch on, a request with no token is a *visitor*: it may
# read the routes that deliberately take ``get_viewer`` instead of
# ``get_current_user`` and nothing else. Every other route keeps the login
# check it has today, so anything new or overlooked stays locked. A visitor
# never gets a token, so the write lock (core/public_access.py) refuses every
# mutating request from one before the route runs.

ANONYMOUS_ROLE = "anonymous"


@dataclass(frozen=True, slots=True)
class AnonymousViewer:
    """The read-only visitor a ``get_viewer`` route sees when nobody is signed in.

    It walks like a ``User`` for the attributes read routes touch, with
    ``id`` ``None``: every per-user filter (``UserEntryState.user_id == user.id``,
    watches, stacks, personal weights, tag visibility) then matches no row,
    which is exactly the "no user" answer — and a route that tried to *write*
    a user-keyed row would fail on the NOT NULL column rather than store
    anything. Routes that must branch (hide feed URLs, skip a stamp) check
    ``user.is_anonymous``.
    """

    id: None = None
    username: None = None
    role: str = ANONYMOUS_ROLE
    is_active: bool = True
    is_anonymous: bool = True
    settings: dict = field(default_factory=dict)
    theme_id: None = None
    custom_css: None = None


def public_read_only_enabled() -> bool:
    """Whether anonymous visitors may browse (Settings → Users → Security)."""
    return bool(settings.get("public_read_only_enabled"))


_optional_bearer = HTTPBearer(auto_error=False)


async def get_viewer(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_optional_bearer),
    db: AsyncSession = Depends(get_db),
) -> User | AnonymousViewer:
    """``get_current_user`` for routes a visitor may read.

    A token is checked exactly as ``get_current_user`` checks it. With no
    token the result is the anonymous viewer while public read-only mode is
    on, and a 401 while it is off. An ``Authorization`` header that carries
    no usable token (``Bearer`` alone, another scheme) is a 401, never a
    visitor: the write lock and response scrubbing key off the same parse.
    """
    if credentials is None and request.headers.get("authorization", "").strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if credentials is not None:
        payload = decode_token(credentials.credentials)
        if payload.get("type") != "access":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
        set_viewer_anonymous(False)
        return await _user_from_payload(payload, db)
    if public_read_only_enabled():
        set_viewer_anonymous(True)
        return AnonymousViewer()
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated", headers={"WWW-Authenticate": "Bearer"}
    )


async def get_entry_viewer(
    entry_id: uuid.UUID,
    user: User | AnonymousViewer = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
) -> User | AnonymousViewer:
    """``get_viewer`` for routes about one article (``{entry_id}`` in the path).

    Their queries read junction tables keyed by the entry id and never load
    the Entry, so the visitor filter can't stop them: a visitor asking about
    an article from a hidden feed gets a 404 here instead.
    """
    if user.is_anonymous:
        from sqlalchemy import select

        from app.models.entry import Entry

        if (await db.execute(select(Entry.id).where(Entry.id == entry_id))).scalar_one_or_none() is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Entry not found")
    return user


@dataclass(frozen=True, slots=True)
class ToolCaller:
    """Who is calling the tool endpoints, and what their credential lets them do.

    ``agent_scope`` is None for a person's own login, else the agent token's
    scope: ``read`` runs read tools only, ``propose`` stages writes on
    ``conversation_id`` instead of running them.
    """

    user: User
    agent_scope: str | None = None
    conversation_id: str | None = None

    @property
    def is_agent(self) -> bool:
        return self.agent_scope is not None


async def get_tool_caller(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: AsyncSession = Depends(get_db),
) -> ToolCaller:
    """get_current_user for /api/tools: also accepts an agent token."""
    payload = decode_token(credentials.credentials)
    token_type = payload.get("type")
    if token_type not in ("access", AGENT_TOKEN_TYPE):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
    user = await _user_from_payload(payload, db)
    if token_type != AGENT_TOKEN_TYPE:
        return ToolCaller(user=user)
    scope = payload.get("scope")
    conversation_id = payload.get("conversation_id")
    if scope != AGENT_SCOPE_PROPOSE or not conversation_id:
        # Anything but a well-formed propose token is read-only.
        return ToolCaller(user=user, agent_scope=AGENT_SCOPE_READ)
    return ToolCaller(user=user, agent_scope=AGENT_SCOPE_PROPOSE, conversation_id=str(conversation_id))


async def _user_from_payload(payload: dict, db: AsyncSession) -> User:
    jti = payload.get("jti")
    if jti and await is_token_blacklisted(jti):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked")

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    return user


async def user_from_access_token(raw_token: str, db: AsyncSession) -> User:
    """The active user an access token names, with every check get_current_user makes.

    For routes that read the token themselves (``?token=`` on an <img> or
    <audio> tag): the logout blacklist applies to them too.
    """
    payload = decode_token(raw_token)
    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
    return await _user_from_payload(payload, db)


async def get_current_user_from_query(
    token: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Auth via query param token — for SSE endpoints where headers aren't possible."""
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    return await user_from_access_token(token, db)


async def get_admin_user(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user
