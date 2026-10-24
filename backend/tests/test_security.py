import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.security import (
    ALGORITHM,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_admin_user,
    hash_password,
    verify_password,
)
from app.models.user import User

# ---------------------------------------------------------------------------
# hash_password / verify_password
# ---------------------------------------------------------------------------


class TestPasswordHashing:
    @pytest.mark.asyncio
    async def test_hash_password_returns_bcrypt_string(self):
        hashed = hash_password("mysecretpassword")
        assert isinstance(hashed, str)
        # bcrypt hashes start with $2b$ (or $2a$/$2y$ depending on variant)
        assert hashed.startswith(("$2b$", "$2a$", "$2y$"))

    @pytest.mark.asyncio
    async def test_hash_password_produces_unique_hashes(self):
        """Different salts mean the same password hashes differently each time."""
        h1 = hash_password("samepassword")
        h2 = hash_password("samepassword")
        assert h1 != h2

    @pytest.mark.asyncio
    async def test_verify_password_correct(self):
        hashed = hash_password("correctpassword")
        assert verify_password("correctpassword", hashed) is True

    @pytest.mark.asyncio
    async def test_verify_password_wrong(self):
        hashed = hash_password("correctpassword")
        assert verify_password("wrongpassword", hashed) is False

    @pytest.mark.asyncio
    async def test_verify_password_empty_string(self):
        hashed = hash_password("notempty")
        assert verify_password("", hashed) is False

    @pytest.mark.asyncio
    async def test_hash_and_verify_unicode_password(self):
        password = "p\u00e4ssw\u00f6rd\U0001f511"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True
        assert verify_password("passw0rd", hashed) is False


# ---------------------------------------------------------------------------
# create_access_token
# ---------------------------------------------------------------------------


class TestCreateAccessToken:
    @pytest.mark.asyncio
    async def test_returns_valid_jwt(self):
        user_id = uuid.uuid4()
        token = create_access_token(user_id, "user")
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        assert payload["sub"] == str(user_id)
        assert payload["role"] == "user"
        assert payload["type"] == "access"

    @pytest.mark.asyncio
    async def test_contains_iat_and_exp_claims(self):
        user_id = uuid.uuid4()
        token = create_access_token(user_id, "admin")
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        assert "iat" in payload
        assert "exp" in payload

    @pytest.mark.asyncio
    async def test_expiration_is_correct_duration(self):
        user_id = uuid.uuid4()
        before = datetime.now(UTC).replace(microsecond=0)
        token = create_access_token(user_id, "user")
        after = datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=1)

        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        exp = datetime.fromtimestamp(payload["exp"], tz=UTC)

        expected_min = before + timedelta(minutes=settings.access_token_expire_minutes)
        expected_max = after + timedelta(minutes=settings.access_token_expire_minutes)
        assert expected_min <= exp <= expected_max

    @pytest.mark.asyncio
    async def test_role_claim_is_preserved(self):
        user_id = uuid.uuid4()
        for role in ("user", "admin"):
            token = create_access_token(user_id, role)
            payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
            assert payload["role"] == role


# ---------------------------------------------------------------------------
# create_refresh_token
# ---------------------------------------------------------------------------


class TestCreateRefreshToken:
    @pytest.mark.asyncio
    async def test_returns_valid_jwt(self):
        user_id = uuid.uuid4()
        token = create_refresh_token(user_id)
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        assert payload["sub"] == str(user_id)
        assert payload["type"] == "refresh"

    @pytest.mark.asyncio
    async def test_does_not_contain_role_claim(self):
        user_id = uuid.uuid4()
        token = create_refresh_token(user_id)
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        assert "role" not in payload

    @pytest.mark.asyncio
    async def test_expiration_is_correct_duration(self):
        user_id = uuid.uuid4()
        before = datetime.now(UTC).replace(microsecond=0)
        token = create_refresh_token(user_id)
        after = datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=1)

        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        exp = datetime.fromtimestamp(payload["exp"], tz=UTC)

        expected_min = before + timedelta(days=settings.refresh_token_expire_days)
        expected_max = after + timedelta(days=settings.refresh_token_expire_days)
        assert expected_min <= exp <= expected_max

    @pytest.mark.asyncio
    async def test_contains_iat_claim(self):
        user_id = uuid.uuid4()
        token = create_refresh_token(user_id)
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        assert "iat" in payload


# ---------------------------------------------------------------------------
# decode_token
# ---------------------------------------------------------------------------


class TestDecodeToken:
    @pytest.mark.asyncio
    async def test_decode_valid_access_token(self):
        user_id = uuid.uuid4()
        token = create_access_token(user_id, "user")
        payload = decode_token(token)
        assert payload["sub"] == str(user_id)
        assert payload["type"] == "access"
        assert payload["role"] == "user"

    @pytest.mark.asyncio
    async def test_decode_valid_refresh_token(self):
        user_id = uuid.uuid4()
        token = create_refresh_token(user_id)
        payload = decode_token(token)
        assert payload["sub"] == str(user_id)
        assert payload["type"] == "refresh"

    @pytest.mark.asyncio
    async def test_decode_expired_token_raises_401(self):
        """A token whose exp is in the past should raise HTTPException 401."""
        payload = {
            "sub": str(uuid.uuid4()),
            "role": "user",
            "exp": datetime.now(UTC) - timedelta(hours=1),
            "iat": datetime.now(UTC) - timedelta(hours=2),
            "type": "access",
        }
        token = jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)

        with pytest.raises(HTTPException) as exc_info:
            decode_token(token)
        assert exc_info.value.status_code == 401
        assert "Invalid or expired token" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_decode_invalid_signature_raises_401(self):
        """A token signed with the wrong key should raise HTTPException 401."""
        payload = {
            "sub": str(uuid.uuid4()),
            "role": "user",
            "exp": datetime.now(UTC) + timedelta(hours=1),
            "iat": datetime.now(UTC),
            "type": "access",
        }
        token = jwt.encode(payload, "wrong-secret-key", algorithm=ALGORITHM)

        with pytest.raises(HTTPException) as exc_info:
            decode_token(token)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_decode_malformed_token_raises_401(self):
        """A completely invalid string should raise HTTPException 401."""
        with pytest.raises(HTTPException) as exc_info:
            decode_token("not.a.valid.jwt.token")
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_decode_empty_string_raises_401(self):
        with pytest.raises(HTTPException) as exc_info:
            decode_token("")
        assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# get_current_user (integration via HTTP client)
# ---------------------------------------------------------------------------


class TestGetCurrentUser:
    @pytest.mark.asyncio
    async def test_valid_token_returns_user(self, client: AsyncClient, auth_headers: dict, test_user: User):
        resp = await client.get("/api/auth/me", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == test_user.username
        assert data["id"] == str(test_user.id)

    @pytest.mark.asyncio
    async def test_expired_token_returns_401(self, client: AsyncClient, test_user: User):
        """An access token with exp in the past should be rejected."""
        payload = {
            "sub": str(test_user.id),
            "role": test_user.role,
            "exp": datetime.now(UTC) - timedelta(minutes=5),
            "iat": datetime.now(UTC) - timedelta(minutes=35),
            "type": "access",
        }
        expired_token = jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)
        resp = await client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {expired_token}"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_refresh_token_rejected_as_access(self, client: AsyncClient, test_user: User):
        """A refresh token should not be accepted by get_current_user (type != access)."""
        refresh = create_refresh_token(test_user.id)
        resp = await client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {refresh}"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_user_not_found_returns_401(self, client: AsyncClient, db_session: AsyncSession):
        """A token referencing a non-existent user_id should return 401."""
        nonexistent_id = uuid.uuid4()
        token = create_access_token(nonexistent_id, "user")
        resp = await client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_inactive_user_returns_401(self, client: AsyncClient, db_session: AsyncSession):
        """An inactive user's token should be rejected."""
        inactive_user = User(
            username="inactiveuser_sec",
            password_hash=hash_password("testpassword"),
            role="user",
            is_active=False,
        )
        db_session.add(inactive_user)
        await db_session.flush()

        token = create_access_token(inactive_user.id, inactive_user.role)
        resp = await client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_missing_authorization_header_rejected(self, client: AsyncClient):
        """A request with no Authorization header should be rejected."""
        resp = await client.get("/api/auth/me")
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_invalid_bearer_token_returns_401(self, client: AsyncClient):
        """A request with a garbage bearer token should return 401."""
        resp = await client.get(
            "/api/auth/me",
            headers={"Authorization": "Bearer totallyinvalid"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_token_missing_sub_claim_returns_401(self, client: AsyncClient):
        """A well-formed JWT that lacks 'sub' should be rejected."""
        payload = {
            "role": "user",
            "exp": datetime.now(UTC) + timedelta(hours=1),
            "iat": datetime.now(UTC),
            "type": "access",
        }
        token = jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)
        resp = await client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# get_admin_user (integration via HTTP client)
# ---------------------------------------------------------------------------


class TestGetAdminUser:
    @pytest.mark.asyncio
    async def test_admin_user_allowed(self, admin_user: User):
        """get_admin_user should return the user when their role is 'admin'."""
        result = await get_admin_user(user=admin_user)
        assert result is admin_user
        assert result.role == "admin"

    @pytest.mark.asyncio
    async def test_regular_user_rejected(self, test_user: User):
        """get_admin_user should raise 403 for a non-admin user."""
        with pytest.raises(HTTPException) as exc_info:
            await get_admin_user(user=test_user)
        assert exc_info.value.status_code == 403
        assert "Admin access required" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_admin_endpoint_integration_admin_passes(
        self, client: AsyncClient, admin_headers: dict, admin_user: User
    ):
        """An admin should pass the gate on an admin-gated endpoint (POST /api/ai/providers).

        We send an intentionally incomplete body so the response is a validation
        error (400/422), NOT a 403 -- proving the admin gate was passed.
        """
        resp = await client.post(
            "/api/ai/providers",
            headers=admin_headers,
            json={},
        )
        # 400/422 means the admin gate passed but the request body was invalid
        assert resp.status_code in (400, 422)

    @pytest.mark.asyncio
    async def test_admin_endpoint_integration_user_rejected(
        self, client: AsyncClient, auth_headers: dict, test_user: User
    ):
        """A regular user should receive 403 from an admin-gated endpoint."""
        # Creating a provider is no longer admin-only (anyone may register a
        # personal key when the admin allows it); the admin's list of every
        # personal key is.
        resp = await client.get("/api/ai/providers/user-keys", headers=auth_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_admin_endpoint_unauthenticated_rejected(self, client: AsyncClient):
        """Unauthenticated requests to admin endpoints should be rejected."""
        resp = await client.get("/api/ai/providers/user-keys")
        assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# Token type boundary tests
# ---------------------------------------------------------------------------


class TestTokenTypeBoundaries:
    @pytest.mark.asyncio
    async def test_access_and_refresh_tokens_differ_for_same_user(self):
        """Access and refresh tokens for the same user should be different strings."""
        user_id = uuid.uuid4()
        access = create_access_token(user_id, "user")
        refresh = create_refresh_token(user_id)
        assert access != refresh

    @pytest.mark.asyncio
    async def test_access_token_type_claim(self):
        user_id = uuid.uuid4()
        token = create_access_token(user_id, "user")
        payload = decode_token(token)
        assert payload["type"] == "access"

    @pytest.mark.asyncio
    async def test_refresh_token_type_claim(self):
        user_id = uuid.uuid4()
        token = create_refresh_token(user_id)
        payload = decode_token(token)
        assert payload["type"] == "refresh"

    @pytest.mark.asyncio
    async def test_algorithm_is_hs256(self):
        """Ensure the module uses HS256 as expected."""
        assert ALGORITHM == "HS256"

    @pytest.mark.asyncio
    async def test_token_header_specifies_hs256(self):
        """The JWT header should declare HS256."""
        user_id = uuid.uuid4()
        token = create_access_token(user_id, "user")
        header = jwt.get_unverified_header(token)
        assert header["alg"] == "HS256"
