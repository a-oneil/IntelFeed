"""Tests for theme management API."""

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.theme import Theme
from app.models.user import User


@pytest_asyncio.fixture
async def second_user(db_session: AsyncSession) -> User:
    """A second regular user for ownership isolation tests."""
    user = User(
        username="seconduser",
        password_hash=hash_password("secondpassword"),
        role="user",
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def second_user_headers(second_user: User) -> dict:
    token = create_access_token(second_user.id, second_user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def system_theme(db_session: AsyncSession) -> Theme:
    """A system theme for tests."""
    theme = Theme(name="System Dark", css_variables={"bg-primary": "#000", "accent-text": "#fff"}, is_system=True)
    db_session.add(theme)
    await db_session.flush()
    await db_session.refresh(theme)
    return theme


@pytest_asyncio.fixture
async def user_theme(db_session: AsyncSession, test_user: User) -> Theme:
    """A custom theme owned by the test user."""
    theme = Theme(
        name="My Custom",
        css_variables={"bg-primary": "#123", "accent-text": "#fff"},
        is_system=False,
        created_by=test_user.id,
    )
    db_session.add(theme)
    await db_session.flush()
    await db_session.refresh(theme)
    return theme


# --- List ---


@pytest.mark.asyncio
async def test_list_themes(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/themes", headers=auth_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_list_themes_includes_system_and_own(
    client: AsyncClient, auth_headers: dict, system_theme: Theme, user_theme: Theme
):
    resp = await client.get("/api/themes", headers=auth_headers)
    assert resp.status_code == 200
    ids = [t["id"] for t in resp.json()]
    assert str(system_theme.id) in ids
    assert str(user_theme.id) in ids


@pytest.mark.asyncio
async def test_list_themes_shows_custom_themes_to_everyone(
    client: AsyncClient, second_user_headers: dict, user_theme: Theme, system_theme: Theme
):
    """Themes are a shared gallery: every user sees system and custom themes alike."""
    resp = await client.get("/api/themes", headers=second_user_headers)
    assert resp.status_code == 200
    ids = [t["id"] for t in resp.json()]
    assert str(system_theme.id) in ids
    assert str(user_theme.id) in ids


# --- Get ---


@pytest.mark.asyncio
async def test_get_theme(client: AsyncClient, auth_headers: dict, system_theme: Theme):
    resp = await client.get(f"/api/themes/{system_theme.id}", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["name"] == "System Dark"


@pytest.mark.asyncio
async def test_get_own_theme(client: AsyncClient, auth_headers: dict, user_theme: Theme):
    resp = await client.get(f"/api/themes/{user_theme.id}", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["name"] == "My Custom"


@pytest.mark.asyncio
async def test_get_theme_created_by_another_user(client: AsyncClient, second_user_headers: dict, user_theme: Theme):
    """A theme another user created is readable — created_by is audit, not ownership."""
    resp = await client.get(f"/api/themes/{user_theme.id}", headers=second_user_headers)
    assert resp.status_code == 200
    assert resp.json()["name"] == "My Custom"


@pytest.mark.asyncio
async def test_get_theme_not_found(client: AsyncClient, auth_headers: dict):
    resp = await client.get(f"/api/themes/{uuid.uuid4()}", headers=auth_headers)
    assert resp.status_code == 404


# --- Create ---


@pytest.mark.asyncio
async def test_create_theme_any_user(client: AsyncClient, auth_headers: dict, test_user: User):
    """Any authenticated user can create a custom theme."""
    resp = await client.post(
        "/api/themes",
        json={"name": "User Theme", "css_variables": {"bg-primary": "#222", "text-primary": "#eee"}},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    theme = resp.json()
    assert theme["name"] == "User Theme"
    assert theme["css_variables"]["bg-primary"] == "#222"
    assert theme["is_system"] is False
    assert theme["created_by"] == str(test_user.id)


@pytest.mark.asyncio
async def test_create_theme_admin(client: AsyncClient, admin_headers: dict, admin_user: User):
    """Admin can also create custom themes (attributed to them)."""
    resp = await client.post(
        "/api/themes",
        json={"name": "Admin Theme", "css_variables": {"bg-primary": "#333"}},
        headers=admin_headers,
    )
    assert resp.status_code == 201
    assert resp.json()["created_by"] == str(admin_user.id)


# --- Update ---


@pytest.mark.asyncio
async def test_update_own_theme(client: AsyncClient, auth_headers: dict, user_theme: Theme):
    resp = await client.put(
        f"/api/themes/{user_theme.id}",
        json={"name": "Renamed", "css_variables": {"bg-primary": "#444"}},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "Renamed"
    assert resp.json()["css_variables"]["bg-primary"] == "#444"


@pytest.mark.asyncio
async def test_update_system_theme_forbidden(client: AsyncClient, auth_headers: dict, system_theme: Theme):
    resp = await client.put(
        f"/api/themes/{system_theme.id}",
        json={"name": "Hacked"},
        headers=auth_headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_update_theme_created_by_another_user(client: AsyncClient, second_user_headers: dict, user_theme: Theme):
    """Only the creator (or an admin) may edit a custom theme — another user gets 403."""
    resp = await client.put(
        f"/api/themes/{user_theme.id}",
        json={"name": "Renamed By Someone Else", "css_variables": {"bg-primary": "#555"}},
        headers=second_user_headers,
    )
    assert resp.status_code == 403

    # The theme is unchanged
    resp = await client.get(f"/api/themes/{user_theme.id}", headers=second_user_headers)
    assert resp.status_code == 200
    assert resp.json()["name"] == "My Custom"
    assert resp.json()["css_variables"]["bg-primary"] == "#123"


# --- Delete ---


@pytest.mark.asyncio
async def test_delete_own_theme(client: AsyncClient, auth_headers: dict, user_theme: Theme):
    resp = await client.delete(f"/api/themes/{user_theme.id}", headers=auth_headers)
    assert resp.status_code == 204

    # Verify it's gone
    resp = await client.get(f"/api/themes/{user_theme.id}", headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_system_theme_forbidden(client: AsyncClient, auth_headers: dict, system_theme: Theme):
    resp = await client.delete(f"/api/themes/{system_theme.id}", headers=auth_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_delete_theme_created_by_another_user(
    client: AsyncClient, second_user_headers: dict, auth_headers: dict, user_theme: Theme
):
    """Only the creator (or an admin) may delete a custom theme — another user gets 403."""
    resp = await client.delete(f"/api/themes/{user_theme.id}", headers=second_user_headers)
    assert resp.status_code == 403

    still_there = await client.get(f"/api/themes/{user_theme.id}", headers=auth_headers)
    assert still_there.status_code == 200
    assert still_there.json()["name"] == "My Custom"


@pytest.mark.asyncio
async def test_delete_active_theme_clears_preference(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, test_user: User, user_theme: Theme
):
    """Deleting the user's active theme should clear their theme_id."""
    test_user.theme_id = user_theme.id
    db_session.add(test_user)
    await db_session.flush()

    resp = await client.delete(f"/api/themes/{user_theme.id}", headers=auth_headers)
    assert resp.status_code == 204

    await db_session.refresh(test_user)
    assert test_user.theme_id is None


# --- Duplicate ---


@pytest.mark.asyncio
async def test_duplicate_system_theme(client: AsyncClient, auth_headers: dict, system_theme: Theme, test_user: User):
    resp = await client.post(
        f"/api/themes/{system_theme.id}/duplicate",
        json={"name": "My Dark Copy"},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    clone = resp.json()
    assert clone["name"] == "My Dark Copy"
    assert clone["is_system"] is False
    assert clone["created_by"] == str(test_user.id)
    assert clone["css_variables"] == system_theme.css_variables


@pytest.mark.asyncio
async def test_duplicate_own_theme(client: AsyncClient, auth_headers: dict, user_theme: Theme):
    resp = await client.post(
        f"/api/themes/{user_theme.id}/duplicate",
        json={"name": "Copy of My Custom"},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    assert resp.json()["name"] == "Copy of My Custom"


@pytest.mark.asyncio
async def test_duplicate_theme_created_by_another_user(
    client: AsyncClient, second_user_headers: dict, second_user: User, user_theme: Theme
):
    """Duplicating a shared theme works and attributes the copy to the duplicator."""
    resp = await client.post(
        f"/api/themes/{user_theme.id}/duplicate",
        json={"name": "Second User Copy"},
        headers=second_user_headers,
    )
    assert resp.status_code == 201
    assert resp.json()["name"] == "Second User Copy"
    assert resp.json()["created_by"] == str(second_user.id)


@pytest.mark.asyncio
async def test_duplicate_not_found(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        f"/api/themes/{uuid.uuid4()}/duplicate",
        json={"name": "Ghost"},
        headers=auth_headers,
    )
    assert resp.status_code == 404


# --- Preferences ---


@pytest.mark.asyncio
async def test_set_theme_preference_system_theme(client: AsyncClient, auth_headers: dict, system_theme: Theme):
    resp = await client.put(
        "/api/themes/user/preferences",
        json={"theme_id": str(system_theme.id)},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["theme_id"] == str(system_theme.id)


@pytest.mark.asyncio
async def test_set_theme_preference_own_theme(client: AsyncClient, auth_headers: dict, user_theme: Theme):
    resp = await client.put(
        "/api/themes/user/preferences",
        json={"theme_id": str(user_theme.id)},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["theme_id"] == str(user_theme.id)


@pytest.mark.asyncio
async def test_set_theme_preference_to_theme_created_by_another_user(
    client: AsyncClient, second_user_headers: dict, user_theme: Theme
):
    """Any theme in the shared gallery can be selected as a personal preference."""
    resp = await client.put(
        "/api/themes/user/preferences",
        json={"theme_id": str(user_theme.id)},
        headers=second_user_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["theme_id"] == str(user_theme.id)


@pytest.mark.asyncio
async def test_set_theme_preference_not_found(client: AsyncClient, auth_headers: dict):
    resp = await client.put(
        "/api/themes/user/preferences",
        json={"theme_id": str(uuid.uuid4())},
        headers=auth_headers,
    )
    assert resp.status_code == 404


# --- UserResponse includes theme_id ---


@pytest.mark.asyncio
async def test_user_response_includes_theme_fields(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/auth/me", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "theme_id" in data
    assert "custom_css" in data


# --- Instance default theme ---


@pytest.mark.asyncio
async def test_set_default_theme_admin(client: AsyncClient, admin_headers: dict, system_theme: Theme):
    resp = await client.put(f"/api/themes/{system_theme.id}/default", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["default_theme_id"] == str(system_theme.id)

    # List reflects the default flag
    resp = await client.get("/api/themes", headers=admin_headers)
    flags = {t["id"]: t["is_default"] for t in resp.json()}
    assert flags[str(system_theme.id)] is True
    assert all(v is False for tid, v in flags.items() if tid != str(system_theme.id))


@pytest.mark.asyncio
async def test_set_default_theme_non_admin_forbidden(client: AsyncClient, auth_headers: dict, system_theme: Theme):
    resp = await client.put(f"/api/themes/{system_theme.id}/default", headers=auth_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_set_default_theme_not_found(client: AsyncClient, admin_headers: dict):
    resp = await client.put(f"/api/themes/{uuid.uuid4()}/default", headers=admin_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_clear_default_theme(client: AsyncClient, admin_headers: dict, system_theme: Theme):
    await client.put(f"/api/themes/{system_theme.id}/default", headers=admin_headers)

    resp = await client.delete(f"/api/themes/{system_theme.id}/default", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["default_theme_id"] is None

    resp = await client.get("/api/themes", headers=admin_headers)
    assert all(t["is_default"] is False for t in resp.json())


@pytest.mark.asyncio
async def test_clear_default_ignores_non_default_theme(
    client: AsyncClient, admin_headers: dict, system_theme: Theme, user_theme: Theme
):
    """Clearing via a theme that isn't the default leaves the default in place."""
    await client.put(f"/api/themes/{system_theme.id}/default", headers=admin_headers)

    resp = await client.delete(f"/api/themes/{user_theme.id}/default", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["default_theme_id"] == str(system_theme.id)


@pytest.mark.asyncio
async def test_clear_theme_preference(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, test_user: User, system_theme: Theme
):
    """A user can clear their own theme so the instance default applies."""
    test_user.theme_id = system_theme.id
    db_session.add(test_user)
    await db_session.flush()

    resp = await client.put("/api/themes/user/preferences", json={"clear_theme": True}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["theme_id"] is None

    await db_session.refresh(test_user)
    assert test_user.theme_id is None


@pytest.mark.asyncio
async def test_public_default_theme_unauthenticated(client: AsyncClient, admin_headers: dict, system_theme: Theme):
    """The default theme is readable without auth (styles login/register pages)."""
    # No default configured yet
    resp = await client.get("/api/themes/default")
    assert resp.status_code == 200
    assert resp.json() is None

    # Admin sets a default; anonymous request sees it
    await client.put(f"/api/themes/{system_theme.id}/default", headers=admin_headers)
    resp = await client.get("/api/themes/default")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == str(system_theme.id)
    assert data["is_default"] is True
    assert "css_variables" in data


@pytest.mark.asyncio
async def test_default_theme_css_unauthenticated(client: AsyncClient, admin_headers: dict, system_theme: Theme):
    """index.html links this stylesheet in <head> to paint the default on first load."""
    # No default configured: an empty sheet, so the baked-in palette stands
    resp = await client.get("/api/themes/default.css")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/css")
    assert resp.text == ""

    await client.put(f"/api/themes/{system_theme.id}/default", headers=admin_headers)
    resp = await client.get("/api/themes/default.css")
    assert resp.status_code == 200
    # Doubled selector so it wins over index.css's :root whatever the load order
    assert resp.text.startswith(":root:root{")
    assert "--bg-primary:#000;" in resp.text
    assert "max-age" in resp.headers["cache-control"]


@pytest.mark.asyncio
async def test_default_theme_css_rejects_unsafe_variables(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    """A malformed css_variables row can't inject rules into every page load."""
    theme = Theme(
        name="Malformed",
        css_variables={
            "bg-primary": "#123456",
            "evil}html{display:none": "#fff",
            "accent": "red;} html {display:none",
        },
        is_system=True,
    )
    db_session.add(theme)
    await db_session.flush()
    await client.put(f"/api/themes/{theme.id}/default", headers=admin_headers)

    resp = await client.get("/api/themes/default.css")
    assert resp.text == ":root:root{--bg-primary:#123456;}"


@pytest.mark.asyncio
async def test_delete_default_custom_theme_clears_default(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession, admin_user: User
):
    """Deleting a custom theme that is the instance default clears the default."""
    theme = Theme(
        name="Admin Custom",
        css_variables={"bg-primary": "#111"},
        is_system=False,
        created_by=admin_user.id,
    )
    db_session.add(theme)
    await db_session.flush()
    await db_session.refresh(theme)

    await client.put(f"/api/themes/{theme.id}/default", headers=admin_headers)

    resp = await client.delete(f"/api/themes/{theme.id}", headers=admin_headers)
    assert resp.status_code == 204

    resp = await client.get("/api/themes", headers=admin_headers)
    assert all(t["is_default"] is False for t in resp.json())


@pytest.mark.asyncio
async def test_get_color_schema_unauthenticated(client: AsyncClient):
    """The server-driven color coding vocabulary is readable without auth."""
    resp = await client.get("/api/themes/schema")
    assert resp.status_code == 200
    data = resp.json()
    assert data["base"]["bg-primary"] == "#0d1117"
    assert data["domain_accents"]["feeds"] == "#f78166"
    assert data["domain_accents"]["intel"] == "#58a6ff"
    assert data["domain_accents"]["detect"] == "#3fb950"
    assert data["domain_accents"]["dash"] == "#bc8cff"
    assert data["entity_types"]["threat_actor"] == "#f97316"
    assert data["entity_types"]["observable"] == "#d946ef"
    assert data["severity"]["critical"] == "#dc2626"
    assert data["rule_formats"]["sigma"] == "#56d364"
    assert data["ransomware_groups"]["lockbit"] == "#e05c2f"
    assert data["pir"]["strategic"] == "#8b5cf6"
    assert data["tlp"]["TLP:AMBER"] == "#f59e0b"
    assert data["automation_nodes"]["trigger"] == "#f59e0b"
    assert data["syntax"]["keyword"] == "#cba6f7"
    assert data["css_variables"]["entity-actor"] == "#f97316"
    assert data["css_variables"]["fmt-sigma"] == "#56d364"

