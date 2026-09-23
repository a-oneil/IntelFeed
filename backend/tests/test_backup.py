"""Tests for the backup/restore (export/import) API."""

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.automation_rule import AutomationRule
from app.models.category import Category
from app.models.dashboard import Dashboard, DashboardWidget
from app.models.detection_rule import DetectionRule
from app.models.feed import Feed
from app.models.saved_search import SavedSearch
from app.models.tag import Tag
from app.models.theme import Theme
from app.models.user import User

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def second_admin(db_session: AsyncSession) -> User:
    """A second admin — export/import are admin-only, so multi-user tests need two admins."""
    user = User(
        username="backupadmin2",
        password_hash=hash_password("password2"),
        role="admin",
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def second_admin_headers(second_admin: User) -> dict:
    token = create_access_token(second_admin.id, second_admin.role)
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def populated_admin(db_session: AsyncSession, admin_user: User) -> User:
    """Seed the admin_user with a variety of owned objects for export tests."""

    # Categories (with parent-child hierarchy)
    parent_cat = Category(created_by=admin_user.id, name="Security", position=0)
    db_session.add(parent_cat)
    await db_session.flush()

    child_cat = Category(created_by=admin_user.id, name="Threat Intel", parent_id=parent_cat.id, position=1)
    db_session.add(child_cat)
    await db_session.flush()

    # Feed (subscription fields now live on Feed directly)
    feed = Feed(
        title="Krebs on Security",
        url="https://krebsonsecurity.com/feed/",
        feed_type="rss",
        category_id=parent_cat.id,
        custom_title="Krebs",
        is_muted=False,
        retention_days=90,
    )
    db_session.add(feed)
    await db_session.flush()

    # Tags
    for name, color in [("ioc", "#FF0000"), ("apt", "#0000FF"), ("cve", "#00FF00")]:
        db_session.add(Tag(created_by=admin_user.id, name=name, color=color))

    # Automation rules
    db_session.add(
        AutomationRule(
            created_by=admin_user.id,
            name="Auto-tag CVEs",
            description="Tags entries mentioning CVE IDs",
            is_enabled=True,
            trigger_type="on_new_entry",
            trigger_config={"pattern": "CVE-\\d{4}-\\d+"},
            conditions={"field": "content", "operator": "regex"},
            actions=[{"type": "add_tag", "tag": "cve"}],
        )
    )

    # Saved searches
    db_session.add(
        SavedSearch(
            created_by=admin_user.id,
            name="Recent APT activity",
            query="APT threat actor",
            filters={"date_range": "7d", "feed_types": ["rss"]},
        )
    )

    # Detection rules
    db_session.add(
        DetectionRule(
            created_by=admin_user.id,
            rule_type="sigma",
            title="Cobalt Strike Beacon",
            description="Detects Cobalt Strike C2 beacon activity",
            rule_content="title: Cobalt Strike\nstatus: experimental\nlogsource:\n  product: windows",
            severity="high",
            tags=["attack.execution", "attack.t1059"],
            source_ttps=[{"id": "T1059", "name": "Command and Scripting Interpreter"}],
        )
    )

    # Themes
    db_session.add(
        Theme(
            created_by=admin_user.id,
            name="Dark SOC",
            css_variables={"bg-primary": "#0a0a0a", "accent-text": "#00ff41"},
            is_system=False,
        )
    )

    # Dashboard with widgets
    dashboard = Dashboard(
        created_by=admin_user.id,
        name="SOC Overview",
        layout={"columns": 3},
        is_default=True,
    )
    db_session.add(dashboard)
    await db_session.flush()

    db_session.add(
        DashboardWidget(
            dashboard_id=dashboard.id,
            widget_type="threat_feed",
            title="Live Threats",
            config={"refresh_interval": 30},
            position_x=0,
            position_y=0,
            width=6,
            height=4,
        )
    )

    # User settings
    admin_user.settings = {"default_view": "unread", "entries_per_page": 50}
    admin_user.custom_css = ".sidebar { width: 300px; }"

    await db_session.flush()
    return admin_user


# ---------------------------------------------------------------------------
# Authentication tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_export_requires_auth(client: AsyncClient):
    resp = await client.get("/api/backup/export")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_import_requires_auth(client: AsyncClient):
    resp = await client.post("/api/backup/import", json={"tags": []})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_export_rejects_invalid_token(client: AsyncClient):
    resp = await client.get(
        "/api/backup/export",
        headers={"Authorization": "Bearer invalid-token-value"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_import_rejects_invalid_token(client: AsyncClient):
    resp = await client.post(
        "/api/backup/import",
        json={"tags": []},
        headers={"Authorization": "Bearer invalid-token-value"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_backup_export_requires_admin(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/backup/export", headers=auth_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_backup_import_requires_admin(client: AsyncClient, auth_headers: dict):
    resp = await client.post("/api/backup/import", json={"tags": []}, headers=auth_headers)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Export structure tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_export_returns_valid_json(client: AsyncClient, admin_headers: dict, admin_user: User):
    resp = await client.get("/api/backup/export", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, dict)


@pytest.mark.asyncio
async def test_export_contains_all_top_level_keys(client: AsyncClient, admin_headers: dict, admin_user: User):
    resp = await client.get("/api/backup/export", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()

    expected_keys = {
        "version",
        "exported_at",
        "user",
        "categories",
        "feeds",
        "tags",
        "ai_providers",
        "ai_task_assignments",
        "ai_prompt_templates",
        "automation_rules",
        "saved_searches",
        "dashboards",
        "detection_rules",
        "themes",
    }
    assert set(data.keys()) == expected_keys


@pytest.mark.asyncio
async def test_export_version_field(client: AsyncClient, admin_headers: dict, admin_user: User):
    resp = await client.get("/api/backup/export", headers=admin_headers)
    data = resp.json()
    assert data["version"] == "1.0"


@pytest.mark.asyncio
async def test_export_exported_at_is_iso_datetime(client: AsyncClient, admin_headers: dict, admin_user: User):
    resp = await client.get("/api/backup/export", headers=admin_headers)
    data = resp.json()
    # Should parse without error as ISO 8601
    from datetime import datetime

    datetime.fromisoformat(data["exported_at"])


@pytest.mark.asyncio
async def test_export_has_content_disposition_header(client: AsyncClient, admin_headers: dict, admin_user: User):
    resp = await client.get("/api/backup/export", headers=admin_headers)
    assert resp.status_code == 200
    disposition = resp.headers.get("content-disposition", "")
    assert "attachment" in disposition
    assert "intelfeed-config-" in disposition
    assert ".json" in disposition


@pytest.mark.asyncio
async def test_export_empty_instance_has_empty_lists(client: AsyncClient, admin_headers: dict, admin_user: User):
    """An instance with no data should get empty lists for collection keys."""
    resp = await client.get("/api/backup/export", headers=admin_headers)
    data = resp.json()

    for key in [
        "categories",
        "feeds",
        "tags",
        "automation_rules",
        "saved_searches",
        "dashboards",
        "detection_rules",
        "themes",
    ]:
        assert isinstance(data[key], list), f"{key} should be a list"
        assert len(data[key]) == 0, f"{key} should be empty for a fresh instance"


@pytest.mark.asyncio
async def test_export_user_settings(client: AsyncClient, admin_headers: dict, populated_admin: User):
    resp = await client.get("/api/backup/export", headers=admin_headers)
    data = resp.json()

    user_data = data["user"]
    assert user_data["settings"]["default_view"] == "unread"
    assert user_data["settings"]["entries_per_page"] == 50
    assert user_data["custom_css"] == ".sidebar { width: 300px; }"


# ---------------------------------------------------------------------------
# Export data correctness tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_export_categories_with_hierarchy(client: AsyncClient, admin_headers: dict, populated_admin: User):
    resp = await client.get("/api/backup/export", headers=admin_headers)
    data = resp.json()
    cats = data["categories"]

    assert len(cats) == 2

    parent = next(c for c in cats if c["name"] == "Security")
    child = next(c for c in cats if c["name"] == "Threat Intel")

    assert parent["parent_id"] is None
    assert parent["position"] == 0
    assert "_id" in parent  # internal id for cross-referencing

    assert child["parent_id"] == parent["_id"]
    assert child["position"] == 1


@pytest.mark.asyncio
async def test_export_feeds(client: AsyncClient, admin_headers: dict, populated_admin: User):
    """Feeds export directly. They used to be exported as per-user subscriptions."""
    resp = await client.get("/api/backup/export", headers=admin_headers)
    data = resp.json()
    feeds = data["feeds"]

    assert len(feeds) == 1
    feed = feeds[0]
    assert feed["feed_url"] == "https://krebsonsecurity.com/feed/"
    assert feed["feed_title"] == "Krebs on Security"
    assert feed["feed_type"] == "rss"
    assert feed["is_muted"] is False
    assert feed["retention_days"] == 90
    assert feed["category_id"] is not None


@pytest.mark.asyncio
async def test_export_tags(client: AsyncClient, admin_headers: dict, populated_admin: User):
    resp = await client.get("/api/backup/export", headers=admin_headers)
    data = resp.json()
    tags = data["tags"]

    assert len(tags) == 3
    tag_names = {t["name"] for t in tags}
    assert tag_names == {"ioc", "apt", "cve"}

    ioc_tag = next(t for t in tags if t["name"] == "ioc")
    assert ioc_tag["color"] == "#FF0000"


@pytest.mark.asyncio
async def test_export_automation_rules(client: AsyncClient, admin_headers: dict, populated_admin: User):
    resp = await client.get("/api/backup/export", headers=admin_headers)
    data = resp.json()
    rules = data["automation_rules"]

    assert len(rules) == 1
    rule = rules[0]
    assert rule["name"] == "Auto-tag CVEs"
    assert rule["description"] == "Tags entries mentioning CVE IDs"
    assert rule["is_enabled"] is True
    assert rule["trigger_type"] == "on_new_entry"
    assert rule["trigger_config"]["pattern"] == "CVE-\\d{4}-\\d+"
    assert rule["actions"][0]["type"] == "add_tag"


@pytest.mark.asyncio
async def test_export_saved_searches(client: AsyncClient, admin_headers: dict, populated_admin: User):
    resp = await client.get("/api/backup/export", headers=admin_headers)
    data = resp.json()
    searches = data["saved_searches"]

    assert len(searches) == 1
    search = searches[0]
    assert search["name"] == "Recent APT activity"
    assert search["query"] == "APT threat actor"
    assert search["filters"]["date_range"] == "7d"


@pytest.mark.asyncio
async def test_export_detection_rules(client: AsyncClient, admin_headers: dict, populated_admin: User):
    resp = await client.get("/api/backup/export", headers=admin_headers)
    data = resp.json()
    rules = data["detection_rules"]

    assert len(rules) == 1
    rule = rules[0]
    assert rule["rule_type"] == "sigma"
    assert rule["title"] == "Cobalt Strike Beacon"
    assert rule["severity"] == "high"
    assert "Cobalt Strike" in rule["rule_content"]
    assert "attack.execution" in rule["tags"]
    assert rule["source_ttps"][0]["id"] == "T1059"


@pytest.mark.asyncio
async def test_export_themes(client: AsyncClient, admin_headers: dict, populated_admin: User):
    resp = await client.get("/api/backup/export", headers=admin_headers)
    data = resp.json()
    themes = data["themes"]

    assert len(themes) == 1
    theme = themes[0]
    assert theme["name"] == "Dark SOC"
    assert theme["css_variables"]["bg-primary"] == "#0a0a0a"
    assert theme["css_variables"]["accent-text"] == "#00ff41"


@pytest.mark.asyncio
async def test_export_dashboards_with_widgets(client: AsyncClient, admin_headers: dict, populated_admin: User):
    resp = await client.get("/api/backup/export", headers=admin_headers)
    data = resp.json()
    dashboards = data["dashboards"]

    assert len(dashboards) == 1
    dash = dashboards[0]
    assert dash["name"] == "SOC Overview"
    assert dash["layout"] == {"columns": 3}
    assert dash["is_default"] is True

    assert len(dash["widgets"]) == 1
    widget = dash["widgets"][0]
    assert widget["widget_type"] == "threat_feed"
    assert widget["title"] == "Live Threats"
    assert widget["config"]["refresh_interval"] == 30
    assert widget["position_x"] == 0
    assert widget["position_y"] == 0
    assert widget["width"] == 6
    assert widget["height"] == 4


@pytest.mark.asyncio
async def test_export_is_instance_wide(
    client: AsyncClient,
    admin_headers: dict,
    second_admin_headers: dict,
    populated_admin: User,
    second_admin: User,
):
    """The export is a snapshot of the whole instance, not of one user's data.

    Feeds, tags, rules and themes are all shared config now, so any admin's
    export contains everything. Only the ``user`` block is caller-specific.
    """
    resp = await client.get("/api/backup/export", headers=second_admin_headers)
    data = resp.json()

    assert len(data["categories"]) == 2
    assert len(data["feeds"]) == 1
    assert len(data["tags"]) == 3
    assert len(data["automation_rules"]) == 1
    assert len(data["saved_searches"]) == 1
    assert len(data["detection_rules"]) == 1
    assert len(data["themes"]) == 1
    assert len(data["dashboards"]) == 1

    # The user block still reflects whoever asked for the export.
    assert data["user"]["display_name"] == second_admin.username


# ---------------------------------------------------------------------------
# Import tests - valid data
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_import_tags(client: AsyncClient, admin_headers: dict, admin_user: User):
    payload = {
        "tags": [
            {"name": "malware", "color": "#FF0000"},
            {"name": "phishing", "color": "#FFAA00"},
        ],
    }
    resp = await client.post("/api/backup/import", json=payload, headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["imported"]["tags"] == 2


@pytest.mark.asyncio
async def test_import_automation_rules(client: AsyncClient, admin_headers: dict, admin_user: User):
    payload = {
        "automation_rules": [
            {
                "name": "Flag ransomware",
                "description": "Flags ransomware-related entries",
                "is_enabled": True,
                "trigger_type": "on_new_entry",
                "trigger_config": {"pattern": "ransomware"},
                "conditions": {"field": "title"},
                "actions": [{"type": "add_tag", "tag": "ransomware"}],
            },
        ],
    }
    resp = await client.post("/api/backup/import", json=payload, headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["imported"]["automation_rules"] == 1


@pytest.mark.asyncio
async def test_import_saved_searches(client: AsyncClient, admin_headers: dict, admin_user: User):
    payload = {
        "saved_searches": [
            {
                "name": "Zero-day alerts",
                "query": "zero-day OR 0-day",
                "filters": {"severity": "critical"},
            },
        ],
    }
    resp = await client.post("/api/backup/import", json=payload, headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["imported"]["saved_searches"] == 1


@pytest.mark.asyncio
async def test_import_themes(client: AsyncClient, admin_headers: dict, admin_user: User):
    payload = {
        "themes": [
            {
                "name": "Solarized",
                "css_variables": {"bg-primary": "#002b36", "text-primary": "#839496"},
            },
        ],
    }
    resp = await client.post("/api/backup/import", json=payload, headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["imported"]["themes"] == 1


@pytest.mark.asyncio
async def test_import_detection_rules(client: AsyncClient, admin_headers: dict, admin_user: User):
    payload = {
        "detection_rules": [
            {
                "rule_type": "splunk_spl",
                "title": "Lateral Movement Detection",
                "description": "Detects lateral movement via SMB",
                "rule_content": 'index=windows EventCode=5140 ShareName="\\\\*\\IPC$"',
                "severity": "medium",
                "tags": ["attack.lateral_movement"],
                "source_ttps": [{"id": "T1021.002", "name": "Remote Services: SMB"}],
            },
        ],
    }
    resp = await client.post("/api/backup/import", json=payload, headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["imported"]["detection_rules"] == 1


@pytest.mark.asyncio
async def test_import_multiple_types_at_once(client: AsyncClient, admin_headers: dict, admin_user: User):
    payload = {
        "tags": [{"name": "multi-tag", "color": "#111111"}],
        "automation_rules": [
            {
                "name": "Multi-rule",
                "trigger_type": "on_manual",
                "trigger_config": {},
                "conditions": {},
                "actions": [],
            },
        ],
        "saved_searches": [{"name": "Multi-search", "query": "test", "filters": {}}],
        "themes": [{"name": "Multi-theme", "css_variables": {"bg": "#000"}}],
        "detection_rules": [
            {
                "rule_type": "sigma",
                "title": "Multi-detection",
                "rule_content": "title: test",
                "tags": [],
                "source_ttps": [],
            },
        ],
    }
    resp = await client.post("/api/backup/import", json=payload, headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["imported"]["tags"] == 1
    assert data["imported"]["automation_rules"] == 1
    assert data["imported"]["saved_searches"] == 1
    assert data["imported"]["themes"] == 1
    assert data["imported"]["detection_rules"] == 1


@pytest.mark.asyncio
async def test_import_persists_to_database(
    client: AsyncClient, admin_headers: dict, admin_user: User, db_session: AsyncSession
):
    payload = {
        "tags": [{"name": "persisted-tag", "color": "#ABCDEF"}],
    }
    resp = await client.post("/api/backup/import", json=payload, headers=admin_headers)
    assert resp.status_code == 200

    result = await db_session.execute(select(Tag).where(Tag.created_by == admin_user.id, Tag.name == "persisted-tag"))
    tag = result.scalar_one_or_none()
    assert tag is not None
    assert tag.color == "#ABCDEF"


# ---------------------------------------------------------------------------
# Import tests - empty / invalid data
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_import_empty_body(client: AsyncClient, admin_headers: dict):
    resp = await client.post("/api/backup/import", json={}, headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    # All counts should be zero
    for key in ["tags", "automation_rules", "saved_searches", "themes", "detection_rules"]:
        assert data["imported"][key] == 0


@pytest.mark.asyncio
async def test_import_empty_lists(client: AsyncClient, admin_headers: dict):
    payload = {
        "tags": [],
        "automation_rules": [],
        "saved_searches": [],
        "themes": [],
        "detection_rules": [],
    }
    resp = await client.post("/api/backup/import", json=payload, headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    for key in ["tags", "automation_rules", "saved_searches", "themes", "detection_rules"]:
        assert data["imported"][key] == 0


@pytest.mark.asyncio
async def test_import_tag_without_name_is_skipped(client: AsyncClient, admin_headers: dict, admin_user: User):
    payload = {
        "tags": [
            {"color": "#FF0000"},  # missing name
            {"name": "", "color": "#00FF00"},  # empty name
        ],
    }
    resp = await client.post("/api/backup/import", json=payload, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["imported"]["tags"] == 0


@pytest.mark.asyncio
async def test_import_automation_rule_without_name_is_skipped(
    client: AsyncClient, admin_headers: dict, admin_user: User
):
    payload = {
        "automation_rules": [
            {
                "description": "No name provided",
                "trigger_type": "on_new_entry",
            },
        ],
    }
    resp = await client.post("/api/backup/import", json=payload, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["imported"]["automation_rules"] == 0


@pytest.mark.asyncio
async def test_import_saved_search_without_name_is_skipped(client: AsyncClient, admin_headers: dict, admin_user: User):
    payload = {
        "saved_searches": [
            {"query": "some query", "filters": {}},
        ],
    }
    resp = await client.post("/api/backup/import", json=payload, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["imported"]["saved_searches"] == 0


@pytest.mark.asyncio
async def test_import_theme_without_name_is_skipped(client: AsyncClient, admin_headers: dict, admin_user: User):
    payload = {
        "themes": [
            {"css_variables": {"bg": "#000"}},
        ],
    }
    resp = await client.post("/api/backup/import", json=payload, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["imported"]["themes"] == 0


@pytest.mark.asyncio
async def test_import_detection_rule_without_title_is_skipped(
    client: AsyncClient, admin_headers: dict, admin_user: User
):
    payload = {
        "detection_rules": [
            {"rule_type": "sigma", "rule_content": "content here"},  # missing title
        ],
    }
    resp = await client.post("/api/backup/import", json=payload, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["imported"]["detection_rules"] == 0


@pytest.mark.asyncio
async def test_import_detection_rule_without_content_is_skipped(
    client: AsyncClient, admin_headers: dict, admin_user: User
):
    payload = {
        "detection_rules": [
            {"rule_type": "sigma", "title": "Missing content"},  # missing rule_content
        ],
    }
    resp = await client.post("/api/backup/import", json=payload, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["imported"]["detection_rules"] == 0


@pytest.mark.asyncio
async def test_import_invalid_json_body(client: AsyncClient, admin_headers: dict):
    resp = await client.post(
        "/api/backup/import",
        content=b"not valid json",
        headers={**admin_headers, "Content-Type": "application/json"},
    )
    assert resp.status_code in (400, 422)


# ---------------------------------------------------------------------------
# Import deduplication tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_import_duplicate_tags_are_skipped(
    client: AsyncClient, admin_headers: dict, admin_user: User, db_session: AsyncSession
):
    # Pre-create a tag
    db_session.add(Tag(created_by=admin_user.id, name="existing-tag", color="#000000"))
    await db_session.flush()

    payload = {
        "tags": [
            {"name": "existing-tag", "color": "#FF0000"},  # duplicate
            {"name": "new-tag", "color": "#00FF00"},  # new
        ],
    }
    resp = await client.post("/api/backup/import", json=payload, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["imported"]["tags"] == 1  # only new-tag


@pytest.mark.asyncio
async def test_import_duplicate_automation_rules_are_skipped(
    client: AsyncClient, admin_headers: dict, admin_user: User, db_session: AsyncSession
):
    db_session.add(
        AutomationRule(
            created_by=admin_user.id,
            name="Existing Rule",
            trigger_type="on_manual",
            trigger_config={},
            conditions={},
            actions=[],
        )
    )
    await db_session.flush()

    payload = {
        "automation_rules": [
            {"name": "Existing Rule", "trigger_type": "on_new_entry"},
            {"name": "New Rule", "trigger_type": "on_new_entry"},
        ],
    }
    resp = await client.post("/api/backup/import", json=payload, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["imported"]["automation_rules"] == 1


@pytest.mark.asyncio
async def test_import_duplicate_saved_searches_are_skipped(
    client: AsyncClient, admin_headers: dict, admin_user: User, db_session: AsyncSession
):
    db_session.add(SavedSearch(created_by=admin_user.id, name="Existing Search", query="test", filters={}))
    await db_session.flush()

    payload = {
        "saved_searches": [
            {"name": "Existing Search", "query": "different query"},
            {"name": "New Search", "query": "new query"},
        ],
    }
    resp = await client.post("/api/backup/import", json=payload, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["imported"]["saved_searches"] == 1


@pytest.mark.asyncio
async def test_import_duplicate_themes_are_skipped(
    client: AsyncClient, admin_headers: dict, admin_user: User, db_session: AsyncSession
):
    db_session.add(
        Theme(created_by=admin_user.id, name="Existing Theme", css_variables={"bg": "#000"}, is_system=False)
    )
    await db_session.flush()

    payload = {
        "themes": [
            {"name": "Existing Theme", "css_variables": {"bg": "#fff"}},
            {"name": "New Theme", "css_variables": {"bg": "#111"}},
        ],
    }
    resp = await client.post("/api/backup/import", json=payload, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["imported"]["themes"] == 1


@pytest.mark.asyncio
async def test_import_detection_rules_always_added(
    client: AsyncClient, admin_headers: dict, admin_user: User, db_session: AsyncSession
):
    """Detection rules have no natural dedup key, so duplicates are always added."""
    db_session.add(
        DetectionRule(
            created_by=admin_user.id,
            rule_type="sigma",
            title="Same Title",
            rule_content="content",
            tags=[],
            source_ttps=[],
        )
    )
    await db_session.flush()

    payload = {
        "detection_rules": [
            {
                "rule_type": "sigma",
                "title": "Same Title",
                "rule_content": "content",
            },
        ],
    }
    resp = await client.post("/api/backup/import", json=payload, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["imported"]["detection_rules"] == 1

    # Verify both exist
    result = await db_session.execute(
        select(DetectionRule).where(DetectionRule.created_by == admin_user.id, DetectionRule.title == "Same Title")
    )
    assert len(result.scalars().all()) == 2


# ---------------------------------------------------------------------------
# Import user isolation tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_import_data_belongs_to_authenticated_user(
    client: AsyncClient,
    admin_headers: dict,
    second_admin_headers: dict,
    admin_user: User,
    second_admin: User,
    db_session: AsyncSession,
):
    """Imported rows are attributed to the importer but shared with everyone."""
    payload = {
        "tags": [{"name": "imported-by-user-a", "color": "#123456"}],
    }
    resp = await client.post("/api/backup/import", json=payload, headers=admin_headers)
    assert resp.status_code == 200

    # created_by records who ran the import...
    result = await db_session.execute(select(Tag).where(Tag.name == "imported-by-user-a"))
    tag = result.scalar_one()
    assert tag.created_by == admin_user.id

    # ...but the tag itself is instance-wide, so user B sees it too.
    resp = await client.get("/api/backup/export", headers=second_admin_headers)
    tag_names = {t["name"] for t in resp.json()["tags"]}
    assert "imported-by-user-a" in tag_names


# ---------------------------------------------------------------------------
# Import default values tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_import_tag_default_color(
    client: AsyncClient, admin_headers: dict, admin_user: User, db_session: AsyncSession
):
    """Tags imported without a color should get the default gray."""
    payload = {
        "tags": [{"name": "no-color-tag"}],
    }
    resp = await client.post("/api/backup/import", json=payload, headers=admin_headers)
    assert resp.status_code == 200

    result = await db_session.execute(select(Tag).where(Tag.created_by == admin_user.id, Tag.name == "no-color-tag"))
    tag = result.scalar_one()
    assert tag.color == "#6B7280"


@pytest.mark.asyncio
async def test_import_automation_rule_defaults(
    client: AsyncClient, admin_headers: dict, admin_user: User, db_session: AsyncSession
):
    """Automation rules should get sensible defaults for optional fields."""
    payload = {
        "automation_rules": [
            {"name": "Minimal Rule"},
        ],
    }
    resp = await client.post("/api/backup/import", json=payload, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["imported"]["automation_rules"] == 1

    result = await db_session.execute(
        select(AutomationRule).where(AutomationRule.created_by == admin_user.id, AutomationRule.name == "Minimal Rule")
    )
    rule = result.scalar_one()
    assert rule.is_enabled is False  # default from import
    assert rule.trigger_type == "on_manual"
    assert rule.trigger_config == {}
    assert rule.conditions == {}
    assert rule.actions == []


@pytest.mark.asyncio
async def test_import_theme_not_system(
    client: AsyncClient, admin_headers: dict, admin_user: User, db_session: AsyncSession
):
    """Imported themes should always be non-system."""
    payload = {
        "themes": [{"name": "Imported Theme", "css_variables": {"bg": "#fff"}}],
    }
    resp = await client.post("/api/backup/import", json=payload, headers=admin_headers)
    assert resp.status_code == 200

    result = await db_session.execute(
        select(Theme).where(Theme.created_by == admin_user.id, Theme.name == "Imported Theme")
    )
    theme = result.scalar_one()
    assert theme.is_system is False


# ---------------------------------------------------------------------------
# Round-trip tests (export -> import)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_round_trip_tags(
    client: AsyncClient,
    admin_headers: dict,
    second_admin_headers: dict,
    populated_admin: User,
    second_admin: User,
):
    """Re-importing an instance's own tag export changes nothing.

    Export is instance-wide, so importing it back finds every tag already
    present and skips them all. The re-export must be byte-identical.
    """
    export_resp = await client.get("/api/backup/export", headers=admin_headers)
    assert export_resp.status_code == 200
    export_data = export_resp.json()
    assert len(export_data["tags"]) == 3

    import_payload = {"tags": export_data["tags"]}
    import_resp = await client.post("/api/backup/import", json=import_payload, headers=second_admin_headers)
    assert import_resp.status_code == 200
    assert import_resp.json()["imported"]["tags"] == 0

    re_export_resp = await client.get("/api/backup/export", headers=second_admin_headers)
    re_export_data = re_export_resp.json()

    original_tags = sorted(export_data["tags"], key=lambda t: t["name"])
    imported_tags = sorted(re_export_data["tags"], key=lambda t: t["name"])

    assert len(original_tags) == len(imported_tags)
    for orig, imp in zip(original_tags, imported_tags):
        assert orig["name"] == imp["name"]
        assert orig["color"] == imp["color"]


@pytest.mark.asyncio
async def test_round_trip_automation_rules(
    client: AsyncClient,
    admin_headers: dict,
    second_admin_headers: dict,
    populated_admin: User,
    second_admin: User,
):
    """Re-importing an instance's own automation rules is a no-op.

    Dedup is by name and instance-wide, so a rule another user authored is not
    duplicated when a second user imports the backup.
    """
    export_resp = await client.get("/api/backup/export", headers=admin_headers)
    export_data = export_resp.json()
    assert len(export_data["automation_rules"]) == 1

    import_payload = {"automation_rules": export_data["automation_rules"]}
    import_resp = await client.post("/api/backup/import", json=import_payload, headers=second_admin_headers)
    assert import_resp.status_code == 200
    assert import_resp.json()["imported"]["automation_rules"] == 0

    re_export_resp = await client.get("/api/backup/export", headers=second_admin_headers)
    re_export_data = re_export_resp.json()

    original_rules = export_data["automation_rules"]
    imported_rules = re_export_data["automation_rules"]

    assert len(original_rules) == len(imported_rules)
    for orig, imp in zip(
        sorted(original_rules, key=lambda r: r["name"]),
        sorted(imported_rules, key=lambda r: r["name"]),
    ):
        assert orig["name"] == imp["name"]
        assert orig["description"] == imp["description"]
        assert orig["is_enabled"] == imp["is_enabled"]
        assert orig["trigger_type"] == imp["trigger_type"]
        assert orig["trigger_config"] == imp["trigger_config"]
        assert orig["actions"] == imp["actions"]


@pytest.mark.asyncio
async def test_round_trip_saved_searches(
    client: AsyncClient,
    admin_headers: dict,
    second_admin_headers: dict,
    populated_admin: User,
    second_admin: User,
):
    export_resp = await client.get("/api/backup/export", headers=admin_headers)
    export_data = export_resp.json()

    import_payload = {"saved_searches": export_data["saved_searches"]}
    import_resp = await client.post("/api/backup/import", json=import_payload, headers=second_admin_headers)
    assert import_resp.status_code == 200
    # Already present instance-wide, so nothing new is created.
    assert import_resp.json()["imported"]["saved_searches"] == 0

    re_export_resp = await client.get("/api/backup/export", headers=second_admin_headers)
    re_export_data = re_export_resp.json()

    for orig, imp in zip(
        sorted(export_data["saved_searches"], key=lambda s: s["name"]),
        sorted(re_export_data["saved_searches"], key=lambda s: s["name"]),
    ):
        assert orig["name"] == imp["name"]
        assert orig["query"] == imp["query"]
        assert orig["filters"] == imp["filters"]


@pytest.mark.asyncio
async def test_round_trip_detection_rules(
    client: AsyncClient,
    admin_headers: dict,
    second_admin_headers: dict,
    populated_admin: User,
    second_admin: User,
):
    export_resp = await client.get("/api/backup/export", headers=admin_headers)
    export_data = export_resp.json()

    import_payload = {"detection_rules": export_data["detection_rules"]}
    import_resp = await client.post("/api/backup/import", json=import_payload, headers=second_admin_headers)
    assert import_resp.status_code == 200
    assert import_resp.json()["imported"]["detection_rules"] == len(export_data["detection_rules"])

    re_export_resp = await client.get("/api/backup/export", headers=second_admin_headers)
    re_export_data = re_export_resp.json()

    for orig, imp in zip(
        sorted(export_data["detection_rules"], key=lambda r: r["title"]),
        sorted(re_export_data["detection_rules"], key=lambda r: r["title"]),
    ):
        assert orig["rule_type"] == imp["rule_type"]
        assert orig["title"] == imp["title"]
        assert orig["description"] == imp["description"]
        assert orig["rule_content"] == imp["rule_content"]
        assert orig["severity"] == imp["severity"]
        assert orig["tags"] == imp["tags"]
        assert orig["source_ttps"] == imp["source_ttps"]


@pytest.mark.asyncio
async def test_round_trip_themes(
    client: AsyncClient,
    admin_headers: dict,
    second_admin_headers: dict,
    populated_admin: User,
    second_admin: User,
):
    export_resp = await client.get("/api/backup/export", headers=admin_headers)
    export_data = export_resp.json()

    import_payload = {"themes": export_data["themes"]}
    import_resp = await client.post("/api/backup/import", json=import_payload, headers=second_admin_headers)
    assert import_resp.status_code == 200
    # Already present instance-wide, so nothing new is created.
    assert import_resp.json()["imported"]["themes"] == 0

    re_export_resp = await client.get("/api/backup/export", headers=second_admin_headers)
    re_export_data = re_export_resp.json()

    for orig, imp in zip(
        sorted(export_data["themes"], key=lambda t: t["name"]),
        sorted(re_export_data["themes"], key=lambda t: t["name"]),
    ):
        assert orig["name"] == imp["name"]
        assert orig["css_variables"] == imp["css_variables"]


@pytest.mark.asyncio
async def test_round_trip_full_export_import(
    client: AsyncClient,
    admin_headers: dict,
    second_admin_headers: dict,
    populated_admin: User,
    second_admin: User,
):
    """Full round-trip: re-importing an instance's own export is a no-op.

    Everything except detection rules dedups by name, so a re-import adds
    nothing. Detection rules have no natural key and are always appended.
    """
    export_resp = await client.get("/api/backup/export", headers=admin_headers)
    export_data = export_resp.json()

    import_payload = {
        "tags": export_data["tags"],
        "automation_rules": export_data["automation_rules"],
        "saved_searches": export_data["saved_searches"],
        "themes": export_data["themes"],
        "detection_rules": export_data["detection_rules"],
    }
    import_resp = await client.post("/api/backup/import", json=import_payload, headers=second_admin_headers)
    assert import_resp.status_code == 200

    imported = import_resp.json()["imported"]
    assert imported["tags"] == 0
    assert imported["automation_rules"] == 0
    assert imported["saved_searches"] == 0
    assert imported["themes"] == 0
    assert imported["detection_rules"] == len(export_data["detection_rules"])

    re_export_resp = await client.get("/api/backup/export", headers=second_admin_headers)
    re_export_data = re_export_resp.json()

    # Deduped collections are unchanged; detection rules doubled.
    assert len(re_export_data["tags"]) == len(export_data["tags"])
    assert len(re_export_data["automation_rules"]) == len(export_data["automation_rules"])
    assert len(re_export_data["saved_searches"]) == len(export_data["saved_searches"])
    assert len(re_export_data["themes"]) == len(export_data["themes"])
    assert len(re_export_data["detection_rules"]) == 2 * len(export_data["detection_rules"])


@pytest.mark.asyncio
async def test_round_trip_idempotent_import(
    client: AsyncClient,
    admin_headers: dict,
    second_admin_headers: dict,
    populated_admin: User,
    second_admin: User,
):
    """Importing foreign data twice creates it once (except detection rules).

    The payload here is deliberately *not* the instance's own export, so the
    first import has real work to do and the second must find every name taken.
    """
    import_payload = {
        "tags": [{"name": "from-another-instance", "color": "#111111"}],
        "automation_rules": [{"name": "Foreign Rule"}],
        "saved_searches": [{"name": "Foreign Search", "query": "apt", "filters": {}}],
        "themes": [{"name": "Foreign Theme", "css_variables": {"bg": "#000"}}],
    }

    # First import creates everything.
    resp1 = await client.post("/api/backup/import", json=import_payload, headers=second_admin_headers)
    assert resp1.status_code == 200
    first = resp1.json()["imported"]
    assert first["tags"] == 1
    assert first["automation_rules"] == 1
    assert first["saved_searches"] == 1
    assert first["themes"] == 1

    # Second import is a no-op thanks to name-based dedup.
    resp2 = await client.post("/api/backup/import", json=import_payload, headers=second_admin_headers)
    assert resp2.status_code == 200
    second = resp2.json()["imported"]

    assert second["tags"] == 0
    assert second["automation_rules"] == 0
    assert second["saved_searches"] == 0
    assert second["themes"] == 0

    # Exactly one copy of each ended up in the instance.
    re_export = (await client.get("/api/backup/export", headers=second_admin_headers)).json()
    assert [t["name"] for t in re_export["tags"]].count("from-another-instance") == 1
    assert [r["name"] for r in re_export["automation_rules"]].count("Foreign Rule") == 1
    assert [s["name"] for s in re_export["saved_searches"]].count("Foreign Search") == 1
    assert [t["name"] for t in re_export["themes"]].count("Foreign Theme") == 1
