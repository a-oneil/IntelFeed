"""The readiness probe behind the onboarding wizard's first and last steps."""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.country import Country
from app.models.feed import Feed


@pytest.mark.asyncio
async def test_status_reports_an_empty_instance_as_unseeded(client: AsyncClient, auth_headers: dict):
    response = await client.get("/api/onboarding/status", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()

    ref = data["reference_data"]
    assert ref["ok"] is False
    # Every seeder is named, so the step can list what's missing rather than
    # just saying "something is wrong".
    assert {"countries", "attack", "cwe", "vendors", "products"} <= set(ref["missing"])
    assert ref["remedy"].endswith("seed_all.py")
    assert "autolinker" in ref["consequence"]
    assert data["ready"] is False


@pytest.mark.asyncio
async def test_status_counts_feeds_by_poll_outcome(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    from datetime import UTC, datetime

    db_session.add_all(
        [
            Feed(title="polled", url="https://a.example/feed", last_fetched_at=datetime.now(UTC), error_count=0),
            Feed(title="broken", url="https://b.example/feed", last_fetched_at=datetime.now(UTC), error_count=9),
            Feed(title="fresh", url="https://c.example/feed", last_fetched_at=None, error_count=0),
        ]
    )
    await db_session.flush()

    data = (await client.get("/api/onboarding/status", headers=auth_headers)).json()
    assert data["feeds"] == {"total": 3, "polled_ok": 1, "errored": 1, "never_polled": 1}


@pytest.mark.asyncio
async def test_status_ignores_inactive_feeds(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    """A disabled feed shouldn't make the verify step claim coverage it hasn't got."""
    db_session.add(Feed(title="off", url="https://off.example/feed", is_active=False))
    await db_session.flush()

    data = (await client.get("/api/onboarding/status", headers=auth_headers)).json()
    assert data["feeds"]["total"] == 0


@pytest.mark.asyncio
async def test_reference_check_needs_a_real_catalog_not_one_row(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession
):
    """The floors exist so a hand-inserted row can't read as a finished seed."""
    db_session.add(Country(name="Testland", iso_code="TL"))
    await db_session.flush()

    data = (await client.get("/api/onboarding/status", headers=auth_headers)).json()
    countries = next(c for c in data["reference_data"]["checks"] if c["key"] == "countries")
    assert countries["count"] == 1
    assert countries["ok"] is False


@pytest.mark.asyncio
async def test_status_requires_authentication(client: AsyncClient):
    assert (await client.get("/api/onboarding/status")).status_code == 401


@pytest.mark.asyncio
async def test_status_is_open_to_non_admins(client: AsyncClient, auth_headers: dict):
    """A non-admin hitting an unusable instance deserves to be told why."""
    assert (await client.get("/api/onboarding/status", headers=auth_headers)).status_code == 200
