"""resolve_country_name: the alpha-2 → stored-name resolver the Malpedia and
MISP Galaxy syncs import. It was deleted in the sector refactor while both
imports stayed, so each sync raised ImportError on every run from 2026-10-18."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.actor_attributes import normalize_country, resolve_country_name
from app.models.country import Country


def test_normalize_country_drops_placeholders():
    assert normalize_country(" Unknown ") is None
    assert normalize_country("n/a") is None
    assert normalize_country(None) is None
    assert normalize_country(" China ") == "China"


@pytest.mark.asyncio
async def test_resolve_country_name_maps_iso_code_to_stored_name(db_session: AsyncSession):
    db_session.add(Country(name="China", iso_code="CN"))
    await db_session.flush()

    assert await resolve_country_name(db_session, "cn") == "China"
    # Full names and unknown codes pass through; placeholders are dropped.
    assert await resolve_country_name(db_session, "China") == "China"
    assert await resolve_country_name(db_session, "ZZ") == "ZZ"
    assert await resolve_country_name(db_session, "Unknown") is None
    assert await resolve_country_name(db_session, None) is None
