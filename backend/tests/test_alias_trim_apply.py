"""Applying an adjudicator alias trim on a type outside the merge registry.

The adjudicator files alias trims for every linkable type; the apply used to
look the entity up in the merge registry (actor/malware/vendor/product/tool)
and refused a country with "unsupported entity_type: country".
"""

import uuid

import pytest
from sqlalchemy import select

from app.models.country import Country, EntryCountry
from app.models.entity_maintenance import EntityMaintenanceLog

pytestmark = pytest.mark.asyncio


async def test_country_alias_trim_applies(client, admin_headers, db_session, test_entry):
    us = Country(name=f"United States {uuid.uuid4().hex[:6]}", aliases=["USA", "America"], article_count=1)
    db_session.add(us)
    await db_session.flush()
    db_session.add(EntryCountry(entry_id=test_entry.id, country_id=us.id, matched_names=["America"]))
    row = EntityMaintenanceLog(
        entity_type="country",
        entity_id=us.id,
        action="alias_collision",
        mode="shadow",
        before={"entity": {"id": str(us.id), "name": us.name, "aliases": ["USA", "America"]}},
        after={"kind": "adjudicator", "bad_alias": "America", "reason": "Bank of America, not the country."},
        applied=False,
    )
    db_session.add(row)
    await db_session.flush()

    # The Review queue's entity row names the alias, not just the reason.
    groups = (await client.get("/api/admin/hygiene/review-groups?entity_type=country", headers=admin_headers)).json()
    mine = [g for g in groups["groups"] if g["entity_id"] == str(us.id)]
    assert mine and mine[0]["trim_aliases"] == ["America"]

    resp = await client.post(f"/api/admin/hygiene/alias-collision/{row.id}/apply", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["skipped"] is False

    await db_session.refresh(us)
    assert us.aliases == ["USA"]
    # The link only "America" matched goes with the alias.
    left = (await db_session.execute(select(EntryCountry).where(EntryCountry.country_id == us.id))).scalars().all()
    assert left == []
