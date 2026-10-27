"""Number entity fields (`cve.cvss`, `cve.poc`) run as numbers, not text.

The text paths call lower()/ILIKE, which Postgres refuses on a numeric
or integer column, so `cve.cvss:9` used to fail the whole search.
"""

from decimal import Decimal

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cve import CVE
from app.search.entity_builder import execute_entity_queries
from app.search.query_parser import parse_query
from app.search.query_planner import build_execution_plan


async def _cve_ids(db: AsyncSession, query: str) -> set[str]:
    plan = build_execution_plan(parse_query(query))
    results, _ = await execute_entity_queries(db, plan.entity_nodes, limit=50)
    return {r["cve_id"] for r in results}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "query,expected",
    [
        ("cve.cvss:9", {"CVE-2026-0001"}),
        ("cve.cvss:9.8", {"CVE-2026-0002"}),
        ("cve.cvss:9*", {"CVE-2026-0001", "CVE-2026-0002"}),
        ("cve.cvss:>9", {"CVE-2026-0002"}),
        ("cve.cvss:high", set()),
        ("cve.poc:2", {"CVE-2026-0003"}),
    ],
)
async def test_cvss_filters(db_session: AsyncSession, query, expected):
    db_session.add_all(
        [
            CVE(cve_id="CVE-2026-0001", cvss_score=Decimal("9.0")),
            CVE(cve_id="CVE-2026-0002", cvss_score=Decimal("9.8")),
            CVE(cve_id="CVE-2026-0003", cvss_score=Decimal("5.3"), github_poc_count=2),
        ]
    )
    await db_session.flush()
    assert await _cve_ids(db_session, query) == expected
