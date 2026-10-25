"""scripts/maintenance/clean_tool_catalog.py — plan and apply against the test DB."""

import importlib.util
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from sqlalchemy import func, select

from app.models.entity_index import EntityNameDenylist
from app.models.product import EntryProduct, Product
from app.models.tool import EntryTool, Tool

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "maintenance" / "clean_tool_catalog.py"

pytestmark = pytest.mark.skipif(not SCRIPT.exists(), reason="repo-root scripts/ not mounted")


def _load():
    spec = importlib.util.spec_from_file_location("clean_tool_catalog", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _NoCommit:
    """The test session, with commit downgraded to flush so the fixture's
    per-test schema still sees everything the script wrote."""

    def __init__(self, db):
        self._db = db

    def __getattr__(self, name):
        return getattr(self._db, name)

    async def commit(self):
        await self._db.flush()


async def _links(db, junction, entry_id) -> int:
    stmt = select(func.count()).select_from(junction).where(junction.entry_id == entry_id)
    return (await db.execute(stmt)).scalar_one()


async def test_dry_run_plans_and_apply_moves_and_deletes(db_session, test_entry, monkeypatch):
    mod = _load()
    kernel = Tool(name="Linux Kernel", aliases=[])
    py = Tool(name="Python", aliases=[])
    py3 = Tool(name="python3", aliases=[])
    sha = Tool(name="SHA-256", aliases=["SHA256"])
    real = Tool(name="Mimikatz", aliases=[])
    existing_product = Product(name="Linux kernel", aliases=[])
    db_session.add_all([kernel, py, py3, sha, real, existing_product])
    await db_session.flush()
    for t in (kernel, py3, sha, real):
        db_session.add(EntryTool(entry_id=test_entry.id, tool_id=t.id, source="autolink"))
    await db_session.flush()

    plan = await mod.build_plan(db_session, mod.RECLASSIFY, mod.DELETE, top_n=10)
    by_name = {r["tool_name"]: r for r in plan.reclassify}
    assert by_name["Linux Kernel"]["target_id"] == existing_product.id
    assert by_name["python3"]["merges_new"] is True
    assert [r["tool_name"] for r in plan.delete] == ["SHA-256"]
    assert plan.delete[0]["deny"] == ["SHA-256", "SHA256"]
    assert {t["tool_name"]: t["planned"] for t in plan.top}["Mimikatz"] == ""
    # Dry run wrote nothing.
    assert (await db_session.execute(select(func.count()).select_from(Tool))).scalar_one() == 5

    @asynccontextmanager
    async def fake_session():
        yield _NoCommit(db_session)

    async def no_refresh(db):
        return 0

    monkeypatch.setattr("app.database.async_session", fake_session)
    monkeypatch.setattr("app.intelligence.autolinker.refresh_vocabulary", no_refresh)
    done = await mod.apply_plan(plan)
    assert done == {"reclassify": 3, "delete": 1, "failed": 0}

    assert (await db_session.execute(select(Tool.name))).scalars().all() == ["Mimikatz"]
    products = {p.name: p for p in (await db_session.execute(select(Product))).scalars()}
    assert set(products) == {"Linux kernel", "Python"}
    assert "python3" in {a.lower() for a in products["Python"].aliases or []}
    # Kernel and python3 links moved onto products; the SHA-256 link is gone.
    assert await _links(db_session, EntryProduct, test_entry.id) == 2
    assert await _links(db_session, EntryTool, test_entry.id) == 1
    # Both spellings normalize to one do-not-recreate row.
    denied = (await db_session.execute(select(EntityNameDenylist))).scalars().all()
    assert [(d.entity_type, d.source) for d in denied] == [("tool", "do_not_recreate")]
    assert denied[0].display_name in {"SHA-256", "SHA256"}
