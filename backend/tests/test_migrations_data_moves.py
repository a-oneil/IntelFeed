"""The enrichment migrations that move data, not just columns: each one's
upgrade and downgrade run against a recording ``alembic.op``, so the
statements they issue are checked without a database.

- c9v4a1l2s3x7: ``cves.aliases``, an empty array by default.
- w4k9e2s7v1c3: ``observables.asn`` to bigint, GreyNoise's made-up
  ``not_seen`` class to NULL with its context row deleted, ``vendors.country_id``.
  The downgrade empties the ASNs int4 can't hold before narrowing the column.
- x5n8b2k4c6d1: the IP sources run on their own; the other sharing sources
  wait to be asked. The downgrade moves back only rows still where the
  upgrade left them.
"""

import importlib.util
import re
import uuid
from pathlib import Path

import pytest

from alembic import op

VERSIONS = Path(__file__).resolve().parents[1] / "alembic" / "versions"

_OPS = (
    "execute",
    "alter_column",
    "add_column",
    "drop_column",
    "create_foreign_key",
    "drop_constraint",
    "create_index",
    "drop_index",
)


def _load(revision: str):
    (path,) = VERSIONS.glob(f"{revision}_*.py")
    spec = importlib.util.spec_from_file_location(f"migration_{revision}_{uuid.uuid4().hex}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def recorded(monkeypatch) -> list[tuple]:
    """Every ``op.<name>(...)`` call, in order, as ``(name, args, kwargs)``."""
    calls: list[tuple] = []
    for name in _OPS:
        monkeypatch.setattr(op, name, lambda *a, _n=name, **kw: calls.append((_n, a, kw)))
    return calls


def _sql(calls: list[tuple]) -> list[str]:
    return [re.sub(r"\s+", " ", a[0]).strip() for n, a, _ in calls if n == "execute"]


def test_cve_aliases_is_an_empty_array_by_default(recorded):
    migration = _load("c9v4a1l2s3x7")

    migration.upgrade()
    (added,) = recorded
    name, (table, column), _ = added
    assert (name, table, column.name) == ("add_column", "cves", "aliases")
    assert column.server_default.arg == "{}" and not column.nullable

    recorded.clear()
    migration.downgrade()
    assert recorded == [("drop_column", ("cves", "aliases"), {})]


def test_enrichment_columns_upgrade_moves_the_data_in_order(recorded):
    migration = _load("w4k9e2s7v1c3")

    migration.upgrade()

    assert [n for n, *_ in recorded] == [
        "alter_column",
        "execute",
        "execute",
        "add_column",
        "create_foreign_key",
        "create_index",
    ]
    _, (table, column), widen = recorded[0]
    assert (table, column) == ("observables", "asn")
    assert type(widen["type_"]).__name__ == "BigInteger" and type(widen["existing_type"]).__name__ == "Integer"
    assert _sql(recorded) == [
        "UPDATE observables SET noise_class = NULL WHERE noise_class = 'not_seen'",
        "DELETE FROM entity_context WHERE source_type = 'greynoise' AND key = 'noise_class' "
        "AND value = '\"not_seen\"'::jsonb",
    ]
    _, (table, column), _ = recorded[3]
    assert (table, column.name, column.nullable) == ("vendors", "country_id", True)
    _, fk, fk_kw = recorded[4]
    assert fk == ("vendors_country_id_fkey", "vendors", "countries", ["country_id"], ["id"])
    assert fk_kw == {"ondelete": "SET NULL"}
    assert recorded[5][1] == ("ix_vendors_country_id", "vendors", ["country_id"])


def test_enrichment_columns_downgrade_empties_wide_asns_before_narrowing(recorded):
    migration = _load("w4k9e2s7v1c3")

    migration.downgrade()

    names = [n for n, *_ in recorded]
    assert names == ["drop_index", "drop_constraint", "drop_column", "execute", "alter_column"]
    # Past int4's ceiling, an ASN is emptied rather than left to fail the cast.
    assert _sql(recorded) == ["UPDATE observables SET asn = NULL WHERE asn > 2147483647"]
    _, (table, column), narrow = recorded[4]
    assert (table, column) == ("observables", "asn")
    assert type(narrow["type_"]).__name__ == "Integer" and type(narrow["existing_type"]).__name__ == "BigInteger"
    assert recorded[2] == ("drop_column", ("vendors", "country_id"), {})
    # NULLed GreyNoise classes stay NULL: nothing writes 'not_seen' back.
    assert not any("not_seen" in s for s in _sql(recorded))


def test_ip_sources_upgrade_turns_them_on_and_parks_the_other_sharing_sources(recorded):
    migration = _load("x5n8b2k4c6d1")

    migration.upgrade()

    assert _sql(recorded) == [
        "UPDATE enrichment_sources SET is_enabled = true, trigger_mode = 'auto' "
        "WHERE source_type IN ('shodan', 'greynoise', 'cymru')",
        # Only rows on auto move to manual: a row already on manual (or off) is left as it is.
        "UPDATE enrichment_sources SET trigger_mode = 'manual' "
        "WHERE source_type IN ('virustotal', 'threatfox', 'urlhaus', 'malwarebazaar') AND trigger_mode = 'auto'",
    ]


def test_ip_sources_downgrade_moves_back_only_rows_the_upgrade_left_in_place(recorded):
    migration = _load("x5n8b2k4c6d1")

    migration.downgrade()

    assert _sql(recorded) == [
        "UPDATE enrichment_sources SET trigger_mode = 'manual' "
        "WHERE source_type IN ('shodan', 'greynoise', 'cymru') AND trigger_mode = 'auto'",
        "UPDATE enrichment_sources SET trigger_mode = 'auto' "
        "WHERE source_type IN ('virustotal', 'threatfox', 'urlhaus', 'malwarebazaar') AND trigger_mode = 'manual'",
    ]
    # is_enabled is not touched either way on the downgrade.
    assert not any("is_enabled" in s for s in _sql(recorded))
