"""Tests for the authoritative CVE↔vendor/product affects-links (cve_affected)."""

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.cpe_resolver import CPEIndex, build_cpe_index
from app.intelligence.cve import parse_cpe_affected, sync_cve_affected
from app.models.cve import CVE
from app.models.cve_affected import CVEAffected
from app.models.product import Product
from app.models.vendor import Vendor


def _nvd_config(*cpes: str) -> dict:
    return {
        "configurations": [{"nodes": [{"cpeMatch": [{"criteria": c, "versionEndIncluding": "9.9"} for c in cpes]}]}]
    }


@pytest.fixture
async def entities(db_session: AsyncSession):
    vendor = Vendor(name="Microsoft", aliases=["MSFT"])
    other_vendor = Vendor(name="VMware", metadata_={"cpe_names": ["vmware"]})
    db_session.add_all([vendor, other_vendor])
    await db_session.flush()
    outlook = Product(name="Outlook", vendor_id=vendor.id)
    vcenter = Product(name="vCenter", vendor_id=other_vendor.id, metadata_={"cpe_names": ["vcenter_server"]})
    # Same-named product under no vendor — exercises ambiguity guard
    generic = Product(name="Windows")
    db_session.add_all([outlook, vcenter, generic])
    await db_session.flush()
    return {"vendor": vendor, "other_vendor": other_vendor, "outlook": outlook, "vcenter": vcenter}


class TestCPEResolver:
    async def test_resolves_by_name_alias_and_cpe_names(self, db_session, entities):
        index = await build_cpe_index(db_session)
        assert index.resolve_vendor("microsoft") == entities["vendor"].id
        assert index.resolve_vendor("msft") == entities["vendor"].id
        assert index.resolve_vendor("vmware") == entities["other_vendor"].id
        assert index.resolve_vendor("unknown_vendor") is None

    async def test_underscore_form_matches_spaced_name(self, db_session, entities):
        index = await build_cpe_index(db_session)
        vid, pid = index.resolve_pair("vmware", "vcenter_server")
        assert vid == entities["other_vendor"].id
        assert pid == entities["vcenter"].id

    async def test_product_prefers_vendor_scope(self, db_session, entities):
        index = await build_cpe_index(db_session)
        vid, pid = index.resolve_pair("microsoft", "outlook")
        assert vid == entities["vendor"].id
        assert pid == entities["outlook"].id

    def test_empty_index_resolves_nothing(self):
        index = CPEIndex()
        assert index.resolve_pair("microsoft", "outlook") == (None, None)

    async def test_compact_form_matches_spaced_and_hyphenated_names(self, db_session, entities):
        redhat = Vendor(name="Red Hat")
        dlink = Vendor(name="D-Link")
        db_session.add_all([redhat, dlink])
        await db_session.flush()
        rhel = Product(name="Enterprise Linux", vendor_id=redhat.id)
        db_session.add(rhel)
        await db_session.flush()
        index = await build_cpe_index(db_session)
        # CPE segments have no separators; entity names do
        assert index.resolve_vendor("redhat") == redhat.id
        assert index.resolve_vendor("dlink") == dlink.id
        assert index.resolve_pair("redhat", "enterprise_linux")[1] == rhel.id


class TestParseCPE:
    def test_parses_and_groups(self):
        data = _nvd_config(
            "cpe:2.3:a:microsoft:outlook:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:microsoft:outlook:2016:*:*:*:*:*:*:*",
            "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*",
        )
        parsed = parse_cpe_affected(data)
        pairs = {(p["vendor"], p["product"]) for p in parsed}
        assert pairs == {("microsoft", "outlook"), ("microsoft", "windows_10")}

    def test_empty_configurations(self):
        assert parse_cpe_affected({}) == []


class TestSyncCVEAffected:
    async def test_upsert_is_idempotent_and_resolves(self, db_session, entities):
        cve = CVE(cve_id="CVE-2024-0001")
        db_session.add(cve)
        await db_session.flush()
        parsed = parse_cpe_affected(_nvd_config("cpe:2.3:a:microsoft:outlook:*:*:*:*:*:*:*:*"))
        index = await build_cpe_index(db_session)

        n1 = await sync_cve_affected(db_session, cve.id, parsed, index)
        n2 = await sync_cve_affected(db_session, cve.id, parsed, index)
        assert n1 == n2 == 1

        rows = (await db_session.execute(select(CVEAffected).where(CVEAffected.cve_id == cve.id))).scalars().all()
        assert len(rows) == 1
        assert rows[0].cpe_vendor == "microsoft"
        assert rows[0].vendor_id == entities["vendor"].id
        assert rows[0].product_id == entities["outlook"].id
        assert rows[0].resolved_at is not None

    async def test_unmatched_pair_keeps_null_fks(self, db_session, entities):
        cve = CVE(cve_id="CVE-2024-0002")
        db_session.add(cve)
        await db_session.flush()
        parsed = parse_cpe_affected(_nvd_config("cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"))
        index = await build_cpe_index(db_session)
        await sync_cve_affected(db_session, cve.id, parsed, index)
        row = (await db_session.execute(select(CVEAffected).where(CVEAffected.cve_id == cve.id))).scalar_one()
        assert row.cpe_vendor == "linux"
        assert row.vendor_id is None
        assert row.product_id is None
        assert row.resolved_at is None


@pytest.fixture
async def affected_data(db_session: AsyncSession, entities):
    """Three CVEs: one Outlook (KEV), one vendor-level Microsoft, one vCenter."""
    cve_kev = CVE(cve_id="CVE-2023-23397", severity="CRITICAL", cvss_score=9.8, epss_score=0.945, is_kev=True)
    cve_vl = CVE(cve_id="CVE-2024-38200", severity="MEDIUM", cvss_score=7.5, exploit_availability="weaponized")
    cve_vc = CVE(cve_id="CVE-2024-37079", severity="CRITICAL", cvss_score=9.8)
    db_session.add_all([cve_kev, cve_vl, cve_vc])
    await db_session.flush()
    index = await build_cpe_index(db_session)
    await sync_cve_affected(
        db_session,
        cve_kev.id,
        parse_cpe_affected(_nvd_config("cpe:2.3:a:microsoft:outlook:*:*:*:*:*:*:*:*")),
        index,
    )
    await sync_cve_affected(
        db_session,
        cve_vl.id,
        parse_cpe_affected(_nvd_config("cpe:2.3:a:microsoft:office_long_term_servicing_channel:*:*:*:*:*:*:*:*")),
        index,
    )
    await sync_cve_affected(
        db_session,
        cve_vc.id,
        parse_cpe_affected(_nvd_config("cpe:2.3:a:vmware:vcenter_server:*:*:*:*:*:*:*:*")),
        index,
    )
    await db_session.commit()
    return {"kev": cve_kev, "vendor_level": cve_vl, "vcenter": cve_vc}


class TestAffectedCVEEndpoints:
    async def test_product_affected_cves(self, client: AsyncClient, auth_headers, entities, affected_data):
        resp = await client.get(f"/api/products/{entities['outlook'].id}/affected-cves", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        assert body["items"][0]["cve_id"] == "CVE-2023-23397"
        assert body["items"][0]["is_kev"] is True
        assert body["items"][0]["products"][0]["name"] == "Outlook"
        assert body["counts"]["kev"] == 1

    async def test_vendor_rollup_includes_products_and_vendor_level(
        self, client: AsyncClient, auth_headers, entities, affected_data
    ):
        resp = await client.get(f"/api/vendors/{entities['vendor'].id}/affected-cves", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        got = {i["cve_id"]: i for i in body["items"]}
        # Outlook CVE + vendor-level Office CVE; NOT the VMware vCenter CVE
        assert set(got) == {"CVE-2023-23397", "CVE-2024-38200"}
        assert got["CVE-2023-23397"]["products"][0]["name"] == "Outlook"
        assert got["CVE-2023-23397"]["vendor_level"] is False
        assert got["CVE-2024-38200"]["vendor_level"] is True
        assert body["vendor_level_count"] == 1
        assert body["by_product"][0]["name"] == "Outlook"

    async def test_vendor_filters(self, client: AsyncClient, auth_headers, entities, affected_data):
        base = f"/api/vendors/{entities['vendor'].id}/affected-cves"
        kev = (await client.get(base, params={"kev": True}, headers=auth_headers)).json()
        assert [i["cve_id"] for i in kev["items"]] == ["CVE-2023-23397"]
        exploited = (await client.get(base, params={"exploited": True}, headers=auth_headers)).json()
        assert [i["cve_id"] for i in exploited["items"]] == ["CVE-2024-38200"]
        sev = (await client.get(base, params={"severity": "critical"}, headers=auth_headers)).json()
        assert [i["cve_id"] for i in sev["items"]] == ["CVE-2023-23397"]
        vl = (await client.get(base, params={"vendor_level": True}, headers=auth_headers)).json()
        assert [i["cve_id"] for i in vl["items"]] == ["CVE-2024-38200"]

    async def test_cve_affected_rows(self, client: AsyncClient, auth_headers, entities, affected_data):
        resp = await client.get(f"/api/cves/{affected_data['kev'].id}/affected", headers=auth_headers)
        assert resp.status_code == 200
        rows = resp.json()
        assert len(rows) == 1
        assert rows[0]["cpe_vendor"] == "microsoft"
        assert rows[0]["vendor_name"] == "Microsoft"
        assert rows[0]["product_name"] == "Outlook"
        # Accepts the CVE string id too
        resp2 = await client.get("/api/cves/CVE-2023-23397/affected", headers=auth_headers)
        assert resp2.status_code == 200
        assert resp2.json() == rows

    async def test_unknown_ids_404(self, client: AsyncClient, auth_headers, affected_data):
        missing = uuid.uuid4()
        assert (await client.get(f"/api/products/{missing}/affected-cves", headers=auth_headers)).status_code == 404
        assert (await client.get(f"/api/vendors/{missing}/affected-cves", headers=auth_headers)).status_code == 404


class TestPrefixAndVendorGuard:
    async def test_prefix_rule_matches_versioned_forms(self, db_session, entities):
        entities["outlook"].metadata_ = {"cpe_names": ["outlook_rt", "windows_server*"]}
        await db_session.flush()
        index = await build_cpe_index(db_session)
        vid, pid = index.resolve_pair("microsoft", "windows_server_2019")
        assert pid == entities["outlook"].id
        vid, pid = index.resolve_pair("microsoft", "windows_serverless")  # prefix is dumb on purpose
        assert pid == entities["outlook"].id
        # "windows" exact-matches the vendor-less Windows product (intended)
        vid, pid = index.resolve_pair("microsoft", "windows")
        assert pid is not None and pid != entities["outlook"].id

    async def test_exact_match_beats_prefix(self, db_session, entities):
        entities["outlook"].metadata_ = {"cpe_names": ["outlook*"]}
        await db_session.flush()
        index = await build_cpe_index(db_session)
        # exact alias/name match on Outlook still wins over any prefix expansion
        assert index.resolve_pair("microsoft", "outlook")[1] == entities["outlook"].id

    async def test_refuses_cross_vendor_single_candidate(self, db_session, entities):
        # "vcenter_server" only maps to vCenter (VMware). A resolved DIFFERENT
        # vendor must not steal the link.
        index = await build_cpe_index(db_session)
        vid, pid = index.resolve_pair("microsoft", "vcenter_server")
        assert vid == entities["vendor"].id
        assert pid is None


class TestReenrichSweep:
    async def test_reenrich_targets_empty_blob_and_stamps_failures(self, db_session, monkeypatch):
        from contextlib import asynccontextmanager

        import app.workers.maintenance as maintenance

        stuck = CVE(cve_id="CVE-2023-4966", description="CitrixBleed", is_kev=True, nvd_data={})
        healthy = CVE(cve_id="CVE-2024-1111", nvd_data={"id": "CVE-2024-1111", "configurations": []})
        junk = CVE(cve_id="CVE-9999-99999", nvd_data={})
        db_session.add_all([stuck, healthy, junk])
        await db_session.flush()

        async def fake_enrich(cve_id, raise_on_rate_limit: bool = False):
            if cve_id == "CVE-2023-4966":
                return {
                    "cvss_score": 9.4,
                    "severity": "CRITICAL",
                    "description": "NetScaler ADC buffer over-read",
                    "affected_products": [
                        {
                            "vendor": "citrix",
                            "product": "netscaler_gateway",
                            "version_start": None,
                            "version_end": "14.1",
                        }
                    ],
                    "references": [],
                    "nvd_data": {"id": "CVE-2023-4966", "configurations": [{"nodes": []}]},
                }
            return None  # junk id — NVD has nothing

        monkeypatch.setattr("app.intelligence.cve.enrich_from_nvd", fake_enrich)

        @asynccontextmanager
        async def fake_session():
            yield db_session

        monkeypatch.setattr(maintenance, "_get_worker_session", fake_session)
        stats = await maintenance._reenrich_cve_nvd(batch_size=10)

        assert stats["attempted"] == 2  # healthy CVE not selected
        assert stats["enriched"] == 1
        assert stats["with_config"] == 1
        assert stats["pairs"] == 1
        await db_session.refresh(stuck)
        await db_session.refresh(junk)
        assert stuck.nvd_data.get("configurations") is not None
        assert float(stuck.cvss_score) == 9.4
        assert stuck.description == "CitrixBleed"  # existing description preserved
        assert junk.nvd_data.get("_enrich_attempts") == 1
        row = (await db_session.execute(select(CVEAffected).where(CVEAffected.cve_id == stuck.id))).scalar_one()
        assert row.cpe_product == "netscaler_gateway"
