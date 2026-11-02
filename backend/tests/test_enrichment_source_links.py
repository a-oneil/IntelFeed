"""Sources that connect entities or describe them: Shodan's exposed CVEs,
Malpedia's family lookup and attribution, Wikidata's vendor country, sector
and victim websites, GitHub repositories of tools, VirusTotal as context only,
and entity context following a merge.

Fixtures in ``tests/fixtures/enrichment/`` are trimmed live answers
(2026-10-29): Malpedia ``get/family/win.emotet`` and ``find/family/lockbit``,
GitHub ``GET /repos/BloodHoundAD/BloodHound`` (renamed, so the answer is
SpecterOps/BloodHound-Legacy) and a Wikidata query-service answer for
microsoft.com and siemens.com.
"""

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from app.enrichment.adapters.malpedia import family_facts, pick_actor, pick_family
from app.enrichment.context import prune_expired_context, rehome_context
from app.enrichment.github_repo import GitHubRepoSource, fetch_repo, repo_facts, repo_path
from app.enrichment.manifest import Column, Relation
from app.enrichment.registry import SOURCE_REGISTRY
from app.enrichment.relations import apply_relations, relations_for
from app.enrichment.wikidata import countries_by_domain, victim_domain, website_query, website_spellings
from app.intelligence.relationship_matrix import is_allowed_relationship
from app.intelligence.sectors import sector_uuid
from app.models.cve import CVE
from app.models.enrichment import EnrichmentResult, EntityContext, EntityRelationClaim
from app.models.entity_relationship import EntityRelationship
from app.models.malware_family import MalwareFamily
from app.models.observable import Observable
from app.models.threat_actor import ThreatActor
from app.models.vendor import Vendor

FIXTURES = Path(__file__).parent / "fixtures" / "enrichment"


def _fixture(name: str):
    return json.loads((FIXTURES / name).read_text())


# ── The matrix and the manifests ─────────────────────────────────────


def test_new_triples_are_in_the_matrix():
    assert is_allowed_relationship("observable", "exposes", "cve")
    assert is_allowed_relationship("vendor", "operates_in", "sector")
    assert is_allowed_relationship("malware", "attributed_to", "threat_actor")


def test_relations_apply_only_where_the_matrix_allows():
    shodan, malpedia, wikidata = (SOURCE_REGISTRY[s] for s in ("shodan", "malpedia", "wikidata"))
    assert [r.relation for r in relations_for(shodan, "observable")] == ["exposes"]
    assert [r.relation for r in relations_for(malpedia, "malware")] == ["attributed_to"]
    # No tool → actor attribution in the matrix: a tool's list stays context.
    assert relations_for(malpedia, "tool") == ()
    assert [r.relation for r in relations_for(wikidata, "vendor")] == ["operates_in"]
    assert relations_for(wikidata, "product") == ()


def test_sources_that_share_an_observable_wait_to_be_asked_except_the_ip_scanners():
    from app.enrichment.manifest import Egress

    sharing = [cls for cls in SOURCE_REGISTRY.values() if cls.egress == Egress.SHARES_IOC]
    assert {"shodan", "greynoise", "virustotal"} <= {cls.source_type for cls in sharing}
    assert {cls.source_type for cls in sharing if cls.default_trigger_mode != "manual"} == {"shodan", "greynoise"}


def test_bazaar_holds_unknown_families_like_threatfox():
    def families(source_type):
        return next(r for r in SOURCE_REGISTRY[source_type].relations() if r.key == "families")

    assert families("malwarebazaar").hold is True
    assert families("threatfox").hold is True
    assert families("urlhaus").hold is False  # URLhaus tags mix families with file types


def test_virustotal_writes_no_network_columns():
    targets = {c.target for c in SOURCE_REGISTRY["virustotal"].columns()}
    assert not targets & {"observable.asn", "observable.asn_org", "observable.geo_country"}
    assert all(t.startswith("observable.reputation.") for t in targets)


def test_wikidata_fills_vendor_and_victim_country_columns():
    columns = {c.target: c for c in SOURCE_REGISTRY["wikidata"].outputs if isinstance(c, Column)}
    assert columns["vendor.country_id"].resolve == "country_id"
    assert columns["ransomware_victim.country_id"].resolve == "country_id"
    industry = next(o for o in SOURCE_REGISTRY["wikidata"].outputs if isinstance(o, Relation))
    assert (industry.key, industry.hold) == ("industry", False)


def test_github_repo_source_manifest():
    assert GitHubRepoSource.applies_to == {"tool": None}
    assert GitHubRepoSource.columns() == ()
    assert GitHubRepoSource.key_setting == "github_token"
    (job,) = GitHubRepoSource.jobs
    assert job.schedule["type"] == "crontab" and "day_of_week" in job.schedule  # weekly


# ── Malpedia ─────────────────────────────────────────────────────────


def test_malpedia_picks_only_an_exact_family():
    lockbit = _fixture("malpedia_find_family_lockbit.json")
    # One family on three platforms: Windows wins.
    assert pick_family("LockBit", lockbit) == "win.lockbit"
    assert pick_family("ABCD Ransomware", lockbit) == "win.lockbit"  # an alternative name
    # A substring is not a match ("lock" is in four ids).
    assert pick_family("lock", lockbit) is None
    assert pick_family("Cobalt Strike", [{"name": "win.cobalt_strike", "alt_names": []}]) == "win.cobalt_strike"
    # Two families both list "qbot": the Windows one is the banking trojan.
    qbot = [
        {"name": "elf.bashlite", "alt_names": ["Gafgyt", "qbot"]},
        {"name": "win.qakbot", "alt_names": ["Qbot", "Quakbot"]},
    ]
    assert pick_family("Qbot", qbot) == "win.qakbot"
    assert pick_family("nothing", qbot) is None
    two_linux = [{"name": "elf.a", "alt_names": ["x"]}, {"name": "elf.b", "alt_names": ["x"]}]
    assert pick_family("x", two_linux) is None


def test_malpedia_picks_an_actor_by_name_before_a_synonym():
    hits = [
        {"name": "lazarus_group", "common_name": "Lazarus Group", "synonyms": ["Andariel", "Hidden Cobra"]},
        {"name": "andariel", "common_name": "Andariel", "synonyms": []},
    ]
    assert pick_actor("Andariel", hits) == "andariel"
    assert pick_actor("Hidden Cobra", hits) == "lazarus_group"
    assert pick_actor("Nobody", hits) is None


def test_malpedia_family_facts_build_the_page_and_find_github_past_ten():
    emotet = _fixture("malpedia_family_win_emotet.json")
    facts = family_facts("win.emotet", emotet, "Emotet")
    assert facts["malpedia_url"] == "https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet"
    assert len(facts["urls"]) == 10
    # Emotet's first github.com reference is past the tenth.
    assert facts["github_urls"][0] == "https://github.com/cecio/EMOTET-2020-Reversing"
    assert facts["attribution"] == ["GOLD CABIN", "MUMMY SPIDER", "Mealybug"]


async def test_malpedia_asks_find_then_get():
    emotet = _fixture("malpedia_family_win_emotet.json")
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/api/find/family/Emotet":
            return httpx.Response(200, json=[{"name": "win.emotet", "alt_names": ["Geodo", "Heodo"]}])
        if request.url.path == "/api/get/family/win.emotet":
            return httpx.Response(200, json=emotet)
        return httpx.Response(404, json={"detail": "No Family matches the given query."})

    from app.enrichment.adapters.malpedia import MalpediaAdapter

    adapter = MalpediaAdapter()
    adapter.http = lambda timeout=10, **kw: httpx.AsyncClient(transport=httpx.MockTransport(handler))
    data = (await adapter.enrich("malware", "Emotet")).parsed_data
    assert [r.url.path for r in requests] == ["/api/find/family/Emotet", "/api/get/family/win.emotet"]
    assert data["family_id"] == "win.emotet"

    requests.clear()
    assert (await adapter.enrich("tool", "Unknownthing")).parsed_data == {"found": False}
    assert [r.url.path for r in requests] == ["/api/find/family/Unknownthing"]


# ── GitHub repositories ──────────────────────────────────────────────


@pytest.mark.parametrize(
    ("url", "path"),
    [
        ("https://github.com/gentilkiwi/mimikatz", "gentilkiwi/mimikatz"),
        ("https://github.com/GhostPack/Rubeus/tree/master", "GhostPack/Rubeus"),
        ("https://github.com/a/b.git", "a/b"),
        ("https://github.com/a/b.git/", "a/b"),
        ("https://github.com/a/b?tab=readme#top", "a/b"),
        ("https://gist.github.com/x/y", None),
        ("https://github.com/gentilkiwi", None),  # a user page, not a repository
        ("https://github.com/", None),
        ("https://example.com/a/b", None),
        ("github.com/a/b", None),
        ("", None),
        (None, None),
    ],
)
def test_repo_path(url, path):
    assert repo_path(url) == path


def test_repo_facts_from_a_live_answer():
    facts = repo_facts(_fixture("github_repo_bloodhound_legacy.json"))
    assert facts == {
        "found": True,
        "full_name": "SpecterOps/BloodHound-Legacy",
        "stars": 10623,
        "pushed_at": "2026-03-02",
        "archived": False,
        "license": "GPL-3.0",
        "repo": {
            "url": "https://github.com/SpecterOps/BloodHound-Legacy",
            "label": "SpecterOps/BloodHound-Legacy",
        },
    }
    assert repo_facts({"license": {"spdx_id": "NOASSERTION"}, "topics": ["c2", 3]}) == {
        "found": True,
        "archived": False,
        "topics": ["c2"],
    }


async def test_fetch_repo_sends_the_token_and_reads_a_missing_repo():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/repos/BloodHoundAD/BloodHound":
            return httpx.Response(200, json=_fixture("github_repo_bloodhound_legacy.json"))
        return httpx.Response(404, json={"message": "Not Found"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        found = await fetch_repo(client, "BloodHoundAD/BloodHound", "ghp_test")
        missing = await fetch_repo(client, "nobody/nothing")
    assert found["stars"] == 10623
    assert seen[0].headers["Authorization"] == "Bearer ghp_test"
    assert "Authorization" not in seen[1].headers
    assert missing == {"found": False}


async def test_fetch_repo_reads_a_blocked_repo_as_missing_and_a_rate_limit_as_a_refusal():
    """GitHub sends 403 both for a repository it won't show and for its rate
    limits; only the second carries a rate-limit signal."""
    from app.enrichment.gateway import RateLimited

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/blocked/repo":
            return httpx.Response(403, json={"message": "Repository access blocked"})
        return httpx.Response(
            403,
            headers={"X-RateLimit-Remaining": "0", "Retry-After": "30"},
            json={"message": "API rate limit exceeded"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        assert await fetch_repo(client, "blocked/repo") == {"found": False}
        with pytest.raises(RateLimited) as exc:
            await fetch_repo(client, "busy/repo")
    assert exc.value.retry_after == 30
    assert 403 not in GitHubRepoSource.throttle_statuses


async def test_github_repo_sync_skips_a_blocked_repo_and_a_server_error_but_stops_on_a_throttle(db_session):
    from app.enrichment.gateway import SourceGateway
    from app.enrichment.github_repo import sync_github_repos
    from app.models.tool import Tool

    blocked = Tool(name="Ghreposync Blocked", github_url="https://github.com/blocked/repo")
    broken = Tool(name="Ghreposync Broken", github_url="https://github.com/broken/repo")
    fine = Tool(name="Ghreposync Fine", github_url="https://github.com/BloodHoundAD/BloodHound")
    db_session.add_all([blocked, broken, fine, Tool(name="Ghreposync User", github_url="https://github.com/someone")])
    await db_session.flush()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/blocked/repo":
            return httpx.Response(403, json={"message": "Repository access blocked"})
        if request.url.path == "/repos/broken/repo":
            return httpx.Response(500)
        return httpx.Response(200, json=_fixture("github_repo_bloodhound_legacy.json"))

    gateway = SourceGateway(
        "github_repo",
        rate_limit_config={"requests_per_period": 100, "period_seconds": 60},
        throttle_statuses=GitHubRepoSource.throttle_statuses,
        inner=httpx.MockTransport(handler),
    )
    stats = await sync_github_repos(db_session, gateway)
    # Keyless, the blocked repository's 403 is an answer (found: False), not a
    # refusal: the run goes on. The 500 costs that tool only; the user page
    # is skipped without a request.
    assert stats["stopped"] is None
    assert (stats["failed"], stats["skipped"]) == (1, 1)
    stored = {
        r.entity_id: r.parsed_data
        for r in (
            await db_session.execute(select(EnrichmentResult).where(EnrichmentResult.source_type == "github_repo"))
        ).scalars()
    }
    assert stored[blocked.id] == {"found": False}
    assert stored[fine.id]["stars"] == 10623
    assert broken.id not in stored

    # A throttle stops the run and keeps what it did.
    throttled = SourceGateway(
        "github_repo",
        rate_limit_config={"requests_per_period": 100, "period_seconds": 60},
        throttle_statuses=GitHubRepoSource.throttle_statuses,
        inner=httpx.MockTransport(lambda request: httpx.Response(429, headers={"Retry-After": "5"})),
    )
    stats = await sync_github_repos(db_session, throttled)
    assert stats["stopped"] == "rate_limited" and stats["written"] == 0


async def test_github_repo_sync_stores_context_for_tools(db_session):
    from app.enrichment.gateway import SourceGateway
    from app.enrichment.github_repo import sync_github_repos
    from app.models.tool import Tool

    tool = Tool(name="Ghreposync Tool", github_url="https://github.com/BloodHoundAD/BloodHound")
    gone = Tool(name="Ghreposync Gone", github_url="https://github.com/nobody/nothing")
    db_session.add_all([tool, gone])
    await db_session.flush()

    asked: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        asked.append(request.url.path)
        if request.url.path == "/repos/BloodHoundAD/BloodHound":
            return httpx.Response(200, json=_fixture("github_repo_bloodhound_legacy.json"))
        return httpx.Response(404, json={"message": "Not Found"})

    gateway = SourceGateway(
        "github_repo",
        rate_limit_config={"requests_per_period": 100, "period_seconds": 60},
        inner=httpx.MockTransport(handler),
    )
    stats = await sync_github_repos(db_session, gateway)
    assert stats["stopped"] is None
    assert {"/repos/BloodHoundAD/BloodHound", "/repos/nobody/nothing"} <= set(asked)

    rows = (
        await db_session.execute(
            select(EntityContext).where(EntityContext.entity_id == tool.id, EntityContext.source_type == "github_repo")
        )
    ).scalars()
    context = {r.key: r.value for r in rows}
    assert context["stars"] == 10623
    assert context["license"] == "GPL-3.0"
    assert context["archived"] is False

    # Fresh answers (found or not) aren't asked for again.
    asked.clear()
    await sync_github_repos(db_session, gateway)
    assert not {"/repos/BloodHoundAD/BloodHound", "/repos/nobody/nothing"} & set(asked)


# ── Wikidata: victims by website ─────────────────────────────────────


def test_victim_domains_and_website_spellings():
    assert victim_domain("https://WWW.Acme.co.uk/contact") == "acme.co.uk"
    assert victim_domain("Acme Corp") is None
    assert victim_domain("acme") is None
    assert victim_domain(None) is None
    assert set(website_spellings("www.acme.com")) == {
        "https://acme.com/",
        "https://acme.com",
        "https://www.acme.com/",
        "https://www.acme.com",
        "http://acme.com/",
        "http://acme.com",
        "http://www.acme.com/",
        "http://www.acme.com",
    }
    query = website_query(["acme.com"])
    assert "<https://www.acme.com/>" in query and "wdt:P856" in query and "wdt:P297" in query


def test_countries_by_domain_from_a_live_answer():
    bindings = _fixture("wikidata_sparql_websites.json")["results"]["bindings"]
    assert countries_by_domain(bindings) == {
        "microsoft.com": {"qid": "Q2283", "iso": "US"},
        "siemens.com": {"qid": "Q81230", "iso": "DE"},
    }

    # Two items claiming one website: no telling which, so neither.
    def row(site, qid, iso):
        item = f"http://www.wikidata.org/entity/{qid}"
        return {"site": {"value": site}, "item": {"value": item}, "iso": {"value": iso}}

    clash = [row("https://acme.com/", "Q1", "US"), row("https://www.acme.com", "Q2", "GB")]
    assert countries_by_domain(clash) == {}


# ── Relations ────────────────────────────────────────────────────────


async def _claims(db, source_type, entity_id) -> list[EntityRelationClaim]:
    rows = await db.execute(
        select(EntityRelationClaim).where(
            EntityRelationClaim.source_type == source_type, EntityRelationClaim.entity_id == entity_id
        )
    )
    return list(rows.scalars())


async def test_shodan_vulns_link_tracked_cves_only(db_session):
    cve = CVE(cve_id="CVE-2024-39001")
    obs = Observable(kind="ipv4", value="198.51.100.77", base_confidence=0.8, current_confidence=0.8)
    db_session.add_all([cve, obs])
    await db_session.flush()

    parsed = {"cve_ids": ["CVE-2024-39001", "CVE-1999-99999", "not-a-cve"]}
    assert await apply_relations(db_session, "observable", obs.id, "shodan", parsed)

    edge = (
        await db_session.execute(select(EntityRelationship).where(EntityRelationship.source_id == obs.id))
    ).scalar_one()
    assert (edge.source_type, edge.relationship_type, edge.target_type, edge.target_id) == (
        "observable",
        "exposes",
        "cve",
        cve.id,
    )
    assert edge.source == "enrichment"
    # Untracked CVEs are dropped, not held.
    assert [c.target_name for c in await _claims(db_session, "shodan", obs.id)] == ["CVE-2024-39001"]


async def test_malpedia_attribution_links_a_family_to_its_actor(db_session):
    family = MalwareFamily(name="Srclinks Emotet")
    actor = ThreatActor(name="Srclinks Mummy Spider")
    db_session.add_all([family, actor])
    await db_session.flush()

    parsed = {"attribution": ["Srclinks Mummy Spider", "Srclinks Gold Cabin"]}
    assert await apply_relations(db_session, "malware", family.id, "malpedia", parsed)

    edge = (
        await db_session.execute(select(EntityRelationship).where(EntityRelationship.source_id == family.id))
    ).scalar_one()
    assert (edge.relationship_type, edge.target_type, edge.target_id) == ("attributed_to", "threat_actor", actor.id)
    claims = {c.target_name: c for c in await _claims(db_session, "malpedia", family.id)}
    assert claims["Srclinks Gold Cabin"].held_reason == "unknown"  # held until the actor exists


async def test_wikidata_industry_links_a_vendor_to_its_sector(db_session):
    vendor = Vendor(name="Srclinks Software Co")
    db_session.add(vendor)
    await db_session.flush()

    parsed = {"industry": ["software industry", "software development", "International Standard"]}
    assert await apply_relations(db_session, "vendor", vendor.id, "wikidata", parsed)

    edges = (
        (await db_session.execute(select(EntityRelationship).where(EntityRelationship.source_id == vendor.id)))
        .scalars()
        .all()
    )
    assert [(e.relationship_type, e.target_type, e.target_id) for e in edges] == [
        ("operates_in", "sector", sector_uuid("technology"))
    ]
    # Industries that name no sector are dropped.
    assert {c.target_name for c in await _claims(db_session, "wikidata", vendor.id)} == {"software industry"}


# ── Context follows a merge ──────────────────────────────────────────


def _row(entity_type, entity_id, source_type, key, value):
    now = datetime.now(UTC)
    return EntityContext(
        entity_type=entity_type,
        entity_id=entity_id,
        source_type=source_type,
        key=key,
        value=value,
        observed_at=now,
        expires_at=now + timedelta(days=7),
    )


async def _context(db, entity_type, entity_id) -> dict:
    rows = await db.execute(
        select(EntityContext).where(EntityContext.entity_type == entity_type, EntityContext.entity_id == entity_id)
    )
    return {(r.source_type, r.key): r.value for r in rows.scalars()}


async def test_context_moves_to_the_merge_survivor(db_session):
    merged, survivor = Vendor(name="Srclinks Merged"), Vendor(name="Srclinks Survivor")
    db_session.add_all([merged, survivor])
    await db_session.flush()
    db_session.add_all(
        [
            _row("vendor", merged.id, "wikidata", "founded", "1975"),
            _row("vendor", merged.id, "wikidata", "logo", {"url": "https://x/merged"}),
            _row("vendor", merged.id, "wikipedia", "summary", "merged"),
            _row("vendor", survivor.id, "wikidata", "founded", "1980"),
        ]
    )
    await db_session.flush()

    assert await rehome_context(db_session, "vendor", merged.id, "vendor", survivor.id) == 1

    # Wikidata's answer on the survivor stands whole; Wikipedia's moves over.
    assert await _context(db_session, "vendor", survivor.id) == {
        ("wikidata", "founded"): "1980",
        ("wikipedia", "summary"): "merged",
    }
    assert await _context(db_session, "vendor", merged.id) == {}


async def test_context_is_dropped_when_the_type_changes(db_session):
    family = MalwareFamily(name="Srclinks Reclassified")
    db_session.add(family)
    await db_session.flush()
    db_session.add(_row("malware", family.id, "malpedia", "attribution", ["X"]))
    await db_session.flush()

    assert await rehome_context(db_session, "malware", family.id, "tool", uuid.uuid4()) == 0
    assert await _context(db_session, "malware", family.id) == {}


async def test_the_merge_endpoint_moves_the_sources_context_to_the_survivor(
    client, admin_headers, db_session, monkeypatch
):
    """``POST /api/vendors/{id}/merge`` repoints the merged vendor's claims,
    context and connections before deleting it."""
    from app.workers import intel_feed_tasks

    monkeypatch.setattr(intel_feed_tasks.link_new_entity_to_entries, "apply_async", lambda *a, **kw: None)
    merged, survivor = Vendor(name="Srclinks Merged Co"), Vendor(name="Srclinks Survivor Co")
    db_session.add_all([merged, survivor])
    await db_session.flush()
    db_session.add_all(
        [
            _row("vendor", merged.id, "wikipedia", "summary", "merged"),
            _row("vendor", survivor.id, "wikidata", "founded", "1980"),
        ]
    )
    await db_session.flush()

    resp = await client.post(
        f"/api/vendors/{survivor.id}/merge", json={"source_id": str(merged.id)}, headers=admin_headers
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["applied"] is True

    assert await _context(db_session, "vendor", survivor.id) == {
        ("wikidata", "founded"): "1980",
        ("wikipedia", "summary"): "merged",
    }
    assert await _context(db_session, "vendor", merged.id) == {}


async def test_the_nightly_prune_drops_context_of_deleted_entities(db_session):
    kept = Vendor(name="Srclinks Kept")
    db_session.add(kept)
    await db_session.flush()
    orphan_id = uuid.uuid4()
    db_session.add_all(
        [_row("vendor", kept.id, "wikidata", "founded", "1990"), _row("vendor", orphan_id, "wikidata", "founded", "1")]
    )
    await db_session.flush()

    assert await prune_expired_context(db_session) == 1
    assert await _context(db_session, "vendor", orphan_id) == {}
    assert await _context(db_session, "vendor", kept.id) == {("wikidata", "founded"): "1990"}


# ── How sources match entities ───────────────────────────────────────


def test_victims_are_looked_up_by_domain_and_names_sources_by_name():
    for source_type in ("rdap", "tranco", "wikidata"):
        cls = SOURCE_REGISTRY[source_type]
        assert cls.lookup_column("ransomware_victim") == "domain", source_type
    assert SOURCE_REGISTRY["rdap"].applies_to["ransomware_victim"] is None  # every victim, no kinds
    assert SOURCE_REGISTRY["malpedia"].lookup_column("malware") == "name"
    assert SOURCE_REGISTRY["wikidata"].lookup_column("vendor") == "wikipedia_url"


async def test_cymru_holds_an_in_flight_slot_per_dns_query():
    from contextlib import asynccontextmanager
    from types import SimpleNamespace

    from app.enrichment.adapters.cymru import CymruAdapter

    events: list = []

    class _Gateway:
        @asynccontextmanager
        async def permit(self, lease=None):
            events.append(("take", lease))
            yield "slot"
            events.append("free")

        async def record(self, response, *, permit=None, release=True):
            events.append(("record", permit, release))

    class _Resolver:
        async def resolve(self, name, rdtype, lifetime=None):
            return [SimpleNamespace(strings=(b"15169 | 8.8.8.0/24 | US | arin | 2023-12-28",))]

    adapter = CymruAdapter(gateway=_Gateway())
    adapter.resolver = _Resolver()
    assert await adapter._txt("8.8.8.8.origin.asn.cymru.com") == ["15169 | 8.8.8.0/24 | US | arin | 2023-12-28"]
    assert events[0][0] == "take" and events[0][1] > 0
    assert events[1:] == [("record", "slot", False), "free"]
