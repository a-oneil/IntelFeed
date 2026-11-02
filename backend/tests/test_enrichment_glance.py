"""The highlight popover's glance (app/enrichment/glance.py): a few chips and
facts from enrichment per highlighted type, only from sources that are on and
that the viewer may see, and nothing when nothing is stored."""

from datetime import UTC, date, datetime, timedelta
from types import SimpleNamespace

from sqlalchemy import select

from app.core.security import AnonymousViewer
from app.enrichment.glance import glance
from app.models.cve import CVE
from app.models.cve_affected import CVEAffected
from app.models.cwe import CWE, CVEWeakness
from app.models.enrichment import EnrichmentSource, EntityContext
from app.models.mitigation import Mitigation, TTPMitigation
from app.models.observable import Observable
from app.models.product import Product
from app.models.threat_actor import ThreatActor
from app.models.ttp import TTP

ADMIN = SimpleNamespace(id=None, role="admin", is_anonymous=False)
VISITOR = AnonymousViewer()


async def _on(db, *source_types, **fields):
    for source_type in source_types:
        row = (
            await db.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == source_type))
        ).scalar_one_or_none()
        if row is None:
            row = EnrichmentSource(source_type=source_type, display_name=source_type)
            db.add(row)
        row.is_enabled = True
        row.trigger_mode = "auto"
        row.rate_limit_config = {"requests_per_period": 100, "period_seconds": 60}
        for k, v in fields.items():
            setattr(row, k, v)
    await db.flush()


def _ctx(db, entity_type, entity_id, source_type, key, value):
    now = datetime.now(UTC)
    db.add(
        EntityContext(
            entity_type=entity_type,
            entity_id=entity_id,
            source_type=source_type,
            key=key,
            value=value,
            observed_at=now,
            expires_at=now + timedelta(days=7),
        )
    )


def _texts(g):
    return [c["text"] for c in g["chips"]], [f["text"] for f in g["facts"]]


async def test_an_ip_reads_as_a_benign_scanner_on_a_network(db_session):
    await _on(db_session, "greynoise", "cymru", "shodan")
    obs = Observable(
        kind="ipv4",
        value="71.6.135.131",
        base_confidence=0.8,
        current_confidence=0.8,
        noise_class="benign",
        asn=10439,
        asn_org="CARINET - CariNet, Inc.",
        geo_country="US",
        infra_tag="vpn",
    )
    db_session.add(obs)
    await db_session.flush()
    _ctx(db_session, "observable", obs.id, "greynoise", "name", "Shodan.io")
    await db_session.flush()

    g = await glance(db_session, "observable", obs, ADMIN)
    chips, facts = _texts(g)
    assert chips == ["Benign scanner"]
    assert facts == ["Shodan.io", "AS10439 CariNet · US", "VPN"]
    assert g["chips"][0]["source"] == "greynoise"
    assert g["chips"][0]["tone"] == "warn"


async def test_a_source_that_is_off_says_nothing(db_session):
    await _on(db_session, "greynoise", "cymru", is_enabled=False)
    obs = Observable(
        kind="ipv4", value="198.51.100.9", base_confidence=0.8, current_confidence=0.8, noise_class="benign", asn=64500
    )
    db_session.add(obs)
    await db_session.flush()
    assert _texts(await glance(db_session, "observable", obs, ADMIN)) == ([], [])


async def test_a_visitor_never_sees_sources_that_share_indicators(db_session):
    # GreyNoise sends the IP off the box; Team Cymru doesn't.
    await _on(db_session, "greynoise", "cymru")
    obs = Observable(
        kind="ipv4", value="198.51.100.10", base_confidence=0.8, current_confidence=0.8, noise_class="benign", asn=64501
    )
    db_session.add(obs)
    await db_session.flush()
    g = await glance(db_session, "observable", obs, VISITOR)
    assert _texts(g) == ([], ["AS64501"])
    assert g["lookup_sources"] == [] and g["needs_key"] == []


async def test_a_new_domain_and_its_registration(db_session):
    await _on(db_session, "rdap")
    obs = Observable(
        kind="domain",
        value="login-micr0soft.top",
        base_confidence=0.8,
        current_confidence=0.8,
        registered_at=datetime.now(UTC) - timedelta(days=3),
    )
    db_session.add(obs)
    await db_session.flush()
    _ctx(db_session, "observable", obs.id, "rdap", "registrar", "NameSilo")
    await db_session.flush()
    assert _texts(await glance(db_session, "observable", obs, ADMIN)) == (
        ["New domain"],
        ["Registered 3 days ago · NameSilo"],
    )


async def test_nothing_stored_means_nothing_shown(db_session):
    await _on(db_session, "greynoise", "cymru", "shodan", "rdap", "tranco")
    obs = Observable(kind="ipv4", value="198.51.100.11", base_confidence=0.8, current_confidence=0.8)
    db_session.add(obs)
    await db_session.flush()
    g = await glance(db_session, "observable", obs, ADMIN)
    assert _texts(g) == ([], [])
    assert g["looked_up"] is False
    assert {s["source_type"] for s in g["lookup_sources"]} >= {"greynoise", "cymru"}


async def test_a_cve_says_exploited_only_when_kev_doesnt_already(db_session):
    await _on(db_session, "cvelist", "metasploit")
    cve = CVE(cve_id="CVE-2026-90001", ssvc_exploitation="active", ssvc_automatable="yes", metasploit_module="x/y")
    kev = CVE(cve_id="CVE-2026-90002", ssvc_exploitation="active", is_kev=True)
    db_session.add_all([cve, kev])
    await db_session.flush()

    assert _texts(await glance(db_session, "cve", cve, ADMIN)) == (["Exploited"], ["Metasploit module", "Automatable"])
    assert _texts(await glance(db_session, "cve", kev, ADMIN))[0] == []


async def test_a_cve_on_an_end_of_life_release_has_no_patch(db_session):
    await _on(db_session, "endoflife")
    product = Product(name="PAN-OS Glance", support_status="maintained")
    cve = CVE(cve_id="CVE-2026-90003")
    db_session.add_all([product, cve])
    await db_session.flush()
    db_session.add(
        CVEAffected(
            cve_id=cve.id,
            cpe_vendor="p",
            cpe_product="panos",
            product_id=product.id,
            version_start="10.1.0",
            version_end="10.1.9",
        )
    )
    _ctx(
        db_session,
        "product",
        product.id,
        "endoflife",
        "releases",
        {
            "columns": ["Release", "Released", "Active until", "Security until", "Status"],
            "rows": [["10.1", "2021-01-01", None, "2025-01-01", "eol"]],
        },
    )
    await db_session.flush()
    g = await glance(db_session, "cve", cve, ADMIN)
    assert _texts(g)[0] == ["No patch"]
    assert g["chips"][0]["source"] == "endoflife"


async def test_no_patch_counts_the_products_when_only_some_are_unpatched(db_session):
    await _on(db_session, "endoflife")
    eol = Product(name="Old Router Glance", support_status="eol")
    patched = Product(name="New Router Glance", support_status="maintained")
    other = Product(name="Other Router Glance", support_status="maintained")
    cve = CVE(cve_id="CVE-2026-90004")
    db_session.add_all([eol, patched, other, cve])
    await db_session.flush()
    for p in (eol, patched, other):
        db_session.add(CVEAffected(cve_id=cve.id, cpe_vendor="r", cpe_product=p.name, product_id=p.id))
    await db_session.flush()
    assert _texts(await glance(db_session, "cve", cve, ADMIN))[0] == ["No patch for 1 of 3 products"]

    # Every affected product unpatched: the plain chip.
    patched.support_status = other.support_status = "eol"
    await db_session.flush()
    assert _texts(await glance(db_session, "cve", cve, ADMIN))[0] == ["No patch"]


async def test_no_patch_hides_with_endoflife_off(db_session):
    await _on(db_session, "endoflife", is_enabled=False)
    product = Product(name="Dead Server Glance", support_status="eol")
    cve = CVE(cve_id="CVE-2026-90005")
    db_session.add_all([product, cve])
    await db_session.flush()
    db_session.add(CVEAffected(cve_id=cve.id, cpe_vendor="d", cpe_product="s", product_id=product.id))
    await db_session.flush()
    assert _texts(await glance(db_session, "cve", cve, ADMIN)) == ([], [])


async def test_a_product_past_end_of_life_and_its_cves(db_session):
    await _on(db_session, "endoflife")
    product = Product(name="Old Server Glance", support_status="eol")
    cves = [CVE(cve_id=f"CVE-2026-9001{i}", is_kev=i == 0) for i in range(2)]
    db_session.add_all([product, *cves])
    await db_session.flush()
    for c in cves:
        db_session.add(CVEAffected(cve_id=c.id, cpe_vendor="o", cpe_product="s", product_id=product.id))
    await db_session.flush()
    assert _texts(await glance(db_session, "product", product, ADMIN)) == (["EOL"], ["2 CVEs, 1 in KEV"])

    product.support_status = "security_only"
    product.next_eol = date(2031, 10, 14)
    await db_session.flush()
    assert _texts(await glance(db_session, "product", product, ADMIN)) == (
        ["Security fixes only"],
        ["Security fixes until 2031-10-14", "2 CVEs, 1 in KEV"],
    )


async def test_an_actor_from_its_threat_group_card(db_session):
    await _on(db_session, "etda")
    actor = ThreatActor(name="Glance Bear")
    db_session.add(actor)
    await db_session.flush()
    _ctx(db_session, "threat_actor", actor.id, "etda", "sponsor", "State-sponsored")
    _ctx(db_session, "threat_actor", actor.id, "etda", "first_seen", "2008")
    await db_session.flush()
    assert _texts(await glance(db_session, "threat_actor", actor, ADMIN)) == (
        [],
        ["State-sponsored", "Active since 2008"],
    )


async def test_a_technique_a_weakness_and_a_mitigation_from_the_links(db_session):
    await _on(db_session, "mitre_attack", "d3fend", "ctid")
    ttp = TTP(
        technique_id="T9999", technique_name="Glance", platforms=["Windows", "Linux"], nist_controls=["AC-2", "AC-3"]
    )
    cwe = CWE(cwe_id="CWE-9999", name="Glance weakness")
    mitigation = Mitigation(name="Glance mitigation", mitre_id="M9999")
    cve = CVE(cve_id="CVE-2026-90020", is_kev=True)
    db_session.add_all([ttp, cwe, mitigation, cve])
    await db_session.flush()
    db_session.add(CVEWeakness(cve_id=cve.id, cwe_ref="CWE-9999", cwe_id_fk=cwe.id))
    db_session.add(TTPMitigation(ttp_id=ttp.id, mitigation_id=mitigation.id))
    _ctx(
        db_session,
        "ttp",
        ttp.id,
        "d3fend",
        "countermeasures",
        {"columns": ["Name", "Tactic"], "rows": [["A", "Harden"]]},
    )
    await db_session.flush()

    assert _texts(await glance(db_session, "ttp", ttp, ADMIN))[1] == [
        "Windows, Linux",
        "1 D3FEND countermeasure",
        "2 NIST controls",
    ]
    assert _texts(await glance(db_session, "cwe", cwe, ADMIN))[1] == ["Behind 1 CVE, 1 in KEV"]
    assert _texts(await glance(db_session, "mitigation", mitigation, ADMIN))[1] == ["Counters 1 technique"]


async def test_a_glance_keeps_two_chips_and_three_facts_and_says_a_thing_once(db_session):
    from app.enrichment.glance import MAX_CHIPS, MAX_FACTS

    await _on(db_session, "urlhaus", "greynoise", "rdap", "tranco", "threatfox", "malwarebazaar", "virustotal", "cymru")
    obs = Observable(
        kind="ipv4",
        value="198.51.100.13",
        base_confidence=0.8,
        current_confidence=0.8,
        noise_class="benign",
        registered_at=datetime.now(UTC) - timedelta(days=2),
        popularity_rank=5,
        asn=64502,
    )
    db_session.add(obs)
    await db_session.flush()
    _ctx(db_session, "observable", obs.id, "urlhaus", "url_status", "online")
    _ctx(db_session, "observable", obs.id, "threatfox", "malware", ["Emotet"])
    _ctx(db_session, "observable", obs.id, "malwarebazaar", "signature", "Emotet")
    _ctx(db_session, "observable", obs.id, "virustotal", "detection_ratio", "12/70")
    _ctx(db_session, "observable", obs.id, "greynoise", "name", "Shodan.io")
    await db_session.flush()

    # Four rules return a chip (malware, scanner, new domain, popular site) and
    # six a fact: the first two and three win, in rule order, and the family
    # ThreatFox and MalwareBazaar both name shows once.
    chips, facts = _texts(await glance(db_session, "observable", obs, ADMIN))
    assert (MAX_CHIPS, MAX_FACTS) == (2, 3)
    assert chips == ["Serving malware", "Benign scanner"]
    assert facts == ["Emotet", "VirusTotal 12/70", "Shodan.io"]


async def test_an_admin_is_told_which_lookups_need_a_key(db_session):
    import uuid

    await _on(db_session, "virustotal", "cymru")
    obs = Observable(kind="ipv4", value="198.51.100.14", base_confidence=0.8, current_confidence=0.8)
    db_session.add(obs)
    await db_session.flush()

    g = await glance(db_session, "observable", obs, ADMIN)
    assert g["needs_key"] == [{"source_type": "virustotal", "label": "virustotal", "key": "virustotal"}]
    assert "virustotal" not in {s["source_type"] for s in g["lookup_sources"]}
    assert "cymru" in {s["source_type"] for s in g["lookup_sources"]}

    # Anyone else only sees the lookups they can run.
    analyst = SimpleNamespace(id=uuid.uuid4(), role="user", is_anonymous=False)
    g = await glance(db_session, "observable", obs, analyst)
    assert g["needs_key"] == []
    assert "virustotal" not in {s["source_type"] for s in g["lookup_sources"]}


async def test_looked_up_once_a_source_stored_an_answer(db_session):
    from app.models.enrichment import EnrichmentResult

    await _on(db_session, "cymru")
    obs = Observable(kind="ipv4", value="198.51.100.15", base_confidence=0.8, current_confidence=0.8)
    db_session.add(obs)
    await db_session.flush()
    assert (await glance(db_session, "observable", obs, ADMIN))["looked_up"] is False

    # A stored answer with no context (the source found nothing) still counts.
    db_session.add(
        EnrichmentResult(
            entity_type="observable",
            entity_id=obs.id,
            source_type="cymru",
            raw_response={},
            parsed_data={"found": False},
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
    )
    await db_session.flush()
    assert (await glance(db_session, "observable", obs, ADMIN))["looked_up"] is True


async def test_every_highlighted_type_has_rules():
    from app.enrichment.glance import RULES

    highlighted = {
        "cve",
        "cwe",
        "ttp",
        "threat_actor",
        "malware",
        "country",
        "vendor",
        "product",
        "tool",
        "mitigation",
        "observable",
    }
    assert highlighted <= set(RULES)


async def test_the_endpoint_answers_visitors_and_404s_the_unknown(
    client, auth_headers, db_session, test_entry, test_feed, monkeypatch
):
    import uuid

    from app.config import settings
    from app.models.threat_actor import EntryThreatActor

    obs = Observable(kind="ipv4", value="198.51.100.12", base_confidence=0.8, current_confidence=0.8)
    db_session.add(obs)
    await db_session.flush()
    resp = await client.get(f"/api/entities/observable/{obs.id}/glance", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    assert set(resp.json()) == {"chips", "facts", "lookup_sources", "needs_key", "looked_up"}

    # With no login: 401 while the instance is private. In public read-only
    # mode a visitor gets an actor known from a feed they may read, with no
    # Look up button, and never an observable (the ledger is hidden from them).
    actor = ThreatActor(name="Glanced Actor")
    db_session.add(actor)
    await db_session.flush()
    test_feed.visible_to_visitors = True
    db_session.add(EntryThreatActor(entry_id=test_entry.id, threat_actor_id=actor.id, matched_names=["Glanced Actor"]))
    await db_session.flush()
    assert (await client.get(f"/api/entities/threat_actor/{actor.id}/glance")).status_code == 401
    monkeypatch.setattr(settings, "public_read_only_enabled", True)
    anon = await client.get(f"/api/entities/threat_actor/{actor.id}/glance")
    assert anon.status_code == 200, anon.text
    assert anon.json()["lookup_sources"] == []
    assert (await client.get(f"/api/entities/observable/{obs.id}/glance")).status_code == 404
    assert (
        await client.get(f"/api/entities/observable/{uuid.uuid4()}/glance", headers=auth_headers)
    ).status_code == 404
    assert (await client.get(f"/api/entities/nonsense/{obs.id}/glance", headers=auth_headers)).status_code == 400
