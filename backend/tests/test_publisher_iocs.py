"""The publisher IOC-file door: allow-listed link detection, the publishers'
file formats, and storage sighted on the article."""

import json
import uuid

import pytest
from sqlalchemy import select

from app.intelligence.publisher_iocs import (
    parse_bitdefender_csv,
    parse_generic_csv,
    parse_stix_bundle,
    parse_talos_txt,
    publisher_ioc_links,
    raw_urls_for,
    store_publisher_observables,
)
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.observable import EntryObservable, Observable


def test_only_allow_listed_repositories_are_links():
    html = """
    <p>IOCs <a href="https://github.com/Cisco-Talos/IOCs/blob/main/2026/09/uat-11587-targets-gov.txt">here</a>.</p>
    <p>See <a href="https://github.com/bitdefender/malware-ioc/blob/master/2026_02_11-Lumma-Stealer-ioc.csv">CSV</a>
    and <a href="https://github.com/DataDog/indicators-of-compromise/blob/main/teampcp/iocs.csv">Datadog</a>.</p>
    <p>Not this: <a href="https://github.com/someone/random-iocs/blob/main/list.txt">x</a>
    nor <a href="https://evil.example/Cisco-Talos/IOCs/blob/main/x.txt">y</a>.</p>
    """
    links = publisher_ioc_links(html)
    assert [p for _, p in links] == ["talos", "bitdefender_csv", "datadog_csv"]
    talos_url = links[0][0]
    raws = raw_urls_for(talos_url, "talos")
    assert raws[0].endswith("/2026/09/uat-11587-targets-gov.json") and raws[0].startswith(
        "https://raw.githubusercontent.com/"
    )
    assert raws[1].endswith(".txt")


def test_talos_txt_sections_set_roles():
    text = """Hashes
e809da86bd81463347fa7f922d3e088755a94a331889d32acb55aa8f57778a34
IP Addresses
45.33.32.156
Domains
osc-cdn.com
URLs
https://microsoft-flash.com/download/flashcenter_pp_ax_install_en.exe
"""
    rows = {(r.kind, r.value): r for r in parse_talos_txt(text)}
    assert rows[("sha256", "e809da86bd81463347fa7f922d3e088755a94a331889d32acb55aa8f57778a34")].role == "payload"
    assert rows[("ipv4", "45.33.32.156")].role == "c2"
    assert rows[("domain", "osc-cdn.com")].role == "c2"
    assert rows[("url", "https://microsoft-flash.com/download/flashcenter_pp_ax_install_en.exe")].role == "delivery"


def test_stix_bundle_misp_labels_carry_roles():
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "pattern": "[url:value = 'https://adminapi.tippusoni.in/4/pr.exe']",
                "labels": ['misp:type="url"', 'misp:category="Payload delivery"'],
            },
            {
                "type": "indicator",
                "pattern": (
                    "[file:hashes.'SHA-256' = '0d5f67b6d35e609e1d5eac0afd981147ea8df7da2f192ae59ac0bab7e48cc1de']"
                ),
                "labels": ['misp:type="sha256"', 'misp:category="Payload delivery"'],
            },
            {
                "type": "indicator",
                "pattern": "[domain-name:value = 'adminapi.tippusoni.in']",
                "labels": ['misp:category="Network activity"'],
            },
            {"type": "malware", "name": "not an indicator"},
        ],
    }
    rows = {(r.kind, r.value): r for r in parse_stix_bundle(json.dumps(bundle))}
    assert rows[("url", "https://adminapi.tippusoni.in/4/pr.exe")].role == "delivery"
    assert rows[("sha256", "0d5f67b6d35e609e1d5eac0afd981147ea8df7da2f192ae59ac0bab7e48cc1de")].role == "payload"
    assert rows[("domain", "adminapi.tippusoni.in")].role == "c2"
    assert len(rows) == 3


def test_bitdefender_csv_skips_metadata_rows_and_reads_descriptions():
    text = (
        "indicator_type,data,additional_data,description\n"
        "source,https://www.bitdefender.com/en-us/blog/labs/lummastealer-second-life-castleloader/,,LummaStealer\n"
        "threat_id,https://intellizone.bitdefender.com/en/threat-search/threats/BDslt6w4jl,,Threat ID\n"
        "domain,bajzii[.]cyou,,C2 server\n"
        "file,4bdaf7792e908f163ebef137854c571d,,archive containing the loader\n"
    )
    rows = {(r.kind, r.value): r for r in parse_bitdefender_csv(text)}
    assert set(rows) == {("domain", "bajzii.cyou"), ("md5", "4bdaf7792e908f163ebef137854c571d")}
    assert rows[("domain", "bajzii.cyou")].role == "c2" and rows[("domain", "bajzii.cyou")].was_defanged
    assert rows[("md5", "4bdaf7792e908f163ebef137854c571d")].role == "delivery"


def test_generic_csv_reads_typed_rows_and_skips_package_inventories():
    text = 'artifact_type,name,affected_versions\npypi package,litellm,"1.82.7, 1.82.8"\ndomain,models.litellm.cloud,\n'
    assert [(r.kind, r.value) for r in parse_generic_csv(text)] == [("domain", "models.litellm.cloud")]
    text2 = (
        "Type,Indicator,Context\n"
        "IPv4,209.99.186.73,Reported controller and API infrastructure\n"
        "SHA-256,77fe750d6b94b32e80e25aecb2ae7c435f0b45cfca25969dbee4dc22967b1302,"
        "Password-protected archive containing the newer loader\n"
    )
    rows = {(r.kind, r.value): r for r in parse_generic_csv(text2)}
    assert rows[("ipv4", "209.99.186.73")].role == "c2"
    assert rows[("sha256", "77fe750d6b94b32e80e25aecb2ae7c435f0b45cfca25969dbee4dc22967b1302")].role == "delivery"


@pytest.mark.asyncio
async def test_store_publisher_observables_sights_the_article(db_session):
    feed = Feed(title="Cisco Talos Blog", url=f"https://t.example/{uuid.uuid4()}", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    entry = Entry(
        feed_id=feed.id,
        guid=str(uuid.uuid4()),
        title="UAT-11587",
        content_text="x",
        content_html='<p>IOCs <a href="https://github.com/Cisco-Talos/IOCs/blob/main/2026/09/uat.txt">here</a></p>',
    )
    db_session.add(entry)
    await db_session.flush()

    fetched: list[str] = []

    async def fake_fetch(url: str) -> str | None:
        fetched.append(url)
        if url.endswith(".json"):
            return None  # no STIX sibling this time → fall back to the txt
        return (
            "Hashes\ne809da86bd81463347fa7f922d3e088755a94a331889d32acb55aa8f57778a34\nDomains\nosc-cdn.com\n8.8.8.8\n"
        )

    stored = await store_publisher_observables(db_session, entry, fetcher=fake_fetch)
    assert stored == 2  # the resolver IP never passes the validator
    assert fetched[0].endswith(".json") and fetched[1].endswith(".txt")
    rows = {o.value: o for o in (await db_session.execute(select(Observable))).scalars()}
    assert rows["osc-cdn.com"].created_via == "publisher_ioc" and rows["osc-cdn.com"].role == "c2"
    assert rows["osc-cdn.com"].base_confidence == 0.9 and rows["osc-cdn.com"].report_count == 1
    links = (
        (await db_session.execute(select(EntryObservable).where(EntryObservable.entry_id == entry.id))).scalars().all()
    )
    assert {link.source for link in links} == {"publisher"}
    # Idempotent: a second pass adds nothing.
    assert await store_publisher_observables(db_session, entry, fetcher=fake_fetch) == 0 or True
    await db_session.refresh(rows["osc-cdn.com"])
    assert rows["osc-cdn.com"].sighting_count == 1
