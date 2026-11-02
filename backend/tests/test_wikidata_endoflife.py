"""Wikidata and endoflife.date: catalog jobs that fill vendor, product and
country columns and profile context.

Responses are trimmed recordings of the live APIs (2026-10-28) in
``tests/fixtures/enrichment``, served through a real SourceGateway (its Redis
bucket, budget and breaker) by ``httpx.MockTransport``.
"""

import copy
import importlib.util
import json
from contextlib import asynccontextmanager
from datetime import UTC, date, datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from sqlalchemy import func, select, text

import app.enrichment.endoflife as endoflife
from app.enrichment.endoflife import lifecycle, match_product, parse_product, product_index, sync_endoflife
from app.enrichment.gateway import USER_AGENT, SourceGateway
from app.enrichment.wikidata import best_values, enwiki_title, fetch_labels, item_facts, sync_wikidata
from app.intelligence.sectors import sector_uuid
from app.models.country import Country
from app.models.enrichment import EnrichmentResult, EnrichmentSource, EntityContext
from app.models.entity_field_claim import EntityFieldClaim
from app.models.entity_relationship import EntityRelationship
from app.models.product import Product
from app.models.ransomware import RansomwareVictim
from app.models.vendor import Vendor

FIXTURES = Path(__file__).parent / "fixtures" / "enrichment"


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


ITEMS = _fixture("wikidata_items.json")
LABELS = _fixture("wikidata_labels.json")
EOL_PRODUCTS = _fixture("endoflife_products.json")
WINDOWS_SERVER = _fixture("endoflife_windows_server.json")

TODAY = date(2026, 10, 28)


@pytest.fixture(autouse=True)
def _recorded_day(monkeypatch):
    """The sync reads the clock; pin it to the day the fixtures were recorded,
    so dates in them (Windows Server 2025's 2031 end) stay in the future."""

    class _Day(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 10, 28, 12, tzinfo=UTC)

    monkeypatch.setattr(endoflife, "datetime", _Day)


class _Wikidata:
    """wbgetentities by titles (items) or by ids (labels), from the fixtures."""

    def __init__(self, items=ITEMS, labels=LABELS):
        self.items = items["entities"]
        self.labels = labels["entities"]
        self.requests: list[httpx.Request] = []
        self.fail_after: int | None = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.fail_after is not None and len(self.requests) > self.fail_after:
            return httpx.Response(429, headers={"Retry-After": "600"})
        params = {k: v[0] for k, v in parse_qs(urlparse(str(request.url)).query).items()}
        if "titles" in params:
            wanted = params["titles"].split("|")
            entities = {
                qid: item
                for qid, item in self.items.items()
                if not qid.startswith("-") and item["sitelinks"]["enwiki"]["title"] in wanted
            }
            found = {item["sitelinks"]["enwiki"]["title"] for item in entities.values()}
            for n, title in enumerate(t for t in wanted if t not in found):
                entities[str(-1 - n)] = {"site": "enwiki", "title": title, "missing": ""}
            return httpx.Response(200, json={"entities": entities, "success": 1})
        ids = params["ids"].split("|")
        return httpx.Response(
            200, json={"entities": {i: self.labels.get(i, {"id": i, "missing": ""}) for i in ids}, "success": 1}
        )


def _gateway(source_type: str, handler) -> SourceGateway:
    return SourceGateway(
        source_type,
        rate_limit_config={"requests_per_period": 100, "period_seconds": 60},
        inner=httpx.MockTransport(handler),
    )


def _wiki(title: str) -> str:
    return f"https://en.wikipedia.org/wiki/{title}"


async def _context(db, entity_type, entity_id, source_type) -> dict:
    rows = (
        await db.execute(
            select(EntityContext).where(
                EntityContext.entity_type == entity_type,
                EntityContext.entity_id == entity_id,
                EntityContext.source_type == source_type,
            )
        )
    ).scalars()
    return {r.key: r.value for r in rows}


async def _vendor_count(db) -> int:
    return (await db.execute(select(func.count()).select_from(Vendor))).scalar_one()


# ── Wikidata: reading claims ─────────────────────────────────────────


def test_preferred_rank_wins_and_deprecated_never_counts():
    claims = ITEMS["entities"]["Q2283"]["claims"]
    # Four logos at normal rank (1980, 1982, 1987) and the current one preferred.
    assert best_values(claims, "P154") == ["Microsoft logo (2012).svg"]
    assert best_values(claims, "P856") == ["https://www.microsoft.com/"]
    # No preferred statement: every normal one, in order.
    assert len(best_values(claims, "P452")) == 5

    def statement(value, rank, snaktype="value"):
        return {"rank": rank, "mainsnak": {"snaktype": snaktype, "datavalue": {"value": value}}}

    claims = {
        "P856": [statement("old", "deprecated"), statement("x", "normal", "somevalue"), statement("new", "normal")]
    }
    assert best_values(claims, "P856") == ["new"]
    assert best_values({"P856": [statement("old", "deprecated")]}, "P856") == []


def test_vendor_facts_and_the_labels_they_need():
    facts, needs = item_facts("vendor", ITEMS["entities"]["Q2283"])
    assert facts["website"] == "https://www.microsoft.com/"
    assert facts["founded"] == "1975-04-04"
    assert facts["logo"] == {
        "url": "https://commons.wikimedia.org/wiki/File:Microsoft_logo_%282012%29.svg",
        "label": "Microsoft logo (2012).svg",
    }
    assert facts["item"] == {"url": "https://www.wikidata.org/wiki/Q2283", "label": "Q2283"}
    assert set(needs) == {"Q30", "Q223718", "Q21157865", "Q880371", "Q638608", "Q1666934", "Q73768396"}


def test_country_region_comes_from_the_continent():
    facts, needs = item_facts("country", ITEMS["entities"]["Q183"])
    assert (facts["region"], facts["iso_code"], needs) == ("Europe", "DE", [])
    fiji = {
        "id": "Q712",
        "claims": {
            "P30": [{"rank": "normal", "mainsnak": {"snaktype": "value", "datavalue": {"value": {"id": "Q538"}}}}]
        },
    }
    assert item_facts("country", fiji)[0]["region"] == "Oceania"


@pytest.mark.parametrize(
    ("url", "title"),
    [
        ("https://en.wikipedia.org/wiki/Okta,_Inc.", "Okta, Inc."),
        ("https://en.wikipedia.org/wiki/Soci%C3%A9t%C3%A9_G%C3%A9n%C3%A9rale", "Société Générale"),
        ("https://en.m.wikipedia.org/wiki/microsoft#History", "Microsoft"),
        ("https://de.wikipedia.org/wiki/Microsoft", None),
        (None, None),
    ],
)
def test_enwiki_titles(url, title):
    assert enwiki_title(url) == title


async def test_labels_are_fetched_fifty_ids_a_call():
    server = _Wikidata()
    ids = [f"Q{n}" for n in range(1, 61)]
    async with _gateway("wikidata", server).client() as client:
        labels = await fetch_labels(client, ids)
    assert [len(parse_qs(urlparse(str(r.url)).query)["ids"][0].split("|")) for r in server.requests] == [50, 10]
    assert set(labels) == set(ids)


# ── Wikidata: the job ────────────────────────────────────────────────


@pytest.fixture
async def wiki_entities(db_session):
    microsoft = Vendor(name="Microsoft", wikipedia_url=_wiki("Microsoft"))
    windows_server = Product(name="Windows Server", wikipedia_url=_wiki("Windows_Server"))
    germany = Country(name="Germany", wikipedia_url=_wiki("Germany"))
    unknown = Product(name="Wikidatatest Nothing", wikipedia_url=_wiki("Nonexistent_page_xyz"))
    db_session.add_all([microsoft, windows_server, germany, unknown])
    await db_session.flush()
    return microsoft, windows_server, germany, unknown


async def test_sync_fills_blank_columns_and_stores_vendor_context(db_session, wiki_entities):
    microsoft, windows_server, germany, unknown = wiki_entities
    # Microsoft's P17 is Q30, labelled "United States": a tracked country.
    united_states = Country(name="United States", iso_code="US", aliases=["United States of America"])
    db_session.add(united_states)
    await db_session.flush()
    server = _Wikidata()
    vendors_before = await _vendor_count(db_session)

    stats = await sync_wikidata(db_session, _gateway("wikidata", server))

    assert stats == {"looked_up": 4, "found": 3, "updated": 3, "failed": 0, "stopped": None}
    # One item call for the batch, one label call for every item it names.
    assert len(server.requests) == 2
    assert all(r.headers["User-Agent"] == USER_AGENT for r in server.requests)
    assert microsoft.website == "https://www.microsoft.com/"
    assert microsoft.country_id == united_states.id
    assert windows_server.vendor_id == microsoft.id
    assert (germany.region, germany.iso_code) == ("Europe", "DE")
    assert await _vendor_count(db_session) == vendors_before

    assert await _context(db_session, "vendor", microsoft.id, "wikidata") == {
        "founded": "1975-04-04",
        "headquarters": "Redmond",
        "country": "United States",
        "industry": [
            "technology industry",
            "software industry",
            "software development",
            "International Standard Industrial Classification",
            "consumer electronics industry",
        ],
        "logo": {
            "url": "https://commons.wikimedia.org/wiki/File:Microsoft_logo_%282012%29.svg",
            "label": "Microsoft logo (2012).svg",
        },
        "item": {"url": "https://www.wikidata.org/wiki/Q2283", "label": "Q2283"},
    }
    assert await _context(db_session, "country", germany.id, "wikidata") == {
        "item": {"url": "https://www.wikidata.org/wiki/Q183", "label": "Q183"}
    }

    claims = dict(
        (
            await db_session.execute(
                select(EntityFieldClaim.field, EntityFieldClaim.value_text).where(
                    EntityFieldClaim.source_ref == "wikidata"
                )
            )
        ).all()
    )
    assert claims == {
        "website": "https://www.microsoft.com/",
        "country_id": str(united_states.id),
        "vendor_id": str(microsoft.id),
        "region": "Europe",
        "iso_code": "DE",
    }

    # A title with no item is remembered, so the next run doesn't ask again.
    missing = (
        await db_session.execute(
            select(EnrichmentResult.parsed_data).where(
                EnrichmentResult.entity_id == unknown.id, EnrichmentResult.source_type == "wikidata"
            )
        )
    ).scalar_one()
    assert missing == {"found": False}
    server.requests.clear()
    assert (await sync_wikidata(db_session, _gateway("wikidata", server)))["looked_up"] == 0
    assert server.requests == []


async def test_filled_columns_are_left_alone(db_session, wiki_entities):
    microsoft, *_ = wiki_entities
    microsoft.website = "https://example.com/"
    other = Vendor(name="Wikidatatest Other Vendor")
    db_session.add(other)
    await db_session.flush()
    product = Product(name="Wikidatatest Server", vendor_id=other.id, wikipedia_url=_wiki("Windows_Server"))
    db_session.add(product)
    await db_session.flush()

    await sync_wikidata(db_session, _gateway("wikidata", _Wikidata()))

    assert microsoft.website == "https://example.com/"
    # A product that has a vendor isn't a candidate at all.
    assert product.vendor_id == other.id
    assert (
        await db_session.execute(select(EnrichmentResult).where(EnrichmentResult.entity_id == product.id))
    ).first() is None


async def test_sync_links_a_vendor_to_the_sectors_its_industries_name(db_session, wiki_entities):
    microsoft, *_ = wiki_entities
    await sync_wikidata(db_session, _wikidata_gateway())

    edges = (
        (await db_session.execute(select(EntityRelationship).where(EntityRelationship.source_id == microsoft.id)))
        .scalars()
        .all()
    )
    # "technology industry" and "software industry" both name the technology sector.
    assert {(e.relationship_type, e.target_type, e.target_id) for e in edges} == {
        ("operates_in", "sector", sector_uuid("technology"))
    }


def _wikidata_gateway(server=None):
    return _gateway("wikidata", server or _Wikidata())


class _Websites(_Wikidata):
    """The query service too: a website query answers from the recording."""

    def __init__(self):
        super().__init__()
        self.queries: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == "query.wikidata.org":
            self.requests.append(request)
            self.queries.append(parse_qs(urlparse(str(request.url)).query)["query"][0])
            return httpx.Response(200, json=_fixture("wikidata_sparql_websites.json"))
        return super().__call__(request)


async def test_sync_finds_a_victim_country_by_its_website(db_session):
    germany = Country(name="Germany", iso_code="DE")
    siemens = RansomwareVictim(name="Siemens AG", domain="www.siemens.com")
    nobody = RansomwareVictim(name="Small Shop", domain="smallshop-wikidatatest.example")
    nameonly = RansomwareVictim(name="No Domain Ltd", domain="No Domain Ltd")
    db_session.add_all([germany, siemens, nobody, nameonly])
    await db_session.flush()
    server = _Websites()

    stats = await sync_wikidata(db_session, _gateway("wikidata", server))

    assert len(server.queries) == 1
    assert "<https://www.siemens.com/>" in server.queries[0] and "No Domain" not in server.queries[0]
    assert stats["victims"]["found"] == 1
    assert siemens.country_id == germany.id
    assert nobody.country_id is None
    assert await _context(db_session, "ransomware_victim", siemens.id, "wikidata") == {
        "item": {"url": "https://www.wikidata.org/wiki/Q81230", "label": "Q81230"}
    }
    # Asked once: the answer (found or not) holds for the TTL.
    server.queries.clear()
    await sync_wikidata(db_session, _gateway("wikidata", server))
    assert server.queries == []


async def test_a_developer_only_links_to_an_existing_vendor(db_session):
    product = Product(name="Windows Server", wikipedia_url=_wiki("Windows_Server"))
    db_session.add(product)
    await db_session.flush()
    vendors_before = await _vendor_count(db_session)

    stats = await sync_wikidata(db_session, _gateway("wikidata", _Wikidata()))

    assert stats["found"] == 1 and stats["updated"] == 0
    assert product.vendor_id is None
    assert await _vendor_count(db_session) == vendors_before
    assert (await db_session.execute(select(Vendor).where(Vendor.name == "Microsoft"))).first() is None


async def test_a_developer_matches_a_vendor_by_name_without_an_article(db_session):
    vendor = Vendor(name="microsoft")  # no wikipedia_url; the label matches case-insensitively
    product = Product(name="Windows Server", wikipedia_url=_wiki("Windows_Server"))
    db_session.add_all([vendor, product])
    await db_session.flush()

    await sync_wikidata(db_session, _gateway("wikidata", _Wikidata()))

    assert product.vendor_id == vendor.id


async def test_wikidata_sync_sends_twenty_titles_a_call(db_session):
    db_session.add_all(
        [Vendor(name=f"Wikidatatest {n:02}", wikipedia_url=_wiki(f"Wikidatatest_{n:02}")) for n in range(25)]
    )
    await db_session.flush()
    server = _Wikidata()

    stats = await sync_wikidata(db_session, _gateway("wikidata", server))

    sizes = [len(parse_qs(urlparse(str(r.url)).query)["titles"][0].split("|")) for r in server.requests]
    assert sizes == [20, 5]
    assert stats["looked_up"] == 25 and stats["found"] == 0


async def test_wikidata_sync_stops_cleanly_on_a_refusal_and_keeps_what_it_did(db_session):
    db_session.add(Vendor(name="Microsoft", wikipedia_url=_wiki("Microsoft")))
    db_session.add_all(
        [Vendor(name=f"Wikidatatest {n:02}", wikipedia_url=_wiki(f"Wikidatatest_{n:02}")) for n in range(20)]
    )
    await db_session.flush()
    server = _Wikidata()
    server.fail_after = 2  # the first batch's items + labels, then 429

    stats = await sync_wikidata(db_session, _gateway("wikidata", server))

    assert stats["stopped"] == "rate_limited"
    assert stats["looked_up"] == 20
    microsoft = (await db_session.execute(select(Vendor).where(Vendor.name == "Microsoft"))).scalar_one()
    assert microsoft.website == "https://www.microsoft.com/"


async def test_wikidata_sync_sends_nothing_while_the_breaker_is_open(db_session, wiki_entities):
    server = _Wikidata()
    gateway = _gateway("wikidata", server)
    await gateway._trip("throttle", 600)

    stats = await sync_wikidata(db_session, gateway)

    assert stats["stopped"] == "breaker_open"
    assert server.requests == []


async def test_the_job_uses_the_wikidata_row_and_gateway(db_session, wiki_entities, monkeypatch):
    import app.workers.enrichment_tasks as tasks
    from app.enrichment import gateway as gw

    @asynccontextmanager
    async def session():
        yield db_session

    server = _Wikidata()
    monkeypatch.setattr(tasks, "_get_worker_session", session)
    monkeypatch.setattr(
        SourceGateway, "transport", lambda self: gw._GatewayTransport(self, httpx.MockTransport(server))
    )
    db_session.add(
        EnrichmentSource(
            source_type="wikidata",
            display_name="Wikidata",
            is_enabled=True,
            trigger_mode="manual",
            config={},
            rate_limit_config={"requests_per_period": 100, "period_seconds": 60},
            daily_budget=1,
        )
    )
    await db_session.flush()

    stats = await tasks._run_wikidata_sync()

    # The row's budget of one request covers the items call, not the labels.
    assert stats["stopped"] == "budget_exhausted"
    assert len(server.requests) == 1


# ── endoflife.date: matching ─────────────────────────────────────────

INDEX = product_index(EOL_PRODUCTS["result"])
KNOWN = {p["name"] for p in EOL_PRODUCTS["result"]}


@pytest.mark.parametrize(
    ("name", "vendor", "slug"),
    [
        ("Windows Server", "Microsoft", "windows-server"),  # the product name
        ("Windows Server", None, "windows-server"),
        ("Exchange", "Microsoft", "msexchange"),  # vendor + name = the label
        ("PAN-OS", "Palo Alto Networks", "panos"),  # an alias
        ("Google Chrome", None, "chrome"),
        ("SUSE Linux Enterprise", "SUSE", "sles"),  # an override
        ("Splunk Enterprise", "Splunk", "splunk"),
        ("Windows Serv", "Microsoft", None),  # never fuzzy
        ("Microsoft Windows Server 2022", None, None),
        ("XDR", None, "cortex-xdr"),
        ("Trend Vision One", "Trend Micro", None),
    ],
)
def test_products_match_exactly_or_by_override(name, vendor, slug):
    assert match_product(name, vendor, INDEX, KNOWN) == slug


def test_a_product_naming_two_lifecycles_matches_neither():
    index = product_index(
        [{"name": "foo", "aliases": [], "label": "Foo"}, {"name": "acme-foo", "aliases": [], "label": "Acme Foo"}]
    )
    assert match_product("Foo", "Acme", index, {"foo", "acme-foo"}) is None
    assert match_product("Foo", None, index, {"foo", "acme-foo"}) == "foo"


def test_an_override_to_a_product_endoflife_dropped_matches_nothing():
    assert match_product("SUSE Linux Enterprise", None, INDEX, KNOWN - {"sles"}) is None


# ── endoflife.date: lifecycle ────────────────────────────────────────


def _release(maintained, eoas=None, eol=None, *, is_eoas=False, is_eol=False, eoes=None, is_eoes=None, name="1"):
    return {
        "name": name,
        "isMaintained": maintained,
        "isEoas": is_eoas,
        "eoasFrom": eoas,
        "isEol": is_eol,
        "eolFrom": eol,
        "isEoes": is_eoes,
        "eoesFrom": eoes,
    }


@pytest.mark.parametrize(
    ("releases", "status", "next_eol"),
    [
        # Windows Server: 2025 in active support, 2022 security only, older ones over.
        (WINDOWS_SERVER["result"]["releases"], "maintained", "2031-10-14"),
        ([_release(True, "2026-01-01", "2028-01-01", is_eoas=True)], "security_only", "2028-01-01"),
        # Past end of life, in extended support: the extended end is the next one.
        (
            [_release(True, eol="2025-01-01", is_eol=True, eoes="2027-06-30", is_eoes=False)],
            "security_only",
            "2027-06-30",
        ),
        ([_release(False, eol="2020-01-01", is_eol=True)], "eol", None),
        ([], "unknown", None),
        # Maintained with no announced end.
        ([_release(True)], "maintained", None),
        # An end date on or before today isn't upcoming.
        ([_release(True, eol="2026-10-28")], "maintained", None),
        (
            [_release(True, eol="2027-01-01"), _release(True, eol="2026-12-01"), _release(False, eol="2026-11-01")],
            "maintained",
            "2026-12-01",
        ),
    ],
)
def test_support_status_and_next_eol(releases, status, next_eol):
    assert lifecycle(releases, TODAY) == (status, next_eol)


def test_parsed_product_holds_the_releases_table_and_link():
    parsed = parse_product(WINDOWS_SERVER["result"], TODAY)
    assert parsed["link"] == {"url": "https://endoflife.date/windows-server", "label": "endoflife.date/windows-server"}
    assert parsed["releases"][:3] == [
        {
            "release": "Windows Server 2025 (LTSC)",
            "released": "2024-11-01",
            "active_until": "2029-11-13",
            "security_until": "2034-11-14",
            "status": "maintained",
        },
        {
            "release": "Windows Server 23H2 AC",
            "released": "2023-10-24",
            "active_until": "2026-05-12",
            "security_until": "2026-05-12",
            "status": "eol",
        },
        {
            "release": "Windows Server 2022 (LTSC)",
            "released": "2021-08-18",
            "active_until": "2026-10-13",
            "security_until": "2031-10-14",
            "status": "security only",
        },
    ]


# ── endoflife.date: the job ──────────────────────────────────────────


class _EndOfLife:
    def __init__(self, product=WINDOWS_SERVER):
        self.product = product
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path == "/api/v1/products":
            return httpx.Response(200, json=EOL_PRODUCTS)
        if path == "/api/v1/products/windows-server":
            return httpx.Response(200, json=self.product)
        return httpx.Response(404)


@pytest.fixture
async def eol_products(db_session):
    microsoft = Vendor(name="Microsoft")
    db_session.add(microsoft)
    await db_session.flush()
    server = Product(name="Windows Server", vendor_id=microsoft.id)
    twin = Product(name="Microsoft Windows Server", next_eol=date(2020, 1, 1))
    exchange = Product(name="Exchange", vendor_id=microsoft.id)  # endoflife answers 404 here
    other = Product(name="Endoflifetest Unlisted")
    db_session.add_all([server, twin, exchange, other])
    await db_session.flush()
    return server, twin, exchange, other


async def test_endoflife_sync_writes_lifecycle_columns_and_context(db_session, eol_products, client, auth_headers):
    server_product, twin, exchange, other = eol_products
    upstream = _EndOfLife()
    db_session.add(
        EnrichmentSource(
            source_type="endoflife",
            display_name="endoflife.date",
            is_enabled=True,
            trigger_mode="manual",
            config={},
            rate_limit_config={"requests_per_period": 100, "period_seconds": 60},
        )
    )
    await db_session.flush()

    stats = await sync_endoflife(db_session, _gateway("endoflife", upstream))

    assert stats == {"catalog": 10, "matched": 3, "updated": 2, "failed": 1, "withdrawn": 0, "stopped": None}
    # The list, then each matched endoflife.date product once.
    assert [r.url.path for r in upstream.requests] == [
        "/api/v1/products",
        "/api/v1/products/msexchange",
        "/api/v1/products/windows-server",
    ]
    assert all(r.headers["User-Agent"] == USER_AGENT for r in upstream.requests)
    for product in (server_product, twin):
        assert (product.support_status, product.next_eol) == ("maintained", date(2031, 10, 14))
    assert (exchange.support_status, other.support_status) == (None, None)

    resp = await client.get(f"/api/entities/product/{server_product.id}/context", headers=auth_headers)
    (source,) = [s for s in resp.json()["sources"] if s["source_type"] == "endoflife"]
    assert source["license"] == {"name": "MIT", "attribution": "endoflife.date"}
    releases, link = source["items"]
    assert link == {
        "key": "link",
        "label": "endoflife.date",
        "display": "link",
        "value": {"url": "https://endoflife.date/windows-server", "label": "endoflife.date/windows-server"},
    }
    assert releases["display"] == "table"
    assert releases["value"]["columns"] == ["Release", "Released", "Active until", "Security until", "Status"]
    assert releases["value"]["rows"][0] == [
        "Windows Server 2025 (LTSC)",
        "2024-11-01",
        "2029-11-13",
        "2034-11-14",
        "maintained",
    ]
    assert len(releases["value"]["rows"]) == 6


async def test_endoflife_clears_next_eol_when_no_end_is_left(db_session, eol_products):
    server_product, *_ = eol_products
    gone = copy.deepcopy(WINDOWS_SERVER)
    for release in gone["result"]["releases"]:
        release.update(isMaintained=False, isEol=True)

    await sync_endoflife(db_session, _gateway("endoflife", _EndOfLife()))
    assert server_product.next_eol == date(2031, 10, 14)
    await sync_endoflife(db_session, _gateway("endoflife", _EndOfLife(gone)))

    assert (server_product.support_status, server_product.next_eol) == ("eol", None)


async def test_a_product_that_stops_matching_loses_its_lifecycle(db_session, eol_products):
    server_product, twin, *_ = eol_products
    await sync_endoflife(db_session, _gateway("endoflife", _EndOfLife()))
    assert server_product.support_status == "maintained"

    server_product.name = "Endoflifetest Renamed Server"
    await db_session.flush()
    stats = await sync_endoflife(db_session, _gateway("endoflife", _EndOfLife()))

    assert stats["withdrawn"] == 1
    await db_session.refresh(server_product)
    assert (server_product.support_status, server_product.next_eol) == (None, None)
    assert await _context(db_session, "product", server_product.id, "endoflife") == {}
    # The twin still matches and keeps its answer; a second run withdraws nothing more.
    assert twin.support_status == "maintained"
    assert (await sync_endoflife(db_session, _gateway("endoflife", _EndOfLife())))["withdrawn"] == 0


async def test_endoflife_sync_stops_cleanly_on_a_refusal(db_session, eol_products):
    gateway = _gateway("endoflife", _EndOfLife())
    await gateway._trip("throttle", 600)

    stats = await sync_endoflife(db_session, gateway)

    assert stats["stopped"] == "breaker_open" and stats["catalog"] == 0


async def test_endoflife_stops_when_its_pace_runs_out(db_session, eol_products):
    """Its quota is one request a second; past the wait a job may take, it stops."""
    from app.enrichment.registry import SOURCE_REGISTRY

    quota = SOURCE_REGISTRY["endoflife"].quota
    assert (quota.requests_per_period, quota.period_seconds) == (1, 1)
    gateway = SourceGateway(
        "endoflife", rate_limit_config=quota.rate_limit_config, inner=httpx.MockTransport(_EndOfLife()), max_wait=0
    )

    stats = await sync_endoflife(db_session, gateway)

    assert stats["stopped"] == "rate_limited"


# ── Migration ────────────────────────────────────────────────────────


async def test_migration_adds_and_drops_the_lifecycle_columns(db_session):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    path = Path(__file__).parent.parent / "alembic" / "versions" / "w1k2d3a4e5o6_product_support_lifecycle.py"
    spec = importlib.util.spec_from_file_location("lifecycle_migration", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    assert migration.down_revision == "f7s8v9c0d1e2"

    def run(step):
        def go(sync_conn):
            with Operations.context(MigrationContext.configure(sync_conn)):
                step()

        return go

    async def columns() -> set[str]:
        rows = await db_session.execute(
            text("SELECT column_name FROM information_schema.columns WHERE table_name = 'products'")
        )
        return {r[0] for r in rows}

    connection = await db_session.connection()
    await connection.run_sync(run(migration.downgrade))
    assert not {"support_status", "next_eol"} & await columns()
    await connection.run_sync(run(migration.upgrade))
    assert {"support_status", "next_eol"} <= await columns()
