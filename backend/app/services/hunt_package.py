"""The hunt package: one zip with everything a hunter takes away from an entity.

Downloaded from the profile's Next steps card and the Threats board drawer.
It replaces an earlier research bundle (the newest hundred articles, every
co-mentioned entity, a flat ATT&CK layer), which for a ransomware actor was
mostly leak-site posts and other groups' names; that is why each file below
is selected and ranked rather than dumped.

What goes in:

- ``README.md``: what is in the zip, the counts, what was left out and why.
- ``profile.md``: the profile export (assessment, aliases, facts).
- ``hunts/``: one ATHF hunt file per hypothesis of the profile pack, and the
  board's window packs under ``hunts/threats-board-<window>/``.
- ``queries/``: each hunt's query on its own, in the pack's language.
- ``telemetry.md``: the data sources the hunts need, collected or not.
- ``detections/``: rules written for this entity in their own formats, and
  the analyst's saved rule sets under ``detections/sets/``.
- ``attack_layer.json``: the claimed techniques, colored by rule coverage;
  ``attack_layer_mentioned.json`` the ones its articles only mention.
- ``entities.md`` / ``entities.json``: claimed relationships first, then
  co-mentions, kept apart and labeled as such.
- ``iocs.csv`` / ``iocs.stix.json``: the observables ledger's rows from the
  entity's articles, with confidence and first/last seen; the STIX bundle
  holds only the rows that pass the publish rules.
- ``timeline.csv``: every linked article, one row each.
- ``articles/``: full text of up to ``ARTICLE_CAP`` articles, leak-site posts
  skipped: those naming the entity in the title first, then those a claim
  rests on, then the ones with the most techniques.

A file with nothing to put in it is left out, and README says so.
"""

import csv
import io
import json
import re
import uuid
import zipfile
from datetime import UTC, datetime

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app import entity_types
from app.ai.query_language import language
from app.services import hunt_pack as hp

ARTICLE_CAP = 100
RULE_CAP = 200
CO_MENTION_MD_CAP = 10
PIVOT_LIMIT = 200

_RULE_EXT = {
    "sigma": "yml",
    "yara": "yar",
    "kql": "kql",
    "splunk_spl": "spl",
    "elastic_ql": "eql",
    "esql": "esql",
    "nuclei": "yaml",
    "panther": "py",
    "crowdstrike_ql": "cql",
    "snort_suricata": "rules",
}
_QUERY_EXT = {
    "kql": "kql",
    "spl": "spl",
    "esql": "esql",
    "eql": "eql",
    "cql": "cql",
    "yaral": "yaral",
    "aql": "aql",
    "sumo": "sumo",
    "sql": "sql",
    "panther": "py",
    "sigma": "yml",
}
# Navigator colors: has a rule / rule can't run (logs not collected) / no rule.
_COVERAGE_COLOR = {"covered": "#3fb950", "library_only": "#d29922", "no_rule": "#f85149"}
_COVERAGE_WORDS = {
    "covered": "has a rule",
    "library_only": "has a rule that can't run: its logs aren't collected",
    "no_rule": "no rule",
}

# Related-list keys in the pivot, by entity type, in the order entities.md lists them.
_RELATED_KEYS = [
    ("ttps", "ttp", "Techniques"),
    ("tools", "tool", "Tools"),
    ("malwares", "malware", "Malware"),
    ("cves", "cve", "CVEs"),
    ("threat_actors", "threat_actor", "Threat actors"),
    ("cwes", "cwe", "Weaknesses"),
    ("sectors", "sector", "Sectors"),
    ("countrys", "country", "Countries"),
    ("vendors", "vendor", "Vendors"),
    ("products", "product", "Products"),
    ("mitigations", "mitigation", "Mitigations"),
]


def _slug(value: str, limit: int = 60) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")[:limit].strip("-") or "item"


def _item_name(item: dict) -> str:
    if item.get("technique_id"):
        return f"{item['technique_id']} {item.get('technique_name') or ''}".strip()
    return item.get("name") or item.get("cve_id") or item.get("cwe_id") or item.get("value") or str(item.get("id"))


def _day(value: str | None) -> str:
    return (value or "")[:10]


# ── data ─────────────────────────────────────────────────────────────────────


async def _entity_entries(db: AsyncSession, entity_type: str, row_id: str, label: str) -> list:
    """Every article linked to the entity, newest first, with what ranks it for articles/."""
    from app.services.coverage_workspace import ENTITY_SOURCES

    junction, fk = ENTITY_SOURCES[entity_type]
    sql = f"""
        SELECT e.id, e.title, e.url, e.author, e.published_at, f.title AS feed_title,
               coalesce((SELECT string_agg(DISTINCT t.technique_id, ' ')
                         FROM entry_ttps j JOIN ttps t ON t.id = j.ttp_id
                         WHERE j.entry_id = e.id), '') AS techniques,
               (SELECT count(*) FROM entry_ttps j WHERE j.entry_id = e.id) AS n_techniques,
               e.title ILIKE :leak AS leak_post,
               e.id = ANY(:evidence) AS is_evidence,
               e.title ILIKE :named AS names_entity
        FROM entries e JOIN feeds f ON f.id = e.feed_id
        WHERE e.id IN (SELECT entry_id FROM {junction} WHERE {fk} = :rid)
        ORDER BY e.published_at DESC NULLS LAST
    """  # noqa: S608 — table names are literals from ENTITY_SOURCES
    params = {
        "rid": uuid.UUID(row_id),
        "leak": hp.LEAK_SITE_TITLE,
        "evidence": await hp.evidence_entry_ids(db, entity_type, row_id),
        "named": hp.title_pattern(label),
    }
    return (await db.execute(text(sql), params)).all()


async def _observables(db: AsyncSession, entry_ids: list[uuid.UUID]) -> list[tuple]:
    """(Observable, article count, newest source title, newest source url) for the entity's articles."""
    from app.models.entry import Entry
    from app.models.observable import EntryObservable, Observable

    if not entry_ids:
        return []
    rows = (
        await db.execute(
            select(Observable, func.count(func.distinct(EntryObservable.entry_id)), func.max(Entry.published_at))
            .join(EntryObservable, EntryObservable.observable_id == Observable.id)
            .join(Entry, Entry.id == EntryObservable.entry_id)
            .where(EntryObservable.entry_id.in_(entry_ids), Observable.is_denied.is_(False))
            .group_by(Observable.id)
            .order_by(Observable.kind, Observable.value)
        )
    ).all()
    out = []
    for obs, n, _latest in rows:
        src = (
            await db.execute(
                select(Entry.title, Entry.url)
                .join(EntryObservable, EntryObservable.entry_id == Entry.id)
                .where(EntryObservable.observable_id == obs.id, Entry.id.in_(entry_ids))
                .order_by(Entry.published_at.desc().nulls_last())
                .limit(1)
            )
        ).first()
        out.append((obs, n, src.title if src else "", src.url if src else ""))
    return out


# The STIX bundle is what a TIP or blocklist ingests, so it takes the publish
# feed's stance: active, never dual-use infrastructure, never a shared host,
# never a site in the Tranco top 10k (a news site an article links to is not
# an indicator, whatever role extraction gave it). iocs.csv keeps every row
# with those columns, for the analyst to judge.
POPULAR_RANK = 10_000


def _stix_worthy(o) -> bool:
    from app.api.publish import _suffix_excluded

    if o.status != "active" or o.infra_tag or not (o.first_seen_at and o.last_seen_at):
        return False
    if o.popularity_rank is not None and o.popularity_rank <= POPULAR_RANK:
        return False
    return not _suffix_excluded(o, [])


# ── files ────────────────────────────────────────────────────────────────────


def _layer(name: str, rows: list[dict], status: dict[str, dict]) -> dict:
    techniques = []
    for r in rows:
        tid = r.get("technique_id")
        if not tid:
            continue
        st = (status.get(tid) or {}).get("status") or "no_rule"
        articles = (r.get("strength") or {}).get("articles") or r.get("article_count") or 0
        bits = [_COVERAGE_WORDS[st], f"{articles} article{'' if articles == 1 else 's'}"]
        if r.get("relationship_confidence"):
            bits.insert(0, f"{r.get('relationship_type') or 'uses'} · {r['relationship_confidence']}")
        techniques.append(
            {
                "techniqueID": tid,
                "tactic": (r.get("tactic") or "").replace(" ", "-").lower(),
                "color": _COVERAGE_COLOR[st],
                "comment": "; ".join(bits),
                "score": articles,
                "enabled": True,
            }
        )
    top = max((t["score"] for t in techniques), default=1) or 1
    return {
        "name": name,
        "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Color: green has a rule, amber has a rule whose logs aren't collected, red no rule. "
        "Score: articles reporting the technique.",
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#ffffff"], "minValue": 0, "maxValue": top},
        "legendItems": [
            {"label": "Has a rule", "color": _COVERAGE_COLOR["covered"]},
            {"label": "Rule can't run: logs not collected", "color": _COVERAGE_COLOR["library_only"]},
            {"label": "No rule", "color": _COVERAGE_COLOR["no_rule"]},
        ],
    }


def _entities(label: str, pivot: dict) -> tuple[str, list[dict], dict]:
    """(entities.md, entities.json rows, counts) — claimed relationships first, co-mentions apart."""
    related = pivot.get("related") or {}
    totals = pivot.get("related_counts") or {}
    rows: list[dict] = []
    own_md: list[str] = []
    co_md: list[str] = []
    counts = {"claimed": 0, "co_mentioned": 0}
    for key, etype, heading in _RELATED_KEYS:
        items = related.get(key) or []
        claimed = [i for i in items if i.get("relationship_id")]
        mentioned = [i for i in items if not i.get("relationship_id")]
        for i in items:
            s = i.get("strength") or {}
            rows.append(
                {
                    "type": etype,
                    "id": str(i.get("id")),
                    "name": _item_name(i),
                    "relation": "claimed" if i.get("relationship_id") else "co_mentioned",
                    "relationship": i.get("relationship_type"),
                    "direction": i.get("relationship_direction"),
                    "confidence": i.get("relationship_confidence"),
                    "evidence_articles": i.get("relationship_evidence_count"),
                    "articles": s.get("articles"),
                    "first_seen": s.get("first_seen"),
                    "last_seen": s.get("last_seen"),
                    "aliases": i.get("aliases") or [],
                }
            )
        counts["claimed"] += len(claimed)
        counts["co_mentioned"] += len(mentioned)
        if claimed:
            own_md += ["", f"### {heading} ({len(claimed)})"]
            for i in sorted(claimed, key=lambda x: (x.get("relationship_confidence") != "confirmed", _item_name(x))):
                s = i.get("strength") or {}
                bits = [
                    f"{i.get('relationship_type') or 'related'} · {i.get('relationship_confidence') or ''}".strip(" ·")
                ]
                if s.get("articles"):
                    bits.append(f"{s['articles']} article{'' if s['articles'] == 1 else 's'}")
                if s.get("first_seen") and s.get("last_seen"):
                    bits.append(f"{_day(s['first_seen'])} → {_day(s['last_seen'])}")
                own_md.append(f"- {_item_name(i)} — {' · '.join(bits)}")
        if mentioned:
            total = max(0, (totals.get(key) or len(items)) - len(claimed))
            co_md += ["", f"### {heading} ({total})"]
            for i in mentioned[:CO_MENTION_MD_CAP]:
                n = (i.get("strength") or {}).get("articles") or i.get("co_occurrence_count")
                co_md.append(f"- {_item_name(i)}" + (f" — {n} article{'' if n == 1 else 's'}" if n else ""))
            if total > CO_MENTION_MD_CAP:
                co_md.append(f"- …{total - CO_MENTION_MD_CAP} more")
    md = [f"# {label} — entities", "", f"## {label}'s own", "Claimed relationships: confirmed or probable."]
    md += own_md or ["", "None claimed yet."]
    md += [
        "",
        f"## Mentioned alongside {label}",
        "In the same articles, not claimed as related. "
        f"Top {CO_MENTION_MD_CAP} per type; entities.json has every one it was exported with.",
    ]
    md += co_md or ["", "None."]
    return "\n".join(md) + "\n", rows, counts


def _telemetry_md(label: str, packs: list[tuple[str, dict]]) -> str:
    lines = [f"# Telemetry the hunts need — {label}", ""]
    for folder, pack in packs:
        lines += [f"## {folder}", "", "| Hunt | Source | Collected |", "|---|---|---|"]
        for h in pack["hypotheses"]:
            for t in h.get("telemetry") or []:
                lines.append(f"| {h['id']} {h['title']} | `{t['source']}` | {'yes' if t['have'] else '**no**'} |")
        lines.append("")
    return "\n".join(lines)


def _query_file(pack: dict, h: dict) -> tuple[str, str]:
    lang = language(pack["language"])
    ext = _QUERY_EXT.get(pack["language"], "txt")
    comment = "#" if ext in ("spl", "py", "yml", "yaral") else "//"
    if ext == "sql":
        comment = "--"
    head = [
        f"{comment} {h['id']}: {h['title']}",
        f"{comment} {h['hypothesis']}",
        f"{comment} Techniques: {', '.join(h.get('techniques') or []) or 'n/a'}",
        f"{comment} Data sources: {', '.join(h.get('data_sources') or []) or 'see query'}",
        f"{comment} Language: {lang.name}",
        "",
    ]
    return f"{h['id']}-{_slug(h['title'], 40)}.{ext}", "\n".join(head) + h["query"].rstrip() + "\n"


# ── the zip ──────────────────────────────────────────────────────────────────


async def build_hunt_package(
    db: AsyncSession, user, entity_type: str, entity_key: str, lang: str
) -> tuple[str, bytes] | None:
    """(file name, zip bytes) for one entity, or None when it doesn't resolve."""
    from app.api.publish import _stix_indicator
    from app.intelligence.correlation import pivot_from_entity
    from app.services.coverage_workspace import build_set_bundle, list_sets
    from app.services.detection_coverage import classify_techniques
    from app.services.entity_markdown import build_entity_profile_markdown
    from app.services.markdown import entry_to_markdown
    from app.services.threat_board import WINDOW_HOURS

    resolved = await hp.resolve(db, entity_type, entity_key)
    if resolved is None:
        return None
    row_uuid = uuid.UUID(resolved.row_id)
    label = resolved.label
    if entity_type == entity_types.TTP:
        label = resolved.coverage_key
    base = _slug(label, 48)
    now = datetime.now(UTC)
    files: list[tuple[str, str]] = []
    notes: list[str] = []

    # profile.md and the pivot behind entities / the layers.
    pivot = await pivot_from_entity(db, entity_type, row_uuid, limit_per_type=PIVOT_LIMIT)
    profile = await build_entity_profile_markdown(db, entity_type, row_uuid)
    if profile:
        files.append(("profile.md", profile[1]))

    # Hunts: the profile pack, then any board window packs.
    packs: list[tuple[str, dict]] = []
    profile_pack = await hp.get_cached_pack(db, entity_type, resolved.coverage_key, hp.PROFILE_SCOPE, lang)
    if profile_pack:
        packs.append(("hunts", await hp.annotate_telemetry(db, profile_pack)))
    else:
        notes.append("No hunts drafted from all reporting yet — use Download hunt package on the profile.")
    for window in WINDOW_HOURS:
        board = await hp.get_cached_pack(db, entity_type, resolved.coverage_key, window, lang)
        if board:
            packs.append((f"hunts/threats-board-{window}", await hp.annotate_telemetry(db, board)))
    hunter = getattr(user, "username", None) or "intelfeed"
    for folder, pack in packs:
        for h in pack["hypotheses"]:
            one = hp.single_hypothesis(pack, h["id"])
            files.append((f"{folder}/{hp.hunt_filename(one)}", await hp.build_hunt_file(db, one, hunter=hunter)))
            qname, qbody = _query_file(pack, h)
            qfolder = "queries" if folder == "hunts" else f"queries/{folder.split('/', 1)[1]}"
            files.append((f"{qfolder}/{qname}", qbody))
    if packs:
        files.append(("telemetry.md", _telemetry_md(label, packs)))

    # Detections: rules written for this entity, then the analyst's saved sets.
    rules = await hp.linked_rules(db, entity_type, resolved, limit=RULE_CAP)
    used: set[str] = set()
    for r in rules:
        ext = _RULE_EXT.get(r["rule_type"], "txt")
        name = f"{_slug(r['title'], 70)}.{ext}"
        n = 2
        while name in used:
            name = f"{_slug(r['title'], 66)}-{n}.{ext}"
            n += 1
        used.add(name)
        files.append((f"detections/{name}", r["content"].rstrip() + "\n"))
    sets = await list_sets(db, user.id, entity_type, resolved.coverage_key)
    for summary in sets:
        folder = f"detections/sets/{_slug(summary.title, 40)}"
        for path, content in await build_set_bundle(db, summary):
            files.append((f"{folder}/{path}", content))

    # ATT&CK layers: claimed techniques colored by coverage, mentions apart.
    ttps = (pivot.get("related") or {}).get("ttps") or []
    status = await classify_techniques(db, [t.get("technique_id") for t in ttps if t.get("technique_id")])
    claimed_ttps = [t for t in ttps if t.get("relationship_id")]
    mentioned_ttps = [t for t in ttps if not t.get("relationship_id")]
    if claimed_ttps:
        files.append(
            ("attack_layer.json", json.dumps(_layer(f"{label}: claimed techniques", claimed_ttps, status), indent=2))
        )
    if mentioned_ttps:
        files.append(
            (
                "attack_layer_mentioned.json",
                json.dumps(_layer(f"{label}: techniques its articles mention", mentioned_ttps, status), indent=2),
            )
        )

    # Entities.
    ent_md, ent_rows, ent_counts = _entities(label, pivot)
    files.append(("entities.md", ent_md))
    files.append(("entities.json", json.dumps(ent_rows, indent=2, default=str)))

    # Articles: timeline of all, full text of the technique-dense ones.
    entries = await _entity_entries(db, entity_type, resolved.row_id, resolved.label)
    tl = io.StringIO()
    w = csv.writer(tl)
    w.writerow(["published", "source", "title", "url", "techniques", "leak_site_post"])
    for e in entries:
        w.writerow(
            [
                e.published_at.date().isoformat() if e.published_at else "",
                e.feed_title,
                e.title,
                e.url or "",
                e.techniques,
                "yes" if e.leak_post else "",
            ]
        )
    if entries:
        files.append(("timeline.csv", tl.getvalue()))
    # The articles naming the entity, then the ones a claim rests on, then the
    # most techniques — the same order the profile pack's prompt reads them in.
    picked = sorted(
        (e for e in entries if not e.leak_post),
        key=lambda e: (
            not e.names_entity,
            not e.is_evidence,
            -e.n_techniques,
            -(e.published_at or now).timestamp(),
        ),
    )[:ARTICLE_CAP]
    if picked:
        from app.models.entry import Entry

        by_id = {
            row.id: row
            for row in (
                await db.execute(
                    select(Entry.id, Entry.content_text, Entry.content_html).where(Entry.id.in_([e.id for e in picked]))
                )
            ).all()
        }
        names: set[str] = set()
        for e in picked:
            body = by_id.get(e.id)
            md = entry_to_markdown(
                title=e.title,
                feed_title=e.feed_title,
                author=e.author,
                published_at=e.published_at.strftime("%Y-%m-%d") if e.published_at else None,
                url=e.url,
                tags=None,
                content_text=body.content_text if body else None,
                content_html=body.content_html if body else None,
            )
            stem = f"{e.published_at.date().isoformat() if e.published_at else 'undated'}-{_slug(e.title, 60)}"
            name, n = stem, 2
            while name in names:
                name, n = f"{stem}-{n}", n + 1
            names.add(name)
            files.append((f"articles/{name}.md", md))

    # Indicators.
    obs = await _observables(db, [e.id for e in entries])
    if obs:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(
            [
                "kind",
                "value",
                "role",
                "confidence",
                "status",
                "first_seen",
                "last_seen",
                "sightings",
                "articles",
                "infra_tag",
                "tranco_rank",
                "in_stix",
                "source_title",
                "source_url",
            ]
        )
        stix_objects = []
        for o, n, src_title, src_url in sorted(obs, key=lambda r: (-r[0].current_confidence, r[0].kind, r[0].value)):
            ind = _stix_indicator(o) if _stix_worthy(o) else None
            if ind:
                stix_objects.append(ind)
            w.writerow(
                [
                    o.kind,
                    o.value,
                    o.role or "",
                    f"{o.current_confidence:.2f}",
                    o.status,
                    o.first_seen_at.date().isoformat() if o.first_seen_at else "",
                    o.last_seen_at.date().isoformat() if o.last_seen_at else "",
                    o.sighting_count,
                    n,
                    o.infra_tag or "",
                    o.popularity_rank or "",
                    "yes" if ind else "",
                    src_title,
                    src_url,
                ]
            )
        files.append(("iocs.csv", buf.getvalue()))
        if stix_objects:
            bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": stix_objects}
            files.append(("iocs.stix.json", json.dumps(bundle, indent=2)))
    else:
        notes.append("No observables in the ledger from these articles, so no iocs.csv.")

    # README last: it describes the rest.
    hunt_count = sum(len(p["hypotheses"]) for _f, p in packs)
    leak = sum(1 for e in entries if e.leak_post)
    readme = [
        f"# Hunt package — {label}",
        "",
        f"Exported from IntelFeed on {now.strftime('%Y-%m-%d %H:%M UTC')} by {hunter}.",
        f"Query language: {language(lang).name}.",
        "",
        "## What's inside",
        "",
    ]
    if profile:
        readme.append("- `profile.md` — the profile: assessment, aliases, key facts.")
    if profile_pack:
        n = len(profile_pack["hypotheses"])
        when = _day(profile_pack.get("generated_at"))
        readme.append(
            f"- `hunts/` — {n} ATHF hunt file{'' if n == 1 else 's'}, one per hypothesis, drafted from all "
            f"reporting on {when} ({profile_pack.get('model') or 'model unknown'}). "
            "Renumber `H-XXXX` in your workspace."
        )
    for folder, pack in packs:
        if folder != "hunts":
            readme.append(f"- `{folder}/` — the Threats board's {pack['window']} hunts ({len(pack['hypotheses'])}).")
    if packs:
        readme.append(f"- `queries/` — each of the {hunt_count} queries on its own.")
        missing = sorted(
            {t["source"] for _f, p in packs for h in p["hypotheses"] for t in h.get("telemetry") or [] if not t["have"]}
        )
        readme.append(
            "- `telemetry.md` — data sources per hunt."
            + (f" Not collected today: {', '.join(missing)}." if missing else " Every one is collected.")
        )
    if rules or sets:
        readme.append(
            f"- `detections/` — {len(rules)} rule{'' if len(rules) == 1 else 's'} written for {label}"
            + (
                f", and {len(sets)} saved rule set{'' if len(sets) == 1 else 's'} under `detections/sets/`"
                if sets
                else ""
            )
            + "."
        )
    if claimed_ttps:
        readme.append(
            f"- `attack_layer.json` — {len(claimed_ttps)} claimed technique{'' if len(claimed_ttps) == 1 else 's'} "
            "for ATT&CK Navigator, colored by rule coverage, scored by articles."
        )
    if mentioned_ttps:
        readme.append(
            f"- `attack_layer_mentioned.json` — {len(mentioned_ttps)} techniques its articles mention "
            "but nobody claimed."
        )
    readme.append(
        f"- `entities.md` / `entities.json` — {ent_counts['claimed']} claimed relationships, then "
        f"{ent_counts['co_mentioned']} entities only mentioned in the same articles, kept apart."
    )
    if obs:
        readme.append(
            f"- `iocs.csv` — {len(obs)} observables from these articles with role, confidence, status and "
            f"first/last seen; `iocs.stix.json` holds the {len(stix_objects)} that pass the publish rules "
            "(active, not dual-use infrastructure, not a shared host or a top-10k site)."
        )
    if entries:
        readme.append(f"- `timeline.csv` — all {len(entries)} linked articles.")
    if picked:
        readme.append(
            f"- `articles/` — full text of the {len(picked)} articles most about {label} "
            "(named in the title first, then cited as evidence, then most techniques)"
            + (f"; {leak} leak-site victim posts are only in timeline.csv." if leak else ".")
        )
    if notes:
        readme += ["", "## Left out", ""] + [f"- {n}" for n in notes]
    files.insert(0, ("README.md", "\n".join(readme) + "\n"))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, content in files:
            zf.writestr(f"{base}-hunt-package/{path}", content)
    return f"{base}-hunt-package.zip", buf.getvalue()
