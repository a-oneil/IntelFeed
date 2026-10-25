"""Auto-import detection rules from github_repo entries into the intelligence graph.

When a github_repo entry is created with a parseable content_type, this service:
- Creates/updates DetectionRule records (Sigma, Elastic, Splunk, Sentinel, YARA)
- Links entries to TTP entities via ATT&CK technique IDs
- Links entries to CVE entities (Nuclei templates)
- Tags LOLBAS/Atomic entries with metadata (no rule creation)
- Cross-references rules with recent intelligence sharing the same TTPs
- Provides detection coverage tracking queries
"""

import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cve import CVE, EntryCVE
from app.models.detection_rule import DetectionRule
from app.models.entry import Entry
from app.models.ttp import TTP, EntryTTP
from app.services.entity_indexer import index_rule, index_rules

logger = logging.getLogger(__name__)

# Map github_repo content_type → DetectionRule.rule_type
_RULE_TYPE_MAP: dict[str, str] = {
    "sigma_rule": "sigma",
    "elastic_rule": "elastic_ql",
    "splunk_detection": "splunk_spl",
    "sentinel_rule": "kql",
    "yara_rule": "yara",
    "nuclei_template": "nuclei",
    "panther_rule": "panther",
    "kql_query": "kql",
}

# Content types whose rule type is chosen per file from the extracted metadata
# (`import_rule_type`): an Anvilogic Armory file names its query language in
# `logic_format`.
_PER_FILE_RULE_TYPES = {"anvilogic_rule"}

# Content types that get metadata tagging but NOT rule creation
_METADATA_ONLY_TYPES = {"lolbas_entry", "loobin_entry", "loldriver_entry", "atomic_test"}

# Best-effort license per upstream owner/repo (keyed lowercase). Used to answer
# "can I reuse this rule?" in the library. Falls back to None when unknown.
_REPO_LICENSE: dict[str, str] = {
    "sigmahq": "DRL-1.1",
    "projectdiscovery": "MIT",
    "elastic": "Elastic-2.0",
    "splunk": "Apache-2.0",
    "azure": "MIT",  # Azure-Sentinel
    "neo23x0": "CC-BY-4.0",  # signature-base / YARA
    "yara-rules": "GPL-2.0",
    "reversinglabs": "MIT",
    "chronicle": "Apache-2.0",
    "panther-labs": "Apache-2.0",
}


def _license_for(owner: str | None, repo: str | None) -> str | None:
    """Look up a best-effort license for a mirrored rule by owner, then owner/repo."""
    if not owner:
        return None
    key = owner.strip().lower()
    if key in _REPO_LICENSE:
        return _REPO_LICENSE[key]
    if repo:
        return _REPO_LICENSE.get(f"{key}/{repo.strip().lower()}")
    return None


def _references_from_meta(meta: dict) -> list[str]:
    """Collect advisory/blog URLs a rule cites, from whatever key the parser used."""
    refs: list[str] = []
    for key in ("references", "rule_references", "rule_reference", "reference"):
        val = meta.get(key)
        if isinstance(val, list):
            refs.extend(str(v).strip() for v in val if v)
        elif isinstance(val, str) and val.strip():
            refs.extend(p.strip() for p in val.split(",") if p.strip())
    # de-dupe, keep only http(s) URLs, preserve order
    seen: set[str] = set()
    out: list[str] = []
    for r in refs:
        if r.startswith("http") and r not in seen:
            seen.add(r)
            out.append(r)
    return out


def _parse_iso_dt(value) -> datetime | None:
    """Parse an ISO-8601 string (commit date) into an aware datetime, tolerantly."""
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


# Severity normalization: source-specific → normalized scale
_SEVERITY_MAP: dict[str, str] = {
    # Sigma levels
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
    # Elastic severity (already matches)
    "info": "info",
    # Nuclei
    "unknown": "info",
}


def _normalize_severity(raw: str) -> str:
    """Normalize severity from various rule formats to a standard scale."""
    if not raw:
        return "medium"
    return _SEVERITY_MAP.get(raw.lower(), raw.lower())


def _is_stable_rule(meta: dict, content_type: str) -> bool:
    """Determine if a rule should be marked as draft or production-ready."""
    if content_type == "sigma_rule":
        status = meta.get("rule_status", "").lower()
        return status in ("stable", "test")
    if content_type == "elastic_rule":
        return True  # Elastic rules in the repo are production
    if content_type == "splunk_detection":
        det_type = (meta.get("detection_type") or meta.get("rule_type") or "").lower()
        return det_type not in ("hunting",)
    if content_type == "nuclei_template":
        return True  # Published templates are production
    if content_type == "panther_rule":
        return True  # Published rules in the repo are production
    return True  # Default: not draft


def rule_type_for(content_type: str, meta: dict | None) -> str | None:
    """The DetectionRule.rule_type a github_repo file imports as, or None."""
    if content_type in _PER_FILE_RULE_TYPES:
        return (meta or {}).get("import_rule_type") or None
    return _RULE_TYPE_MAP.get(content_type)


def _extract_technique_ids(meta: dict) -> list[str]:
    """Pull ATT&CK technique IDs from extracted metadata."""
    ids = meta.get("mitre_attack_ids", [])
    return [tid for tid in ids if tid.upper().startswith("T")]


def _extract_tactic_names(meta: dict) -> list[str]:
    """Pull ATT&CK tactic names from extracted metadata."""
    return meta.get("mitre_tactics", [])


def _extract_cve_ids(meta: dict) -> list[str]:
    """Pull CVE IDs from extracted metadata (Nuclei templates)."""
    return meta.get("cve_ids", [])


async def import_detection_rule(
    db: AsyncSession,
    entry: Entry,
    user_id: uuid.UUID,
) -> DetectionRule | list[DetectionRule] | None:
    """Auto-import detection rule(s) from a github_repo entry.

    For YARA files containing multiple rules, extracts and stores each
    individual rule separately. Other formats produce one rule per entry.

    Returns the created/updated DetectionRule(s), or None if the entry isn't a rule type.
    """
    meta = (entry.metadata_ or {}).get("extracted", {})
    content_type = (entry.metadata_ or {}).get("content_type", "")
    raw_content = (entry.metadata_ or {}).get("raw_content", "")
    owner = (entry.metadata_ or {}).get("owner", "")
    repo = (entry.metadata_ or {}).get("repo", "")
    commit_sha = (entry.metadata_ or {}).get("commit_sha", "")

    rule_type = rule_type_for(content_type, meta)
    if not rule_type:
        return None

    # YARA files often contain many individual rules — extract and store each one
    if content_type == "yara_rule" and raw_content:
        return await _import_yara_multi_rules(
            db,
            entry,
            user_id,
            meta,
            raw_content,
            owner,
            repo,
            commit_sha,
        )

    # --- Single-rule path (Sigma, Elastic, Splunk, Sentinel, Nuclei, Panther) ---
    return await _import_single_rule(
        db,
        entry,
        user_id,
        meta,
        content_type,
        raw_content,
        rule_type,
        owner,
        repo,
        commit_sha,
    )


async def _import_yara_multi_rules(
    db: AsyncSession,
    entry: Entry,
    user_id: uuid.UUID,
    meta: dict,
    raw_content: str,
    owner: str,
    repo: str,
    commit_sha: str,
) -> list[DetectionRule]:
    """Extract individual YARA rules from a multi-rule file and upsert each one.

    Deduplicates by file_path + rule title within the same owner/repo.
    """
    from app.intelligence.rule_extraction import _extract_yara_rules

    file_path = (entry.metadata_ or {}).get("file_path", "")
    commit_record = _build_commit_record(entry, commit_sha)
    technique_ids = _extract_technique_ids(meta)
    tactic_names = _extract_tactic_names(meta)

    parsed_rules = _extract_yara_rules(raw_content)
    if not parsed_rules:
        # Fallback: store the whole file as a single rule
        return await _import_single_rule(
            db,
            entry,
            user_id,
            meta,
            "yara_rule",
            raw_content,
            "yara",
            owner,
            repo,
            commit_sha,
        )

    # Load all existing rules for this file (by file_path + owner/repo) in one query
    existing_rules_by_title: dict[str, DetectionRule] = {}
    if file_path:
        result = await db.execute(
            select(DetectionRule).where(
                DetectionRule.created_by == user_id,
                DetectionRule.metadata_["file_path"].astext == file_path,
                DetectionRule.metadata_["owner"].astext == owner,
                DetectionRule.metadata_["repo"].astext == repo,
            )
        )
        for rule in result.scalars().all():
            existing_rules_by_title[rule.title] = rule

    # Also load rules linked to this entry_id that may lack metadata (legacy)
    result2 = await db.execute(
        select(DetectionRule).where(
            DetectionRule.entry_id == entry.id,
            DetectionRule.rule_type == "yara",
        )
    )
    for rule in result2.scalars().all():
        if rule.title not in existing_rules_by_title:
            existing_rules_by_title[rule.title] = rule

    rules: list[DetectionRule] = []
    seen_titles: set[str] = set()

    for parsed in parsed_rules:
        title = parsed["title"][:500]
        rule_content = parsed["rule_content"]

        # Skip duplicate titles within the same file
        if title in seen_titles:
            continue
        seen_titles.add(title)

        tags = ["yara_rule", f"{owner}/{repo}"]
        severity = parsed.get("severity")
        rule_meta = {
            "file_path": file_path,
            "owner": owner,
            "repo": repo,
            "commit_sha": commit_sha,
            "commit_author": commit_record["author"],
            "commit_message": commit_record["message"],
            "commit_date": commit_record["date"],
            "change_type": commit_record["change_type"],
            "commit_history": [commit_record],
        }

        existing = existing_rules_by_title.get(title)
        if existing:
            # Update existing rule
            _accumulate_commit_history(existing, commit_sha, commit_record)
            existing.rule_content = rule_content
            existing.severity = severity
            existing.tags = tags
            existing.source_ttps = technique_ids
            existing.mitre_tactics = tactic_names
            existing.entry_id = entry.id
            existing.notes = f"Imported from {owner}/{repo} via commit {commit_sha[:8]}"
            # Preserve commit history from accumulation, update rest of metadata
            enriched = dict(rule_meta)
            enriched["commit_history"] = (existing.metadata_ or {}).get("commit_history", [commit_record])
            existing.metadata_ = enriched
            # Accumulate source_entries
            source_entries = list(existing.source_entries or [])
            if entry.id not in source_entries:
                source_entries.append(entry.id)
            existing.source_entries = source_entries
            rules.append(existing)
        else:
            rule = DetectionRule(
                entry_id=entry.id,
                created_by=user_id,
                rule_type="yara",
                title=title,
                description=parsed.get("description") or "",
                rule_content=rule_content,
                severity=severity,
                tags=tags,
                source_ttps=technique_ids,
                mitre_tactics=tactic_names,
                is_draft=False,
                notes=f"Imported from {owner}/{repo} via commit {commit_sha[:8]}",
                source_entries=[entry.id],
                metadata_=rule_meta,
            )
            db.add(rule)
            rules.append(rule)

    await db.flush()
    await index_rules(db, rules)
    return rules


def _build_commit_record(entry: "Entry", commit_sha: str) -> dict:
    """Build a commit history record from entry metadata."""
    return {
        "sha": commit_sha,
        "author": (entry.metadata_ or {}).get("commit_author", entry.author or "unknown"),
        "message": (entry.metadata_ or {}).get("commit_message", ""),
        "date": entry.published_at.isoformat() if entry.published_at else None,
        "change_type": (entry.metadata_ or {}).get("change_type", "modified"),
    }


def _accumulate_commit_history(existing: DetectionRule, commit_sha: str, commit_record: dict) -> None:
    """Add commit to an existing rule's history if not already present."""
    existing_meta = existing.metadata_ or {}
    commit_history = list(existing_meta.get("commit_history", []))

    prev_sha = existing_meta.get("commit_sha", "")
    if prev_sha and prev_sha != commit_sha:
        existing_shas = {c.get("sha") for c in commit_history}
        if prev_sha not in existing_shas:
            commit_history.append(
                {
                    "sha": prev_sha,
                    "author": existing_meta.get("commit_author", "unknown"),
                    "message": existing_meta.get("commit_message", ""),
                    "date": existing_meta.get("commit_date"),
                    "change_type": existing_meta.get("change_type", "modified"),
                }
            )

    existing_shas = {c.get("sha") for c in commit_history}
    if commit_sha and commit_sha not in existing_shas:
        commit_history.append(commit_record)

    commit_history.sort(key=lambda c: c.get("date") or "", reverse=True)

    # Store back on metadata so the caller can use it
    updated_meta = dict(existing_meta)
    updated_meta["commit_history"] = commit_history
    existing.metadata_ = updated_meta


async def _import_single_rule(
    db: AsyncSession,
    entry: Entry,
    user_id: uuid.UUID,
    meta: dict,
    content_type: str,
    raw_content: str,
    rule_type: str,
    owner: str,
    repo: str,
    commit_sha: str,
) -> DetectionRule | None:
    """Import a single detection rule (non-YARA or single-rule file)."""
    # Determine rule fields from extracted metadata
    title = (
        meta.get("rule_title")  # Sigma, Anvilogic
        or meta.get("rule_name")  # Elastic, YARA, Sentinel, .kql header
        or meta.get("detection_name")  # Splunk
        or meta.get("template_name")  # Nuclei
        or entry.title
    )
    description = (
        meta.get("rule_description")  # Sigma, Elastic, YARA, Sentinel
        or meta.get("detection_description")  # Splunk
        or meta.get("template_description")  # Nuclei
        or ""
    )
    severity = _normalize_severity(
        meta.get("rule_level")  # Sigma
        or meta.get("rule_severity")  # Elastic, Sentinel
        or meta.get("template_severity")  # Nuclei
        or ""
    )
    technique_ids = _extract_technique_ids(meta)
    tactic_names = _extract_tactic_names(meta)
    cve_ids = _extract_cve_ids(meta)

    # For formats with a separate query field, use the query as rule_content
    query_content = (
        meta.get("search_query")  # Splunk SPL
        or meta.get("rule_query")  # Elastic EQL, Sentinel KQL, Anvilogic logic, .kql file
        or ""
    )
    if query_content:
        rule_content = query_content
    else:
        rule_content = raw_content or ""

    # Build tags
    tags = [content_type, f"{owner}/{repo}"]
    if meta.get("rule_author"):
        tags.append(f"author:{meta['rule_author']}")
    if meta.get("template_author"):
        tags.append(f"author:{meta['template_author']}")

    if meta.get("analytic_stories"):
        for story in meta["analytic_stories"]:
            tags.append(f"story:{story}")
    if meta.get("detection_type"):
        tags.append(f"type:{meta['detection_type']}")

    if content_type == "nuclei_template" and meta.get("tags"):
        tags.extend(meta["tags"])

    if content_type == "panther_rule":
        if meta.get("log_types"):
            for lt in meta["log_types"]:
                tags.append(f"log_type:{lt}")
        if meta.get("tags"):
            tags.extend(meta["tags"])

    # Log sources
    log_sources = meta.get("log_source") or meta.get("rule_log_source")
    if isinstance(log_sources, str):
        log_sources = {"raw": log_sources}
    elif not isinstance(log_sources, dict):
        log_sources = None

    if not log_sources and meta.get("rule_index"):
        log_sources = {"indices": meta["rule_index"]}

    # Data sources
    data_sources: list[str] = []
    for dm_key in ("data_models", "data_model"):
        dm = meta.get(dm_key)
        if dm:
            data_sources.extend(dm if isinstance(dm, list) else [dm])
            break
    if meta.get("required_data_connectors"):
        data_sources.extend(meta["required_data_connectors"])
    if meta.get("rule_index"):
        indices = meta["rule_index"]
        data_sources.extend(indices if isinstance(indices, list) else [indices])
    if meta.get("log_types"):
        data_sources.extend(meta["log_types"])

    is_draft = not _is_stable_rule(meta, content_type)
    notes = f"Imported from {owner}/{repo} via commit {commit_sha[:8]}"
    commit_record = _build_commit_record(entry, commit_sha)

    # Dedup: check by entry_id, then by file path in metadata
    file_path = (entry.metadata_ or {}).get("file_path", "")
    result = await db.execute(select(DetectionRule).where(DetectionRule.entry_id == entry.id))
    existing = result.scalar_one_or_none()

    if not existing and file_path:
        result2 = await db.execute(
            select(DetectionRule).where(
                DetectionRule.created_by == user_id,
                DetectionRule.metadata_["file_path"].astext == file_path,
                DetectionRule.metadata_["owner"].astext == owner,
                DetectionRule.metadata_["repo"].astext == repo,
            )
        )
        existing = result2.scalar_one_or_none()

    if existing:
        _accumulate_commit_history(existing, commit_sha, commit_record)

        existing.title = title
        existing.description = description
        existing.rule_content = rule_content
        existing.rule_type = rule_type
        existing.severity = severity
        existing.tags = tags
        existing.source_ttps = technique_ids
        existing.source_cves = cve_ids
        existing.mitre_tactics = tactic_names
        existing.log_sources = log_sources
        existing.data_sources = data_sources
        existing.is_draft = is_draft
        existing.notes = notes
        existing.license = _license_for(owner, repo)
        existing.upstream_updated_at = _parse_iso_dt(commit_record["date"])
        existing.references = _references_from_meta(meta)
        existing.entry_id = entry.id
        enriched_meta = dict(meta)
        enriched_meta["commit_history"] = (existing.metadata_ or {}).get("commit_history", [commit_record])
        enriched_meta["file_path"] = file_path
        enriched_meta["owner"] = owner
        enriched_meta["repo"] = repo
        enriched_meta["commit_sha"] = commit_sha
        enriched_meta["commit_author"] = commit_record["author"]
        enriched_meta["commit_message"] = commit_record["message"]
        enriched_meta["commit_date"] = commit_record["date"]
        enriched_meta["change_type"] = commit_record["change_type"]
        existing.metadata_ = enriched_meta

        source_entries = list(existing.source_entries or [])
        if entry.id not in source_entries:
            source_entries.append(entry.id)
        existing.source_entries = source_entries

        rule = existing
    else:
        initial_meta = dict(meta)
        initial_meta["commit_history"] = [commit_record]
        initial_meta["file_path"] = file_path
        initial_meta["owner"] = owner
        initial_meta["repo"] = repo
        initial_meta["commit_sha"] = commit_sha
        initial_meta["commit_author"] = commit_record["author"]
        initial_meta["commit_message"] = commit_record["message"]
        initial_meta["commit_date"] = commit_record["date"]
        initial_meta["change_type"] = commit_record["change_type"]

        rule = DetectionRule(
            entry_id=entry.id,
            created_by=user_id,
            rule_type=rule_type,
            title=title,
            description=description,
            rule_content=rule_content,
            severity=severity,
            tags=tags,
            source_ttps=technique_ids,
            source_cves=cve_ids,
            mitre_tactics=tactic_names,
            log_sources=log_sources,
            data_sources=data_sources,
            is_draft=is_draft,
            notes=notes,
            license=_license_for(owner, repo),
            upstream_updated_at=_parse_iso_dt(commit_record["date"]),
            references=_references_from_meta(meta),
            source_entries=[entry.id],
            metadata_=initial_meta,
        )
        db.add(rule)

    await db.flush()
    await index_rule(db, rule)
    return rule


async def link_entry_ttps(
    db: AsyncSession,
    entry_id: uuid.UUID,
    technique_ids: list[str],
    tactic_names: list[str] | None = None,
) -> list[TTP]:
    """Look up or create TTP records and link them to the entry via EntryTTP.

    Uses "high" confidence since the rule explicitly maps to these techniques.
    """
    if not technique_ids:
        return []

    linked: list[TTP] = []
    for tid in technique_ids:
        tid = tid.strip().upper()
        if not tid:
            continue

        result = await db.execute(select(TTP).where(TTP.technique_id == tid))
        ttp = result.scalar_one_or_none()

        if ttp:
            ttp.last_seen_at = datetime.now(UTC)
            ttp.article_count += 1
        else:
            ttp = TTP(
                technique_id=tid,
                technique_name=tid,
                tactic=tactic_names[0] if tactic_names else None,
                is_subtechnique="." in tid,
            )
            db.add(ttp)
            await db.flush()

        # Create EntryTTP link if not exists
        link_result = await db.execute(
            select(EntryTTP).where(
                EntryTTP.entry_id == entry_id,
                EntryTTP.ttp_id == ttp.id,
            )
        )
        if not link_result.scalar_one_or_none():
            db.add(
                EntryTTP(
                    entry_id=entry_id,
                    ttp_id=ttp.id,
                    confidence="high",
                    source_text=f"ATT&CK mapping from detection rule: {tid}",
                )
            )

        linked.append(ttp)

    await db.flush()

    # Dispatch auto-enrichment for newly created TTPs
    try:
        from app.workers.enrichment_tasks import auto_enrich_entity

        for ttp in linked:
            if (datetime.now(UTC) - ttp.first_seen_at).total_seconds() < 5:
                auto_enrich_entity.delay(
                    entity_type="ttp",
                    entity_id=str(ttp.id),
                    entity_value=ttp.technique_id,
                )
    except Exception:
        pass  # Don't fail import if enrichment dispatch fails

    return linked


async def link_entry_cves(
    db: AsyncSession,
    entry_id: uuid.UUID,
    cve_ids: list[str],
) -> list[CVE]:
    """Look up or create CVE records and link them to the entry via EntryCVE.

    Used for Nuclei templates that reference specific CVEs.
    """
    if not cve_ids:
        return []

    linked: list[CVE] = []
    for cve_id in cve_ids:
        cve_id = cve_id.strip().upper()
        if not cve_id:
            continue

        result = await db.execute(select(CVE).where(CVE.cve_id == cve_id))
        cve = result.scalar_one_or_none()

        if cve:
            cve.updated_at = datetime.now(UTC)
        else:
            cve = CVE(cve_id=cve_id)
            db.add(cve)
            await db.flush()

        # Create EntryCVE link if not exists
        link_result = await db.execute(
            select(EntryCVE).where(
                EntryCVE.entry_id == entry_id,
                EntryCVE.cve_id == cve.id,
            )
        )
        if not link_result.scalar_one_or_none():
            db.add(EntryCVE(entry_id=entry_id, cve_id=cve.id))

        linked.append(cve)

    await db.flush()

    # Dispatch NVD enrichment for newly created CVEs
    try:
        from app.workers.enrichment_tasks import auto_enrich_entity

        for cve in linked:
            if (datetime.now(UTC) - cve.first_seen_at).total_seconds() < 5:
                auto_enrich_entity.delay(
                    entity_type="cve",
                    entity_id=str(cve.id),
                    entity_value=cve.cve_id,
                )
    except Exception:
        pass

    return linked


async def find_related_intelligence(
    db: AsyncSession,
    entry_id: uuid.UUID,
    technique_ids: list[str],
    days: int = 30,
) -> list[dict]:
    """Find recent entries that share TTPs with the given detection rule.

    Returns a list of related intelligence summaries for cross-referencing.
    """
    if not technique_ids:
        return []

    cutoff = datetime.now(UTC) - timedelta(days=days)

    # Find TTP IDs for the given technique IDs
    ttp_result = await db.execute(select(TTP.id, TTP.technique_id).where(TTP.technique_id.in_(technique_ids)))
    ttp_rows = ttp_result.all()
    if not ttp_rows:
        return []

    ttp_id_map = {row.id: row.technique_id for row in ttp_rows}
    ttp_uuids = list(ttp_id_map.keys())

    # Find other entries linked to these TTPs (excluding the current entry)
    related_result = await db.execute(
        select(
            EntryTTP.entry_id,
            EntryTTP.ttp_id,
        ).where(
            EntryTTP.ttp_id.in_(ttp_uuids),
            EntryTTP.entry_id != entry_id,
            EntryTTP.extracted_at >= cutoff,
        )
    )
    related_rows = related_result.all()
    if not related_rows:
        return []

    # Group by entry_id → set of shared technique_ids
    entry_ttps: dict[uuid.UUID, set[str]] = {}
    for row in related_rows:
        tid = ttp_id_map.get(row.ttp_id, "")
        entry_ttps.setdefault(row.entry_id, set()).add(tid)

    # Fetch entry details (limit to 20 most relevant)
    from sqlalchemy.orm import selectinload

    related_entry_ids = list(entry_ttps.keys())[:20]
    entries_result = await db.execute(
        select(Entry)
        .options(selectinload(Entry.feed))
        .where(Entry.id.in_(related_entry_ids))
        .order_by(Entry.published_at.desc().nullslast())
    )
    entries = entries_result.scalars().all()

    related = []
    for e in entries:
        shared = sorted(entry_ttps.get(e.id, set()))
        if not shared:
            continue
        feed_title = ""
        if e.feed:
            feed_title = e.feed.title
        related.append(
            {
                "entry_id": str(e.id),
                "title": e.title,
                "feed_title": feed_title,
                "shared_ttps": shared,
                "published_at": e.published_at.isoformat() if e.published_at else None,
            }
        )

    return related


def tag_metadata_only_entry(entry: Entry) -> dict:
    """Tag LOLBAS/Atomic/LOOBins entries with structured metadata.

    These entries don't become DetectionRules but carry metadata useful
    for the detection workbench and TTP linking.
    """
    meta = (entry.metadata_ or {}).get("extracted", {})
    content_type = (entry.metadata_ or {}).get("content_type", "")

    tags: list[str] = []
    if content_type in ("lolbas_entry", "loobin_entry", "loldriver_entry"):
        tags.append("detection_opportunity")
    if content_type == "atomic_test":
        tags.append("validation_available")

    return {
        "import_tags": tags,
        "content_type": content_type,
        "technique_ids": _extract_technique_ids(meta),
        "tactic_names": _extract_tactic_names(meta),
    }


async def process_github_entry(
    db: AsyncSession,
    entry: Entry,
    user_id: uuid.UUID,
) -> dict:
    """Full Phase 3 pipeline for a single github_repo entry.

    Orchestrates rule import, TTP/CVE linking, cross-referencing, and metadata tagging.
    Returns a summary dict of what was done.
    """
    metadata = entry.metadata_ or {}
    content_type = metadata.get("content_type", "")
    extracted = metadata.get("extracted", {})

    if not content_type:
        return {"status": "skipped", "reason": "no_content_type"}

    result: dict = {"status": "processed", "content_type": content_type}

    technique_ids = _extract_technique_ids(extracted)
    tactic_names = _extract_tactic_names(extracted)
    cve_ids = _extract_cve_ids(extracted)

    # Step 1: Import detection rule(s) (if applicable)
    if rule_type_for(content_type, extracted):
        imported = await import_detection_rule(db, entry, user_id)
        if imported:
            if isinstance(imported, list):
                # YARA multi-rule file
                result["rule_count"] = len(imported)
                result["rule_type"] = "yara"
                if imported:
                    result["rule_id"] = str(imported[0].id)
            else:
                result["rule_id"] = str(imported.id)
                result["rule_type"] = imported.rule_type

            # Resolve the imported rules into rule_coverage on the spot: a
            # freshly mirrored community rule should reach the Threats board
            # this hour, not after the nightly rebuild. Best-effort — a
            # vocabulary failure must never fail the import.
            try:
                from app.services.rule_coverage import resolve_rule

                for rule in imported if isinstance(imported, list) else [imported]:
                    await resolve_rule(db, rule)
            except Exception:
                logger.exception("rule_coverage resolve failed during repo sync for entry %s", entry.id)

    # Step 2: Handle metadata-only types (LOLBAS, Atomic, etc.)
    elif content_type in _METADATA_ONLY_TYPES:
        tag_info = tag_metadata_only_entry(entry)
        result["import_tags"] = tag_info["import_tags"]

    # Step 3: Link TTPs (for both rules and metadata-only types)
    if technique_ids:
        ttps = await link_entry_ttps(db, entry.id, technique_ids, tactic_names)
        result["ttps_linked"] = len(ttps)

    # Step 4: Link CVEs (primarily Nuclei templates)
    if cve_ids:
        cves = await link_entry_cves(db, entry.id, cve_ids)
        result["cves_linked"] = len(cves)

    # Step 5: Cross-reference with recent intelligence
    if technique_ids:
        related = await find_related_intelligence(db, entry.id, technique_ids)
        if related:
            # Store cross-references in entry metadata
            updated_meta = dict(metadata)
            updated_meta["related_intelligence"] = related
            entry.metadata_ = updated_meta
            metadata = updated_meta
            result["related_intelligence_count"] = len(related)

    # Step 6: Score rule relevance
    relevance = await score_rule_relevance(db, entry, user_id)
    updated_meta = dict(metadata)
    updated_meta["relevance_score"] = relevance
    entry.metadata_ = updated_meta
    metadata = updated_meta
    result["relevance_score"] = relevance

    # Step 7: Campaign correlation
    if technique_ids:
        campaigns = await correlate_with_campaigns(db, entry.id, technique_ids)
        if campaigns:
            updated_meta = dict(metadata)
            updated_meta["campaign_matches"] = campaigns
            entry.metadata_ = updated_meta
            result["campaign_matches"] = len(campaigns)

    await db.flush()
    return result


async def score_rule_relevance(
    db: AsyncSession,
    entry: Entry,
    user_id: uuid.UUID,
) -> int:
    """Score an imported rule by operational relevance (0–100).

    Scoring factors:
    - **Recency** (0–30): TTPs seen in intelligence in the last 7 days
    - **Coverage gap** (0–35): Rule covers previously uncovered techniques
    - **Source authority** (0–15): Stable rules from authoritative repos score higher
    - **ATT&CK breadth** (0–20): Rules covering multiple techniques are more valuable
    """
    metadata = entry.metadata_ or {}
    extracted = metadata.get("extracted", {})
    content_type = metadata.get("content_type", "")
    owner = metadata.get("owner", "")

    technique_ids = _extract_technique_ids(extracted)
    score = 0

    # --- Recency: Do any of the rule's TTPs appear in recent intelligence? ---
    if technique_ids:
        recent_cutoff = datetime.now(UTC) - timedelta(days=7)
        recent_result = await db.execute(
            select(TTP.technique_id).where(
                TTP.technique_id.in_(technique_ids),
                TTP.last_seen_at >= recent_cutoff,
            )
        )
        recent_ttps = {row[0] for row in recent_result.all()}
        if recent_ttps:
            # More recent matches = higher score, cap at 30
            recency_score = min(len(recent_ttps) * 10, 30)
            score += recency_score

    # --- Coverage gap: Does this rule cover techniques with no existing detection? ---
    if technique_ids:
        covered_result = await db.execute(
            select(DetectionRule.source_ttps).where(
                DetectionRule.created_by == user_id,
                DetectionRule.is_draft.is_(False),
                DetectionRule.entry_id != entry.id,
            )
        )
        already_covered: set[str] = set()
        for row in covered_result.all():
            for tid in row[0] or []:
                already_covered.add(tid)

        new_coverage = [tid for tid in technique_ids if tid not in already_covered]
        if new_coverage:
            # New coverage is the most valuable signal
            gap_score = min(len(new_coverage) * 12, 35)
            score += gap_score

    # --- Source authority: Stable rules from well-known repos ---
    authority_repos = {"sigmahq", "elastic", "splunk", "azure"}
    if owner.lower() in authority_repos:
        score += 10
    if content_type == "sigma_rule":
        status = extracted.get("rule_status", "").lower()
        if status in ("stable", "test"):
            score += 5
    elif content_type in ("elastic_rule", "splunk_detection"):
        score += 5  # Published rules in these repos are authoritative

    # --- ATT&CK breadth: Multiple techniques in one rule ---
    if len(technique_ids) >= 3:
        score += 20
    elif len(technique_ids) == 2:
        score += 12
    elif len(technique_ids) == 1:
        score += 5

    return min(score, 100)


async def correlate_with_campaigns(
    db: AsyncSession,
    entry_id: uuid.UUID,
    technique_ids: list[str],
) -> list[dict]:
    """Check if any active campaigns reference the same TTPs as this rule.

    Returns a list of campaign summaries for cross-referencing.
    Enables: "New Sigma rule covers T1059.001 — this technique is part of
    your tracked campaign 'Volt Typhoon Activity'"
    """
    if not technique_ids:
        return []

    from app.models.campaign import Campaign, CampaignEntity

    # Find TTP IDs for the given technique IDs
    ttp_result = await db.execute(select(TTP.id, TTP.technique_id).where(TTP.technique_id.in_(technique_ids)))
    ttp_rows = ttp_result.all()
    if not ttp_rows:
        return []

    ttp_id_map = {row.id: row.technique_id for row in ttp_rows}
    ttp_uuids = list(ttp_id_map.keys())

    # Find active campaigns that reference these TTPs
    campaign_result = await db.execute(
        select(
            CampaignEntity.campaign_id,
            CampaignEntity.entity_id,
        ).where(
            CampaignEntity.entity_type == "ttp",
            CampaignEntity.entity_id.in_(ttp_uuids),
        )
    )
    campaign_rows = campaign_result.all()
    if not campaign_rows:
        return []

    # Group by campaign_id → shared techniques
    campaign_ttps: dict[uuid.UUID, set[str]] = {}
    for row in campaign_rows:
        tid = ttp_id_map.get(row.entity_id, "")
        if tid:
            campaign_ttps.setdefault(row.campaign_id, set()).add(tid)

    # Fetch campaign details (only active/monitoring)
    campaign_ids = list(campaign_ttps.keys())
    campaigns_result = await db.execute(
        select(Campaign).where(
            Campaign.id.in_(campaign_ids),
            Campaign.status.in_(("active", "monitoring")),
        )
    )
    campaigns = campaigns_result.scalars().all()

    matches = []
    for c in campaigns:
        shared = sorted(campaign_ttps.get(c.id, set()))
        if not shared:
            continue
        matches.append(
            {
                "campaign_id": str(c.id),
                "campaign_name": c.name,
                "status": c.status,
                "shared_ttps": shared,
            }
        )

    return matches


async def get_detection_coverage(
    db: AsyncSession,
    user_id: uuid.UUID,
) -> dict:
    """Calculate detection coverage: TTPs seen in intelligence vs covered by rules.

    Returns a summary of coverage gaps and statistics.
    """
    # TTPs that appear in the intelligence graph (from threat reports, etc.)
    intel_ttps_result = await db.execute(
        select(TTP.technique_id, TTP.technique_name, TTP.article_count).order_by(TTP.article_count.desc())
    )
    intel_ttps = {
        row.technique_id: {
            "technique_id": row.technique_id,
            "technique_name": row.technique_name,
            "article_count": row.article_count,
        }
        for row in intel_ttps_result.all()
    }

    # TTPs covered by detection rules (from source_ttps JSONB)
    rules_result = await db.execute(
        select(DetectionRule.source_ttps, DetectionRule.title, DetectionRule.rule_type).where(
            DetectionRule.created_by == user_id,
            DetectionRule.is_draft.is_(False),
        )
    )
    covered_ttps: dict[str, list[dict]] = {}
    for row in rules_result.all():
        for tid in row.source_ttps or []:
            covered_ttps.setdefault(tid, []).append(
                {
                    "title": row.title,
                    "rule_type": row.rule_type,
                }
            )

    # Calculate gaps
    all_technique_ids = set(intel_ttps.keys())
    covered_ids = set(covered_ttps.keys())
    uncovered_ids = all_technique_ids - covered_ids

    # Sort gaps by article_count (most-seen uncovered techniques first)
    gaps = sorted(
        [intel_ttps[tid] for tid in uncovered_ids],
        key=lambda x: x["article_count"],
        reverse=True,
    )

    total = len(all_technique_ids)
    covered = len(all_technique_ids & covered_ids)

    return {
        "total_ttps_in_intelligence": total,
        "ttps_with_detection": covered,
        "ttps_without_detection": total - covered,
        "coverage_percentage": round(covered / total * 100, 1) if total > 0 else 0.0,
        "coverage_gaps": gaps[:50],  # Top 50 uncovered
        "covered_ttps": {
            tid: {
                **intel_ttps.get(tid, {"technique_id": tid, "technique_name": tid, "article_count": 0}),
                "rules": rules,
            }
            for tid, rules in covered_ttps.items()
        },
    }


async def get_validation_for_technique(
    db: AsyncSession,
    technique_id: str,
) -> list[dict]:
    """Find Atomic Red Team tests that validate detection for a given technique.

    Returns a list of entry summaries with test metadata.
    """
    # Find entries with atomic_test content_type matching this technique
    result = await db.execute(
        select(Entry).where(
            Entry.metadata_["content_type"].astext == "atomic_test",
            Entry.metadata_["extracted"]["technique_id"].astext == technique_id,
        )
    )
    entries = result.scalars().all()

    validations = []
    for e in entries:
        meta = (e.metadata_ or {}).get("extracted", {})
        validations.append(
            {
                "entry_id": str(e.id),
                "title": e.title,
                "technique_id": meta.get("technique_id", ""),
                "tests": meta.get("atomic_tests", []),
                "supported_platforms": meta.get("supported_platforms", []),
            }
        )

    return validations
