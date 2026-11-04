"""Pipeline stage registry — the entry processing chain as data.

Mirrors the enrichment adapter registry pattern: stages are code-defined here,
composition/config is data-defined via PipelinePlan rows (feed > category >
global) resolved in app/pipeline/plans.py. The Celery chord structure built
from this registry is asserted structurally identical to the previous
hand-built dispatch by tests/test_pipeline_registry.py.

Stage kinds:
- inline   — runs synchronously inside the fetch loop (documented here for the
             Engine UI; not dispatched as Celery tasks)
- pre      — chained ahead of the chord so its output (e.g. translated text) is
             visible to every later stage; must never raise (a raised prologue
             would stop the chain and skip the whole pipeline)
- parallel — chord header after entry creation (autolink ∥ telegram_links ∥ extract)
- post     — second chord header after the parallel stages complete
- final    — second chord callback (signal scoring)
- post_analysis — runs after the entry's one-pass AI analysis has landed
             (minutes to hours after `score`, from the ai queue); dispatched by
             services/entry_adjudication.enqueue_adjudication, never by the chord
- side     — dispatched independently of the chord (automation)
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class StageDef:
    name: str
    kind: str  # inline | pre | parallel | post | final | post_analysis | side
    task_path: str | None
    description: str
    default_enabled: bool = True
    # Jsonschema-ish hints for the Engine UI config panel
    config_schema: dict = field(default_factory=dict)


PIPELINE_STAGES: dict[str, StageDef] = {
    "sanitize": StageDef(
        name="sanitize",
        kind="inline",
        task_path=None,
        description="HTML sanitization (nh3 allowlist) + text extraction during fetch",
    ),
    "dedup": StageDef(
        name="dedup",
        kind="inline",
        task_path=None,
        description="GUID + cross-feed content-hash deduplication during fetch",
    ),
    "relevance": StageDef(
        name="relevance",
        kind="inline",
        task_path=None,
        description="Keyword/pattern relevance score — gates autolink (selective mode) and the AI junk filter",
        config_schema={"threshold": {"type": "number", "setting": "ai_analysis_relevance_threshold"}},
    ),
    "index": StageDef(
        name="index",
        kind="inline",
        task_path=None,
        description="Meilisearch indexing (with failed-index retry queue)",
    ),
    "translate": StageDef(
        name="translate",
        kind="pre",
        task_path="app.workers.translation_tasks.translate_entry_task",
        description=(
            "Auto-translation for feeds with translation enabled — runs before "
            "autolink/extract so all later stages see the translated text"
        ),
    ),
    "autolink": StageDef(
        name="autolink",
        kind="parallel",
        task_path="app.workers.intel_feed_tasks.autolink_entry_task",
        description=(
            "Aho-Corasick entity linking (actors, malware, CVEs, TTPs, vendors, products, tools); "
            "dictionary-word matches held pending AI confirmation"
        ),
    ),
    "observables": StageDef(
        name="observables",
        kind="parallel",
        task_path="app.workers.intel_feed_tasks.observables_entry_task",
        description=(
            "Observable candidates (refang + precision regex) staged on the entry, sightings of "
            "known ledger values, and curated ioc_list body parsing — regex never creates a ledger row"
        ),
    ),
    "telegram_links": StageDef(
        name="telegram_links",
        kind="parallel",
        task_path="app.workers.telegram_link_tasks.scan_telegram_links_task",
        description="Telegram URL/mention extraction",
    ),
    "extract": StageDef(
        name="extract",
        kind="parallel",
        task_path="app.workers.intel_feed_tasks.extract_entry_intel_task",
        description=(
            "Regex intel extraction (TTP/CVE/mitigation IDs, detection rules); AI analysis runs via the batch queue"
        ),
        default_enabled=False,  # historical default: only when feed.auto_extract_on_ingest
        config_schema={
            "mode": {"type": "string", "setting": "feed.intel_extraction_mode"},
            "detection_rules": {"type": "boolean", "setting": "feed.extract_detection_rules"},
        },
    ),
    "cooccurrence": StageDef(
        name="cooccurrence",
        kind="post",
        task_path="app.workers.intel_feed_tasks.create_cooccurrence_relationships_task",
        description="Entity co-occurrence relationship edges",
    ),
    "correlation": StageDef(
        name="correlation",
        kind="post",
        task_path="app.workers.automation_tasks.detect_correlation_events",
        description="Correlation event detection",
    ),
    "requirements": StageDef(
        name="requirements",
        kind="post",
        task_path="app.workers.intel_feed_tasks.match_requirements_task",
        description="Intelligence requirement (PIR) matching",
    ),
    "score": StageDef(
        name="score",
        kind="final",
        task_path="app.workers.signal_tasks.score_entry_task",
        description="Signal engine scoring + one-pass AI analysis enqueue",
    ),
    "adjudicate": StageDef(
        name="adjudicate",
        kind="post_analysis",
        task_path="app.workers.adjudication_tasks.adjudicate_entry_task",
        description=(
            "AI review of everything the one-pass analysis wrote to the entry — links, minted entities, "
            "asserted edges, observables — with the article in hand; verdicts are filed as proposals "
            "(shadow) or applied inline. Replaces the nightly hygiene jobs"
        ),
        # Enabled in the registry so that, with pipeline plans off (the default),
        # the adjudication_mode setting alone decides; plans only subtract feeds.
        default_enabled=True,
        config_schema={"mode": {"type": "string", "setting": "adjudication_mode"}},
    ),
    "enrich": StageDef(
        name="enrich",
        kind="side",
        task_path="app.workers.enrichment_dispatch_tasks.dispatch_enrichment_jobs",
        description=(
            "Entity enrichment from external sources: new entities queue lookups in enrichment_jobs, "
            "the dispatcher runs them as each source allows"
        ),
    ),
    "automate": StageDef(
        name="automate",
        kind="side",
        task_path="app.workers.automation_tasks.run_entry_automations",
        description="Automation rule evaluation (on_new_entry / keyword / CVE triggers)",
    ),
}


def stages_of_kind(kind: str) -> list[StageDef]:
    return [s for s in PIPELINE_STAGES.values() if s.kind == kind]
