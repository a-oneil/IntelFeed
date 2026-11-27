"""The analyst's preferred query language, and where it reaches.

One setting (``users.settings.query_language``) says which SIEM or query
language the analyst works in. Everything that writes a query or detection
logic for them reads it from here: the Threats board's hunt packs, the default
rule formats offered when drafting detection rules, and — through
``run_task`` — every AI prompt, which receives ``query_language`` and
``query_language_name`` as template variables whether or not the caller set
them. A prompt that produces queries says "write it in {{ query_language_name }}";
a prompt that does not ignores the variables.

The ids are IntelFeed's own. ``rule_type`` is the library format a language
maps onto (``RULE_TYPE_PATTERN`` in schemas/intelligence.py), so a preference
can pick the default formats for rule generation.
"""

import uuid
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True)
class QueryLanguage:
    id: str
    name: str
    short: str
    # The detection-rule format this language is stored as. Every language has
    # one (``RULE_TYPE_PATTERN`` in schemas/intelligence.py), so a conversion
    # into it can be saved as a sibling rule; ``yaral``, ``aql``, ``sumo`` and
    # ``sql`` are stored unchecked, since the validator has no parser for them.
    # ES|QL and EQL share ``elastic_ql`` and are told apart by dialect.
    rule_type: str | None
    # Markdown fence tag for exported queries.
    fence: str
    # What ATHF's frontmatter ``data_sources`` calls the platform.
    platform: str


QUERY_LANGUAGES: dict[str, QueryLanguage] = {
    q.id: q
    for q in (
        QueryLanguage("kql", "KQL (Microsoft Sentinel / Defender XDR)", "KQL", "kql", "kql", "Sentinel"),
        QueryLanguage("spl", "SPL (Splunk)", "SPL", "splunk_spl", "spl", "Splunk"),
        QueryLanguage("esql", "ES|QL (Elastic)", "ES|QL", "elastic_ql", "esql", "Elasticsearch"),
        QueryLanguage("eql", "EQL (Elastic)", "EQL", "elastic_ql", "eql", "Elasticsearch"),
        QueryLanguage("cql", "CQL (CrowdStrike Falcon / LogScale)", "CQL", "crowdstrike_ql", "text", "CrowdStrike"),
        QueryLanguage("yaral", "YARA-L (Google SecOps, Chronicle)", "YARA-L", "yaral", "yaral", "Google SecOps"),
        QueryLanguage("aql", "AQL (IBM QRadar)", "AQL", "aql", "sql", "QRadar"),
        QueryLanguage("sumo", "Sumo Logic search", "Sumo", "sumo", "text", "Sumo Logic"),
        QueryLanguage("sql", "SQL (data lake: Athena, Snowflake, BigQuery)", "SQL", "sql", "sql", "SQL"),
        QueryLanguage("panther", "Panther (Python detections)", "Panther", "panther", "python", "Panther"),
        QueryLanguage("sigma", "Sigma (vendor-neutral)", "Sigma", "sigma", "yaml", "Sigma"),
    )
}
DEFAULT_QUERY_LANGUAGE = "kql"
SETTING_KEY = "query_language"

# Rule formats offered by default when drafting detection rules: Sigma, which
# converts everywhere, plus the analyst's own language when the library stores
# it. Two formats at most; the analyst can add more by hand.
BASE_RULE_TYPE = "sigma"


def preferred_query_language(settings: dict | None) -> str:
    """The analyst's language id from their settings blob, or the default."""
    raw = (settings or {}).get(SETTING_KEY)
    return raw if isinstance(raw, str) and raw in QUERY_LANGUAGES else DEFAULT_QUERY_LANGUAGE


def language(lang_id: str) -> QueryLanguage:
    return QUERY_LANGUAGES.get(lang_id) or QUERY_LANGUAGES[DEFAULT_QUERY_LANGUAGE]


def default_rule_types(settings: dict | None) -> list[str]:
    """Rule formats to generate when the caller does not choose: Sigma plus the preferred language's format."""
    own = language(preferred_query_language(settings)).rule_type
    return [BASE_RULE_TYPE] if own in (None, BASE_RULE_TYPE) else [BASE_RULE_TYPE, own]


def prompt_variables(lang_id: str) -> dict[str, str]:
    """The two template variables every prompt can rely on."""
    q = language(lang_id)
    return {"query_language": q.id, "query_language_name": q.name}


async def preferred_for_user(db: AsyncSession, user_id: uuid.UUID | None) -> str:
    """The language for a user id — the default for the system sentinel or an unknown id."""
    if user_id is None or user_id == uuid.UUID(int=0):
        return DEFAULT_QUERY_LANGUAGE
    from app.models.user import User

    user = await db.get(User, user_id)
    return preferred_query_language(user.settings if user is not None else None)


def with_query_language(variables: dict, lang_id: str) -> dict:
    """``variables`` plus the language keys, without overriding ones the caller set."""
    merged = dict(variables)
    for k, v in prompt_variables(lang_id).items():
        merged.setdefault(k, v)
    return merged
