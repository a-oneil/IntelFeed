"""Derived content-type classification for entries.

Entries have no content_type column — the type is derived from the parent
feed's feed_type plus entry metadata (github_repo imports store the detected
file content type in entry.metadata_["content_type"]). Keeping this derived
avoids a backfill migration and stays correct automatically as feeds change.

Taxonomy: article / advisory / rule / vuln_record / video / podcast / social.
"""

# github_content_types.detect_content_type() values that represent machine
# detection/IOC content rather than prose (rule repos ingested as entries).
RULE_FILE_CONTENT_TYPES = {
    "sigma_rule",
    "elastic_rule",
    "splunk_detection",
    "splunk_story",
    "sentinel_rule",
    "panther_rule",
    "yara_rule",
    "nuclei_template",
    "atomic_test",
    "lolbas_entry",
    "loobin_entry",
    "loldriver_entry",
    "ioc_list",
}

_SOCIAL_FEED_TYPES = {"reddit", "telegram", "mastodon", "bluesky"}

# Content types that are machine-generated records, not analyst-readable
# reporting — excluded from PIR auto-matching and campaign source stats.
NON_REPORTING_CONTENT_TYPES = {"rule", "vuln_record"}


def classify_entry_content_type(feed_type: str | None, metadata: dict | None) -> str:
    """Classify an entry's content type from its feed type and metadata.

    Returns one of: article, advisory, rule, vuln_record, video, podcast, social.
    """
    ft = (feed_type or "").lower()
    if ft == "nvd":
        return "vuln_record"
    if ft == "github_advisories":
        return "advisory"
    if ft == "youtube":
        return "video"
    if ft == "podcast":
        return "podcast"
    if ft in _SOCIAL_FEED_TYPES:
        return "social"
    if ft == "github_repo":
        file_type = ((metadata or {}).get("content_type") or "").lower()
        if file_type in RULE_FILE_CONTENT_TYPES:
            return "rule"
        # Markdown/docs files from repos read like articles
        return "article"
    return "article"


def is_reporting_content(feed_type: str | None, metadata: dict | None) -> bool:
    """True if the entry is analyst-readable reporting (article/advisory/etc.),
    False for machine records (detection rule files, NVD vuln records)."""
    return classify_entry_content_type(feed_type, metadata) not in NON_REPORTING_CONTENT_TYPES
