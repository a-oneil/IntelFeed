"""Tests for derived entry content-type classification."""

from app.services.content_classification import (
    classify_entry_content_type,
    is_reporting_content,
)


def test_rss_is_article():
    assert classify_entry_content_type("rss", {}) == "article"
    assert classify_entry_content_type("atom", None) == "article"
    assert classify_entry_content_type(None, None) == "article"


def test_nvd_is_vuln_record():
    assert classify_entry_content_type("nvd", {}) == "vuln_record"


def test_github_advisories_is_advisory():
    assert classify_entry_content_type("github_advisories", {}) == "advisory"


def test_media_feed_types():
    assert classify_entry_content_type("youtube", {}) == "video"
    assert classify_entry_content_type("podcast", {}) == "podcast"


def test_social_feed_types():
    for ft in ("reddit", "telegram", "mastodon", "bluesky"):
        assert classify_entry_content_type(ft, {}) == "social"


def test_github_repo_rule_files_are_rules():
    for file_type in ("sigma_rule", "elastic_rule", "yara_rule", "splunk_detection", "ioc_list"):
        assert classify_entry_content_type("github_repo", {"content_type": file_type}) == "rule"


def test_github_repo_docs_are_articles():
    assert classify_entry_content_type("github_repo", {"content_type": "markdown_file"}) == "article"
    assert classify_entry_content_type("github_repo", {}) == "article"
    assert classify_entry_content_type("github_repo", None) == "article"


def test_is_reporting_content_excludes_machine_records():
    assert is_reporting_content("rss", {}) is True
    assert is_reporting_content("github_advisories", {}) is True
    assert is_reporting_content("youtube", {}) is True
    assert is_reporting_content("nvd", {}) is False
    assert is_reporting_content("github_repo", {"content_type": "sigma_rule"}) is False
