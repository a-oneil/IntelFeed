"""Article intelligence metadata normalization — plan items 3.9.6-3.9.9."""

from app.intelligence.enrichment import normalize_article_metadata


def test_valid_full_payload():
    out = normalize_article_metadata(
        {
            "report_type": "Incident Report",
            "victim_organizations": ["Acme Corp", "acme corp", "Globex"],
            "timeline": {"disclosure_date": "2026-01-05", "compromise_date": None, "patch_date": "2026-01-10"},
            "patch": {"status": "available", "reference": "https://vendor/patch"},
        }
    )
    assert out["report_type"] == "incident_report"
    assert out["victim_organizations"] == ["Acme Corp", "Globex"]  # deduped case-insensitively
    assert out["timeline"]["disclosure_date"] == "2026-01-05"
    assert out["timeline"]["compromise_date"] is None
    assert out["patch"] == {"status": "available", "reference": "https://vendor/patch"}


def test_invalid_report_type_dropped():
    assert normalize_article_metadata({"report_type": "clickbait"})["report_type"] is None


def test_invalid_patch_status_defaults_unknown():
    out = normalize_article_metadata({"patch": {"status": "maybe", "reference": None}})
    assert out["patch"]["status"] == "unknown"


def test_empty_and_none_inputs():
    for out in (normalize_article_metadata(None), normalize_article_metadata({})):
        assert out["report_type"] is None
        assert out["victim_organizations"] == []
        assert out["timeline"] == {"disclosure_date": None, "compromise_date": None, "patch_date": None}
        assert out["patch"] == {"status": "unknown", "reference": None}


def test_report_type_hyphen_and_space_normalized():
    assert normalize_article_metadata({"report_type": "malware analysis"})["report_type"] == "malware_analysis"
    assert normalize_article_metadata({"report_type": "vendor-marketing"})["report_type"] == "vendor_marketing"
