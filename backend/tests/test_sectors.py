"""Controlled-vocabulary sector normalization (plan item 3.5)."""

from app.intelligence.sectors import (
    CANONICAL_SECTORS,
    normalize_sector,
    normalize_sectors,
    parse_sector_setting,
    sector_label,
)


def test_alias_maps_to_canonical_slug():
    assert normalize_sector("banks") == "financial-services"
    assert normalize_sector("Hospitals") == "healthcare"


def test_canonical_name_passthrough():
    assert normalize_sector("healthcare") == "healthcare"


def test_unknown_sector_dropped():
    assert normalize_sector("xyzzy") is None
    assert normalize_sector("") is None
    assert normalize_sector(None) is None


def test_normalize_sectors_dedupes_and_drops_unknown():
    assert normalize_sectors(["banks", "financial services", "xyzzy", "healthcare"]) == [
        "financial-services",
        "healthcare",
    ]


def test_parse_setting_splits_and_normalizes():
    assert parse_sector_setting("healthcare, banks, xyzzy") == ["healthcare", "financial-services"]
    assert parse_sector_setting("") == []
    assert parse_sector_setting(None) == []


def test_sector_label_is_human_readable():
    assert sector_label("financial-services") == "Financial Services"
    for slug in CANONICAL_SECTORS:
        assert sector_label(slug)
