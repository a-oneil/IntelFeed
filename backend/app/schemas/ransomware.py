"""Pydantic schemas for the ransomware victim tracker API (plan §7).

Powers the two UI surfaces: Leak Watch (the disclosures feed) and Ransomware
Landscape (the stats dashboard).
"""

import uuid
from datetime import date, datetime

from pydantic import BaseModel

# Canonical group → CVD-validated color slug from the mockups. The frontend maps
# the slug to a CSS var (--g-lockbit …); colour is always paired with the label.
_GROUP_COLORS = {
    "lockbit": "lockbit",
    "cl0p": "clop",
    "clop": "clop",
    "akira": "akira",
    "qilin": "qilin",
    "play": "play",
    "ransomhub": "ransomhub",
}


def group_color_slug(name: str | None) -> str:
    """Map a group name to a categorical color slug, 'other' when unknown."""
    if not name:
        return "other"
    return _GROUP_COLORS.get(name.strip().lower(), "other")


class DisclosureResponse(BaseModel):
    id: uuid.UUID
    victim_id: uuid.UUID
    victim_name: str
    domain: str | None = None
    watched: bool = False
    group_id: uuid.UUID | None = None
    group_name: str | None = None
    group_color: str = "other"
    sector: str | None = None
    sector_label: str | None = None
    country_id: uuid.UUID | None = None
    country_name: str | None = None
    country_code: str | None = None
    posted_at: datetime
    published_at: datetime | None = None
    claimed_data: str | None = None
    leak_site_url: str | None = None
    source: str
    is_new: bool = False


class TimeseriesPoint(BaseModel):
    week_start: date
    label: str
    count: int


class GroupStat(BaseModel):
    id: uuid.UUID | None = None
    name: str
    color: str = "other"
    victims: int
    share: float  # % of window total
    wow_trend: float  # week-over-week % change
    trend_up: bool


class SectorStat(BaseModel):
    sector: str
    label: str
    victims: int
    share: float


class CountryStat(BaseModel):
    id: uuid.UUID | None = None
    name: str
    iso_code: str | None = None
    victims: int


class ExposureItem(BaseModel):
    name: str
    kind: str  # "watched org" | "watched group" | "watched sector"
    status: str  # "hit" | "clear"
    detail: str
    hit: bool


class StatsTotals(BaseModel):
    victims: int
    prior_victims: int
    victims_wow: float  # % change vs prior equal window
    groups_active: int
    sectors_hit: int
    watchlist_hits: int


class RansomwareStats(BaseModel):
    days: int
    totals: StatsTotals
    timeseries: list[TimeseriesPoint]
    groups: list[GroupStat]
    sectors: list[SectorStat]
    countries: list[CountryStat]
    watchlist_exposure: list[ExposureItem]
    most_active_group: GroupStat | None = None
    fastest_riser: GroupStat | None = None


class VictimSummary(BaseModel):
    id: uuid.UUID
    name: str
    domain: str | None = None
    sector: str | None = None
    sector_label: str | None = None
    country_name: str | None = None
    country_code: str | None = None
    last_seen_at: datetime
    disclosure_count: int
    watched: bool = False


class GroupVictimStats(BaseModel):
    """Windowed leak-site victim counts for one group — the profile Snapshot's
    "Leak-site victims · 30d" row (count + delta vs the prior 30 days)."""

    total: int
    last_30d: int
    prev_30d: int


class VictimGroupRef(BaseModel):
    id: uuid.UUID | None = None
    name: str | None = None
    color: str = "other"


class VictimDetail(BaseModel):
    id: uuid.UUID
    name: str
    domain: str | None = None
    aliases: list[str] = []
    country_id: uuid.UUID | None = None
    country_name: str | None = None
    country_code: str | None = None
    sector: str | None = None
    sector_label: str | None = None
    first_seen_at: datetime
    last_seen_at: datetime
    disclosure_count: int
    watched: bool = False
    groups: list[VictimGroupRef] = []
    disclosures: list[DisclosureResponse] = []
