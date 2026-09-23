"""Attack-chain (kill-chain) ordering for extracted TTPs — plan item 3.9.4.

Renders an article's or entity's techniques as an *ordered* narrative
(initial access → execution → …) instead of a bag of technique IDs. The
order is derived from each technique's ATT&CK tactic(s), so no new
extraction is needed once the TTP catalog is hydrated (see W2a).
"""

from __future__ import annotations

# Canonical ATT&CK Enterprise tactic kill-chain order (attack.mitre.org).
# Slugs match the hydrated catalog's `tactic` / `tactics` values.
ENTERPRISE_TACTIC_ORDER: list[str] = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

_TACTIC_LABELS = {slug: slug.replace("-", " ").title() for slug in ENTERPRISE_TACTIC_ORDER}
_ORDER_INDEX = {slug: i for i, slug in enumerate(ENTERPRISE_TACTIC_ORDER)}


def tactic_label(slug: str | None) -> str:
    if not slug:
        return "Unmapped"
    return _TACTIC_LABELS.get(slug, slug.replace("-", " ").title())


def _tactics_of(ttp: dict) -> list[str]:
    """Return a technique's tactic slugs, tolerating single `tactic` or list `tactics`."""
    tactics = ttp.get("tactics")
    if isinstance(tactics, list) and tactics:
        return [t for t in tactics if t]
    single = ttp.get("tactic")
    return [single] if single else []


def order_by_kill_chain(ttps: list[dict]) -> list[dict]:
    """Group techniques into ordered kill-chain phases.

    Each input dict should carry at least `technique_id`, `technique_name`,
    and `tactic` or `tactics`. A technique spanning multiple tactics appears
    in each relevant phase. Techniques with no known tactic collect into a
    trailing "Unmapped" phase. Empty phases are omitted.

    Returns a list of {tactic, label, order, techniques: [...]} in kill-chain
    order, so the frontend can render a left-to-right chain strip.
    """
    buckets: dict[str, list[dict]] = {}
    for ttp in ttps:
        tactics = _tactics_of(ttp)
        placed = False
        for slug in tactics:
            if slug in _ORDER_INDEX:
                buckets.setdefault(slug, []).append(ttp)
                placed = True
        if not placed:
            buckets.setdefault("__unmapped__", []).append(ttp)

    phases: list[dict] = []
    for slug in ENTERPRISE_TACTIC_ORDER:
        if slug in buckets:
            phases.append(
                {
                    "tactic": slug,
                    "label": tactic_label(slug),
                    "order": _ORDER_INDEX[slug],
                    "techniques": buckets[slug],
                }
            )
    if "__unmapped__" in buckets:
        phases.append(
            {
                "tactic": None,
                "label": "Unmapped",
                "order": len(ENTERPRISE_TACTIC_ORDER),
                "techniques": buckets["__unmapped__"],
            }
        )
    return phases
