"""TLP 2.0 marking vocabulary — the single Python source for ``tlp_marking`` values.

Matches the DB CHECK constraints ``ck_campaigns_tlp_marking`` and
``ck_intel_reports_tlp_marking`` (alembic ``a3b7c9d2e4f1``). TLP 1.0's
``TLP:WHITE`` was renamed to ``TLP:CLEAR`` in TLP 2.0; ``normalize_tlp``
folds it (and stray casing/whitespace) onto the canonical value so agent
and import inputs stay friendly without widening what gets stored.
"""

from typing import Final

TLP_VALUES: Final[tuple[str, ...]] = (
    "TLP:CLEAR",
    "TLP:GREEN",
    "TLP:AMBER",
    "TLP:AMBER+STRICT",
    "TLP:RED",
)

#: Regex for pydantic ``Field(pattern=...)`` — same vocabulary as TLP_VALUES.
TLP_PATTERN: Final = r"^TLP:(CLEAR|GREEN|AMBER|AMBER\+STRICT|RED)$"

#: Retired spellings accepted as input and folded to their TLP 2.0 value.
TLP_ALIASES: Final[dict[str, str]] = {"TLP:WHITE": "TLP:CLEAR"}


def normalize_tlp(value: str) -> str:
    """Uppercase/trim a TLP marking and fold retired aliases (TLP:WHITE → TLP:CLEAR).

    Returns the input (normalized) even when it is not a valid marking —
    callers validate against ``TLP_VALUES``.
    """
    v = (value or "").strip().upper()
    return TLP_ALIASES.get(v, v)
