"""Resolve NVD CPE vendor/product strings to canonical Vendor/Product entities.

CPE 2.3 segments are lowercase-underscore ("vmware", "vcenter_server"). Matching
is exact against three sources per entity, all lowercased:
  - name
  - aliases
  - metadata_["cpe_names"]  (resolver-only curation list — NEVER written to
    aliases, which feed the autolinker vocab)

Besides the raw and underscores-to-spaces forms, both sides are also compared
in a compacted form with separators ([ _.-]) stripped, so "Red Hat" matches
the CPE segment "redhat" and "D-Link" matches "dlink" without curation.

A cpe_names entry ending in "*" is a prefix rule ("windows_server*" matches
windows_server_2019, windows_server_2022, …) — products only, checked after
exact matches. Both the raw segment and its underscores-to-spaces form are
tried. Products matching by name alone are only accepted when unambiguous: a
candidate whose vendor_id matches the resolved vendor wins; a candidate with
no vendor is acceptable; a lone candidate belonging to a DIFFERENT resolved
vendor is refused (prevents generic names like "gateway" cross-linking). No
entities are ever auto-created from CPE data.
"""

import logging
import re
import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.product import Product
from app.models.vendor import Vendor

logger = logging.getLogger(__name__)


_SEPARATORS = re.compile(r"[ _.\-]")


def _compact(value: str) -> str:
    return _SEPARATORS.sub("", value)


def _candidate_forms(segment: str) -> set[str]:
    seg = (segment or "").strip().lower()
    if not seg:
        return set()
    return {seg, seg.replace("_", " "), _compact(seg)}


def _entity_keys(name: str, aliases: list[str] | None, metadata: dict | None) -> set[str]:
    keys = {name.lower()}
    for alias in aliases or []:
        keys.add(alias.lower())
    for cpe_name in (metadata or {}).get("cpe_names", []) or []:
        if isinstance(cpe_name, str):
            keys.add(cpe_name.lower())
    for key in list(keys):
        if not key.endswith("*"):
            keys.add(_compact(key))
    return keys


@dataclass
class CPEIndex:
    """In-memory lookup built from the (small) vendors/products tables."""

    vendor_by_key: dict[str, uuid.UUID] = field(default_factory=dict)
    products_by_key: dict[str, list[tuple[uuid.UUID, uuid.UUID | None]]] = field(default_factory=dict)
    # (prefix, product_id, vendor_id) from cpe_names entries ending in "*"
    product_prefixes: list[tuple[str, uuid.UUID, uuid.UUID | None]] = field(default_factory=list)

    def resolve_vendor(self, cpe_vendor: str) -> uuid.UUID | None:
        for form in _candidate_forms(cpe_vendor):
            vendor_id = self.vendor_by_key.get(form)
            if vendor_id:
                return vendor_id
        return None

    def resolve_product(self, cpe_product: str, vendor_id: uuid.UUID | None) -> uuid.UUID | None:
        candidates: list[tuple[uuid.UUID, uuid.UUID | None]] = []
        for form in _candidate_forms(cpe_product):
            for cand in self.products_by_key.get(form, []):
                if cand not in candidates:
                    candidates.append(cand)
        if not candidates:
            # Prefix rules, longest prefix first so more specific curation wins
            seg = (cpe_product or "").strip().lower()
            for prefix, pid, vid in sorted(self.product_prefixes, key=lambda p: -len(p[0])):
                if seg.startswith(prefix) and (pid, vid) not in candidates:
                    candidates.append((pid, vid))
        if not candidates:
            return None
        if vendor_id:
            scoped = [pid for pid, vid in candidates if vid == vendor_id]
            if scoped:
                return scoped[0]  # same vendor, same key — arbitrary but stable
            unvendored = [pid for pid, vid in candidates if vid is None]
            if len(unvendored) == 1:
                return unvendored[0]
            # Every candidate belongs to a different vendor — refuse to cross-link
            return None
        if len(candidates) == 1:
            return candidates[0][0]
        # Ambiguous across vendors with no vendor context — refuse to guess
        return None

    def resolve_pair(self, cpe_vendor: str, cpe_product: str) -> tuple[uuid.UUID | None, uuid.UUID | None]:
        vendor_id = self.resolve_vendor(cpe_vendor)
        product_id = self.resolve_product(cpe_product, vendor_id)
        return vendor_id, product_id


async def build_cpe_index(db: AsyncSession) -> CPEIndex:
    index = CPEIndex()
    vendors = (await db.execute(select(Vendor.id, Vendor.name, Vendor.aliases, Vendor.metadata_))).all()
    for vendor_id, name, aliases, metadata in vendors:
        for key in _entity_keys(name, aliases, metadata):
            index.vendor_by_key.setdefault(key, vendor_id)
    products = (
        await db.execute(select(Product.id, Product.vendor_id, Product.name, Product.aliases, Product.metadata_))
    ).all()
    for product_id, vendor_id, name, aliases, metadata in products:
        for key in _entity_keys(name, aliases, metadata):
            if key.endswith("*"):
                prefix = key.rstrip("*")
                if prefix:
                    index.product_prefixes.append((prefix, product_id, vendor_id))
            else:
                index.products_by_key.setdefault(key, []).append((product_id, vendor_id))
    return index
