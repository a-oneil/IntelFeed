"""One-shot prod data chores from the entity-guardrails follow-up (2026-08-16).

1. Merge leetspeak duplicate malware ``n0_esc4pe`` -> ``NoEscape`` (unblocks the
   malware normalized_name unique constraint).
2. Strip the generic-family AV detection alias ``Trojan.GenericFCA.Script.37952``
   from both entities that carry it (a malware and a tool twin of the same
   browser extension) — "Generic" detection names are shared across unrelated
   malware, so as an alias it cross-links wrong entities. The 2026-08 alias
   audit found all OTHER filename/AV-string aliases to be legitimate, precise
   match surfaces (cmd.exe, W32.Stuxnet, client32.exe, ...) — do NOT mass-strip.
3. Fold the ``product`` "Metasploit" (which absorbed 274 autolinks) into the
   canonical ``tool`` "Metasploit" — relinks entries, unions aliases
   (MSF, Metasploit Framework, Metasploit Project), writes a product-type
   tombstone so it can't resurrect, deletes the product row.

Entity ids are looked up by name at runtime; every action no-ops cleanly if
already applied (idempotent). Run inside the prod api container:

    docker compose -f docker-compose.prod.yml exec -T api \
        python scripts/archive/guardrails_prod_chores_2026_08.py
"""

import asyncio

from sqlalchemy import select

from app.api.entity_merge import (
    MergeRequest,
    ReclassifyRequest,
    perform_malware_merge,
    perform_reclassify,
)
from app.database import async_session
from app.models.malware_family import MalwareFamily
from app.models.product import Product
from app.models.tool import Tool

BAD_ALIAS = "Trojan.GenericFCA.Script.37952"


async def main():
    async with async_session() as db:
        # 1. n0_esc4pe -> NoEscape
        target = (await db.execute(select(MalwareFamily).where(MalwareFamily.name == "NoEscape"))).scalar_one_or_none()
        source = (await db.execute(select(MalwareFamily).where(MalwareFamily.name == "n0_esc4pe"))).scalar_one_or_none()
        if target is not None and source is not None:
            res = await perform_malware_merge(
                db,
                target.id,
                MergeRequest(source_id=source.id, reasoning="leetspeak duplicate of NoEscape (guardrails follow-up)"),
            )
            print("merge n0_esc4pe -> NoEscape:", getattr(res, "status", "ok"))
        else:
            print("merge: skipped (source or target missing — already merged?)")

        # 2. strip the generic-family AV alias from both carriers
        for model in (MalwareFamily, Tool):
            rows = (await db.execute(select(model))).scalars().all()
            for r in rows:
                if BAD_ALIAS in (r.aliases or []):
                    r.aliases = [a for a in r.aliases if a != BAD_ALIAS]
                    print(f"alias stripped from {model.__name__} {r.name!r}")

        # 3. product Metasploit -> tool Metasploit
        prod = (await db.execute(select(Product).where(Product.name == "Metasploit"))).scalar_one_or_none()
        tool = (await db.execute(select(Tool).where(Tool.name == "Metasploit"))).scalar_one_or_none()
        if prod is not None and tool is not None:
            res = await perform_reclassify(
                db,
                ReclassifyRequest(
                    source_type="product",
                    source_id=prod.id,
                    target_type="tool",
                    target_id=tool.id,
                    reasoning=(
                        "Metasploit product/tool twin: tool is canonical under the broad tools "
                        "scope; the product row had absorbed the autolinks"
                    ),
                ),
            )
            print("reclassify product Metasploit -> tool:", getattr(res, "status", "ok"))
        else:
            print("reclassify: skipped (product or tool missing — already folded?)")

        await db.commit()

        tool = (await db.execute(select(Tool).where(Tool.name == "Metasploit"))).scalar_one_or_none()
        if tool is not None:
            print("tool Metasploit now:", tool.article_count, "articles; aliases:", tool.aliases)

        from app.intelligence.autolinker import refresh_vocabulary

        print("vocab refreshed:", await refresh_vocabulary(db), "surface forms")


if __name__ == "__main__":
    asyncio.run(main())
