"""One-shot repair of entities the cross-type fold typed wrong, Sept 2026.

fold_cross_type_twins.py picks a survivor by coverage, which is right for a
ransomware brand wearing two types and wrong when two unrelated things happen
to share a name. Three such merges went through on the 2026-09-13 prod run, and
two long-standing NetSupport entities carry each other's names. This fixes each
one explicitly; it is not a general rule, which is why every target is named.

  Medusa       The Kali login brute-forcer (tool) was folded into Medusa
               ransomware (malware). Unrelated. The tool is restored under a
               disambiguated name so it cannot re-poison the autolinker — bare
               "Medusa" in an article means the ransomware essentially always.
  Medusa (2)   With the tool out of the way, the ransomware folds into the
               Medusa Group actor like every other ransomware brand.
  Sigma        Sigma ransomware was folded into Sigma, the detection-rule
               format. The format is not a threat entity and its name collides
               with a real malware family, so the entity is deleted outright
               and the name denied so extraction cannot recreate it.
  Storm-1175   A Microsoft actor designation that ended up tombstoned toward
               malware. The correct actor already exists; the tombstone just
               needs standing down so it stops redirecting.
  NetSupport   NetSupport Manager is a legitimate RMM product; NetSupport RAT
               is the name for its abuse (Malpedia win.netsupportmanager_rat).
               Both were on the wrong entities. The RAT collapses into one
               malware entity, and the legit product keeps the tool slot.
  DoppelPaymer Grief is DoppelPaymer rebranded, so the alias on Grief is right
               and the empty doppelpaymer actor is the duplicate. Deleted.

Dry-run by default. Idempotent: every step checks current state first, so a
re-run after a partial failure picks up where it stopped.

    docker compose -f docker-compose.prod.yml exec -T api \
        python scripts/maintenance/fix_mistyped_entities_2026_09.py [--apply]

Run reconcile_search_index.py afterwards.
"""

import argparse
import asyncio
import sys

sys.path.insert(0, "/app")

from sqlalchemy import delete, or_, select

from app.api.entity_merge import ReclassifyRequest, perform_reclassify
from app.database import async_session
from app.intelligence.correlation_cache import invalidate_entity_cache
from app.intelligence.entity_resolution import deny_entity_names
from app.models.entity_maintenance import EntityReclassifyTombstone
from app.models.entity_relationship import EntityRelationship
from app.models.malware_family import MalwareFamily
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool
from app.services.entity_indexer import delete_entity_document

# Restored under a disambiguated name on purpose: a tool called plain "Medusa"
# would immediately re-collide with the ransomware and regenerate false links.
MEDUSA_TOOL_NAME = "Medusa (login brute-forcer)"
MEDUSA_TOOL_DESC = (
    "Medusa is a parallel, modular network login brute-forcer by Joe Mondloch (JoMo-Kun), "
    "shipped in Kali Linux. Unrelated to Medusa ransomware despite the shared name."
)


class Steps:
    def __init__(self, db, apply: bool):
        self.db = db
        self.apply = apply
        self.done: list[str] = []
        self.skipped: list[str] = []

    def did(self, msg: str) -> None:
        self.done.append(msg)
        print(f"  {'[apply]' if self.apply else '[dry] '} {msg}")

    def skip(self, msg: str) -> None:
        self.skipped.append(msg)
        print(f"  [skip]  {msg}")

    async def deactivate_tombstone(self, normalized: str) -> None:
        rows = (
            (
                await self.db.execute(
                    select(EntityReclassifyTombstone).where(
                        EntityReclassifyTombstone.normalized_name == normalized,
                        EntityReclassifyTombstone.active.is_(True),
                    )
                )
            )
            .scalars()
            .all()
        )
        if not rows:
            self.skip(f"tombstone '{normalized}' already inactive")
            return
        for row in rows:
            if self.apply:
                row.active = False
            self.did(f"stand down tombstone '{normalized}' ({row.source_type} -> {row.target_type})")

    async def delete_tool(self, name: str, *, deny: bool) -> None:
        tool = (await self.db.execute(select(Tool).where(Tool.name == name))).scalar_one_or_none()
        if tool is None:
            self.skip(f"tool '{name}' already gone")
            return
        links = len((await self.db.execute(select(EntryTool).where(EntryTool.tool_id == tool.id))).scalars().all())
        if self.apply:
            await self.db.execute(delete(EntryTool).where(EntryTool.tool_id == tool.id))
            await self.db.execute(
                delete(EntityRelationship).where(
                    or_(
                        (EntityRelationship.source_type == "tool") & (EntityRelationship.source_id == tool.id),
                        (EntityRelationship.target_type == "tool") & (EntityRelationship.target_id == tool.id),
                    )
                )
            )
            names = [tool.name, *(tool.aliases or [])]
            tool_id = tool.id
            await self.db.delete(tool)
            await self.db.flush()
            delete_entity_document("tool", tool_id)
            if deny:
                await deny_entity_names(
                    self.db, "tool", names, reason="detection rule format, not a threat entity (analyst decision)"
                )
        self.did(f"delete tool '{name}' (+{links} entry links)" + (", deny its names" if deny else ""))

    async def delete_actor(self, name: str) -> None:
        actor = (await self.db.execute(select(ThreatActor).where(ThreatActor.name == name))).scalar_one_or_none()
        if actor is None:
            self.skip(f"actor '{name}' already gone")
            return
        links = len(
            (await self.db.execute(select(EntryThreatActor).where(EntryThreatActor.threat_actor_id == actor.id)))
            .scalars()
            .all()
        )
        if links:
            self.skip(f"actor '{name}' now has {links} entry links — not deleting, review by hand")
            return
        if self.apply:
            await self.db.execute(
                delete(EntityRelationship).where(
                    or_(
                        (EntityRelationship.source_type == "threat_actor") & (EntityRelationship.source_id == actor.id),
                        (EntityRelationship.target_type == "threat_actor") & (EntityRelationship.target_id == actor.id),
                    )
                )
            )
            actor_id = actor.id
            await self.db.delete(actor)
            await self.db.flush()
            delete_entity_document("threat_actor", actor_id)
        self.did(f"delete empty actor '{name}'")

    async def create_tool(self, name: str, description: str) -> None:
        existing = (await self.db.execute(select(Tool).where(Tool.name == name))).scalar_one_or_none()
        if existing is not None:
            self.skip(f"tool '{name}' already exists")
            return
        if self.apply:
            self.db.add(
                Tool(
                    name=name,
                    aliases=[],
                    description=description,
                    tool_type="credential_access",
                    created_via="manual",
                )
            )
            await self.db.flush()
        self.did(f"recreate tool '{name}'")

    async def rename(self, model, entity_type: str, old: str, new: str) -> None:
        entity = (await self.db.execute(select(model).where(model.name == old))).scalar_one_or_none()
        if entity is None:
            self.skip(f"{entity_type} '{old}' not found (already renamed?)")
            return
        if self.apply:
            entity.name = new
            await self.db.flush()
            await invalidate_entity_cache(entity_type, str(entity.id))
        self.did(f"rename {entity_type} '{old}' -> '{new}'")

    async def strip_alias(self, model, entity_type: str, name: str, alias: str) -> None:
        entity = (await self.db.execute(select(model).where(model.name == name))).scalar_one_or_none()
        if entity is None:
            self.skip(f"{entity_type} '{name}' not found for alias strip")
            return
        remaining = [a for a in (entity.aliases or []) if a.lower() != alias.lower()]
        if len(remaining) == len(entity.aliases or []):
            self.skip(f"{entity_type} '{name}' no longer carries alias '{alias}'")
            return
        if self.apply:
            entity.aliases = remaining
            await self.db.flush()
        self.did(f"strip alias '{alias}' from {entity_type} '{name}'")

    async def fold(self, src_model, src_type: str, src_name: str, tgt_model, tgt_type: str, tgt_name: str) -> None:
        src = (await self.db.execute(select(src_model).where(src_model.name == src_name))).scalar_one_or_none()
        tgt = (await self.db.execute(select(tgt_model).where(tgt_model.name == tgt_name))).scalar_one_or_none()
        if src is None:
            self.skip(f"{src_type} '{src_name}' already folded away")
            return
        if tgt is None:
            self.skip(f"{tgt_type} '{tgt_name}' not found — cannot fold '{src_name}' into it")
            return
        if not self.apply:
            self.did(f"fold {src_type} '{src_name}' -> {tgt_type} '{tgt_name}'")
            return
        res = await perform_reclassify(
            self.db,
            ReclassifyRequest(
                source_type=src_type,
                source_id=src.id,
                target_type=tgt_type,
                target_id=tgt.id,
                mode="apply",
                reasoning="fix_mistyped_entities_2026_09.py — explicit analyst-reviewed fold",
            ),
        )
        self.did(f"fold {src_type} '{src_name}' -> {tgt_type} '{tgt_name}' ({res.moved_entry_links} links moved)")


async def main(apply: bool) -> None:
    async with async_session() as db:
        s = Steps(db, apply)

        print("\nSigma — delete the detection-rule format entity")
        await s.delete_tool("Sigma", deny=True)
        await s.deactivate_tombstone("sigma")

        print("\nStorm-1175 — actor already exists; stop the tombstone redirecting to malware")
        await s.deactivate_tombstone("storm-1175")

        print("\nDoppelPaymer — Grief is the rebrand; the empty actor is the duplicate")
        await s.delete_actor("doppelpaymer")

        print("\nNetSupport — collapse the RAT, give the tool slot back to the legit product")
        await s.fold(Tool, "tool", "NetSupport RAT", MalwareFamily, "malware", "netsupport manager")
        await s.rename(MalwareFamily, "malware", "netsupport manager", "NetSupport RAT")
        await s.rename(Tool, "tool", "NetSupport RMM Tool Abuse", "NetSupport Manager")
        await s.strip_alias(Tool, "tool", "NetSupport Manager", "NetSupportManager RAT")

        print("\nMedusa — restore the brute-forcer, then fold the ransomware into its gang")
        await s.deactivate_tombstone("medusa")
        await s.create_tool(MEDUSA_TOOL_NAME, MEDUSA_TOOL_DESC)
        await s.fold(MalwareFamily, "malware", "Medusa", ThreatActor, "threat_actor", "Medusa Group")

        if apply:
            await db.commit()

    print(f"\n{len(s.done)} step(s) {'applied' if apply else 'planned'}, {len(s.skipped)} already in place")
    if apply:
        print("Next: python scripts/maintenance/reconcile_search_index.py")
    else:
        print("Re-run with --apply to execute.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="Execute (default is a dry run).")
    asyncio.run(main(ap.parse_args().apply))
