"""Malpedia adapter — free (optional API key for higher access).

Provides malware family and threat actor intelligence from Fraunhofer FKIE's Malpedia database.

Malpedia keys a family by platform and name (``win.emotet``), so a family name
alone never answers ``get/family``. The adapter asks ``find/family`` for the
name and takes only an exact hit: a family whose id names it, else one whose
alternative names include it. A Windows family wins over the same name on
another platform; two different families that both claim the name are left
alone rather than guessed between.
"""

from urllib.parse import quote

import httpx

from app import entity_types
from app.enrichment.base import EnrichmentAdapter, EnrichmentData
from app.enrichment.manifest import Column, Context, Display, Egress, Job, License, Policy, Quota, Relation

_TYPES = ("malware", "tool", "threat_actor")

#: A family's page on Malpedia, by family id.
DETAILS_URL = "https://malpedia.caad.fkie.fraunhofer.de/details/"

#: References kept for the profile's table.
URL_LIMIT = 10


def _norm(name: str) -> str:
    """A name as Malpedia spells ids: lower case, underscores for spaces and hyphens."""
    return name.strip().lower().replace(" ", "_").replace("-", "_")


def _platform_first(ids: list[str]) -> list[str]:
    """Windows families first, then the rest by id."""
    return sorted(set(ids), key=lambda i: (not i.startswith("win."), i))


def pick_family(name: str, hits: list) -> str | None:
    """The family id ``find/family`` hits name exactly, or None.

    An id whose name part is the name wins (``win.lockbit`` over ``elf.lockbit``:
    one family, several platforms). Else a family listing the name among its
    alternative names, when only one family (Windows ones first) does."""
    norm = _norm(name)
    rows = [h for h in hits if isinstance(h, dict) and isinstance(h.get("name"), str)]
    by_id = [h["name"] for h in rows if h["name"].partition(".")[2] == norm]
    if by_id:
        return _platform_first(by_id)[0]
    by_alt = [h["name"] for h in rows if norm in {_norm(a) for a in h.get("alt_names") or [] if isinstance(a, str)}]
    windows = [i for i in by_alt if i.startswith("win.")]
    candidates = set(windows or by_alt)
    return candidates.pop() if len(candidates) == 1 else None


def pick_actor(name: str, hits: list) -> str | None:
    """The actor id ``find/actor`` hits name exactly: by its name, else by a
    synonym only one actor lists. Malpedia files groups like Andariel as a
    synonym of Lazarus, so a synonym hit never beats a name hit."""
    norm = _norm(name)
    rows = [h for h in hits if isinstance(h, dict) and isinstance(h.get("name"), str)]
    named = {h["name"] for h in rows if norm in (_norm(h["name"]), _norm(h.get("common_name") or ""))}
    if len(named) == 1:
        return named.pop()
    if named:
        return None
    synonym = {h["name"] for h in rows if norm in {_norm(s) for s in h.get("synonyms") or [] if isinstance(s, str)}}
    return synonym.pop() if len(synonym) == 1 else None


def family_facts(family_id: str, data: dict, fallback_name: str) -> dict:
    """A ``get/family`` answer as parsed_data."""
    urls = [u for u in data.get("urls") or [] if isinstance(u, str)]
    return {
        "found": True,
        "family_id": family_id,
        "family_name": data.get("common_name") or fallback_name,
        "description": (data.get("description") or "")[:2000],
        "alt_names": data.get("alt_names", []),
        # Actor names; the relation links the ones IntelFeed tracks.
        "attribution": [a for a in data.get("attribution") or [] if isinstance(a, str)],
        "urls": urls[:URL_LIMIT],  # plain URL strings, for the profile
        # Picked from every reference, not the first ten: Emotet's first
        # GitHub link is its 48th.
        "github_urls": [u for u in urls if "github.com/" in u][:5],
        "malpedia_url": DETAILS_URL + family_id,
    }


class MalpediaAdapter(EnrichmentAdapter):
    source_type = "malpedia"
    display_name = "Malpedia"
    about = "Fraunhofer's catalog of malware families and the actors behind them."
    # Families by name or alternative name (find/family), actors by name or synonym.
    applies_to = {
        "malware": None,
        "tool": None,
        "threat_actor": None,
    }
    quota = Quota(30, 60, daily_budget=1000)
    egress = Egress.LOW
    license = License("CC BY-NC-SA 3.0", attribution="Malpedia (Fraunhofer FKIE)", commercial_ok=False)
    jobs = (
        # Writes malware, tool and actor rows, so it runs on its own day: the
        # Sunday catalog syncs also write threat_actors, and sharing their slot
        # deadlocked.
        Job(
            "malpedia-sync",
            "app.workers.enrichment_tasks.run_malpedia_sync",
            {"type": "crontab", "minute": "0", "hour": "1", "day_of_week": "6"},
            "Sync malware families from Malpedia",
        ),
    )
    outputs = (
        *(Column("description", f"{t}.description", Policy.RANK, rank=3) for t in _TYPES),
        *(Column("malpedia_url", f"{t}.malpedia_url") for t in ("malware", "tool")),
        # The only place a tool's repository already shows up.
        Column("github_urls", "tool.github_url", filter="github_url"),
        *(Column("alt_names", f"{t}.aliases", Policy.UNION, rank=2, filter="aliases") for t in _TYPES),
        Column("country", "threat_actor.country", resolve="country"),
        # A family's attribution names actors: "malware attributed_to
        # threat_actor". The matrix has no tool → actor attribution, so a
        # tool's list stays context only.
        Relation("attribution", "attributed_to", (entity_types.THREAT_ACTOR,)),
        Context("attribution", "Attributed to", Display.CHIPS, entity_types=("malware", "tool")),
        Context("urls", "References", Display.TABLE, item={"Link": None}, entity_types=("malware", "tool")),
        Context("families", "Families", Display.CHIPS, entity_types=("threat_actor",)),
        Context("refs", "References", Display.TABLE, item={"Link": None}, entity_types=("threat_actor",)),
    )

    _api_base = "https://malpedia.caad.fkie.fraunhofer.de/api/"

    def _headers(self) -> dict:
        return {"Authorization": f"apitoken {self.api_key}"} if self.api_key else {}

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        # Malpedia files offensive tooling (Cobalt Strike, Mimikatz) under the
        # same "family" namespace as malware, so tools use the same lookup.
        if entity_type in ("malware", "tool"):
            return await self._enrich_malware(entity_value)
        elif entity_type == "threat_actor":
            return await self._enrich_actor(entity_value)
        return _not_found()

    async def _find(self, client: httpx.AsyncClient, kind: str, name: str) -> list:
        resp = await client.get(f"{self._api_base}find/{kind}/{quote(name.strip(), safe='')}", headers=self._headers())
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        hits = resp.json()
        return hits if isinstance(hits, list) else []

    async def _enrich_malware(self, family_name: str) -> EnrichmentData:
        async with self.http(timeout=15) as client:
            # A value that looks like a family id ("win.emotet") is tried as one
            # first; "Agent.BTZ" 404s there and falls back to a name search.
            name = family_name.strip()
            family_id = name.lower() if "." in name and " " not in name else None
            resp = None
            if family_id is not None:
                resp = await client.get(f"{self._api_base}get/family/{family_id}", headers=self._headers())
                if resp.status_code == 404:
                    family_id, resp = None, None
            if family_id is None:
                family_id = pick_family(family_name, await self._find(client, "family", family_name))
                if family_id is None:
                    return _not_found()
                resp = await client.get(f"{self._api_base}get/family/{family_id}", headers=self._headers())
                if resp.status_code == 404:
                    return _not_found()
            resp.raise_for_status()
            data = resp.json()

        return EnrichmentData(raw_response=data, parsed_data=family_facts(family_id, data, family_name), ttl_hours=168)

    async def _enrich_actor(self, actor_name: str) -> EnrichmentData:
        async with self.http(timeout=15) as client:
            resp = await client.get(f"{self._api_base}get/actor/{_norm(actor_name)}", headers=self._headers())
            if resp.status_code == 404:
                actor_id = pick_actor(actor_name, await self._find(client, "actor", actor_name))
                if actor_id is None:
                    return _not_found()
                resp = await client.get(f"{self._api_base}get/actor/{actor_id}", headers=self._headers())
                if resp.status_code == 404:
                    return _not_found()
            resp.raise_for_status()
            data = resp.json()

        meta = data.get("meta") or {}
        return EnrichmentData(
            raw_response=data,
            parsed_data={
                "found": True,
                "actor_name": data.get("value", actor_name),
                "description": (data.get("description") or "")[:2000],
                "alt_names": meta.get("synonyms", []),
                "country": meta.get("country"),
                "refs": meta.get("refs", [])[:10],
                # Malpedia keys an actor's families by family id ("win.wannacryptor").
                "families": list(data.get("families") or {})[:20],
            },
            ttl_hours=168,
        )

    async def check_health(self) -> bool:
        try:
            async with self.http(timeout=5) as client:
                resp = await client.get(f"{self._api_base}find/family/emotet", headers=self._headers())
                return resp.status_code == 200
        except httpx.HTTPError:
            return False


def _not_found() -> EnrichmentData:
    return EnrichmentData(raw_response={"status": "not_found"}, parsed_data={"found": False}, ttl_hours=168)
