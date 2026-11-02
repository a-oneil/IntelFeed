"""The API keys enrichment uses, one row per credential.

A credential is what one key unlocks: a shared key group (``abuse_ch``: one
Auth-Key for ThreatFox, URLhaus and MalwareBazaar), an instance setting
(``nvd_api_key``, ``github_token``: the setting is the key, read by every
source that names it), or a single source's own key (VirusTotal). Settings →
Engine → Enrichment → Keys is the one place keys are set, through
``set_shared_key`` and ``set_my_key``:

- A setting credential stores its key in the setting. Any key on a member
  source's row is cleared, so the setting is the only copy.
- A group or single-source credential stores the key on every member's row,
  so each member resolves the same key (``resolve_api_key``).
- A person's own key is an override on every member's row; it replaces the
  shared key for the lookups that person starts.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.encryption import encrypt_value
from app.enrichment.gateway import GatewayUnavailable
from app.enrichment.registry import ADAPTER_REGISTRY, SOURCE_REGISTRY, source_gateway
from app.models.enrichment import EnrichmentSource, UserEnrichmentOverride

#: Display names for credentials that aren't one source's own key.
_LABELS = {"abuse_ch": "abuse.ch Auth-Key"}

#: Where to get each key.
SIGNUP_URLS = {
    "nvd_api_key": "https://nvd.nist.gov/developers/request-an-api-key",
    "github_token": "https://github.com/settings/tokens",
    "abuse_ch": "https://auth.abuse.ch/",
    "virustotal": "https://www.virustotal.com/gui/my-apikey",
    "vulncheck": "https://vulncheck.com/register",
    "greynoise": "https://viz.greynoise.io/account/api-key",
    "cvedetails": "https://www.cvedetails.com/api-access",
}

#: Other users of an instance setting, outside enrichment.
_ALSO_USED_BY = {"github_token": "GitHub repository feeds"}


@dataclass(frozen=True)
class Credential:
    id: str
    sources: tuple[str, ...]
    setting: str | None = None


def _credential_id(cls) -> str | None:
    """The credential a source draws on, or None when it takes no key."""
    if cls.shared_key_group:
        return cls.shared_key_group
    if cls.key_setting:
        return cls.key_setting
    if cls.requires_api_key or cls.quota.keyed or cls.optional_key:
        return cls.source_type
    return None


def credentials() -> dict[str, Credential]:
    """Every credential, keyed by id, with its member sources in registry order."""
    members: dict[str, list[str]] = {}
    settings: dict[str, str | None] = {}
    for source_type, cls in SOURCE_REGISTRY.items():
        cid = _credential_id(cls)
        if cid:
            members.setdefault(cid, []).append(source_type)
            if cid == cls.key_setting:
                settings[cid] = cid
    return {cid: Credential(cid, tuple(srcs), settings.get(cid)) for cid, srcs in members.items()}


def credential_for(source_type: str) -> str | None:
    cls = SOURCE_REGISTRY.get(source_type)
    return _credential_id(cls) if cls else None


def label(cred: Credential) -> str:
    if cred.id in _LABELS:
        return _LABELS[cred.id]
    if cred.setting:
        from app.services.system_settings import SETTING_METADATA

        return (SETTING_METADATA.get(cred.setting) or {}).get("label") or cred.setting
    return f"{SOURCE_REGISTRY[cred.sources[0]].display_name} API key"


def _note(cred: Credential) -> str:
    """What the key does, in one sentence."""
    classes = [SOURCE_REGISTRY[s] for s in cred.sources]
    if any(c.requires_api_key for c in classes):
        if len(classes) > 1:
            return f"Needed. One key for all {len(classes)} sources."
        return "Needed. The source answers nothing without it."
    keyed = next((c.quota for c in classes if c.quota.keyed), None)
    if keyed:
        k = keyed.keyed
        if keyed.period_seconds == k.period_seconds:
            per = f"per {keyed.period_seconds} seconds" if keyed.period_seconds != 3600 else "an hour"
            return f"Optional. Raises the limit from {keyed.requests_per_period} to {k.requests_per_period} {per}."
        return "Optional. Raises the source's rate limit."
    return "Optional. Raises the source's daily limit."


async def _rows(db: AsyncSession, cred: Credential) -> list[EnrichmentSource]:
    rows = (
        (await db.execute(select(EnrichmentSource).where(EnrichmentSource.source_type.in_(cred.sources))))
        .scalars()
        .all()
    )
    order = {s: i for i, s in enumerate(cred.sources)}
    return sorted(rows, key=lambda r: order[r.source_type])


async def _shared_set(db: AsyncSession, cred: Credential, rows: list[EnrichmentSource]) -> bool:
    if any(r.api_key_encrypted for r in rows):
        return True
    if cred.setting:
        from app.services.system_settings import get_setting

        return bool(await get_setting(cred.setting, db))
    return False


async def _rejected(db: AsyncSession, rows: list[EnrichmentSource]) -> str | None:
    """The message of a recorded auth failure on any member that is on."""
    from app.enrichment.pipeline import resolve_api_key

    for row in rows:
        if not row.is_enabled:
            continue
        gateway = source_gateway(row, await resolve_api_key(row, None, db))
        auth_failure = getattr(gateway, "auth_failure", None)
        if not callable(auth_failure):
            continue
        try:
            failure = await auth_failure()
        except GatewayUnavailable:
            return None
        if failure:
            return failure.get("message") or "the source rejected the key"
    return None


async def list_keys(db: AsyncSession, user_id: uuid.UUID) -> list[dict]:
    """One row per credential: its sources, whether the shared key is set,
    rejected or missing, and whether ``user_id`` has an own key."""
    mine = set(
        (
            await db.execute(
                select(EnrichmentSource.source_type)
                .join(UserEnrichmentOverride, UserEnrichmentOverride.source_id == EnrichmentSource.id)
                .where(
                    UserEnrichmentOverride.created_by == user_id, UserEnrichmentOverride.api_key_encrypted.isnot(None)
                )
            )
        ).scalars()
    )
    out = []
    for cred in credentials().values():
        rows = await _rows(db, cred)
        if not rows:
            continue
        classes = [SOURCE_REGISTRY[r.source_type] for r in rows]
        required = any(c.requires_api_key for c in classes)
        shared = await _shared_set(db, cred, rows)
        rejected = await _rejected(db, rows) if shared else None
        status = "rejected" if rejected else "set" if shared else "missing" if required else "optional"
        users = [
            {"source_type": r.source_type, "label": r.display_name or SOURCE_REGISTRY[r.source_type].display_name}
            for r in rows
        ]
        out.append(
            {
                "id": cred.id,
                "label": label(cred),
                "note": _note(cred),
                "required": required,
                "sources": users,
                "also_used_by": _ALSO_USED_BY.get(cred.id),
                "status": status,
                "message": rejected,
                "mine": any(r.source_type in mine for r in rows),
                # A person's own key goes only to lookups they start, so a
                # credential no lookup uses has none.
                "personal_allowed": any(r.source_type in ADAPTER_REGISTRY for r in rows),
                "signup_url": SIGNUP_URLS.get(cred.id),
            }
        )
    # Problems first, then what's needed and missing, then the rest.
    rank = {"rejected": 0, "missing": 1, "set": 2, "optional": 3}
    return sorted(out, key=lambda k: (rank[k["status"]], k["label"].lower()))


class UnknownKey(LookupError):
    """No credential by that id (or none of its sources has a row)."""


async def _credential(db: AsyncSession, key_id: str) -> tuple[Credential, list[EnrichmentSource]]:
    cred = credentials().get(key_id)
    rows = await _rows(db, cred) if cred else []
    if not cred or not rows:
        raise UnknownKey(key_id)
    return cred, rows


async def _forget_auth_failures(db: AsyncSession, rows: list[EnrichmentSource]) -> None:
    """Drop the members' recorded rejections. The gateway keys the auth flag
    by a hash of the key, so a different key has none to drop; the clear
    matters when the same key is saved again after the source turned it down."""
    from app.enrichment.pipeline import resolve_api_key

    for row in rows:
        gateway = source_gateway(row, await resolve_api_key(row, None, db))
        clear = getattr(gateway, "clear_auth_failure", None)
        if callable(clear):
            try:
                await clear()
            except GatewayUnavailable:
                return


async def set_shared_key(db: AsyncSession, key_id: str, api_key: str | None) -> None:
    """Store (or, with None/"", remove) the credential's shared key."""
    cred, rows = await _credential(db, key_id)
    value = api_key or None
    if cred.setting:
        from app.services.system_settings import update_settings

        await update_settings(db, {cred.setting: value})
        for row in rows:
            row.api_key_encrypted = None
    else:
        encrypted = encrypt_value(value) if value else None
        for row in rows:
            row.api_key_encrypted = encrypted
    await db.flush()
    await _forget_auth_failures(db, rows)


async def set_my_key(db: AsyncSession, key_id: str, user_id: uuid.UUID, api_key: str | None) -> None:
    """Store (or, with None/"", remove) ``user_id``'s own key for the credential."""
    _, rows = await _credential(db, key_id)
    ids = [r.id for r in rows]
    await db.execute(
        delete(UserEnrichmentOverride).where(
            UserEnrichmentOverride.created_by == user_id, UserEnrichmentOverride.source_id.in_(ids)
        )
    )
    if api_key:
        encrypted = encrypt_value(api_key)
        for source_id in ids:
            db.add(UserEnrichmentOverride(created_by=user_id, source_id=source_id, api_key_encrypted=encrypted))
    await db.flush()


async def test_key(db: AsyncSession, key_id: str) -> dict:
    """Probe the credential with the shared key through its first member that
    has a lookup: ``{"status": "ok"|"rejected"|"unreachable"|"missing"|"untestable", ...}``.
    ``rejected`` means the source answered and turned the key down;
    ``unreachable`` means it did not answer, which says nothing about the key.
    A gateway refusal (rate limit, pause) raises, for the same reason."""
    from app.enrichment.pipeline import resolve_api_key
    from app.enrichment.registry import adapter_for_source

    cred, rows = await _credential(db, key_id)
    row = next((r for r in rows if r.source_type in ADAPTER_REGISTRY), None)
    if row is None:
        return {"status": "untestable", "message": "These sources only run scheduled jobs; their next run tells."}
    api_key = await resolve_api_key(row, None, db)
    if not api_key:
        return {"status": "missing", "message": None}
    from app.enrichment.gateway import AuthFailed, GatewayError

    # The person testing has usually just replaced the key: the members'
    # recorded rejection goes, so the probe actually goes out.
    await _forget_auth_failures(db, rows)
    adapter = adapter_for_source(row, api_key)
    try:
        healthy = await adapter.check_health()
    except AuthFailed as e:
        # The source turned the key down: that is the answer, not a refusal.
        for r in rows:
            r.health_status = "down"
        await db.flush()
        return {"status": "rejected", "message": str(e) or f"{row.display_name} refused it"}
    except GatewayError:
        raise
    except Exception:
        healthy = False
    if not healthy:
        return {"status": "unreachable", "message": f"Couldn't reach {row.display_name}; try again in a moment"}
    for r in rows:
        r.health_status = "healthy"
    await db.flush()
    return {"status": "ok", "message": None}
