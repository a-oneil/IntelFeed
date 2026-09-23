"""Outbound observable feeds — IntelFeed as a source (design Phase 3, optional).

Two consumer-facing shapes over the same policy-filtered ledger slice:

- **EDL / lookup files** — plain text or CSV your firewall and SIEM pull on a
  schedule (Palo Alto EDL, pfBlockerNG, a Splunk lookup). Network atoms only;
  host artifacts go to the lookup CSV, never a blocklist.
- **A minimal TAXII 2.1 read-only collection** — STIX 2.1 indicator objects
  with ``valid_until`` derived from confidence decay, so downstream tools age
  indicators exactly the way the ledger does.

Everything is OFF until ``observables_publish_enabled`` is set and a bearer
token is configured; every request must present that token. The policy is
confidence + age + lifecycle — no sharing-protocol ceremony — plus the
analyst's never-capture tombstones, which are excluded everywhere by
definition. Each pull stamps redis so the Engine's Publishing view can show
which feeds are actually consumed (a feed nobody pulls is a signal to cut).
"""

import csv
import io
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Header, Query, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.database import get_db
from app.intelligence.observables import is_shared_infra
from app.models.observable import Observable
from app.models.user import User
from app.services.redis_client import get_redis
from app.services.system_settings import get_setting

router = APIRouter()

_PULL_KEY = "intelfeed:publish:pulls"


def _csv_safe(value: str) -> str:
    """Neutralize spreadsheet formula injection — a cmdline starting with
    ``=``/``+``/``-``/``@`` must not execute when the CSV opens in Excel."""
    return "'" + value if value[:1] in "=+-@\t" else value


#: EDL files: network atoms a blocklist can carry, one value per line.
_EDL_FILES: dict[str, list[str]] = {
    "ipv4.txt": ["ipv4", "ipv6"],
    "domains.txt": ["domain"],
    "urls.txt": ["url"],
}
#: CSV files: hashes for SIEM lookup tables, host artifacts for hunting.
_CSV_FILES: dict[str, list[str]] = {
    "hashes.csv": ["md5", "sha1", "sha256"],
    "host_artifacts.csv": ["cmdline", "registry", "path", "mutex", "named_pipe", "service_name", "user_agent"],
}


#: STIX 2.1 pattern builders per kind. Kinds without a sane pattern (ja3/ja4,
#: uri_path, scripts) stay out of the TAXII slice rather than shipping junk.
def _stix_escape(v: str) -> str:
    return v.replace("\\", "\\\\").replace("'", "\\'")


_STIX_PATTERNS: dict[str, str] = {
    "ipv4": "[ipv4-addr:value = '{v}']",
    "ipv6": "[ipv6-addr:value = '{v}']",
    "domain": "[domain-name:value = '{v}']",
    "url": "[url:value = '{v}']",
    "email": "[email-addr:value = '{v}']",
    "md5": "[file:hashes.'MD5' = '{v}']",
    "sha1": "[file:hashes.'SHA-1' = '{v}']",
    "sha256": "[file:hashes.'SHA-256' = '{v}']",
    "cmdline": "[process:command_line = '{v}']",
    "registry": "[windows-registry-key:key = '{v}']",
    "mutex": "[mutex:name = '{v}']",
    "cert_fingerprint": "[x509-certificate:hashes.'SHA-1' = '{v}']",
}


def _parse_tokens(raw: str) -> dict[str, str]:
    """secret -> consumer name. The setting is a comma list of ``name:secret``
    entries (bare secrets get the consumer name "default"), so each puller —
    the firewall, the SIEM, OpenCTI — carries its own revocable token and the
    pull telemetry can say who is actually consuming a feed."""
    tokens: dict[str, str] = {}
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        name, sep, secret = part.partition(":")
        if sep and secret.strip():
            tokens[secret.strip()] = name.strip() or "default"
        else:
            tokens[part] = "default"
    return tokens


async def _check_publish_auth(db: AsyncSession, authorization: str | None, token_param: str | None) -> str:
    """Feeds are consumer-facing: bearer token (or ?token= for appliances that
    can't set headers). Returns the consumer name the token belongs to."""
    enabled = str(await get_setting("observables_publish_enabled", db)).lower() in ("true", "1", "yes")
    if not enabled:
        raise AppError(code="publishing_disabled", message="Observable publishing is not enabled", status_code=404)
    tokens = _parse_tokens(await get_setting("observables_publish_token", db) or "")
    if not tokens:
        raise AppError(code="publishing_unconfigured", message="No publish token configured", status_code=404)
    presented = token_param or ""
    if authorization and authorization.lower().startswith("bearer "):
        presented = authorization[7:].strip()
    import hmac

    consumer = None
    for secret, name in tokens.items():
        # compare_digest over every configured secret — constant-time per
        # secret, no early exit on the match.
        if hmac.compare_digest(presented.encode(), secret.encode()) and consumer is None:
            consumer = name
    if consumer is None:
        raise AppError(code="unauthorized", message="Invalid publish token", status_code=401)
    return consumer


def _publish_host(o: Observable) -> str | None:
    """The hostname a domain/url/email row would block, or None for other kinds."""
    v = o.value.lower()
    if o.kind == "domain":
        return v
    if o.kind == "url":
        try:
            return v.split("/", 3)[2].split(":")[0].split("@")[-1]
        except IndexError:
            return v
    if o.kind == "email" and "@" in v:
        return v.rsplit("@", 1)[1]
    return None


def _suffix_excluded(o: Observable, never_suffixes: list[str]) -> bool:
    """Publish-boundary exclusion for host-bearing kinds: shared CDN/hosting
    suffixes (blocking cloudfront blocks a CDN edge for everyone) plus the
    analyst's own never-publish suffixes (your own org's domains must never
    land on your own blocklist). Excluded rows stay in the ledger — this is a
    publish filter, not a capture rule."""
    host = _publish_host(o)
    if host is None:
        return False
    if is_shared_infra(host):
        return True
    return any(host == s or host.endswith("." + s) for s in never_suffixes)


async def _policy_rows(db: AsyncSession, kinds: list[str]) -> list[Observable]:
    """The policy-filtered slice: active, confident, fresh, never denied,
    never dual-use infrastructure (a VPN exit on an EDL blocks customers),
    never shared-infra or never-publish suffixes."""
    min_conf = float(await get_setting("observables_publish_min_confidence", db) or 0.6)
    max_age_days = int(await get_setting("observables_publish_max_age_days", db) or 90)
    raw_suffixes = str(await get_setting("observables_publish_never_suffixes", db) or "")
    never_suffixes = [s.strip().lower().lstrip("*.") for s in raw_suffixes.split(",") if s.strip()]
    cutoff = datetime.now(UTC) - timedelta(days=max_age_days)
    rows = await db.execute(
        select(Observable)
        .where(
            Observable.kind.in_(kinds),
            Observable.is_denied.is_(False),
            Observable.infra_tag.is_(None),
            Observable.status == "active",
            Observable.current_confidence >= min_conf,
            Observable.last_seen_at >= cutoff,
        )
        .order_by(Observable.kind, Observable.value)
    )
    return [o for o in rows.scalars() if not _suffix_excluded(o, never_suffixes)]


async def _stamp_pull(feed: str, consumer: str = "default") -> None:
    try:
        redis = await get_redis()
        await redis.hset(_PULL_KEY, feed, f"{datetime.now(UTC).isoformat()}|{consumer}")
    except Exception:
        pass  # pull telemetry is best-effort; never fail a feed over it


@router.get("/publish/edl/{filename}")
async def publish_edl(
    filename: str,
    authorization: str | None = Header(None),
    token: str | None = Query(None, description="Publish token (for pullers that can't set headers)"),
    db: AsyncSession = Depends(get_db),
):
    """Plain-text blocklist: one value per line, comments carry provenance."""
    consumer = await _check_publish_auth(db, authorization, token)
    kinds = _EDL_FILES.get(filename)
    if kinds is None:
        raise AppError(code="not_found", message=f"Unknown EDL file (have: {', '.join(_EDL_FILES)})", status_code=404)
    items = await _policy_rows(db, kinds)
    lines = [
        f"# IntelFeed observables — {filename} — {len(items)} entries — generated {datetime.now(UTC):%Y-%m-%d %H:%M}Z"
    ]
    lines += [o.value for o in items]
    await _stamp_pull(f"edl/{filename}", consumer)
    return Response("\n".join(lines) + "\n", media_type="text/plain")


@router.get("/publish/lookup/{filename}")
async def publish_lookup(
    filename: str,
    authorization: str | None = Header(None),
    token: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """CSV lookup table: kind, value, label, role, confidence, last_seen."""
    consumer = await _check_publish_auth(db, authorization, token)
    kinds = _CSV_FILES.get(filename)
    if kinds is None:
        raise AppError(
            code="not_found", message=f"Unknown lookup file (have: {', '.join(_CSV_FILES)})", status_code=404
        )
    items = await _policy_rows(db, kinds)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["kind", "value", "label", "role", "confidence", "last_seen"])
    for o in items:
        writer.writerow(
            [
                o.kind,
                _csv_safe(o.value),
                _csv_safe(o.label or ""),
                o.role or "",
                round(o.current_confidence, 2),
                o.last_seen_at.isoformat(),
            ]
        )
    await _stamp_pull(f"lookup/{filename}", consumer)
    return Response(buf.getvalue(), media_type="text/csv")


# ---------------------------------------------------------------------------
# Minimal TAXII 2.1 read-only server (one collection)
# ---------------------------------------------------------------------------

_TAXII_MEDIA = "application/taxii+json;version=2.1"
_COLLECTION_ID = "observables"


def _taxii(payload: dict, status: int = 200, headers: dict[str, str] | None = None) -> Response:
    import json

    return Response(json.dumps(payload), status_code=status, media_type=_TAXII_MEDIA, headers=headers)


def _stix_indicator(o: Observable) -> dict | None:
    template = _STIX_PATTERNS.get(o.kind)
    if template is None:
        return None
    first = o.first_seen_at.astimezone(UTC)
    last = o.last_seen_at.astimezone(UTC)
    obj = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{o.id}",
        "created": first.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "modified": last.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "name": o.label or o.value,
        "pattern": template.format(v=_stix_escape(o.value)),
        "pattern_type": "stix",
        "valid_from": first.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "confidence": int(round(o.current_confidence * 100)),
        "labels": ["malicious-activity"] + ([o.role] if o.role else []),
    }
    if o.evidence:
        obj["description"] = o.evidence
    from app.api.intelligence import _observable_expiry

    _, expires_at = _observable_expiry(o)
    if expires_at is not None:
        obj["valid_until"] = expires_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return obj


@router.get("/taxii2/")
async def taxii_discovery(
    authorization: str | None = Header(None),
    token: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    await _check_publish_auth(db, authorization, token)
    return _taxii(
        {
            "title": "IntelFeed TAXII 2.1",
            "description": "Read-only observable indicators from the IntelFeed ledger",
            "default": "/taxii2/api/",
            "api_roots": ["/taxii2/api/"],
        }
    )


@router.get("/taxii2/api/")
async def taxii_api_root(
    authorization: str | None = Header(None),
    token: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    await _check_publish_auth(db, authorization, token)
    return _taxii(
        {
            "title": "IntelFeed observables",
            "versions": ["application/taxii+json;version=2.1"],
            "max_content_length": 10485760,
        }
    )


@router.get("/taxii2/api/collections/")
async def taxii_collections(
    authorization: str | None = Header(None),
    token: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    await _check_publish_auth(db, authorization, token)
    return _taxii(
        {
            "collections": [
                {
                    "id": _COLLECTION_ID,
                    "title": "Observables",
                    "description": "Judgment-captured indicators; valid_until tracks confidence decay",
                    "can_read": True,
                    "can_write": False,
                    "media_types": ["application/stix+json;version=2.1"],
                }
            ]
        }
    )


@router.get("/taxii2/api/collections/{collection_id}/")
async def taxii_collection(
    collection_id: str,
    authorization: str | None = Header(None),
    token: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    await _check_publish_auth(db, authorization, token)
    if collection_id != _COLLECTION_ID:
        raise AppError(code="not_found", message="Unknown collection", status_code=404)
    return _taxii(
        {
            "id": _COLLECTION_ID,
            "title": "Observables",
            "can_read": True,
            "can_write": False,
            "media_types": ["application/stix+json;version=2.1"],
        }
    )


@router.get("/taxii2/api/collections/{collection_id}/objects/")
async def taxii_objects(
    collection_id: str,
    authorization: str | None = Header(None),
    token: str | None = Query(None),
    added_after: str | None = Query(None, description="ISO timestamp; only objects modified after it"),
    next_cursor: str | None = Query(
        None, alias="next", description="Pagination cursor from a previous envelope's 'next'"
    ),
    limit: int = Query(500, ge=1, le=5000),
    db: AsyncSession = Depends(get_db),
):
    consumer = await _check_publish_auth(db, authorization, token)
    if collection_id != _COLLECTION_ID:
        raise AppError(code="not_found", message="Unknown collection", status_code=404)
    rows = await _policy_rows(db, list(_STIX_PATTERNS.keys()))
    # TAXII 2.1 clients paginate with ?next=<envelope.next>; added_after is the
    # spec's own timestamp filter. Both parse the same composite "iso|uuid"
    # cursor — a strictly-greater timestamp filter alone would lose every row
    # sharing the boundary timestamp (bulk ingests land thousands on one clock).
    cursor = next_cursor or added_after
    if cursor:
        ts_part, _, id_part = cursor.partition("|")
        try:
            cutoff = datetime.fromisoformat(ts_part.replace("Z", "+00:00"))
        except ValueError:
            raise AppError(code="invalid_cursor", message="next/added_after must be an ISO timestamp", status_code=400)
        if cutoff.tzinfo is None:
            cutoff = cutoff.replace(tzinfo=UTC)
        cursor_id = id_part or ""
        rows = [o for o in rows if (o.last_seen_at.astimezone(UTC), str(o.id)) > (cutoff, cursor_id)]
    rows.sort(key=lambda o: (o.last_seen_at, str(o.id)))
    page = rows[:limit]
    objects = [obj for o in page if (obj := _stix_indicator(o)) is not None]
    envelope: dict = {"objects": objects, "more": len(rows) > limit}
    headers = None
    if page:
        headers = {
            "X-TAXII-Date-Added-First": page[0].last_seen_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "X-TAXII-Date-Added-Last": page[-1].last_seen_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        }
    if envelope["more"] and page:
        # Z-suffixed, not "+00:00": clients paste the cursor into a query
        # string, where an unencoded "+" decodes to a space and breaks parsing.
        last_ts = page[-1].last_seen_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        envelope["next"] = f"{last_ts}|{page[-1].id}"
    await _stamp_pull("taxii2/objects", consumer)
    return _taxii(envelope, headers=headers)


# ---------------------------------------------------------------------------
# Status (the Engine → Publishing view; normal app auth, not the feed token)
# ---------------------------------------------------------------------------


@router.get("/publish/status")
async def publish_status(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    enabled = str(await get_setting("observables_publish_enabled", db)).lower() in ("true", "1", "yes")
    token_set = bool((await get_setting("observables_publish_token", db) or "").strip())
    min_conf = float(await get_setting("observables_publish_min_confidence", db) or 0.6)
    max_age_days = int(await get_setting("observables_publish_max_age_days", db) or 90)

    counts: dict[str, int] = {}
    for filename, kinds in {**_EDL_FILES, **{f"lookup:{k}": v for k, v in _CSV_FILES.items()}}.items():
        counts[filename] = len(await _policy_rows(db, kinds))
    taxii_eligible = len(await _policy_rows(db, list(_STIX_PATTERNS.keys())))
    denied = (
        await db.execute(select(func.count()).select_from(Observable).where(Observable.is_denied.is_(True)))
    ).scalar_one()

    raw_pulls: dict[str, str] = {}
    try:
        redis = await get_redis()
        raw_pulls = await redis.hgetall(_PULL_KEY) or {}
    except Exception:
        pass
    pulls: dict[str, dict] = {}
    for feed, stamp in raw_pulls.items():
        at, _, consumer = stamp.partition("|")
        pulls[feed] = {"at": at, "consumer": consumer or "default"}

    return {
        "enabled": enabled,
        "token_configured": token_set,
        "policy": {"min_confidence": min_conf, "max_age_days": max_age_days, "states": ["active"]},
        "never_publish_count": denied,
        "feeds": {
            "edl": [
                {
                    "path": f"/api/publish/edl/{f}",
                    "count": counts[f],
                    "last_pulled_at": (pulls.get(f"edl/{f}") or {}).get("at"),
                    "last_consumer": (pulls.get(f"edl/{f}") or {}).get("consumer"),
                }
                for f in _EDL_FILES
            ],
            "lookup": [
                {
                    "path": f"/api/publish/lookup/{f}",
                    "count": counts[f"lookup:{f}"],
                    "last_pulled_at": (pulls.get(f"lookup/{f}") or {}).get("at"),
                    "last_consumer": (pulls.get(f"lookup/{f}") or {}).get("consumer"),
                }
                for f in _CSV_FILES
            ],
            "taxii": {
                "path": "/api/taxii2/api/collections/observables/objects/",
                "count": taxii_eligible,
                "last_pulled_at": (pulls.get("taxii2/objects") or {}).get("at"),
                "last_consumer": (pulls.get("taxii2/objects") or {}).get("consumer"),
            },
        },
    }
