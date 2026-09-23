#!/usr/bin/env python3
"""Local bulk runner for the entity-link validator.

Bypasses the production celery-worker-ai queue and chews through the entire
backlog using the operator's local `claude` CLI. Useful when the scheduled
batches are stalling (canary failures, quota windows, single-concurrency
serialization) and there are thousands of unvalidated entries piling up.

Mirrors the server-side logic in backend/app/workers/link_validation_tasks.py
exactly — same candidate selection, same prompt rendering, same removal +
audit log + article_count decrement. Resumable: each finished entry stamps
`entries.last_link_validation_at`, so reruns skip done work.

Setup
-----
    # Install local Python deps (one-time)
    pip install 'psycopg[binary]' jinja2

    # Authenticate the claude CLI once (uses your Max OAuth credentials)
    claude /login

Usage
-----
    # Open SSH tunnel to prod Postgres and start chewing through everything.
    # Honours the proposed/applied mode currently set in Settings → System.
    python3 scripts/dev/local_link_validator.py \
        --ssh-host user@host

    # Override mode for this run only (without touching system_settings):
    python3 scripts/dev/local_link_validator.py --ssh-host ... --mode apply
    python3 scripts/dev/local_link_validator.py --ssh-host ... --mode proposed

    # Trial run on 25 oldest pending entries.
    python3 scripts/dev/local_link_validator.py --ssh-host ... --limit 25

    # Faster: use haiku instead of sonnet (much cheaper on the Max quota).
    python3 scripts/dev/local_link_validator.py --ssh-host ... --model haiku

    # Don't write anything; just print decisions per entry.
    python3 scripts/dev/local_link_validator.py --ssh-host ... --dry-run --limit 5

    # Force re-validation regardless of last_link_validation_at.
    python3 scripts/dev/local_link_validator.py --ssh-host ... --ignore-recheck-window

Safety
------
- The script holds a NOWAIT advisory lock per entry so two concurrent runs
  (or this script vs. the prod scheduler) never collide on the same entry.
- Removals respect the prod circuit breaker: if more than 40% of an entry's
  links are flagged REMOVE, the warning is logged but removals still proceed
  (same as prod). Use --circuit-breaker-pct to tune.
- Sequential by default (workers=1). Recent claude CLI versions handle parallel
  invocations safely; raise --workers to actually parallelize claude calls.
- Set --batch-size N to validate N entries per claude call (default 10). Each
  CLI call has ~1-2s of bun startup + OAuth overhead that batching amortizes;
  combined with --workers, this is typically a 20-50x speedup over the old
  one-entry-at-a-time mode.
- The script never touches `ai_results` — the log rows it writes have
  `ai_result_id = NULL`. (Operator can still pivot from log → entry to find
  the AI prompt that produced the decision via the audit UI's "view entry"
  link.)
"""

from __future__ import annotations

import argparse
import atexit
import json
import logging
import os
import pathlib
import re
import socket
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import Event, Lock, Thread
from typing import Any

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    sys.exit("Missing dependency: pip install 'psycopg[binary]'")

try:
    from jinja2 import Environment, StrictUndefined
except ImportError:
    sys.exit("Missing dependency: pip install jinja2")


# ---------------------------------------------------------------- constants
# Must match the server-side junction model layout.
JUNCTIONS: list[tuple[str, str, str, str, str]] = [
    # (entity_type, junction_table, entity_table, fk_column, entity_name_col)
    ("threat_actor", "entry_threat_actors", "threat_actors", "threat_actor_id", "name"),
    ("malware", "entry_malware", "malware_families", "malware_family_id", "name"),
    ("vendor", "entry_vendors", "vendors", "vendor_id", "name"),
    ("product", "entry_products", "products", "product_id", "name"),
    ("country", "entry_countries", "countries", "country_id", "name"),
]

PARAGRAPH_SPLIT_RE = re.compile(r"\n\s*\n")
PREVIOUSLY_RESTORED_LOOKBACK_DAYS = 90

# Heartbeat cadence — every N seconds of an in-flight claude call, log a
# warning so silent hangs (network blip, bun startup retry, stuck OAuth
# refresh) are immediately visible instead of waiting out the timeout.
HEARTBEAT_INTERVAL_SECONDS = 30

# Per-model default timeouts. Tuned around observed p99 latencies + a comfort
# margin. Hangs caught faster on the cheap models. Override with --timeout.
MODEL_TIMEOUTS: dict[str, float] = {
    "haiku": 90.0,
    "sonnet": 180.0,
    "opus": 300.0,
}
DEFAULT_TIMEOUT_FALLBACK = 180.0

# Wallclock watchdog — if no entry result is reported for this many seconds,
# the script is wedged somewhere outside the heartbeat-instrumented claude
# call (typically Mac sleep killing the SSH tunnel into a half-open state, or
# a libpq read on a dead TCP socket). The watchdog hard-exits so the operator
# can just rerun — the candidate query picks up unstamped entries automatically.
_progress_lock = Lock()
_last_progress_at: float = time.monotonic()

# Auto-restart: bookkeeping so a watchdog-triggered re-exec doesn't loop
# forever if the underlying problem isn't transient. The env var travels
# across exec(), so the next process knows its restart depth and caps it.
_RESTART_ENV_VAR = "_LOCAL_LINK_VALIDATOR_RESTART_COUNT"
_NO_PROGRESS_STREAK_ENV = "_LOCAL_LINK_VALIDATOR_NO_PROGRESS_STREAK"
_MAX_AUTO_RESTARTS = 250
# Exponential backoff for restarts that happen without any entry making
# progress — protects against SSH fail2ban triggering when the host itself
# is unreachable and we'd otherwise hammer it every 3 seconds.
_RESTART_BACKOFF_BASE_SECONDS = 3.0
_RESTART_BACKOFF_MAX_SECONDS = 120.0
# Module-level flag the report() callback flips on the first successful
# entry of a process lifetime. Read by _self_restart to decide whether to
# reset the no-progress streak or keep escalating the backoff.
_had_progress_this_run = False

# Local seen-list: a simple append-only file of entry UUIDs we've already
# scanned. Lets `--ignore-recheck-window` runs avoid revisiting an entry
# even after every candidate has been stamped. Outcomes that get appended:
# applied, proposed, no_links. Errors (ai_error, ai_bad_shape, connection_lost,
# locked, missing_entry) stay unrecorded so they're retried on the next run.
_SEEN_FILE_DEFAULT = ".local_link_validator_seen.txt"
_SEEN_TERMINAL_STATUSES = {"applied", "proposed", "no_links"}

logger = logging.getLogger("local_link_validator")


# ---------------------------------------------------------------- ssh tunnel


@dataclass
class TunnelConfig:
    ssh_host: str
    local_port: int
    db_password: str
    db_user: str
    db_name: str


def _find_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _fetch_prod_env(ssh_host: str, env_path: str) -> dict[str, str]:
    """SSH to prod and dump .env so the script can find POSTGRES_* + db container IP."""
    logger.info("Reading prod env via ssh %s:%s", ssh_host, env_path)
    res = subprocess.run(
        ["ssh", ssh_host, f"cat {env_path}"],
        check=True,
        capture_output=True,
        text=True,
    )
    out: dict[str, str] = {}
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        v = v.strip().strip('"').strip("'")
        out[k.strip()] = v
    if "POSTGRES_PASSWORD" not in out:
        raise RuntimeError(f"POSTGRES_PASSWORD not found in {env_path} on {ssh_host}")
    return out


def _db_container_ip(ssh_host: str, compose_project: str) -> str:
    """Resolve the Postgres container's IP on the docker `backend` network."""
    cmd = (
        # match container by service label OR by name suffix, get IP on backend net.
        "docker ps --filter 'label=com.docker.compose.service=db' --format '{{.ID}}' | head -1 "
        "| xargs -I{} docker inspect -f "
        f"'{{{{(index .NetworkSettings.Networks \"{compose_project}_backend\").IPAddress}}}}' {{}}"
    )
    res = subprocess.run(
        ["ssh", ssh_host, cmd],
        check=True,
        capture_output=True,
        text=True,
    )
    ip = res.stdout.strip()
    if not ip or ip in {"<no value>", ""}:
        raise RuntimeError(
            f"Could not resolve db container IP on {ssh_host} (compose project={compose_project}). "
            "Pass --compose-project to override."
        )
    return ip


_tunnel_proc: subprocess.Popen | None = None


def open_tunnel(ssh_host: str, compose_project: str, env_path: str) -> TunnelConfig:
    """Resolve prod creds + db container IP, open ssh -L tunnel, return config.

    The tunnel runs as a backgrounded ssh process and is torn down on exit.
    """
    global _tunnel_proc

    env = _fetch_prod_env(ssh_host, env_path)
    db_password = env["POSTGRES_PASSWORD"]
    db_user = env.get("POSTGRES_USER", "intelfeed")
    db_name = env.get("POSTGRES_DB", "intelfeed")

    ip = _db_container_ip(ssh_host, compose_project)
    local_port = _find_free_port()

    logger.info("Opening ssh tunnel: localhost:%s → %s:5432 via %s", local_port, ip, ssh_host)
    # -N: no remote command, -T: no tty, -o ExitOnForwardFailure=yes: fail fast on bind error.
    _tunnel_proc = subprocess.Popen(
        [
            "ssh",
            "-N",
            "-T",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "ServerAliveInterval=30",
            "-L",
            f"127.0.0.1:{local_port}:{ip}:5432",
            ssh_host,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    atexit.register(_close_tunnel)

    # Wait for the tunnel to come up.
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if _tunnel_proc.poll() is not None:
            err = _tunnel_proc.stderr.read().decode(errors="replace") if _tunnel_proc.stderr else ""
            raise RuntimeError(f"ssh tunnel exited prematurely: {err.strip() or '(no stderr)'}")
        with socket.socket() as s:
            s.settimeout(1)
            try:
                s.connect(("127.0.0.1", local_port))
                logger.info("Tunnel ready on localhost:%s", local_port)
                return TunnelConfig(
                    ssh_host=ssh_host,
                    local_port=local_port,
                    db_password=db_password,
                    db_user=db_user,
                    db_name=db_name,
                )
            except OSError:
                time.sleep(0.5)
    raise RuntimeError("ssh tunnel did not come up within 15s")


def _close_tunnel() -> None:
    global _tunnel_proc
    if _tunnel_proc and _tunnel_proc.poll() is None:
        _tunnel_proc.terminate()
        try:
            _tunnel_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _tunnel_proc.kill()


# ---------------------------------------------------------------- candidate selection


def select_candidates(
    conn: psycopg.Connection,
    limit: int | None,
    recheck_days: int,
    ignore_recheck_window: bool,
) -> list[uuid.UUID]:
    """Return entry IDs ordered by oldest-validated-first, same as prod kickoff."""
    exists_subqueries = " OR ".join(
        f"EXISTS (SELECT 1 FROM {tbl} j WHERE j.entry_id = e.id AND j.source = 'auto_link')"
        for _et, tbl, _ent_tbl, _fk, _name_col in JUNCTIONS
    )
    where_window = (
        ""
        if ignore_recheck_window
        else ("AND (e.last_link_validation_at IS NULL OR e.last_link_validation_at < %(cutoff)s)")
    )
    limit_clause = "LIMIT %(limit)s" if limit else ""

    sql = f"""
        SELECT e.id
        FROM entries e
        WHERE ({exists_subqueries})
          {where_window}
        ORDER BY e.last_link_validation_at ASC NULLS FIRST, e.created_at DESC
        {limit_clause}
    """
    params: dict[str, Any] = {}
    if not ignore_recheck_window:
        # Only computed when needed — recheck_days may be a misconfigured large
        # value in system_settings that would overflow timedelta.
        try:
            params["cutoff"] = datetime.now(UTC) - timedelta(days=recheck_days)
        except OverflowError:
            raise SystemExit(
                f"link_validation_recheck_days={recheck_days} overflows timedelta. "
                "Fix the value in system_settings, or pass --recheck-days N, or use --ignore-recheck-window."
            )
    if limit:
        params["limit"] = limit

    with conn.cursor() as cur:
        cur.execute(sql, params)
        return [row[0] for row in cur.fetchall()]


# ---------------------------------------------------------------- entry assembly


@dataclass
class LinkRow:
    entity_key: str
    entity_type: str
    entity_id: uuid.UUID
    name: str
    matched_names: list[str]
    confidence: str | None
    source: str | None
    paragraph_indices: list[int]
    extracted_at: datetime | None
    previously_restored: bool = False


@dataclass
class EntryBundle:
    id: uuid.UUID
    title: str
    summary: str | None
    content_text: str | None
    language: str | None
    published_at: datetime | None
    feed_name: str | None
    links: list[LinkRow]


def fetch_entry_bundle(
    conn: psycopg.Connection,
    entry_id: uuid.UUID,
    skip_confidence: str | None,
) -> EntryBundle | None:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT e.id, e.title, e.summary, e.content_text, e.language,
                   e.published_at, f.title AS feed_name
            FROM entries e
            LEFT JOIN feeds f ON f.id = e.feed_id
            WHERE e.id = %s
            """,
            (entry_id,),
        )
        entry_row = cur.fetchone()
        if not entry_row:
            return None

        links: list[LinkRow] = []
        for entity_type, jtable, etable, fk_col, name_col in JUNCTIONS:
            extra = ""
            if skip_confidence:
                extra = " AND (j.confidence IS NULL OR j.confidence <> %s)"
                params: tuple[Any, ...] = (entry_id, skip_confidence)
            else:
                params = (entry_id,)
            cur.execute(
                f"""
                SELECT j.{fk_col} AS entity_id, e.{name_col} AS name,
                       j.matched_names, j.confidence, j.source,
                       j.paragraph_indices, j.extracted_at
                FROM {jtable} j
                JOIN {etable} e ON e.id = j.{fk_col}
                WHERE j.entry_id = %s AND j.source = 'auto_link'{extra}
                """,
                params,
            )
            for r in cur.fetchall():
                links.append(
                    LinkRow(
                        entity_key=f"{entity_type}:{r['entity_id']}",
                        entity_type=entity_type,
                        entity_id=r["entity_id"],
                        name=r["name"],
                        matched_names=list(r["matched_names"] or []),
                        confidence=r["confidence"],
                        source=r["source"],
                        paragraph_indices=list(r["paragraph_indices"] or []),
                        extracted_at=r["extracted_at"],
                    )
                )

        # previously_restored signal: any analyst-restored link for this entry within lookback?
        if links:
            cur.execute(
                """
                SELECT entity_type, entity_id
                FROM entity_link_validation_log
                WHERE entry_id = %s
                  AND action = 'restored'
                  AND created_at >= %s
                """,
                (
                    entry_id,
                    datetime.now(UTC) - timedelta(days=PREVIOUSLY_RESTORED_LOOKBACK_DAYS),
                ),
            )
            restored = {(r["entity_type"], r["entity_id"]) for r in cur.fetchall()}
            for link in links:
                if (link.entity_type, link.entity_id) in restored:
                    link.previously_restored = True

        return EntryBundle(
            id=entry_row["id"],
            title=entry_row["title"] or "",
            summary=entry_row["summary"],
            content_text=entry_row["content_text"],
            language=entry_row["language"],
            published_at=entry_row["published_at"],
            feed_name=entry_row["feed_name"],
            links=links,
        )


# ---------------------------------------------------------------- paragraph slicing


def split_into_paragraphs(title: str, summary: str, content_text: str) -> list[tuple[int, str]]:
    """Mirrors backend/app/intelligence/autolinker.py:split_into_paragraphs."""
    paragraphs: list[tuple[int, str]] = []
    idx = 0
    if title and title.strip():
        paragraphs.append((idx, title.strip()))
        idx += 1
    if summary and summary.strip():
        paragraphs.append((idx, summary.strip()))
        idx += 1
    if content_text and content_text.strip():
        for chunk in PARAGRAPH_SPLIT_RE.split(content_text):
            chunk = chunk.strip()
            if chunk:
                paragraphs.append((idx, chunk))
                idx += 1
    return paragraphs


def select_paragraphs_for_links(
    title: str,
    summary: str | None,
    content_text: str | None,
    paragraph_indices: list[int],
    max_chars: int,
) -> str:
    """Mirrors backend/app/workers/link_validation_tasks.py:select_paragraphs_for_links."""
    paragraphs = split_into_paragraphs(title, summary or "", content_text or "")
    if not paragraphs:
        return ""
    max_index = len(paragraphs) - 1

    selected: set[int] = {0}
    if len(paragraphs) > 1:
        selected.add(1)
    for idx in paragraph_indices:
        if 0 <= idx <= max_index:
            selected.add(idx)
            if idx - 1 >= 0:
                selected.add(idx - 1)
            if idx + 1 <= max_index:
                selected.add(idx + 1)

    ordered = sorted(selected)
    parts: list[str] = []
    last_idx: int | None = None
    for idx in ordered:
        if last_idx is not None and idx > last_idx + 1:
            parts.append("[...]")
        parts.append(paragraphs[idx][1])
        last_idx = idx
    rendered = "\n\n".join(parts)

    if len(rendered) > max_chars:
        rendered = _truncate_rendered(parts, max_chars)
    return rendered


def _truncate_rendered(parts: list[str], max_chars: int) -> str:
    while True:
        joined = "\n\n".join(parts)
        if len(joined) <= max_chars:
            return joined
        idx_to_trim = None
        max_len = 0
        for i in range(1, len(parts)):
            if parts[i] == "[...]":
                continue
            if len(parts[i]) > max_len:
                max_len = len(parts[i])
                idx_to_trim = i
        if idx_to_trim is None:
            return joined[: max_chars - 1] + "…"
        new_len = max(80, max_len // 2)
        new_part = parts[idx_to_trim][:new_len].rstrip() + " […]"
        # Forward-progress guard: if the "shrunk" part is the same length or
        # longer than what we had, no iteration will ever shrink the total.
        # Hard-truncate the joined output to avoid an infinite spin.
        if len(new_part) >= len(parts[idx_to_trim]):
            return joined[: max_chars - 1] + "…"
        parts[idx_to_trim] = new_part


# ---------------------------------------------------------------- prompt rendering


def load_active_prompt(conn: psycopg.Connection) -> tuple[str | None, str, dict | None]:
    """Return (system_text, user_template, schema) for entity_link_validation.

    Resolution mirrors backend/app/ai/engine.py:get_active_prompt:
      1. Any system-level (created_by IS NULL) active override in ai_prompt_templates
      2. Fall back to ai_tasks.default_system_template + default_prompt_template
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("""
            SELECT t.id AS task_id, t.default_system_template, t.default_prompt_template,
                   t.output_schema
            FROM ai_tasks t
            WHERE t.name = 'entity_link_validation'
            """)
        task = cur.fetchone()
        if not task:
            raise RuntimeError("ai_tasks row for 'entity_link_validation' not found")

        cur.execute(
            """
            SELECT system_text, template_text
            FROM ai_prompt_templates
            WHERE task_id = %s
              AND created_by IS NULL
              AND is_active = TRUE
            ORDER BY version DESC
            LIMIT 1
            """,
            (task["task_id"],),
        )
        override = cur.fetchone()
        if override:
            return (
                override["system_text"],
                override["template_text"],
                task["output_schema"],
            )
        return (
            task["default_system_template"],
            task["default_prompt_template"],
            task["output_schema"],
        )


def build_prompt_variables(entry: EntryBundle, max_chars: int) -> dict:
    para_idx_union = sorted({i for link in entry.links for i in link.paragraph_indices})
    rendered = select_paragraphs_for_links(
        title=entry.title,
        summary=entry.summary,
        content_text=entry.content_text,
        paragraph_indices=para_idx_union,
        max_chars=max_chars,
    )
    return {
        "entry_title": entry.title or "(no title)",
        "entry_feed_name": entry.feed_name or "(unknown feed)",
        "entry_published_at": (entry.published_at.isoformat() if entry.published_at else ""),
        "entry_summary": entry.summary or "",
        "entry_language": entry.language or "",
        "entry_paragraphs": rendered,
        "linked_entities": [
            {
                "entity_key": link.entity_key,
                "entity_type": link.entity_type,
                "name": link.name,
                "matched_names": link.matched_names,
                "confidence": link.confidence or "",
                "previously_restored": link.previously_restored,
            }
            for link in entry.links
        ],
    }


def render_prompt(template_text: str, variables: dict) -> str:
    env = Environment(undefined=StrictUndefined, autoescape=False)
    return env.from_string(template_text).render(**variables)


# ---------------------------------------------------------------- batching


def batched_schema(single_schema: dict | None) -> dict | None:
    """Wrap the single-entry validations schema in {entries: [{entry_id, validations}]}.

    Returns None if the input schema doesn't expose a `validations` property
    in the expected shape — in which case the batch call falls back to
    unstructured output and we parse JSON from the model's text response.
    """
    if not single_schema or not isinstance(single_schema, dict):
        return None
    props = single_schema.get("properties") or {}
    validations_def = props.get("validations")
    if not validations_def:
        return None
    return {
        "type": "object",
        "properties": {
            "entries": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "entry_id": {"type": "string"},
                        "validations": validations_def,
                    },
                    "required": ["entry_id", "validations"],
                    "additionalProperties": False,
                },
            }
        },
        "required": ["entries"],
        "additionalProperties": False,
    }


def build_batched_prompt(rendered_entries: list[tuple[uuid.UUID, str]]) -> str:
    """Wrap N single-entry rendered user prompts into one batched user prompt.

    The per-entry template (stored in the DB) describes outputting JSON of
    shape `{"validations": [...]}` for one entry. The wrapper here tells the
    model to combine all N per-entry outputs into ONE `{"entries": [...]}`
    object, keyed by the entry UUID from each `=== ENTRY <uuid> ===` marker.
    """
    n = len(rendered_entries)
    envelope = (
        "# BATCHED VALIDATION REQUEST\n\n"
        f"Below are {n} independent entry-validation tasks. Each task's instructions "
        'describe outputting a JSON object like `{"validations": [...]}`.\n\n'
        "**Do NOT output that per-task. Instead, output ONE combined JSON object** "
        "with this exact shape:\n\n"
        "```json\n"
        '{"entries": [\n'
        '  {"entry_id": "<uuid-from-marker>", "validations": [...per task instructions...]},\n'
        '  {"entry_id": "<uuid-from-marker>", "validations": [...per task instructions...]}\n'
        "]}\n"
        "```\n\n"
        "Each task below is delimited by `=== ENTRY <uuid> START ===` and "
        "`=== ENTRY <uuid> END ===` markers. Use the UUID from the START marker "
        "as the `entry_id`. Follow each task's per-entity decision rules exactly — "
        f"only the outer wrapping is different. Include exactly one entries[] item "
        f"per input task ({n} total), in the same order as the inputs.\n\n"
        "---\n"
    )
    parts = [envelope]
    for entry_id, rendered in rendered_entries:
        parts.append(f"\n=== ENTRY {entry_id} START ===\n")
        parts.append(rendered)
        parts.append(f"\n=== ENTRY {entry_id} END ===\n")
    return "".join(parts)


def _chunked(seq: list, n: int):
    """Yield successive n-sized chunks from seq."""
    for i in range(0, len(seq), n):
        yield seq[i : i + n]


# ---------------------------------------------------------------- claude CLI


def _heartbeat(label: str, started: float, stop: Event, interval: float) -> None:
    """Daemon thread that logs progress every `interval` seconds until `stop` fires."""
    while not stop.wait(interval):
        elapsed = time.monotonic() - started
        logger.warning("still waiting on %s — %.0fs elapsed", label, elapsed)


def _touch_progress() -> None:
    """Mark that an entry result was reported.

    Updates the watchdog's progress timestamp AND flips the module-level
    `had_progress` flag so a subsequent auto-restart resets its backoff.
    Without this, transient watchdog trips during a real run would escalate
    backoff alongside startup failures.
    """
    global _last_progress_at, _had_progress_this_run
    with _progress_lock:
        _last_progress_at = time.monotonic()
        _had_progress_this_run = True


def _load_seen(path: pathlib.Path) -> set[uuid.UUID]:
    """Load the set of already-scanned entry UUIDs from the seen-file."""
    if not path.exists():
        return set()
    seen: set[uuid.UUID] = set()
    skipped = 0
    with path.open() as f:
        for line in f:
            token = line.strip()
            if not token or token.startswith("#"):
                continue
            try:
                seen.add(uuid.UUID(token))
            except ValueError:
                skipped += 1
    if skipped:
        logger.warning("seen-file %s: ignored %d malformed line(s)", path, skipped)
    return seen


_seen_lock = Lock()


def _append_seen(path: pathlib.Path, entry_id: uuid.UUID) -> None:
    """Append a single entry UUID to the seen-file (line-buffered + flushed)."""
    with _seen_lock:
        with path.open("a") as f:
            f.write(f"{entry_id}\n")
            f.flush()


def _watchdog(timeout_seconds: float, stop: Event, auto_restart: bool) -> None:
    """Hard-exit (or re-exec) the process if no entry result lands within the window."""
    check_interval = max(15.0, timeout_seconds / 6.0)
    while not stop.wait(check_interval):
        with _progress_lock:
            stale = time.monotonic() - _last_progress_at
        if stale > timeout_seconds:
            reason = (
                f"no entry progress for {stale:.0f}s (limit {timeout_seconds:.0f}s). "
                "Likely Mac sleep dropped the SSH tunnel, or libpq is stuck on a "
                "half-open TCP socket."
            )
            if auto_restart:
                _self_restart(f"watchdog: {reason}")
            else:
                logger.error(
                    "watchdog: %s — aborting. Rerun to resume unstamped entries.",
                    reason,
                )
                os._exit(2)


def _self_restart(reason: str) -> None:
    """Re-exec this script in place with the same argv, capped at _MAX_AUTO_RESTARTS.

    Closes the SSH tunnel child first so we don't leak forwarders across restarts.
    Uses execvpe so the restart count + backoff streak env vars travel into the
    new process. Applies exponential backoff when consecutive restarts happen
    without any entry making progress — protects against hammering SSH into
    fail2ban-ban territory when the host itself is the problem.
    """
    count = int(os.environ.get(_RESTART_ENV_VAR, "0"))
    streak = int(os.environ.get(_NO_PROGRESS_STREAK_ENV, "0"))
    if count >= _MAX_AUTO_RESTARTS:
        logger.error(
            "auto-restart cap (%d) reached — exiting for real. Last reason: %s",
            _MAX_AUTO_RESTARTS,
            reason,
        )
        os._exit(3)

    # If THIS process reported at least one entry, the underlying connection
    # is healthy — reset the streak so post-progress hiccups don't backoff
    # alongside true startup failures.
    if _had_progress_this_run:
        streak = 0
    next_streak = streak + 1
    backoff = min(_RESTART_BACKOFF_BASE_SECONDS * (2**streak), _RESTART_BACKOFF_MAX_SECONDS)

    next_count = count + 1
    logger.warning(
        "auto-restart #%d/%d in %.0fs (no-progress streak: %d) — %s",
        next_count,
        _MAX_AUTO_RESTARTS,
        backoff,
        next_streak if not _had_progress_this_run else 1,
        reason,
    )
    # Flush logs and tear down the SSH tunnel before exec so the new process
    # binds a fresh tunnel cleanly.
    try:
        _close_tunnel()
    except Exception:
        pass
    for h in logging.getLogger().handlers:
        try:
            h.flush()
        except Exception:
            pass
    time.sleep(backoff)
    new_env = dict(os.environ)
    new_env[_RESTART_ENV_VAR] = str(next_count)
    new_env[_NO_PROGRESS_STREAK_ENV] = str(next_streak)
    os.execvpe(sys.executable, [sys.executable, *sys.argv], new_env)


def call_claude(
    prompt: str,
    schema: dict | None,
    model: str,
    timeout_seconds: float,
    system_prompt: str | None = None,
    heartbeat_label: str = "claude call",
    max_retries: int = 1,
) -> dict:
    """Subprocess the local `claude -p` CLI and return parsed JSON output.

    On timeout the CLI is hard-killed and the call retried up to `max_retries`
    times — many hangs are transient (Anthropic blip, bun startup retry,
    stale OAuth refresh). After exhausting retries, raises TimeoutError so the
    caller can record an ai_error and move on to the next entry.
    """
    argv = [
        "claude",
        "-p",
        "--output-format",
        "json",
        "--model",
        model,
        "--disallowedTools",
        "*",
        "--dangerously-skip-permissions",
    ]
    if system_prompt:
        argv += ["--append-system-prompt", system_prompt]
    if schema is not None:
        argv += ["--json-schema", json.dumps(schema, separators=(",", ":"))]

    last_err: Exception | None = None
    for attempt in range(max_retries + 1):
        label = heartbeat_label if attempt == 0 else f"{heartbeat_label} (retry {attempt}/{max_retries})"
        stop = Event()
        started = time.monotonic()
        hb = Thread(
            target=_heartbeat,
            args=(label, started, stop, HEARTBEAT_INTERVAL_SECONDS),
            daemon=True,
        )
        hb.start()
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = proc.communicate(
                input=prompt.encode("utf-8"),
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.communicate(timeout=5)
            except Exception:
                pass
            stop.set()
            last_err = TimeoutError(
                f"claude CLI exceeded {timeout_seconds:.0f}s on attempt {attempt + 1}/{max_retries + 1}"
            )
            logger.warning(str(last_err))
            continue
        finally:
            stop.set()

        if proc.returncode != 0:
            err = stderr_b.decode(errors="replace")[:1000]
            raise RuntimeError(f"claude CLI exited {proc.returncode}: {err or '(no stderr)'}")

        stdout = stdout_b.decode("utf-8", errors="replace").strip()
        if not stdout:
            raise RuntimeError("claude CLI returned empty stdout")
        break
    else:
        # All attempts timed out — surface to caller as ai_error.
        raise last_err or RuntimeError("claude CLI call failed without diagnostic")
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        # Sometimes there's a trailing telemetry line; try the last JSON object.
        candidates = [line for line in stdout.splitlines() if line.strip().startswith("{")]
        if not candidates:
            raise
        payload = json.loads(candidates[-1])

    # When --json-schema is supplied the CLI returns parsed output as `structured_output`.
    if isinstance(payload, dict):
        if isinstance(payload.get("structured_output"), (dict, list)):
            so = payload["structured_output"]
            return so if isinstance(so, dict) else {"validations": so}
        if "result" in payload:
            # Might be a JSON string (possibly markdown-fenced).
            text = str(payload["result"]).strip()
            if text.startswith("```json"):
                text = text.split("```json", 1)[1].split("```", 1)[0].strip()
            elif text.startswith("```"):
                text = text.split("```", 1)[1].split("```", 1)[0].strip()
            return json.loads(text)
    raise RuntimeError(f"Unexpected claude output shape: {str(payload)[:300]}")


# ---------------------------------------------------------------- decision handling


def validate_decisions(result: dict, links: list[LinkRow]) -> list[dict] | None:
    """Mirror of backend _validate_decisions: cross-check by entity_key."""
    validations = result.get("validations")
    if not isinstance(validations, list):
        return None

    valid_decisions = {"KEEP", "REMOVE", "RECLASSIFY"}
    valid_types = {"threat_actor", "malware", "vendor", "product", "country"}

    by_key: dict[str, dict] = {}
    for v in validations:
        if not isinstance(v, dict):
            continue
        key = v.get("entity_key")
        decision = v.get("decision")
        reason = v.get("reason", "")
        sugg = v.get("suggested_type")
        if not key or decision not in valid_decisions:
            continue
        if decision == "RECLASSIFY" and sugg not in valid_types:
            decision = "KEEP"
            sugg = None
        if key in by_key:
            return None
        by_key[key] = {"decision": decision, "reason": reason, "suggested_type": sugg}

    input_keys = {link.entity_key for link in links}
    if set(by_key.keys()) - input_keys:
        return None

    out: list[dict] = []
    for link in links:
        v = by_key.get(link.entity_key)
        if v is None:
            out.append(
                {
                    "decision": "KEEP",
                    "reason": "(no decision returned)",
                    "suggested_type": None,
                    "link": link,
                }
            )
        else:
            out.append(
                {
                    "decision": v["decision"],
                    "reason": v["reason"],
                    "suggested_type": v["suggested_type"],
                    "link": link,
                }
            )
    return out


# ---------------------------------------------------------------- DB mutations


def apply_removal(
    conn: psycopg.Connection,
    entry_id: uuid.UUID,
    link: LinkRow,
    reason: str,
) -> bool:
    """Mirror of backend _apply_removal: delete junction + decrement count + log."""
    spec = next((s for s in JUNCTIONS if s[0] == link.entity_type), None)
    if not spec:
        return False
    entity_type, jtable, etable, fk_col, _name_col = spec
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            SELECT confidence, source, matched_names, paragraph_indices, extracted_at
            FROM {jtable}
            WHERE entry_id = %s AND {fk_col} = %s
            FOR UPDATE
            """,
            (entry_id, link.entity_id),
        )
        junction = cur.fetchone()
        if not junction:
            return False
        if junction["extracted_at"] and link.extracted_at and junction["extracted_at"] > link.extracted_at:
            return False

        cur.execute(
            """
            INSERT INTO entity_link_validation_log
                (id, entry_id, entity_type, entity_id, entity_name_snapshot, action, reason,
                 original_source, original_confidence, original_matched_names,
                 original_paragraph_indices, original_extracted_at)
            VALUES (%s, %s, %s, %s, %s, 'removed', %s,
                    %s, %s, %s, %s, %s)
            """,
            (
                uuid.uuid4(),
                entry_id,
                entity_type,
                link.entity_id,
                link.name,
                (reason or "")[:500] or None,
                junction["source"],
                junction["confidence"],
                list(junction["matched_names"] or []),
                list(junction["paragraph_indices"] or []),
                junction["extracted_at"],
            ),
        )
        cur.execute(
            f"DELETE FROM {jtable} WHERE entry_id = %s AND {fk_col} = %s",
            (entry_id, link.entity_id),
        )
        cur.execute(
            f"UPDATE {etable} SET article_count = GREATEST(article_count - 1, 0) WHERE id = %s",
            (link.entity_id,),
        )
    return True


def log_proposed_removal(
    conn: psycopg.Connection,
    entry_id: uuid.UUID,
    link: LinkRow,
    reason: str,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO entity_link_validation_log
                (id, entry_id, entity_type, entity_id, entity_name_snapshot, action, reason,
                 original_source, original_confidence, original_matched_names,
                 original_paragraph_indices, original_extracted_at)
            VALUES (%s, %s, %s, %s, %s, 'shadow_remove', %s,
                    %s, %s, %s, %s, %s)
            """,
            (
                uuid.uuid4(),
                entry_id,
                link.entity_type,
                link.entity_id,
                link.name,
                (reason or "")[:500] or None,
                link.source,
                link.confidence,
                list(link.matched_names),
                list(link.paragraph_indices),
                link.extracted_at,
            ),
        )


def log_reclassification(
    conn: psycopg.Connection,
    entry_id: uuid.UUID,
    link: LinkRow,
    reason: str,
    suggested_type: str | None,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO entity_link_validation_log
                (id, entry_id, entity_type, entity_id, entity_name_snapshot, action, reason,
                 original_source, original_confidence, original_matched_names,
                 original_paragraph_indices, original_extracted_at, suggested_entity_type)
            VALUES (%s, %s, %s, %s, %s, 'needs_reclassification', %s,
                    %s, %s, %s, %s, %s, %s)
            """,
            (
                uuid.uuid4(),
                entry_id,
                link.entity_type,
                link.entity_id,
                link.name,
                (reason or "")[:500] or None,
                link.source,
                link.confidence,
                list(link.matched_names),
                list(link.paragraph_indices),
                link.extracted_at,
                suggested_type,
            ),
        )


def stamp_validated(conn: psycopg.Connection, entry_id: uuid.UUID) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE entries SET last_link_validation_at = NOW() WHERE id = %s",
            (entry_id,),
        )


# ---------------------------------------------------------------- system_settings
#
# system_settings is a singleton row (id=1) with a JSONB `settings` column.
# Keys live inside that blob, not as separate rows.


def _load_settings_blob(conn: psycopg.Connection) -> dict:
    with conn.cursor() as cur:
        cur.execute("SELECT settings FROM system_settings WHERE id = 1")
        row = cur.fetchone()
        return (row[0] if row else None) or {}


def read_mode(blob: dict) -> str:
    """Return the underlying DB enum value ('shadow' or 'apply').

    The DB column still stores the original enum; callers translate to the
    user-facing 'proposed'/'applied' vocabulary at display time.
    """
    val = blob.get("link_validation_mode")
    if val is None:
        return "shadow"
    val = str(val).strip().strip('"').lower()
    return val if val in {"shadow", "apply"} else "shadow"


def read_int_setting(blob: dict, key: str, default: int) -> int:
    val = blob.get(key)
    if val is None:
        return default
    try:
        return int(str(val).strip().strip('"'))
    except (TypeError, ValueError):
        return default


def read_float_setting(blob: dict, key: str, default: float) -> float:
    val = blob.get(key)
    if val is None:
        return default
    try:
        return float(str(val).strip().strip('"'))
    except (TypeError, ValueError):
        return default


def read_str_setting(blob: dict, key: str) -> str | None:
    val = blob.get(key)
    if val is None:
        return None
    s = str(val).strip().strip('"')
    return s or None


# ---------------------------------------------------------------- per-entry runner


@dataclass
class EntryResult:
    entry_id: uuid.UUID
    status: str  # applied, proposed, no_links, ai_error, ai_bad_shape, locked, skipped, dry_run
    total_links: int = 0
    kept: int = 0
    removed: int = 0
    proposed_removed: int = 0
    reclassified: int = 0
    elapsed_s: float = 0.0
    error: str | None = None


def lock_entry(conn: psycopg.Connection, entry_id: uuid.UUID) -> bool:
    """Try to acquire a Postgres advisory lock for this entry (NOWAIT)."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT pg_try_advisory_lock(hashtext('linkval'), hashtext(%s::text))",
            (str(entry_id),),
        )
        got = cur.fetchone()[0]
        return bool(got)


def unlock_entry(conn: psycopg.Connection, entry_id: uuid.UUID) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT pg_advisory_unlock(hashtext('linkval'), hashtext(%s::text))",
            (str(entry_id),),
        )


def process_entry(
    conn: psycopg.Connection,
    entry_id: uuid.UUID,
    system_text: str | None,
    template_text: str,
    schema: dict | None,
    mode: str,
    max_chars: int,
    skip_confidence: str | None,
    model: str,
    timeout_seconds: float,
    circuit_breaker_pct: float,
    dry_run: bool,
    ai_retries: int = 1,
) -> EntryResult:
    start = time.monotonic()

    if not lock_entry(conn, entry_id):
        return EntryResult(entry_id=entry_id, status="locked", elapsed_s=time.monotonic() - start)
    try:
        entry = fetch_entry_bundle(conn, entry_id, skip_confidence)
        if not entry:
            return EntryResult(
                entry_id=entry_id,
                status="missing_entry",
                elapsed_s=time.monotonic() - start,
            )

        if not entry.links:
            if not dry_run:
                stamp_validated(conn, entry_id)
                conn.commit()
            return EntryResult(entry_id=entry_id, status="no_links", elapsed_s=time.monotonic() - start)

        variables = build_prompt_variables(entry, max_chars)
        prompt = render_prompt(template_text, variables)
        rendered_system = render_prompt(system_text, variables) if system_text else None

        try:
            ai_out = call_claude(
                prompt=prompt,
                schema=schema,
                model=model,
                timeout_seconds=timeout_seconds,
                system_prompt=rendered_system,
                heartbeat_label=f"entry {entry_id}",
                max_retries=ai_retries,
            )
        except Exception as e:
            if not dry_run:
                stamp_validated(conn, entry_id)
                conn.commit()
            return EntryResult(
                entry_id=entry_id,
                status="ai_error",
                total_links=len(entry.links),
                elapsed_s=time.monotonic() - start,
                error=str(e)[:300],
            )

        decisions = validate_decisions(ai_out, entry.links)
        if decisions is None:
            if not dry_run:
                stamp_validated(conn, entry_id)
                conn.commit()
            return EntryResult(
                entry_id=entry_id,
                status="ai_bad_shape",
                total_links=len(entry.links),
                elapsed_s=time.monotonic() - start,
            )

        removals = [d for d in decisions if d["decision"] == "REMOVE"]
        reclassifies = [d for d in decisions if d["decision"] == "RECLASSIFY"]
        keep_count = sum(1 for d in decisions if d["decision"] == "KEEP")

        removal_pct = (len(removals) / len(decisions)) if decisions else 0.0
        cb_tripped = removal_pct > circuit_breaker_pct

        if dry_run:
            decision_label = {
                "REMOVE": "remove_proposed",
                "RECLASSIFY": "reclassify_proposed",
            }
            for d in decisions:
                if d["decision"] != "KEEP":
                    logger.info(
                        "  [DRY] %s %s/%s name=%r reason=%r%s",
                        decision_label.get(d["decision"], d["decision"]),
                        d["link"].entity_type,
                        d["link"].entity_id,
                        d["link"].name,
                        d["reason"],
                        f" → {d['suggested_type']}" if d.get("suggested_type") else "",
                    )
            return EntryResult(
                entry_id=entry_id,
                status="dry_run",
                total_links=len(decisions),
                kept=keep_count,
                removed=sum(1 for d in removals),
                reclassified=len(reclassifies),
                elapsed_s=time.monotonic() - start,
            )

        applied = 0
        proposed = 0
        reclassified = 0
        for d in removals:
            if mode == "apply":
                if apply_removal(conn, entry_id, d["link"], d["reason"]):
                    applied += 1
            else:
                log_proposed_removal(conn, entry_id, d["link"], d["reason"])
                proposed += 1
        for d in reclassifies:
            log_reclassification(conn, entry_id, d["link"], d["reason"], d["suggested_type"])
            reclassified += 1

        stamp_validated(conn, entry_id)
        conn.commit()

        if cb_tripped:
            logger.warning(
                "circuit breaker tripped on entry=%s: %.0f%% of %d links flagged REMOVE",
                entry_id,
                removal_pct * 100,
                len(decisions),
            )

        return EntryResult(
            entry_id=entry_id,
            status="applied" if mode == "apply" else "proposed",
            total_links=len(decisions),
            kept=keep_count,
            removed=applied,
            proposed_removed=proposed,
            reclassified=reclassified,
            elapsed_s=time.monotonic() - start,
        )
    finally:
        # Best-effort cleanup — connection may already be dead, in which case
        # the advisory lock dies with it (Postgres releases session-scoped
        # locks on disconnect). Swallow every failure so the outer except can
        # see the original error instead of a cascading rollback exception.
        try:
            if not conn.closed:
                unlock_entry(conn, entry_id)
                conn.commit()
        except Exception:
            try:
                if not conn.closed:
                    conn.rollback()
            except Exception:
                pass


def process_batch(
    conn: psycopg.Connection,
    entry_ids: list[uuid.UUID],
    system_text: str | None,
    template_text: str,
    schema: dict | None,
    mode: str,
    max_chars: int,
    skip_confidence: str | None,
    model: str,
    timeout_seconds: float,
    circuit_breaker_pct: float,
    dry_run: bool,
    ai_retries: int = 1,
) -> list[EntryResult]:
    """Validate N entries in a single claude call.

    Mirrors process_entry's per-entry logic exactly, but groups the AI call:
    fetches bundles + locks per entry, builds one batched prompt with the
    per-entry templates wrapped in a batching envelope, makes ONE claude call,
    then routes decisions back per entry_id and applies them.

    A batch-wide failure (timeout, malformed output, schema mismatch) marks
    every entry in the batch with ai_error / ai_bad_shape — those entries
    stay unstamped so the next run retries them. Entries already locked by
    another worker are skipped individually without affecting the rest.
    """
    batch_start = time.monotonic()
    results: list[EntryResult] = []
    locked: list[uuid.UUID] = []
    bundles: dict[uuid.UUID, EntryBundle] = {}

    # Phase 1: lock + fetch each entry. Skip locked-elsewhere and missing entries.
    for eid in entry_ids:
        if not lock_entry(conn, eid):
            results.append(EntryResult(entry_id=eid, status="locked", elapsed_s=0.0))
            continue
        locked.append(eid)
        bundle = fetch_entry_bundle(conn, eid, skip_confidence)
        if bundle is None:
            results.append(EntryResult(entry_id=eid, status="missing_entry", elapsed_s=0.0))
            continue
        bundles[eid] = bundle

    try:
        # Phase 2: handle no-links entries up front (no AI call needed).
        rendered_entries: list[tuple[uuid.UUID, str]] = []
        for eid, bundle in bundles.items():
            if not bundle.links:
                if not dry_run:
                    stamp_validated(conn, eid)
                results.append(
                    EntryResult(
                        entry_id=eid,
                        status="no_links",
                        elapsed_s=time.monotonic() - batch_start,
                    )
                )
                continue
            variables = build_prompt_variables(bundle, max_chars)
            rendered_entries.append((eid, render_prompt(template_text, variables)))

        if not dry_run:
            conn.commit()

        if not rendered_entries:
            return results

        # Phase 3: build batched prompt + schema, make ONE claude call.
        batched_prompt = build_batched_prompt(rendered_entries)
        batched_sch = batched_schema(schema)

        # The system prompt is entry-agnostic in practice — render with the
        # first bundle's variables to satisfy any {{entry_*}} references.
        first_bundle = bundles[rendered_entries[0][0]]
        first_vars = build_prompt_variables(first_bundle, max_chars)
        rendered_system = render_prompt(system_text, first_vars) if system_text else None

        try:
            ai_out = call_claude(
                prompt=batched_prompt,
                schema=batched_sch,
                model=model,
                timeout_seconds=timeout_seconds,
                system_prompt=rendered_system,
                heartbeat_label=f"batch of {len(rendered_entries)} entries",
                max_retries=ai_retries,
            )
        except Exception as e:
            elapsed = time.monotonic() - batch_start
            for eid, _ in rendered_entries:
                results.append(
                    EntryResult(
                        entry_id=eid,
                        status="ai_error",
                        total_links=len(bundles[eid].links),
                        elapsed_s=elapsed,
                        error=str(e)[:300],
                    )
                )
            return results

        # Phase 4: parse + route the batched response back per entry.
        batched_entries = ai_out.get("entries") if isinstance(ai_out, dict) else None
        if not isinstance(batched_entries, list):
            # Fallback: if model returned the un-batched single-entry shape
            # AND there's exactly one entry in the batch, treat it as that
            # entry's validations.
            if len(rendered_entries) == 1 and isinstance(ai_out, dict) and isinstance(ai_out.get("validations"), list):
                batched_entries = [
                    {
                        "entry_id": str(rendered_entries[0][0]),
                        "validations": ai_out["validations"],
                    }
                ]
            else:
                elapsed = time.monotonic() - batch_start
                for eid, _ in rendered_entries:
                    results.append(
                        EntryResult(
                            entry_id=eid,
                            status="ai_bad_shape",
                            total_links=len(bundles[eid].links),
                            elapsed_s=elapsed,
                        )
                    )
                return results

        per_entry_out: dict[str, list] = {}
        for item in batched_entries:
            if not isinstance(item, dict):
                continue
            eid_str = item.get("entry_id")
            vals = item.get("validations")
            if eid_str and isinstance(vals, list):
                per_entry_out[str(eid_str)] = vals

        # Phase 5: apply per-entry decisions (or log them in dry-run).
        for eid, _ in rendered_entries:
            entry_start = time.monotonic()
            bundle = bundles[eid]
            vals = per_entry_out.get(str(eid))
            if vals is None:
                results.append(
                    EntryResult(
                        entry_id=eid,
                        status="ai_bad_shape",
                        total_links=len(bundle.links),
                        elapsed_s=time.monotonic() - batch_start,
                    )
                )
                continue

            decisions = validate_decisions({"validations": vals}, bundle.links)
            if decisions is None:
                results.append(
                    EntryResult(
                        entry_id=eid,
                        status="ai_bad_shape",
                        total_links=len(bundle.links),
                        elapsed_s=time.monotonic() - batch_start,
                    )
                )
                continue

            removals = [d for d in decisions if d["decision"] == "REMOVE"]
            reclassifies = [d for d in decisions if d["decision"] == "RECLASSIFY"]
            keep_count = sum(1 for d in decisions if d["decision"] == "KEEP")
            removal_pct = (len(removals) / len(decisions)) if decisions else 0.0
            cb_tripped = removal_pct > circuit_breaker_pct

            if dry_run:
                decision_label = {
                    "REMOVE": "remove_proposed",
                    "RECLASSIFY": "reclassify_proposed",
                }
                for d in decisions:
                    if d["decision"] != "KEEP":
                        logger.info(
                            "  [DRY] %s %s/%s name=%r reason=%r%s",
                            decision_label.get(d["decision"], d["decision"]),
                            d["link"].entity_type,
                            d["link"].entity_id,
                            d["link"].name,
                            d["reason"],
                            f" → {d['suggested_type']}" if d.get("suggested_type") else "",
                        )
                results.append(
                    EntryResult(
                        entry_id=eid,
                        status="dry_run",
                        total_links=len(decisions),
                        kept=keep_count,
                        removed=len(removals),
                        reclassified=len(reclassifies),
                        elapsed_s=time.monotonic() - entry_start,
                    )
                )
                continue

            applied = 0
            proposed = 0
            reclassified = 0
            for d in removals:
                if mode == "apply":
                    if apply_removal(conn, eid, d["link"], d["reason"]):
                        applied += 1
                else:
                    log_proposed_removal(conn, eid, d["link"], d["reason"])
                    proposed += 1
            for d in reclassifies:
                log_reclassification(conn, eid, d["link"], d["reason"], d["suggested_type"])
                reclassified += 1

            stamp_validated(conn, eid)
            conn.commit()

            if cb_tripped:
                logger.warning(
                    "circuit breaker tripped on entry=%s: %.0f%% of %d links flagged REMOVE",
                    eid,
                    removal_pct * 100,
                    len(decisions),
                )

            results.append(
                EntryResult(
                    entry_id=eid,
                    status="applied" if mode == "apply" else "proposed",
                    total_links=len(decisions),
                    kept=keep_count,
                    removed=applied,
                    proposed_removed=proposed,
                    reclassified=reclassified,
                    elapsed_s=time.monotonic() - entry_start,
                )
            )

        return results
    finally:
        # Best-effort cleanup of advisory locks for every entry we acquired.
        for eid in locked:
            try:
                if not conn.closed:
                    unlock_entry(conn, eid)
            except Exception:
                pass
        try:
            if not conn.closed:
                conn.commit()
        except Exception:
            try:
                if not conn.closed:
                    conn.rollback()
            except Exception:
                pass


# ---------------------------------------------------------------- driver


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ssh-host", required=True, help="SSH target for prod, e.g. user@prod.example.com")
    ap.add_argument(
        "--env-path",
        default="~/intelfeed/.env",
        help="Path to .env on the prod host",
    )
    ap.add_argument(
        "--compose-project",
        default="intelfeed",
        help="Docker compose project name (network prefix)",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Cap on entries this run (default: all pending)",
    )
    ap.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Parallel workers — each worker holds its own DB connection + claude subprocess (default 1)",
    )
    ap.add_argument(
        "--batch-size",
        type=int,
        default=10,
        help=(
            "Entries to validate per claude call (default 10). Each CLI call has "
            "~1-2s of bun/auth overhead that batching amortizes. Combined with "
            "--workers, this is the main speedup vs. the old one-entry-at-a-time mode. "
            "A batch-wide AI failure marks all N entries unstamped so they retry next run."
        ),
    )
    ap.add_argument("--model", default="sonnet", help="Claude model alias: sonnet / haiku / opus")
    ap.add_argument(
        "--mode",
        choices=["auto", "proposed", "applied", "shadow", "apply"],
        default="auto",
        help=("proposed/applied match the UI; shadow/apply are accepted as the underlying DB values"),
    )
    ap.add_argument("--recheck-days", type=int, default=None, help="Override recheck window")
    ap.add_argument(
        "--ignore-recheck-window",
        action="store_true",
        help="Re-validate every candidate regardless of last_link_validation_at",
    )
    ap.add_argument(
        "--max-chars",
        type=int,
        default=None,
        help="Override link_validation_content_max_chars",
    )
    ap.add_argument(
        "--circuit-breaker-pct",
        type=float,
        default=None,
        help="Override link_validation_circuit_breaker_pct",
    )
    ap.add_argument(
        "--skip-confidence",
        default=None,
        help="Override link_validation_skip_confidence (e.g. 'high')",
    )
    ap.add_argument(
        "--timeout",
        type=float,
        default=0.0,
        help=(
            "Per-CLI-call timeout in seconds. 0 = auto by model (haiku=90, sonnet=180, opus=300). "
            "Lower values catch hangs faster."
        ),
    )
    ap.add_argument(
        "--ai-retries",
        type=int,
        default=1,
        help="Retry the claude CLI this many times on timeout before logging ai_error (default 1)",
    )
    ap.add_argument(
        "--watchdog",
        type=float,
        default=300.0,
        help=(
            "Hard-exit the script if no entry completes for this many seconds (default 600). "
            "Catches silent freezes from Mac sleep / dropped SSH tunnel / wedged DB connection. "
            "Set to 0 to disable."
        ),
    )
    ap.add_argument(
        "--auto-restart",
        action="store_true",
        help=(
            "Re-exec the script in place on watchdog trip or unhandled error, instead of exiting. "
            f"Capped at {_MAX_AUTO_RESTARTS} restarts per process tree to prevent runaway loops. "
            "Pair with --watchdog so unattended runs survive transient hangs."
        ),
    )
    ap.add_argument(
        "--seen-file",
        default=_SEEN_FILE_DEFAULT,
        help=(
            "Path to a local append-only file of already-scanned entry UUIDs. Entries listed "
            "here are filtered out of the candidate set before the run starts. Successful "
            "outcomes (applied/proposed/no_links) are appended after each entry — errors are "
            f"not, so they get retried. Default: {_SEEN_FILE_DEFAULT}"
        ),
    )
    ap.add_argument(
        "--no-seen-file",
        action="store_true",
        help="Disable the local seen-file entirely (every candidate is eligible)",
    )
    ap.add_argument(
        "--reset-seen",
        action="store_true",
        help="Truncate the seen-file before this run, so every candidate is scanned again",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Run prompts, log decisions, don't mutate DB",
    )
    ap.add_argument(
        "--web-url",
        default="http://localhost:3001",
        help="Base URL used to render per-entry links in the progress output",
    )
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.workers > 1:
        logger.warning(
            "workers=%d — running parallel claude CLI invocations. Recent CLI versions "
            "handle concurrent OAuth refreshes safely, but if you see auth errors, drop to --workers 1.",
            args.workers,
        )
    if args.batch_size < 1:
        sys.exit("--batch-size must be >= 1")

    tunnel = open_tunnel(args.ssh_host, args.compose_project, args.env_path)

    dsn = (
        f"host=127.0.0.1 port={tunnel.local_port} "
        f"dbname={tunnel.db_name} user={tunnel.db_user} password={tunnel.db_password} "
        # TCP keepalives so worker connections survive the long idle window
        # while another worker holds the CLI lock or the SSH tunnel has a blip.
        f"sslmode=disable keepalives=1 keepalives_idle=30 keepalives_interval=10 keepalives_count=5"
    )

    # Resolve runtime settings.
    with psycopg.connect(dsn, autocommit=False) as bootstrap:
        blob = _load_settings_blob(bootstrap)
        # Normalize UI vocabulary back to the DB enum values.
        cli_mode = {"proposed": "shadow", "applied": "apply"}.get(args.mode, args.mode)
        mode = cli_mode if cli_mode != "auto" else read_mode(blob)
        recheck_days = (
            args.recheck_days
            if args.recheck_days is not None
            else read_int_setting(blob, "link_validation_recheck_days", 30)
        )
        max_chars = (
            args.max_chars
            if args.max_chars is not None
            else read_int_setting(blob, "link_validation_content_max_chars", 3000)
        )
        circuit_pct = (
            args.circuit_breaker_pct
            if args.circuit_breaker_pct is not None
            else read_float_setting(blob, "link_validation_circuit_breaker_pct", 0.4)
        )
        skip_conf = args.skip_confidence or read_str_setting(blob, "link_validation_skip_confidence")
        system_text, template_text, schema = load_active_prompt(bootstrap)
        candidates = select_candidates(bootstrap, args.limit, recheck_days, args.ignore_recheck_window)

    # Resolve seen-file. The candidate query doesn't know about it; we filter
    # in memory so the seen-list survives across runs even with full DB resets.
    seen_path: pathlib.Path | None = None
    seen: set[uuid.UUID] = set()
    if not args.no_seen_file:
        seen_path = pathlib.Path(args.seen_file).expanduser()
        if args.reset_seen and seen_path.exists():
            seen_path.unlink()
            logger.info("Reset seen-file: %s", seen_path)
        seen = _load_seen(seen_path)
    pre_filter = len(candidates)
    if seen:
        candidates = [c for c in candidates if c not in seen]
    skipped_seen = pre_filter - len(candidates)

    mode_label = "applied" if mode == "apply" else "proposed"
    if args.timeout > 0:
        effective_timeout = args.timeout
    else:
        # Auto-scale by batch size: MODEL_TIMEOUTS values were tuned for
        # single-entry calls. A batched call has to chew through N entries
        # in one shot — add 50% of the base timeout per additional entry,
        # capped at 600s so a hung call still gets killed eventually.
        base = MODEL_TIMEOUTS.get(args.model, DEFAULT_TIMEOUT_FALLBACK)
        if args.batch_size > 1:
            effective_timeout = min(600.0, base * (1.0 + 0.5 * (args.batch_size - 1)))
        else:
            effective_timeout = base
    logger.info(
        "Configuration: mode=%s model=%s timeout=%.0fs ai_retries=%d recheck_days=%d"
        "max_chars=%d circuit_breaker_pct=%.2f skip_confidence=%r workers=%d dry_run=%s",
        mode_label,
        args.model,
        effective_timeout,
        args.ai_retries,
        recheck_days,
        max_chars,
        circuit_pct,
        skip_conf,
        args.workers,
        args.dry_run,
    )
    if seen_path is not None:
        logger.info(
            "Candidate count: %d (%d skipped via seen-file %s, %d in seen-list total)",
            len(candidates),
            skipped_seen,
            seen_path,
            len(seen),
        )
    else:
        logger.info("Candidate count: %d (seen-file disabled)", len(candidates))
    if not candidates:
        return 0

    counters: dict[str, int] = {}
    counters_lock = Lock()
    totals = {
        "kept": 0,
        "links_removed": 0,
        "removes_proposed": 0,
        "reclassifies_proposed": 0,
    }
    started = time.monotonic()

    # Watchdog: hard-exit (or re-exec, if --auto-restart) the process when no
    # entry completes within --watchdog seconds. Catches Mac sleep, half-open
    # SSH tunnels, and any other silent freeze the per-call timeout doesn't cover.
    watchdog_stop = Event()
    if args.watchdog > 0:
        _touch_progress()  # reset baseline so we don't trip on import-time delay
        Thread(
            target=_watchdog,
            args=(args.watchdog, watchdog_stop, args.auto_restart),
            daemon=True,
        ).start()
        restart_depth = int(os.environ.get(_RESTART_ENV_VAR, "0"))
        action = "re-exec" if args.auto_restart else "abort"
        logger.info(
            "Watchdog armed: will %s if no entry completes within %.0fs%s",
            action,
            args.watchdog,
            (f" (auto-restart #{restart_depth}/{_MAX_AUTO_RESTARTS})" if restart_depth else ""),
        )

    def worker_batch(entry_ids: list[uuid.UUID]) -> list[EntryResult]:
        # Each worker holds its own DB connection. Connections can drop while
        # idle (notably on a flaky SSH tunnel). Catch and report so one blip
        # doesn't tear down the whole run — entries stay unstamped and will
        # be picked up on the next invocation.
        start = time.monotonic()
        try:
            with psycopg.connect(dsn, autocommit=False, connect_timeout=10) as conn:
                return process_batch(
                    conn=conn,
                    entry_ids=entry_ids,
                    system_text=system_text,
                    template_text=template_text,
                    schema=schema,
                    mode=mode,
                    max_chars=max_chars,
                    skip_confidence=skip_conf,
                    model=args.model,
                    timeout_seconds=effective_timeout,
                    ai_retries=args.ai_retries,
                    circuit_breaker_pct=circuit_pct,
                    dry_run=args.dry_run,
                )
        except psycopg.OperationalError as e:
            elapsed = time.monotonic() - start
            return [
                EntryResult(
                    entry_id=eid,
                    status="connection_lost",
                    elapsed_s=elapsed,
                    error=str(e)[:300],
                )
                for eid in entry_ids
            ]
        except Exception as e:
            elapsed = time.monotonic() - start
            return [
                EntryResult(
                    entry_id=eid,
                    status="worker_error",
                    elapsed_s=elapsed,
                    error=f"{type(e).__name__}: {str(e)[:280]}",
                )
                for eid in entry_ids
            ]

    web_base = args.web_url.rstrip("/")

    def report(idx: int, total: int, r: EntryResult) -> None:
        _touch_progress()
        if seen_path is not None and not args.dry_run and r.status in _SEEN_TERMINAL_STATUSES:
            try:
                _append_seen(seen_path, r.entry_id)
            except OSError as e:
                logger.warning("seen-file append failed for %s: %s", r.entry_id, e)
        with counters_lock:
            counters[r.status] = counters.get(r.status, 0) + 1
            totals["kept"] += r.kept
            totals["links_removed"] += r.removed
            totals["removes_proposed"] += r.proposed_removed
            totals["reclassifies_proposed"] += r.reclassified
        elapsed_total = time.monotonic() - started
        rate = (idx / elapsed_total) if elapsed_total > 0 else 0.0
        eta_s = ((total - idx) / rate) if rate > 0 else 0.0
        eta = str(timedelta(seconds=int(eta_s)))
        logger.info(
            "[%d/%d] %s %s/?entry=%s links=%d kept=%d link_removed=%d"
            "remove_proposed=%d reclassify_proposed=%d in %.1fs (%.2f/s, ETA %s)%s",
            idx,
            total,
            r.status,
            web_base,
            r.entry_id,
            r.total_links,
            r.kept,
            r.removed,
            r.proposed_removed,
            r.reclassified,
            r.elapsed_s,
            rate,
            eta,
            f" err={r.error}" if r.error else "",
        )

    batches = list(_chunked(candidates, args.batch_size))
    logger.info(
        "Dispatching %d entries in %d batch(es) of up to %d, with %d worker(s)",
        len(candidates),
        len(batches),
        args.batch_size,
        args.workers,
    )

    try:
        done_count = 0
        if args.workers <= 1:
            for batch in batches:
                results_batch = worker_batch(batch)
                for r in results_batch:
                    done_count += 1
                    report(done_count, len(candidates), r)
        else:
            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                future_to_batch = {pool.submit(worker_batch, batch): batch for batch in batches}
                for fut in as_completed(future_to_batch):
                    results_batch = fut.result()
                    for r in results_batch:
                        done_count += 1
                        report(done_count, len(candidates), r)
    except KeyboardInterrupt:
        logger.warning("Interrupted — progress so far is committed; rerun the script to continue.")
    finally:
        watchdog_stop.set()

    logger.info("--- summary ---")
    for status, n in sorted(counters.items()):
        logger.info("  %s: %d", status, n)
    logger.info(
        "totals: kept=%d link_removed=%d remove_proposed=%d reclassify_proposed=%d",
        totals["kept"],
        totals["links_removed"],
        totals["removes_proposed"],
        totals["reclassifies_proposed"],
    )
    return 0


if __name__ == "__main__":
    # If --auto-restart is set, re-exec on any unhandled exception too — not
    # just on watchdog trip. KeyboardInterrupt is honored as a deliberate stop.
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as exc:
        if "--auto-restart" in sys.argv:
            _self_restart(f"unhandled exception: {type(exc).__name__}: {str(exc)[:200]}")
        raise
