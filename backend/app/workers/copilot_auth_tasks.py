"""Celery tasks that (re)authenticate the Claude Code CLI used by the copilot.

Why this exists (prod topology): the copilot drives the ``claude`` CLI, which
authenticates via an OAuth session stored at ``~/.claude/.credentials.json``.
Only ``celery-worker-ai`` owns that credentials volume, so both reading the
credential's health and rewriting it via ``claude setup-token`` must happen on
that worker. The api container dispatches here.

``run_claude_auth`` drives the interactive ``claude auth login`` flow under a
pty: it captures the authorization URL the CLI prints, relays it to the api over
Redis, waits (again over Redis) for the user to paste the code back from the
browser, feeds that code to the CLI on the pty, and reports success/failure. The
whole interactive session lives inside this one task so the PKCE state held in
the CLI process survives between the two api round-trips — the same Redis-bridge
pattern the copilot stream uses.

``refresh_claude_auth_status`` is a cheap read of the credential file that
publishes a health snapshot (``copilot:auth:status``) the settings UI renders and
that doubles as an expiry monitor. It's beat-scheduled and also runs on demand.

Both tasks are routed to the ``ai`` queue (see ``celery_app.py``).
Because that worker runs ``--concurrency=1``, an in-flight re-auth briefly
occupies it; the code-wait is bounded so an abandoned flow can't wedge it.
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import pty
import re
import select
import shutil
import signal
import struct
import subprocess
import termios
import time
from datetime import UTC, datetime

import redis
from celery.exceptions import SoftTimeLimitExceeded

from app.config import settings
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

# The CLI stores its OAuth session here inside the celery-worker-ai container.
CREDENTIALS_PATH = os.path.expanduser("~/.claude/.credentials.json")

# Redis namespace shared with app/api/copilot_auth.py.
_SESSION_PREFIX = "copilot:auth:session:"  # per-run state (string, JSON)
_CODE_PREFIX = "copilot:auth:code:"  # pasted code inbox (list, BLPOP)
_STATUS_KEY = "copilot:auth:status"  # credential health snapshot (string, JSON)
_LOCK_KEY = "copilot:auth:lock"  # single-active-run lock (acquired by the api)
_SESSION_TTL = 900
_CANCEL_TOKEN = "__cancel__"

# Timeouts (seconds). The sum bounds how long a re-auth can hold the worker.
_URL_WAIT = 90  # for the authorize URL to appear on the pty
_CODE_WAIT = 300  # for the user to authorize in a browser and paste the code
_EXCHANGE_WAIT = 90  # for the CLI to exchange the code and write credentials

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
# OSC-8 hyperlink: ESC ] 8 ; params ; URI  ST(ESC \ or BEL). The URI here is the
# clean, un-line-wrapped authorize URL — the plain-text copy is wrapped by the
# terminal and unreliable, so prefer this.
_OSC8_RE = re.compile(r"\x1b\]8;[^;]*;([^\x1b\x07]+)(?:\x1b\\|\x07)")
_AUTHORIZE_RE = re.compile(r"https://claude\.com/cai/oauth/authorize\?\S+")


def _redis() -> redis.Redis:
    return redis.from_url(settings.redis_url, decode_responses=True)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _set_session(r: redis.Redis, session_id: str, **fields) -> None:
    fields["updated_at"] = _now_iso()
    r.set(f"{_SESSION_PREFIX}{session_id}", json.dumps(fields), ex=_SESSION_TTL)


def _clean(text: str) -> str:
    """Strip ANSI + OSC-8 escapes so a transcript tail is human-readable."""
    text = _OSC8_RE.sub("", text)
    text = re.sub(r"\x1b\][^\x07\x1b]*(?:\x1b\\|\x07)", "", text)
    text = _ANSI_RE.sub("", text)
    # Charset-select (ESC ( B / ESC ( 0), other 2-byte escapes, and shift-in/out.
    text = re.sub(r"\x1b[()][0-9A-Za-z]", "", text)
    text = re.sub(r"\x1b[=>]", "", text)
    return text.replace("\r", "").replace("\x0f", "").replace("\x0e", "")


def _is_complete_url(url: str | None) -> bool:
    """A usable authorize URL has all PKCE params — a pty-truncated one won't."""
    return bool(url) and "redirect_uri" in url and "state=" in url and "code_challenge=" in url


def _extract_url(buf: str) -> str | None:
    for m in _OSC8_RE.finditer(buf):
        cand = m.group(1)
        if "oauth/authorize" in cand and _is_complete_url(cand):
            return cand
    m = _AUTHORIZE_RE.search(_ANSI_RE.sub("", buf))
    return m.group(0) if m and _is_complete_url(m.group(0)) else None


def _cli_auth_status() -> dict:
    """Authoritative logged-in state via ``claude auth status --json``.

    Covers both auth methods the CLI supports: a ``.credentials.json`` OAuth
    session (prod) and a ``CLAUDE_CODE_OAUTH_TOKEN`` env token (some deploys).
    Runs with the worker's normal env so it reflects what the copilot sees.
    """
    try:
        cli = shutil.which("claude") or "claude"
        out = subprocess.run(
            [cli, "auth", "status", "--json"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        return json.loads((out.stdout or "").strip() or "{}")
    except Exception:
        return {}


def _credentials_from_file() -> dict | None:
    """Parse ``.credentials.json`` directly (no CLI call) — used for the
    unambiguous success signal that ``auth login`` wrote a fresh session."""
    try:
        with open(CREDENTIALS_PATH) as f:
            oauth = json.load(f)
    except Exception:
        return None
    oauth = oauth.get("claudeAiOauth", oauth)
    expires_at = oauth.get("expiresAt")
    if not isinstance(expires_at, int | float):
        return None
    return {
        "expires_at": expires_at,
        "expires_at_iso": datetime.fromtimestamp(expires_at / 1000, UTC).isoformat(),
        "subscription_type": oauth.get("subscriptionType"),
        "valid": (expires_at / 1000) > time.time(),
    }


def read_credential_status() -> dict:
    """Build a copilot-auth health snapshot (never raises).

    ``loggedIn`` comes from the CLI itself; expiry (when the auth method is a
    credentials file) is read from that file so the UI can warn before it lapses.
    """
    snap: dict = {"state": "known", "checked_at": _now_iso()}
    status = _cli_auth_status()
    logged_in = bool(status.get("loggedIn"))
    snap["logged_in"] = logged_in
    snap["auth_method"] = status.get("authMethod")

    # Expiry only exists for the credentials-file auth method.
    try:
        with open(CREDENTIALS_PATH) as f:
            oauth = json.load(f)
        oauth = oauth.get("claudeAiOauth", oauth)
        expires_at = oauth.get("expiresAt")
        if isinstance(expires_at, int | float):
            snap["expires_at"] = expires_at
            snap["expires_at_iso"] = datetime.fromtimestamp(expires_at / 1000, UTC).isoformat()
            snap["subscription_type"] = oauth.get("subscriptionType")
            snap["scopes"] = oauth.get("scopes")
    except Exception:
        pass

    expires_at = snap.get("expires_at")
    snap["valid"] = logged_in and (expires_at is None or (expires_at / 1000) > time.time())
    snap["exists"] = logged_in or expires_at is not None
    return snap


def _wait_for_url(master_fd: int, proc: subprocess.Popen, transcript: list[str], deadline: float) -> str | None:
    buf = ""
    while time.monotonic() < deadline:
        rlist, _, _ = select.select([master_fd], [], [], 0.5)
        if rlist:
            try:
                chunk = os.read(master_fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            text = chunk.decode("utf-8", "replace")
            transcript.append(text)
            buf += text
            url = _extract_url(buf)
            if url:
                return url
        elif proc.poll() is not None:
            break  # CLI exited before emitting a URL
    return _extract_url(buf)


def _diagnose_failure(cleaned: str, returncode: int | None) -> str:
    """Turn the CLI's post-code output into a human-actionable error message."""
    low = cleaned.lower()
    if "too many requests" in low or "rate limit" in low or "429" in low:
        return "Claude's sign-in service is rate-limiting right now. Wait about a minute, then try again."
    if "invalid" in low or "expired" in low or "did not match" in low or "не" in low:
        return "That authorization code was invalid or expired. Start over and paste a fresh code promptly."
    # Fall back to the last meaningful line (skip spinner frames / masked input).
    spinner = set("·✢*✶✻✽ ")
    lines = [
        ln.strip()
        for ln in cleaned.splitlines()
        if ln.strip() and not set(ln.strip()) <= {"*"} and not set(ln.strip()) <= spinner
    ]
    last = lines[-1][:200] if lines else ""
    return f"Sign-in didn't complete (CLI exit {returncode}). {last}".strip()


@celery_app.task(
    name="app.workers.copilot_auth_tasks.run_claude_auth",
    bind=True,
    soft_time_limit=_URL_WAIT + _CODE_WAIT + _EXCHANGE_WAIT + 30,
    time_limit=_URL_WAIT + _CODE_WAIT + _EXCHANGE_WAIT + 90,
)
def run_claude_auth(self, session_id: str) -> dict:
    """Drive ``claude auth login`` under a pty, relaying URL/code over Redis."""
    r = _redis()
    master_fd: int | None = None
    proc: subprocess.Popen | None = None
    transcript: list[str] = []
    started_at = time.time()

    def fail(message: str, state: str = "error") -> dict:
        tail = _clean("".join(transcript))[-600:].strip()
        _set_session(r, session_id, state=state, message=message, transcript_tail=tail)
        logger.warning("claude re-auth %s %s: %s", session_id[:8], state, message)
        return {"status": state, "session_id": session_id}

    try:
        _set_session(r, session_id, state="starting")
        cli = shutil.which("claude") or "claude"

        # Force a fresh interactive OAuth login: strip any prebaked token/key so
        # `auth login` actually runs the browser flow (and writes a new
        # .credentials.json) instead of reporting "already logged in".
        env = os.environ.copy()
        env["TERM"] = "xterm-256color"
        for var in ("ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN"):
            env.pop(var, None)

        master_fd, slave_fd = pty.openpty()
        # Force a very wide window. At the default 80 columns the CLI wraps the
        # long OAuth authorize URL, truncating the OSC-8 hyperlink target we
        # parse (dropping redirect_uri and everything after) → "Invalid OAuth
        # Request". A 1000-column pty keeps the URL on one line.
        try:
            fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 1000, 0, 0))
        except Exception:
            pass
        proc = subprocess.Popen(
            [cli, "auth", "login", "--claudeai"],
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            env=env,
            close_fds=True,
            start_new_session=True,
        )
        os.close(slave_fd)

        url = _wait_for_url(master_fd, proc, transcript, deadline=time.monotonic() + _URL_WAIT)
        if not url:
            return fail("Timed out waiting for the authorization URL from the CLI.")
        _set_session(r, session_id, state="awaiting_code", url=url)

        popped = r.blpop([f"{_CODE_PREFIX}{session_id}"], timeout=_CODE_WAIT)
        if popped is None:
            return fail("Timed out waiting for the authorization code. Please retry.", state="timeout")
        code = popped[1].strip()
        if code == _CANCEL_TOKEN:
            _set_session(r, session_id, state="cancelled", message="Re-authentication cancelled.")
            return {"status": "cancelled", "session_id": session_id}

        _set_session(r, session_id, state="exchanging", url=url)
        os.write(master_fd, (code + "\r").encode("utf-8"))

        # Success = `auth login` writes a fresh, valid .credentials.json. Poll for
        # that file (mtime newer than this run) rather than the CLI process exit,
        # which is the unambiguous signal on every deploy topology. Drain output
        # meanwhile so a failure has a readable transcript.
        fresh: dict | None = None
        deadline = time.monotonic() + _EXCHANGE_WAIT
        while time.monotonic() < deadline:
            rlist, _, _ = select.select([master_fd], [], [], 1.0)
            if rlist:
                try:
                    chunk = os.read(master_fd, 4096)
                    if chunk:
                        transcript.append(chunk.decode("utf-8", "replace"))
                except OSError:
                    pass
            try:
                if os.stat(CREDENTIALS_PATH).st_mtime >= started_at - 2:
                    cand = _credentials_from_file()
                    if cand and cand.get("valid"):
                        fresh = cand
                        break
            except FileNotFoundError:
                pass
            if proc.poll() is not None:
                cand = _credentials_from_file()
                if cand and cand.get("valid"):
                    fresh = cand
                break

        logger.info("claude re-auth %s post-code output: %s", session_id[:8], _clean("".join(transcript))[-800:])

        if fresh:
            snap = read_credential_status()
            r.set(_STATUS_KEY, json.dumps(snap))
            _set_session(
                r,
                session_id,
                state="success",
                message="Copilot re-authenticated.",
                expires_at=fresh.get("expires_at"),
                expires_at_iso=fresh.get("expires_at_iso"),
                subscription_type=fresh.get("subscription_type"),
            )
            logger.info("claude re-auth %s succeeded (expires %s)", session_id[:8], fresh.get("expires_at_iso"))
            return {"status": "ok", "session_id": session_id}

        return fail(_diagnose_failure(_clean("".join(transcript)), proc.poll()))
    except SoftTimeLimitExceeded:
        return fail("Re-authentication timed out.", state="timeout")
    except Exception as e:
        logger.exception("claude re-auth %s crashed", session_id[:8])
        return fail(f"Unexpected error: {e}")
    finally:
        if proc is not None and proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                pass
        if master_fd is not None:
            try:
                os.close(master_fd)
            except Exception:
                pass
        # Release the single-active-run lock the api acquired for this session.
        try:
            if r.get(_LOCK_KEY) == session_id:
                r.delete(_LOCK_KEY)
        except Exception:
            pass
        try:
            r.close()
        except Exception:
            pass


@celery_app.task(name="app.workers.copilot_auth_tasks.refresh_claude_auth_status")
def refresh_claude_auth_status() -> dict:
    """Publish a fresh copilot-credential health snapshot to Redis."""
    status = read_credential_status()
    r = _redis()
    try:
        r.set(_STATUS_KEY, json.dumps(status))
    finally:
        try:
            r.close()
        except Exception:
            pass
    return status
