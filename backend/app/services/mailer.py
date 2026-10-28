"""Outbound email over the instance's SMTP relay (Settings > System > Email).

One relay for the whole instance, configured by an admin. The send_email
automation action and the settings page's test button are the only senders.
"""

import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from email.message import EmailMessage
from email.utils import formataddr, getaddresses, make_msgid, parseaddr

import aiosmtplib
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# To + Cc together. A rule mails whoever its author typed, so keep a digest
# from turning into a mailing list.
MAX_RECIPIENTS = 20

# No plain-text option: the login and every message would cross the network
# unencrypted.
SECURITY_MODES = ("starttls", "tls")

_ADDRESS_RE = re.compile(r"^[^@\s<>,;\"]+@[^@\s<>,;\"]+\.[^@\s<>,;\"]+$")

NOT_CONFIGURED = "Email isn't set up. An admin sets the SMTP server under Settings > System > Email."


class MailError(Exception):
    """Configuration or delivery failure, worded for the person who set it up."""


@dataclass
class SmtpConfig:
    host: str
    port: int
    security: str
    username: str
    password: str
    from_address: str
    max_per_hour: int = 0  # 0 = no limit


async def load_smtp_config(db: AsyncSession) -> SmtpConfig | None:
    """The saved relay, or None when no server or sender is set."""
    from app.services.system_settings import get_setting

    host = (await get_setting("smtp_host", db) or "").strip()
    from_address = (await get_setting("smtp_from_address", db) or "").strip()
    if not host or not from_address:
        return None
    return SmtpConfig(
        host=host,
        port=int(await get_setting("smtp_port", db) or 587),
        security=(await get_setting("smtp_security", db) or "starttls").lower(),
        username=(await get_setting("smtp_username", db) or "").strip(),
        password=await get_setting("smtp_password", db) or "",
        from_address=from_address,
        max_per_hour=int(await get_setting("smtp_max_per_hour", db) or 0),
    )


def parse_recipients(value: str | list | None) -> tuple[list[str], list[str]]:
    """(valid, invalid) addresses from a comma/semicolon list or a JSON array.
    Display names are kept: ``Jane <jane@example.com>``."""
    if not value:
        return [], []
    raw = ", ".join(str(v) for v in value) if isinstance(value, list) else str(value)
    valid: list[str] = []
    invalid: list[str] = []
    seen: set[str] = set()
    for part in raw.replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        name, addr = parseaddr(part)
        if not _ADDRESS_RE.match(addr or "") or "\n" in part or "\r" in part:
            invalid.append(part)
            continue
        if addr.lower() in seen:
            continue
        seen.add(addr.lower())
        valid.append(formataddr((name, addr)) if name else addr)
    return valid, invalid


def check_recipients(to: list[str], cc: list[str], invalid: list[str]) -> str | None:
    """Why this recipient list can't be sent to, or None."""
    if invalid:
        return f"Not a valid email address: {', '.join(invalid)}"
    if not to:
        return "No recipients: set 'to'"
    if len(to) + len(cc) > MAX_RECIPIENTS:
        return f"Too many recipients ({len(to) + len(cc)}); the limit is {MAX_RECIPIENTS}"
    return None


def one_line(text: str, limit: int = 250) -> str:
    """A header-safe subject: newlines from an entry title would otherwise be
    refused by the email library (or, elsewhere, inject a header)."""
    return " ".join((text or "").split())[:limit]


async def _counter_redis():
    from app.services.redis_client import get_redis

    return await get_redis()


async def _reserve_send_slot(limit: int) -> bool:
    """Count one message against this clock hour's instance-wide budget.

    Providers throttle or suspend an account that sends in bursts, and one
    broad "on new entry" rule can email per article. The counter lives in
    Redis so every worker shares it. If Redis is down the message goes out:
    losing an alert is worse than one unmetered hour.
    """
    if limit <= 0:
        return True
    key = f"intelfeed:smtp:sent:{datetime.now(UTC):%Y%m%d%H}"
    try:
        r = await _counter_redis()
        count = await r.incr(key)
        if count == 1:
            await r.expire(key, 7200)
        if count > limit:
            await r.decr(key)
            return False
    except Exception as e:
        logger.warning("smtp send counter unavailable, sending unmetered: %s", e)
    return True


async def send_mail(
    cfg: SmtpConfig,
    *,
    to: list[str],
    subject: str,
    text_body: str,
    html_body: str | None = None,
    cc: list[str] | None = None,
) -> None:
    """Send one message. Raises MailError with a readable reason."""
    if cfg.security not in SECURITY_MODES:
        raise MailError(
            f"Connection Security '{cfg.security}' isn't supported; use starttls or tls (Settings > System > Email)"
        )
    if not await _reserve_send_slot(cfg.max_per_hour):
        raise MailError(
            f"Hourly email limit reached ({cfg.max_per_hour} per hour, Settings > System > Email); not sent"
        )
    msg = EmailMessage()
    msg["From"] = cfg.from_address
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Subject"] = one_line(subject) or "IntelFeed"
    domain = (getaddresses([cfg.from_address])[0][1] or "intelfeed.local").rpartition("@")[2]
    msg["Message-ID"] = make_msgid(domain=domain or None)
    msg.set_content(text_body or "")
    if html_body:
        msg.add_alternative(html_body, subtype="html")

    try:
        await aiosmtplib.send(
            msg,
            hostname=cfg.host,
            port=cfg.port,
            username=cfg.username or None,
            password=(cfg.password or None) if cfg.username else None,
            use_tls=cfg.security == "tls",
            start_tls=cfg.security == "starttls",
            timeout=30,
        )
    except aiosmtplib.SMTPAuthenticationError as e:
        raise MailError(f"SMTP login failed: {e.message}") from e
    except aiosmtplib.SMTPRecipientsRefused as e:
        raise MailError(f"The server refused the recipients: {', '.join(r.recipient for r in e.recipients)}") from e
    except aiosmtplib.SMTPException as e:
        raise MailError(f"SMTP error: {e}") from e
    except OSError as e:
        raise MailError(f"Couldn't reach {cfg.host}:{cfg.port}: {e}") from e
