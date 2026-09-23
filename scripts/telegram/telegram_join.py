"""Join a private Telegram channel from an invite link / hash.

Public channels can be added directly via @username. Private channels require
the IntelFeed Telegram account to first join via an invite link, after which
adapter_config.channel can reference the channel by id or @username (if any).

Usage:

    docker compose -f docker-compose.dev.yml exec -it api \\
      python scripts/telegram/telegram_join.py "https://t.me/+abcdef1234567890"

    docker compose -f docker-compose.dev.yml exec -it api \\
      python scripts/telegram/telegram_join.py --session osint "https://t.me/+xyz"

The script is idempotent — if the account is already a member, it prints the
resolved channel id and exits 0. If the invite has expired or been revoked,
it exits non-zero with the Telegram error.
"""

import argparse
import asyncio
import os
import sys

sys.path.insert(0, "/app")
sys.path.insert(0, "backend")

from app.config import settings


def _session_path_for(session_name: str | None) -> str:
    if not session_name:
        return settings.telegram_session_path
    safe = "".join(c for c in session_name if c.isalnum() or c in "_-")
    if not safe or safe != session_name:
        raise SystemExit(f"ERROR: invalid session name {session_name!r}")
    base_dir = os.path.dirname(settings.telegram_session_path)
    return os.path.join(base_dir, f"{safe}.session")


def _extract_invite_hash(invite: str) -> str:
    """Extract the invite hash from a t.me/+HASH or t.me/joinchat/HASH URL, or accept a bare hash."""
    s = invite.strip()
    for prefix in ("https://t.me/+", "http://t.me/+", "t.me/+", "https://t.me/joinchat/", "t.me/joinchat/"):
        if s.startswith(prefix):
            return s[len(prefix) :].rstrip("/")
    return s


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("invite", help="Telegram invite link (https://t.me/+HASH) or raw hash")
    parser.add_argument(
        "--session",
        default="",
        help="Optional named session (must match a previously bootstrapped one).",
    )
    args = parser.parse_args()

    if not settings.telegram_api_id or not settings.telegram_api_hash:
        print("ERROR: TELEGRAM_API_ID and TELEGRAM_API_HASH must be set.")
        return 1

    try:
        from telethon import TelegramClient
        from telethon import errors as tg_errors
        from telethon.tl.functions.messages import (
            CheckChatInviteRequest,
            ImportChatInviteRequest,
        )
    except ImportError:
        print("ERROR: telethon is not installed. Did you rebuild the api image?")
        return 1

    invite_hash = _extract_invite_hash(args.invite)
    if not invite_hash:
        print(f"ERROR: could not parse invite '{args.invite}'")
        return 1

    session_path = _session_path_for(args.session)
    if not os.path.exists(session_path):
        print(
            f"ERROR: session file {session_path} does not exist. "
            f"Run scripts/telegram/telegram_login.py{f' --session {args.session}' if args.session else ''} first."
        )
        return 1

    client = TelegramClient(session_path, settings.telegram_api_id, settings.telegram_api_hash)
    await client.connect()

    if not await client.is_user_authorized():
        print(f"ERROR: session at {session_path} is not authorized. Re-run telegram_login.py.")
        return 1

    # Probe the invite first — surfaces "expired", "revoked", or "you're already a member"
    try:
        info = await client(CheckChatInviteRequest(invite_hash))
    except tg_errors.InviteHashExpiredError:
        print("ERROR: invite link has expired.")
        return 1
    except tg_errors.InviteHashInvalidError:
        print("ERROR: invite link is invalid or revoked.")
        return 1
    except tg_errors.InviteHashEmptyError:
        print("ERROR: invite hash is empty.")
        return 1

    # ChatInviteAlready means we're a member already; ChatInvite is a join-required preview.
    chat = getattr(info, "chat", None)
    if chat is not None:
        chat_id = getattr(chat, "id", None)
        title = getattr(chat, "title", "(unknown)")
        username = getattr(chat, "username", None)
        print(f"Already a member of: {title} (id {chat_id}{', @' + username if username else ''})")
        print("Use this in adapter_config:")
        print(f'    {{"channel": {chat_id!r}}}')
        return 0

    # Not a member yet — perform the join
    try:
        result = await client(ImportChatInviteRequest(invite_hash))
    except tg_errors.UserAlreadyParticipantError:
        print("Already a participant (race-condition path). Try again to read the channel info.")
        return 0
    except tg_errors.FloodWaitError as e:
        print(f"ERROR: Telegram flood wait {e.seconds}s. Wait and retry.")
        return 1

    chat = result.chats[0] if result.chats else None
    if chat is None:
        print("Joined, but no chat info returned. Inspect telegram client.")
        return 0

    chat_id = getattr(chat, "id", None)
    title = getattr(chat, "title", "(unknown)")
    username = getattr(chat, "username", None)
    print(f"Joined channel: {title} (id {chat_id}{', @' + username if username else ''})")
    print("")
    print("Add to IntelFeed via the API or UI with adapter_config:")
    print(f'    {{"channel": {chat_id!r}}}')
    if username:
        print(f'  or alternatively: {{"channel": "@{username}"}}')
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
