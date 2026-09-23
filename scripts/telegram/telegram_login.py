"""Bootstrap a Telegram session for IntelFeed channel ingestion.

Run once per IntelFeed instance, interactively. The -it flags are critical
because Telethon prompts for the phone number, the SMS code Telegram sends,
and (if enabled) a 2FA password on stdin:

    docker compose -f docker-compose.dev.yml exec -it api python scripts/telegram/telegram_login.py
    docker compose -f docker-compose.prod.yml exec -it api python scripts/telegram/telegram_login.py

For multi-session deployments (one identity for OSINT, one for darker channels),
pass --session NAME and reference the same name in adapter_config.session_name:

    docker compose -f docker-compose.dev.yml exec -it api python scripts/telegram/telegram_login.py --session osint

The resulting session file is a credential equivalent to the account password.
Anyone who has it can read every joined channel, post messages, and harvest
the contact list. Restrict file permissions and back it up to encrypted storage.
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
    if not safe:
        raise SystemExit(f"ERROR: invalid session name {session_name!r}")
    base_dir = os.path.dirname(settings.telegram_session_path)
    return os.path.join(base_dir, f"{safe}.session")


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--session",
        default="",
        help="Optional named session (alphanumeric, _, -). Default uses TELEGRAM_SESSION_PATH.",
    )
    args = parser.parse_args()

    api_id = settings.telegram_api_id
    api_hash = settings.telegram_api_hash
    session_path = _session_path_for(args.session)

    if not api_id or not api_hash:
        print("ERROR: TELEGRAM_API_ID and TELEGRAM_API_HASH must be set.")
        print("Get them from https://my.telegram.org -> API development tools.")
        print("Then set them in .env and restart the api+celery-worker services.")
        return 1

    try:
        from telethon import TelegramClient
    except ImportError:
        print("ERROR: telethon is not installed. Did you rebuild the api image?")
        print("Run: docker compose -f docker-compose.dev.yml build api celery-worker")
        return 1

    session_dir = os.path.dirname(session_path)
    if session_dir and not os.path.isdir(session_dir):
        print(
            f"ERROR: session directory {session_dir} does not exist. "
            "Did you mount the telegram_data volume on the api container?"
        )
        return 1

    client = TelegramClient(session_path, api_id, api_hash)
    await client.connect()

    if await client.is_user_authorized():
        me = await client.get_me()
        username = f"@{me.username}" if me.username else "(no username)"
        full_name = " ".join(p for p in [me.first_name, me.last_name] if p) or "(no name)"
        print(f"Already logged in as {full_name} {username}, id {me.id}")
        print(f"Session: {session_path}")
        return 0

    print("Starting interactive Telegram login.")
    print("You will be prompted for your phone number, the SMS code, and (if enabled) your 2FA password.")
    print("")

    await client.start()

    me = await client.get_me()
    username = f"@{me.username}" if me.username else "(no username)"
    full_name = " ".join(p for p in [me.first_name, me.last_name] if p) or "(no name)"

    size = os.path.getsize(session_path) if os.path.exists(session_path) else 0
    print("")
    print(f"Logged in as {full_name} {username}, id {me.id}")
    print(f"Session written to: {session_path} ({size} bytes)")
    print("")
    print("WARNING: this session file is a credential equivalent to your Telegram password.")
    print("- Anyone with this file can read every joined channel and post as you.")
    print("- Restrict file permissions (chmod 600) and back it up to encrypted storage only.")
    print("- Do not commit it to git.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
