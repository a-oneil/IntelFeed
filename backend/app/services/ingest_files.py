"""On-disk store for the original bytes behind a manual upload.

Modeled on the Telegram media directory: a bind-mount shared by the api (which
writes uploads and serves downloads) and celery-worker (which parses them and
runs the TTL eviction). Paths are ``<batch_id>/<file_id>.<ext>`` under
``settings.ingest_files_dir``; nothing from the client's filename reaches the
filesystem except a vetted extension.
"""

import logging
import os
import re
import uuid
from pathlib import Path

from app.config import settings

logger = logging.getLogger(__name__)

_EXT_RE = re.compile(r"\.([A-Za-z0-9]{1,8})$")


def files_root() -> Path:
    return Path(settings.ingest_files_dir)


def safe_extension(filename: str | None) -> str:
    """The filename's extension if it is plain alphanumerics, else ``bin``."""
    if not filename:
        return "bin"
    match = _EXT_RE.search(filename.strip())
    return match.group(1).lower() if match else "bin"


def relative_path(batch_id: uuid.UUID, file_id: uuid.UUID, filename: str | None) -> str:
    return f"{batch_id}/{file_id}.{safe_extension(filename)}"


def absolute_path(rel_path: str) -> Path | None:
    """Resolve a stored path under the root, or None if it would escape it."""
    base = files_root().resolve()
    target = (base / rel_path).resolve()
    try:
        target.relative_to(base)
    except ValueError:
        return None
    return target


def write_bytes(rel_path: str, data: bytes) -> Path:
    target = absolute_path(rel_path)
    if target is None:
        raise ValueError(f"refusing to write outside the ingest files root: {rel_path}")
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".part")
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, target)
    return target


def read_bytes(rel_path: str) -> bytes:
    target = absolute_path(rel_path)
    if target is None or not target.is_file():
        raise FileNotFoundError(rel_path)
    return target.read_bytes()


def remove(rel_path: str) -> bool:
    """Delete one stored file; True if something was removed. Prunes an empty batch dir."""
    target = absolute_path(rel_path)
    if target is None:
        return False
    removed = False
    try:
        target.unlink()
        removed = True
    except FileNotFoundError:
        pass
    except OSError:
        logger.warning("Could not remove ingest file %s", rel_path, exc_info=True)
    try:
        if target.parent != files_root().resolve() and not any(target.parent.iterdir()):
            target.parent.rmdir()
    except OSError:
        pass
    return removed


def max_file_bytes() -> int:
    """Per-file cap from the ``ingest_max_file_mb`` setting (DB override, then env)."""
    try:
        mb = int(settings.get("ingest_max_file_mb") or 50)
    except (TypeError, ValueError):
        mb = 50
    return max(1, mb) * 1024 * 1024


def max_batch_items() -> int:
    try:
        return max(1, int(settings.get("ingest_max_batch_items") or 200))
    except (TypeError, ValueError):
        return 200


def zip_max_members() -> int:
    try:
        return max(1, int(settings.get("ingest_zip_max_members") or 100))
    except (TypeError, ValueError):
        return 100
