"""Admin-only endpoints for reading application log files."""

import os
from collections import deque
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Path, Query
from fastapi.responses import PlainTextResponse

from app.core.logging import LOG_DIR
from app.core.security import get_admin_user
from app.models.user import User

router = APIRouter()

# Only these filenames can be served — no path traversal possible.
ALLOWED_LOG_FILES = {
    "app.log",
    "error.log",
    "http.log",
    "tasks.log",
    "audit.log",
    "update.log",
}


@router.get("/logs")
async def list_logs(_user: User = Depends(get_admin_user)):
    """Return metadata for each available log file."""
    files = []
    for name in sorted(ALLOWED_LOG_FILES):
        path = os.path.join(LOG_DIR, name)
        if os.path.isfile(path):
            stat = os.stat(path)
            files.append(
                {
                    "name": name,
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat(),
                }
            )
    return {"files": files}


@router.get("/logs/{filename}")
async def read_log(
    filename: str = Path(
        ..., description="Log file name; one of app.log, error.log, http.log, tasks.log, audit.log, update.log"
    ),
    lines: int = Query(default=500, ge=1, le=10000, description="Number of trailing lines to return"),
    _user: User = Depends(get_admin_user),
):
    """Return the last *lines* lines of a log file as plain text."""
    if filename not in ALLOWED_LOG_FILES:
        return PlainTextResponse("Not found", status_code=404)

    path = os.path.join(LOG_DIR, filename)
    if not os.path.isfile(path):
        return PlainTextResponse("", status_code=200)

    tail = _tail_file(path, lines)
    return PlainTextResponse(tail)


@router.delete("/logs/{filename}")
async def clear_log(
    filename: str = Path(..., description="Log file name to truncate; must be one of the allowed log files"),
    _user: User = Depends(get_admin_user),
):
    """Truncate a log file."""
    if filename not in ALLOWED_LOG_FILES:
        return PlainTextResponse("Not found", status_code=404)

    path = os.path.join(LOG_DIR, filename)
    if os.path.isfile(path):
        open(path, "w").close()

    return {"status": "cleared"}


def _tail_file(path: str, n: int) -> str:
    """Read the last *n* lines from a file efficiently."""
    try:
        with open(path, "rb") as f:
            # For small files, just read everything
            f.seek(0, 2)
            size = f.tell()
            if size == 0:
                return ""
            if size <= 1_048_576:  # ≤1 MB — read whole file
                f.seek(0)
                all_lines = f.read().decode("utf-8", errors="replace").splitlines()
                lines = all_lines[-n:]
            else:
                # For larger files, seek backwards in chunks
                buf = b""
                chunk = min(size, 65_536)
                pos = size
                result: deque[str] = deque(maxlen=n)
                while pos > 0 and len(result) < n:
                    pos = max(pos - chunk, 0)
                    f.seek(pos)
                    buf = f.read(min(chunk, size - pos)) + buf
                    lines_found = buf.decode("utf-8", errors="replace").splitlines()
                    result = deque(lines_found[-n:], maxlen=n)
                    buf = b""
                lines = list(result)

            # Drop trailing incomplete JSON line — multiple processes write to
            # the same log files, so a read can catch a line mid-write.
            if lines:
                last = lines[-1].strip()
                if last.startswith("{") and not last.endswith("}"):
                    lines.pop()

            return "\n".join(lines)
    except OSError:
        return ""
