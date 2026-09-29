"""What commit the running code came from.

Three sources, in descending order of precision, mirroring the frontend's
`buildStamp()` in vite.config.ts:

1. The ``APP_VERSION`` / ``GIT_SHA`` / ``BUILD_TIME`` env vars, baked into the
   image by ``scripts/ops/version.sh`` via compose build args. This is the
   production answer and the only one that can carry a tag.
2. ``.git`` bind-mounted at ``/app/.git`` (the dev stack does this), read by
   hand. The dev image is stamped once at build time but serves volume-mounted
   code, so the baked value goes stale on the first edit; the checkout does not.
3. Nothing — report "dev".
"""

from functools import lru_cache
from pathlib import Path

from app.config import settings

# Both compose files default the build arg to this, so a stamp of "dev" means
# "unstamped" rather than a real version. Fall through to the next source.
_UNSTAMPED = {"", "dev"}


def _sha_from_git_dir(git_dir: Path) -> str:
    """HEAD's short SHA read straight out of a .git directory, no git binary."""
    try:
        head = (git_dir / "HEAD").read_text().strip()
        # Detached HEAD stores the SHA itself rather than a ref.
        if not head.startswith("ref: "):
            return head[:8]
        ref = head[5:].strip()
        loose = git_dir / ref
        if loose.exists():
            return loose.read_text().strip()[:8]
        # A fresh clone has no loose ref for its branch — it lives in packed-refs.
        for line in (git_dir / "packed-refs").read_text().splitlines():
            if line.endswith(f" {ref}"):
                return line[:8]
        return ""
    except OSError:
        return ""


@lru_cache(maxsize=1)
def build_stamp() -> dict:
    """Version, commit and build time of this container. Cached — it cannot change."""
    version = settings.app_version if settings.app_version not in _UNSTAMPED else ""
    sha = settings.git_sha if settings.git_sha not in _UNSTAMPED else ""

    if not version or not sha:
        mounted = _sha_from_git_dir(Path("/app/.git"))
        version = version or mounted
        sha = sha or mounted

    return {
        "version": version or "dev",
        "git_sha": sha or None,
        "built_at": settings.build_time or None,
    }
