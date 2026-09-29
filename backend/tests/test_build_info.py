from pathlib import Path

from app.core.build_info import _sha_from_git_dir


def _write_git_dir(root: Path, head: str, **files: str) -> Path:
    git_dir = root / ".git"
    (git_dir / "refs" / "heads").mkdir(parents=True)
    (git_dir / "HEAD").write_text(head)
    for name, body in files.items():
        (git_dir / name.replace("__", "/")).write_text(body)
    return git_dir


def test_reads_loose_ref(tmp_path: Path):
    """The ordinary case: a checked-out branch with a loose ref file."""
    git_dir = _write_git_dir(
        tmp_path,
        "ref: refs/heads/main\n",
        refs__heads__main="c684f224abcdef0123456789abcdef0123456789\n",
    )
    assert _sha_from_git_dir(git_dir) == "c684f224"


def test_reads_packed_ref(tmp_path: Path):
    """A fresh clone keeps its branch in packed-refs, with no loose ref."""
    git_dir = _write_git_dir(
        tmp_path,
        "ref: refs/heads/main\n",
        **{
            "packed-refs": (
                "# pack-refs with: peeled fully-peeled sorted \n"
                "aaaaaaaa11111111111111111111111111111111 refs/heads/other\n"
                "c684f224abcdef0123456789abcdef0123456789 refs/heads/main\n"
            )
        },
    )
    assert _sha_from_git_dir(git_dir) == "c684f224"


def test_reads_detached_head(tmp_path: Path):
    """A detached HEAD holds the SHA directly instead of a ref."""
    git_dir = _write_git_dir(tmp_path, "c684f224abcdef0123456789abcdef0123456789\n")
    assert _sha_from_git_dir(git_dir) == "c684f224"


def test_missing_git_dir_is_not_an_error(tmp_path: Path):
    """No mount (the production image) must fall through, never raise."""
    assert _sha_from_git_dir(tmp_path / "nope" / ".git") == ""
