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


def test_env_stamp_wins_over_a_mounted_checkout(monkeypatch):
    """A stamped image reports its build, not whatever .git happens to say."""
    from app.core import build_info

    build_info._env_stamp.cache_clear()
    monkeypatch.setattr(build_info.settings, "app_version", "v1.2.3")
    monkeypatch.setattr(build_info.settings, "git_sha", "abcd1234")
    monkeypatch.setattr(build_info, "_sha_from_git_dir", lambda _: "ffffffff", raising=True)
    try:
        assert build_info.build_stamp()["git_sha"] == "abcd1234"
    finally:
        build_info._env_stamp.cache_clear()


def test_unstamped_build_rereads_the_checkout(monkeypatch):
    """The .git half is not cached, so dev tracks commits without a restart."""
    from app.core import build_info

    build_info._env_stamp.cache_clear()
    monkeypatch.setattr(build_info.settings, "app_version", "dev")
    monkeypatch.setattr(build_info.settings, "git_sha", "")
    seen = iter(["11111111", "22222222"])
    monkeypatch.setattr(build_info, "_sha_from_git_dir", lambda _: next(seen), raising=True)
    try:
        assert build_info.build_stamp()["version"] == "11111111"
        # Second call after a commit must reflect the new HEAD, not the first.
        assert build_info.build_stamp()["version"] == "22222222"
    finally:
        build_info._env_stamp.cache_clear()
