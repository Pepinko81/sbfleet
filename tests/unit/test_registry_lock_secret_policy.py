"""Registry lock secret policy."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from sbfleet import registry as reg


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    return reg.ensure_root(tmp_path / "home")


def test_lock_refuses_hardlink_sentinel_byte_identical(home: Path, tmp_path: Path) -> None:
    sentinel = tmp_path / "sentinel.txt"
    payload = b"DO-NOT-TRUNCATE-THIS-SENTINEL\n"
    sentinel.write_bytes(payload)
    os.chmod(sentinel, 0o600)
    lock_path = home / "locks" / "hardlink.lock"
    os.link(sentinel, lock_path)
    before = sentinel.read_bytes()
    with pytest.raises(reg.OwnershipError, match="hardlinked"):
        with reg.FileLock(lock_path, timeout=0.5):
            pass
    assert sentinel.read_bytes() == before
    assert lock_path.read_bytes() == before


def test_assert_secret_file_refuses_hardlink_symlink_mode(home: Path, tmp_path: Path) -> None:
    good = home / "projects" / "a" / "deployment"
    good.mkdir(parents=True)
    env = good / ".env"
    env.write_text("X=1\n", encoding="utf-8")
    os.chmod(env, 0o600)
    reg.assert_secret_file(env)

    loose = good / "loose.env"
    loose.write_text("X=1\n", encoding="utf-8")
    os.chmod(loose, 0o644)
    with pytest.raises(reg.OwnershipError, match="0600"):
        reg.assert_secret_file(loose)

    link = good / "link.env"
    link.symlink_to(env)
    with pytest.raises(reg.OwnershipError, match="symlink"):
        reg.assert_secret_file(link)

    other = tmp_path / "other.env"
    other.write_text("X=1\n", encoding="utf-8")
    os.chmod(other, 0o600)
    hl = good / "hl.env"
    os.link(other, hl)
    with pytest.raises(reg.OwnershipError, match="hardlinked"):
        reg.assert_secret_file(hl)


def test_assert_secret_file_refuses_directory(home: Path) -> None:
    d = home / "projects" / "a"
    d.mkdir(parents=True)
    with pytest.raises(reg.OwnershipError, match="regular file"):
        reg.assert_secret_file(d)


def test_destructive_tree_refuses_descendant_mount(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    under = home / "projects" / "alpha" / "deployment"
    volumes = under / "volumes"
    nested = volumes / "db" / "data"
    nested.mkdir(parents=True)
    mounts = {
        under.resolve(strict=False),
        nested.resolve(strict=False),
    }
    monkeypatch.setattr(reg, "_mountinfo_points", lambda: mounts)
    with pytest.raises(reg.OwnershipError, match="nested mountpoint"):
        reg.assert_destructive_tree_safe(volumes, under=under)


def test_destructive_tree_fail_closed_unreadable_mountinfo(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    under = home / "projects" / "alpha"
    target = under / "volumes"
    target.mkdir(parents=True)
    monkeypatch.setattr(reg, "_mountinfo_points", lambda: None)
    with pytest.raises(reg.OwnershipError, match="mountpoint authority"):
        reg.assert_destructive_tree_safe(target, under=under)


def test_mountinfo_parser_malformed_line(monkeypatch: pytest.MonkeyPatch) -> None:
    original = Path.read_text

    def patched(self: Path, *args, **kwargs):  # noqa: ANN001
        if str(self) == "/proc/self/mountinfo":
            return "1 0 0:0 / /good rw - ext4 /dev/sda1 rw\nmalformed\n"
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", patched)
    assert reg._mountinfo_points() is None


def test_destructive_tree_allows_clean_tree(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    under = home / "projects" / "alpha" / "deployment"
    volumes = under / "volumes" / "db" / "data"
    volumes.mkdir(parents=True)
    monkeypatch.setattr(
        reg,
        "_mountinfo_points",
        lambda: {under.resolve(strict=False), Path("/").resolve(strict=False)},
    )
    got = reg.assert_destructive_tree_safe(under / "volumes", under=under)
    assert got == (under / "volumes").resolve(strict=False)


def test_assert_secret_file_does_not_chmod(home: Path) -> None:
    p = home / "projects" / "a" / "deployment"
    p.mkdir(parents=True)
    f = p / ".env"
    f.write_text("X=1\n", encoding="utf-8")
    os.chmod(f, 0o644)
    mode_before = f.stat().st_mode
    with pytest.raises(reg.OwnershipError):
        reg.assert_secret_file(f)
    assert f.stat().st_mode == mode_before
    assert stat.S_IMODE(f.stat().st_mode) == 0o644
