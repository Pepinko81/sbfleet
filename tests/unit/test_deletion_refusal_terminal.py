"""Deletion refusal terminal."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

from sbfleet import registry as reg
from sbfleet.backup import BackupError, _wipe_staging
from sbfleet.update import _wipe_update_staging
from sbfleet.upstream import materialize_cache


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    return reg.ensure_root(tmp_path / "home")


def test_safe_rmtree_refuses_descendant_mount_no_delete(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    under = home / "cache"
    under.mkdir(parents=True, exist_ok=True)
    target = under / "deadbeef"
    target.mkdir()
    sentinel = target / "sentinel.txt"
    sentinel.write_text("KEEP-ME", encoding="utf-8")
    nested = target / "nested"
    nested.mkdir()
    mounts = {
        under.resolve(strict=False),
        nested.resolve(strict=False),
        Path("/").resolve(strict=False),
    }
    monkeypatch.setattr(reg, "_mountinfo_points", lambda: mounts)
    rmtree = mock.Mock()
    monkeypatch.setattr("sbfleet.registry.shutil.rmtree", rmtree)
    with pytest.raises(reg.OwnershipError, match="nested mountpoint"):
        reg.safe_rmtree(target, under=under)
    rmtree.assert_not_called()
    assert sentinel.read_text(encoding="utf-8") == "KEEP-ME"


def test_safe_rmtree_refuses_unreadable_mountinfo(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    under = home / "cache"
    target = under / "x"
    target.mkdir(parents=True)
    sentinel = target / "s.txt"
    sentinel.write_bytes(b"SENT")
    monkeypatch.setattr(reg, "_mountinfo_points", lambda: None)
    rmtree = mock.Mock()
    monkeypatch.setattr("sbfleet.registry.shutil.rmtree", rmtree)
    with pytest.raises(reg.OwnershipError, match="mountpoint authority"):
        reg.safe_rmtree(target, under=under)
    rmtree.assert_not_called()
    assert sentinel.read_bytes() == b"SENT"


def test_mountinfo_malformed_missing_separator(monkeypatch: pytest.MonkeyPatch) -> None:
    original = Path.read_text

    def patched(self: Path, *args, **kwargs):  # noqa: ANN001
        if str(self) == "/proc/self/mountinfo":
            # Enough tokens but no "-" separator → refuse whole table.
            return "1 0 8:1 / /good rw,relatime shared:1 ext4 /dev/sda1 rw\n"
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", patched)
    assert reg._mountinfo_points() is None


def test_mountinfo_malformed_short_line(monkeypatch: pytest.MonkeyPatch) -> None:
    original = Path.read_text

    def patched(self: Path, *args, **kwargs):  # noqa: ANN001
        if str(self) == "/proc/self/mountinfo":
            return "1 0 0:0 / /good rw - ext4 /dev/sda1 rw\nmalformed\n"
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", patched)
    assert reg._mountinfo_points() is None


def test_wipe_update_staging_no_fallback_rmtree(
    home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    staging = tmp_path / "update-staging"
    staging.mkdir()
    sentinel = staging / "sentinel.bin"
    sentinel.write_bytes(b"UPDATE-SENTINEL")
    monkeypatch.setattr(
        "sbfleet.backup._wipe_staging",
        mock.Mock(side_effect=BackupError("descendant mount", code=5)),
    )
    rmtree = mock.Mock()
    monkeypatch.setattr("shutil.rmtree", rmtree)
    monkeypatch.setattr("sbfleet.update.shutil.rmtree", rmtree)
    with pytest.raises(BackupError, match="descendant mount"):
        _wipe_update_staging(staging)
    rmtree.assert_not_called()
    assert sentinel.read_bytes() == b"UPDATE-SENTINEL"


def test_wipe_staging_refuses_descendant_mount_no_docker_no_host(
    home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    staging = tmp_path / "backup-staging"
    staging.mkdir()
    (staging / "plain.tar").write_bytes(b"PLAINTEXT")
    nested = staging / "mnt"
    nested.mkdir()
    mounts = {
        staging.parent.resolve(strict=False),
        nested.resolve(strict=False),
        Path("/").resolve(strict=False),
    }
    monkeypatch.setattr(reg, "_mountinfo_points", lambda: mounts)
    docker = mock.Mock()
    monkeypatch.setattr("sbfleet.backup._docker", docker)
    rmtree = mock.Mock()
    monkeypatch.setattr("sbfleet.registry.shutil.rmtree", rmtree)
    with pytest.raises(BackupError, match="nested mountpoint|mount"):
        _wipe_staging(staging)
    docker.assert_not_called()
    rmtree.assert_not_called()
    assert (staging / "plain.tar").read_bytes() == b"PLAINTEXT"


def test_materialize_cache_corrupt_replace_refuses_descendant_mount(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sbfleet import upstream as up

    sha = up.PINNED_SHA
    dest = up.cache_dir(home, sha)
    dest.mkdir(parents=True)
    sentinel = dest / "sentinel.txt"
    sentinel.write_text("CACHE-SENTINEL", encoding="utf-8")
    (dest / "docker").mkdir()
    nested = dest / "evil-mnt"
    nested.mkdir()

    def refuse_verify(cache: Path, *, sha: str = "") -> None:  # noqa: ARG001
        raise up.UpstreamError("corrupt")

    monkeypatch.setattr(up, "verify_cache", refuse_verify)
    mounts = {
        dest.parent.resolve(strict=False),
        nested.resolve(strict=False),
        Path("/").resolve(strict=False),
    }
    monkeypatch.setattr(reg, "_mountinfo_points", lambda: mounts)
    rmtree = mock.Mock()
    monkeypatch.setattr("sbfleet.registry.shutil.rmtree", rmtree)
    monkeypatch.setattr("shutil.rmtree", rmtree)
    with pytest.raises(up.UpstreamError, match="mount authority|refusing to replace"):
        materialize_cache(home, force=False)
    rmtree.assert_not_called()
    assert sentinel.read_text(encoding="utf-8") == "CACHE-SENTINEL"


def test_projects_staging_cleanup_refuses_descendant_mount(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staging_root = home / "staging"
    staging_root.mkdir(parents=True, exist_ok=True)
    staging = staging_root / "create-staging"
    staging.mkdir()
    sentinel = staging / "keep.txt"
    sentinel.write_text("CREATE-STAGING", encoding="utf-8")
    nested = staging / "mnt"
    nested.mkdir()
    mounts = {
        staging_root.resolve(strict=False),
        nested.resolve(strict=False),
        Path("/").resolve(strict=False),
    }
    monkeypatch.setattr(reg, "_mountinfo_points", lambda: mounts)
    rmtree = mock.Mock()
    monkeypatch.setattr("sbfleet.registry.shutil.rmtree", rmtree)
    with pytest.raises(reg.OwnershipError, match="nested mountpoint"):
        reg.safe_rmtree(staging, under=staging_root)
    rmtree.assert_not_called()
    assert sentinel.read_text(encoding="utf-8") == "CREATE-STAGING"
