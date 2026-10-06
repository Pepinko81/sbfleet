"""Capacity unknown fail closed."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from sbfleet import backup as bak


def test_dir_size_chmod_000_is_unknown_not_zero(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    secret = root / "secret"
    secret.mkdir(parents=True)
    (secret / "f").write_bytes(b"x" * 100)
    os.chmod(secret, 0)
    try:
        assert bak._dir_size_bytes(root) is None
    finally:
        os.chmod(secret, 0o700)


def test_dir_size_file_stat_error_is_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    f = root / "x"
    f.write_bytes(b"data")
    real_is_file = Path.is_file
    real_stat = Path.stat

    def is_file(self: Path, *a: object, **k: object) -> bool:  # noqa: ANN001
        if self.name == "x":
            return True
        return bool(real_is_file(self, *a, **k))

    def stat(self: Path, *a: object, **k: object):  # noqa: ANN001
        if self.name == "x":
            raise PermissionError("denied")
        return real_stat(self, *a, **k)

    monkeypatch.setattr(Path, "is_symlink", lambda self, *a, **k: False)
    monkeypatch.setattr(Path, "is_file", is_file)
    monkeypatch.setattr(Path, "stat", stat)
    assert bak._dir_size_bytes(root) is None


def test_disk_preflight_sums_same_filesystem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    dep = root / "proj" / "deployment"
    (dep / "volumes" / "db" / "data").mkdir(parents=True)
    (dep / "volumes" / "storage").mkdir(parents=True)
    (dep / "volumes" / "db" / "data" / "a").write_bytes(b"a" * 50)
    (dep / "volumes" / "storage" / "b").write_bytes(b"b" * 50)
    # source=100; staging+extract+output+verifier each 100 + reserve 1 => need 401 on same FS
    monkeypatch.setattr(bak, "_docker_root_dir", lambda: root)
    monkeypatch.setattr(bak, "_disk_free_bytes", lambda p: 350)
    with pytest.raises(bak.BackupError, match="insufficient disk"):
        bak.disk_preflight(root, dep, reserve_bytes=1)


def test_disk_preflight_separate_docker_fs_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    docker_fs = tmp_path / "docker-root"
    docker_fs.mkdir()
    dep = root / "proj" / "deployment"
    (dep / "volumes" / "db" / "data").mkdir(parents=True)
    (dep / "volumes" / "storage").mkdir(parents=True)
    (dep / "volumes" / "db" / "data" / "a").write_bytes(b"a" * 50)
    (dep / "volumes" / "storage" / "b").write_bytes(b"b" * 50)
    monkeypatch.setattr(bak, "_docker_root_dir", lambda: docker_fs)

    def ident(p: Path) -> str | None:
        try:
            resolved = p.resolve()
        except OSError:
            return None
        if docker_fs.resolve() in resolved.parents or resolved == docker_fs.resolve():
            return "dev:docker"
        return "dev:host"

    monkeypatch.setattr(bak, "_fs_identity", ident)

    def free(p: Path) -> int | None:
        try:
            resolved = p.resolve()
        except OSError:
            return None
        if docker_fs.resolve() in resolved.parents or resolved == docker_fs.resolve():
            return 10
        return 10 * 1024**3

    monkeypatch.setattr(bak, "_disk_free_bytes", free)
    with pytest.raises(bak.BackupError, match="insufficient disk"):
        bak.disk_preflight(root, dep, reserve_bytes=1)


def test_disk_preflight_unknown_docker_root_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    dep = root / "proj" / "deployment"
    (dep / "volumes" / "db" / "data").mkdir(parents=True)
    (dep / "volumes" / "storage").mkdir(parents=True)
    monkeypatch.setattr(bak, "_measure_tree_bytes", lambda p: 10)
    monkeypatch.setattr(bak, "_docker_root_dir", lambda: None)
    with pytest.raises(bak.BackupError, match="DockerRootDir UNKNOWN"):
        bak.disk_preflight(root, dep, reserve_bytes=1)
