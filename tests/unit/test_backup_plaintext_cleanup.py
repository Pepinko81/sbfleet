"""Backup plaintext cleanup."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from sbfleet.backup import BackupError, BackupLockedResult, _wipe_staging


def test_wipe_staging_refuses_when_docker_wipe_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "secret.tar").write_bytes(b"plaintext")

    class Fake:
        ok = False
        stderr = "permission denied"
        stdout = ""

    monkeypatch.setattr("sbfleet.backup._docker", lambda *a, **k: Fake())
    monkeypatch.setattr(
        "sbfleet.registry.assert_destructive_tree_safe",
        lambda path, under=None: path,
    )
    with pytest.raises(BackupError, match="docker staging wipe failed"):
        _wipe_staging(staging)
    assert (staging / "secret.tar").is_file()


def test_wipe_staging_refuses_when_residual_remains(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "left").write_text("x", encoding="utf-8")

    class Fake:
        ok = True
        stderr = ""
        stdout = ""

    monkeypatch.setattr("sbfleet.backup._docker", lambda *a, **k: Fake())
    monkeypatch.setattr(
        "sbfleet.registry.assert_destructive_tree_safe",
        lambda path, under=None: path,
    )

    def _noop_rmtree(path: Path, *, under: Path | None = None) -> Path:
        # Pretend host delete succeeded without removing.
        return path

    monkeypatch.setattr("sbfleet.registry.safe_rmtree", _noop_rmtree)
    with pytest.raises(BackupError, match="residual plaintext"):
        _wipe_staging(staging)
    assert staging.exists()


def test_wipe_staging_success_removes_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "secret.tar").write_bytes(b"plaintext")

    class Fake:
        ok = True
        stderr = ""
        stdout = ""

    monkeypatch.setattr("sbfleet.backup._docker", lambda *a, **k: Fake())
    monkeypatch.setattr(
        "sbfleet.registry.assert_destructive_tree_safe",
        lambda path, under=None: path,
    )

    def _rm(path: Path, *, under: Path | None = None) -> Path:
        import shutil

        shutil.rmtree(path)
        return path

    monkeypatch.setattr("sbfleet.registry.safe_rmtree", _rm)
    _wipe_staging(staging)
    assert not staging.exists()


def test_backup_locked_result_tracks_cleanup_fields() -> None:
    r = BackupLockedResult(
        backup_id="b",
        archive_path=Path("/tmp/a"),
        receipt={},
        verification="recovery",
        prior_state="STOPPED",
    )
    assert r.cleanup_ok is True
    assert r.cleanup_residuals == []
    r.cleanup_ok = False
    r.cleanup_residuals = ["/tmp/staging"]
    assert r.cleanup_residuals == ["/tmp/staging"]


def test_create_backup_surfaces_cleanup_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ordinary create_backup path distinguishes archive OK from cleanup fail."""
    from sbfleet import backup as bak

    fake = BackupLockedResult(
        backup_id="bid",
        archive_path=tmp_path / "bid.tar.age",
        receipt={"verification": "recovery"},
        verification="recovery",
        prior_state="STOPPED",
        cleanup_ok=False,
        cleanup_residuals=[str(tmp_path / "staging"), "docker staging wipe failed"],
    )
    fake.archive_path.write_bytes(b"age")

    class Ctx:
        operation_id = "op1"
        meta: dict[str, Any] = {"id": "p1"}
        deployment = tmp_path
        compose_project = "cp"
        root = tmp_path
        slug = "s"

    class CM:
        def __enter__(self) -> Ctx:
            return Ctx()

        def __exit__(self, *a: object) -> None:
            return None

    monkeypatch.setattr("sbfleet.authority.authorize_mutation", lambda *a, **k: CM())
    monkeypatch.setattr("sbfleet.authority.begin_operation", lambda *a, **k: None)
    monkeypatch.setattr("sbfleet.authority.complete_operation", lambda *a, **k: None)
    monkeypatch.setattr("sbfleet.authority.fail_operation", lambda *a, **k: None)
    monkeypatch.setattr(bak, "_create_backup_locked", lambda *a, **k: fake)
    monkeypatch.setattr(bak, "_resolve_identity", lambda *a, **k: tmp_path / "id")
    monkeypatch.setattr(bak, "_require_age", lambda: "age")
    monkeypatch.setattr(bak, "_fleet_recipients", lambda root: ["r"])
    (tmp_path / "id").write_text("AGE-SECRET-KEY-1", encoding="utf-8")

    code = bak.create_backup(tmp_path, "s", verify=True, identity=str(tmp_path / "id"))
    assert code != 0
    assert fake.archive_path.is_file()
