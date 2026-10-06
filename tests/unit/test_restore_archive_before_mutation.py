"""Restore archive before mutation."""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any

import pytest

from sbfleet import backup as bak
from sbfleet.backup_recovery import RecoveryVerificationResult
from sbfleet.cli import EXIT_BACKUP


def test_restore_calls_requested_verifier_before_pre_restore_and_quiesce() -> None:
    """Production restore_backup must recovery-verify requested extract before mutation."""
    src = inspect.getsource(bak.restore_backup)
    idx_verify = src.find("run_disposable_recovery_verification")
    idx_pre = src.find("creating_pre_restore_backup")
    idx_stop = src.find("stopping_target")
    idx_quar = src.find("quarantining_current")
    assert idx_verify != -1
    assert idx_verify < idx_pre < idx_stop < idx_quar
    assert "before target mutation" in src


def test_restore_refuses_unrecoverable_archive_without_quiesce(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Canonical extract present, verifier fails → zero target quiesce/quarantine."""
    root = tmp_path / "fleet"
    root.mkdir()
    (root / "backups").mkdir()
    archive = root / "bad.tar.age"
    archive.write_bytes(b"ciphertext")
    identity = root / "id"
    identity.write_text("AGE-SECRET-KEY-1\n", encoding="utf-8")
    deployment = root / "dep"
    deployment.mkdir()
    sentinel = deployment / "volumes" / "db" / "data" / "PG_VERSION"
    sentinel.parent.mkdir(parents=True)
    sentinel.write_text("15\n", encoding="utf-8")
    before = sentinel.read_bytes()

    calls: list[str] = []

    class Ctx:
        pass

    ctx = Ctx()
    ctx.operation_id = "op-restore"  # type: ignore[attr-defined]
    ctx.meta = {  # type: ignore[attr-defined]
        "id": "proj-1",
        "fleet_id": "fleet-1",
        "compose_project": "cp1",
        "upstream": {"ref": "r", "sha": "a" * 40},
    }
    ctx.compose_project = "cp1"  # type: ignore[attr-defined]
    ctx.slug = "s1"  # type: ignore[attr-defined]
    ctx.compose_env = {}  # type: ignore[attr-defined]
    ctx.root = root  # type: ignore[attr-defined]
    ctx.deployment = deployment  # type: ignore[attr-defined]

    class CM:
        def __enter__(self) -> Ctx:
            return ctx

        def __exit__(self, *a: object) -> None:
            return None

    monkeypatch.setattr("sbfleet.authority.authorize_mutation", lambda *a, **k: CM())
    monkeypatch.setattr("sbfleet.authority.begin_operation", lambda *a, **k: None)
    monkeypatch.setattr("sbfleet.authority.record_operation_phase", lambda *a, **k: None)
    monkeypatch.setattr("sbfleet.authority.fail_operation", lambda *a, **k: None)
    monkeypatch.setattr("sbfleet.authority.complete_operation", lambda *a, **k: None)
    monkeypatch.setattr(bak, "_require_age", lambda: "age")
    monkeypatch.setattr(bak, "_resolve_identity", lambda *a, **k: identity)

    class AgeOk:
        ok = True

    monkeypatch.setattr(bak, "run", lambda *a, **k: AgeOk())
    monkeypatch.setattr(
        bak,
        "prevalidate_restore_archive",
        lambda **k: (
            {
                "backup_id": "b1",
                "project_id": "proj-1",
                "source_facts": {"databases": "postgres"},
                "source_crypto": {"name": "x"},
                "images": {"db": {"image_id": "sha256:" + "a" * 64}},
            },
            {"POSTGRES_PASSWORD": "x"},
            "m" * 64,
        ),
    )
    monkeypatch.setattr(bak, "disk_preflight", lambda *a, **k: None)

    def fake_rv(**kwargs: Any) -> RecoveryVerificationResult:
        calls.append("requested_verify")
        return RecoveryVerificationResult(
            ok=False,
            verifier_id="rv-bad",
            operation_id="op",
            error="postgres not ready",
            assertions=[],
        )

    monkeypatch.setattr(bak, "run_disposable_recovery_verification", fake_rv)

    def boom_quiesce(*a: Any, **k: Any) -> None:
        calls.append("quiesce")
        raise AssertionError("quiesce must not run")

    def boom_backup(*a: Any, **k: Any) -> None:
        calls.append("pre_restore_backup")
        raise AssertionError("pre-restore backup must not run")

    monkeypatch.setattr(bak, "_quiesce_ordered", boom_quiesce)
    monkeypatch.setattr(bak, "_create_backup_locked", boom_backup)

    code = bak.restore_backup(root, "s1", str(archive), yes=True, identity=str(identity))
    assert code == EXIT_BACKUP
    assert "requested_verify" in calls
    assert "quiesce" not in calls
    assert "pre_restore_backup" not in calls
    assert sentinel.read_bytes() == before
