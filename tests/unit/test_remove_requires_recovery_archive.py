"""Remove requires recovery archive."""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from sbfleet import backup as bak
from sbfleet.backup_manifest import (
    REQUIRED_RECOVERY_ASSERTIONS,
    VERIFICATION_RECOVERY,
    VERIFIER_CONTRACT_VERSION,
    public_receipt,
)


def _recovery_receipt(**overrides: object) -> dict:
    assertions = [
        {"name": n, "ok": True, "detail": "ok"} for n in sorted(REQUIRED_RECOVERY_ASSERTIONS)
    ]
    receipt = public_receipt(
        backup_id="bid-1",
        project_id="proj-a",
        slug="slug-a",
        digest="a" * 64,
        size=128,
        upstream={"ref": "self-hosted/v0.8.2", "sha": "b" * 40},
        verification=VERIFICATION_RECOVERY,
        manifest_sha256="c" * 64,
        recovery={
            "outcome_version": VERIFIER_CONTRACT_VERSION,
            "verifier_contract": VERIFIER_CONTRACT_VERSION,
            "verifier_id": "rv-1",
            "operation_id": "op-1",
            "ok": True,
            "assertions": assertions,
            "required_assertions": sorted(REQUIRED_RECOVERY_ASSERTIONS),
            "source_pin": {"ref": "self-hosted/v0.8.2", "sha": "b" * 40},
            "manifest_sha256": "c" * 64,
            "project_id": "proj-a",
            "backup_id": "bid-1",
            "verified_at": "2026-10-01T00:00:00Z",
        },
        operation_id="op-1",
    )
    receipt["verified_at"] = "2026-10-01T00:00:00Z"
    receipt.update(overrides)
    return receipt


def _write_pair(root: Path, receipt: dict, *, archive_bytes: bytes = b"x" * 128) -> Path:
    pid = str(receipt["project_id"])
    bid = str(receipt["backup_id"])
    d = root / "backups" / pid
    d.mkdir(parents=True)
    receipt = dict(receipt)
    receipt["ciphertext_bytes"] = len(archive_bytes)
    arch = d / f"{bid}.tar.age"
    arch.write_bytes(archive_bytes)
    import hashlib

    receipt["ciphertext_sha256"] = hashlib.sha256(archive_bytes).hexdigest()
    (d / f"{bid}.json").write_text(json.dumps(receipt) + "\n", encoding="utf-8")
    return arch


def test_missing_archive_refuses(tmp_path: Path) -> None:
    receipt = _recovery_receipt()
    d = tmp_path / "backups" / "proj-a"
    d.mkdir(parents=True)
    (d / "bid-1.json").write_text(json.dumps(receipt) + "\n", encoding="utf-8")
    meta = {"id": "proj-a", "last_backup_id": "bid-1"}
    with pytest.raises(bak.BackupError, match="archive missing"):
        bak.require_recovery_backup(tmp_path, meta)


def test_wrong_project_receipt_refuses(tmp_path: Path) -> None:
    receipt = _recovery_receipt()
    receipt["project_id"] = "other-project"
    receipt["recovery"]["project_id"] = "other-project"
    # Receipt lives under expected project path but claims another UUID.
    d = tmp_path / "backups" / "proj-a"
    d.mkdir(parents=True)
    archive_bytes = b"x" * 128
    import hashlib

    receipt["ciphertext_bytes"] = len(archive_bytes)
    receipt["ciphertext_sha256"] = hashlib.sha256(archive_bytes).hexdigest()
    (d / "bid-1.tar.age").write_bytes(archive_bytes)
    (d / "bid-1.json").write_text(json.dumps(receipt) + "\n", encoding="utf-8")
    meta = {"id": "proj-a", "last_backup_id": "bid-1"}
    with pytest.raises(bak.BackupError, match="project_id mismatch|unusable|binding"):
        bak.require_recovery_backup(tmp_path, meta)


def test_truncated_archive_refuses(tmp_path: Path) -> None:
    receipt = _recovery_receipt()
    _write_pair(tmp_path, receipt, archive_bytes=b"tiny")
    meta = {"id": "proj-a", "last_backup_id": "bid-1"}
    with pytest.raises(bak.BackupError, match="size mismatch|truncated"):
        bak.require_recovery_backup(tmp_path, meta)


def test_ciphertext_hash_mismatch_refuses(tmp_path: Path) -> None:
    receipt = _recovery_receipt()
    arch = _write_pair(tmp_path, receipt)
    # Corrupt receipt hash after writing matching archive.
    path = tmp_path / "backups" / "proj-a" / "bid-1.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["ciphertext_sha256"] = "d" * 64
    path.write_text(json.dumps(data) + "\n", encoding="utf-8")
    meta = {"id": "proj-a", "last_backup_id": "bid-1"}
    with pytest.raises(bak.BackupError, match="binding failed|mismatch"):
        bak.require_recovery_backup(tmp_path, meta)
    assert arch.is_file()


def test_weak_v1_evidence_schema_refuses(tmp_path: Path) -> None:
    receipt = _recovery_receipt()
    receipt["recovery"]["outcome_version"] = "recovery-verify/v1"
    receipt["recovery"]["verifier_contract"] = "recovery-verify/v1"
    # Drop mandatory vault_crypto assertion set.
    receipt["recovery"]["assertions"] = [
        {"name": "postgres_ready", "ok": True, "detail": "ok"},
        {"name": "databases", "ok": True, "detail": "ok"},
        {"name": "roles", "ok": True, "detail": "ok"},
        {"name": "storage_tree", "ok": True, "detail": "ok"},
    ]
    _write_pair(tmp_path, receipt)
    meta = {"id": "proj-a", "last_backup_id": "bid-1"}
    with pytest.raises(bak.BackupError, match="unusable|contract|assertions"):
        bak.require_recovery_backup(tmp_path, meta)


def test_genuine_usable_pair_passes(tmp_path: Path) -> None:
    receipt = _recovery_receipt()
    _write_pair(tmp_path, receipt)
    meta = {"id": "proj-a", "last_backup_id": "bid-1"}
    got = bak.require_recovery_backup(tmp_path, meta)
    assert got["backup_id"] == "bid-1"


def test_remove_does_not_mutate_when_archive_missing(tmp_path: Path) -> None:
    """String-only recovery sidecar must not authorize remove stop/wipe."""
    from sbfleet import projects_remove as pr

    receipt = {
        "format_version": 1,
        "verification": "recovery",
        "project_id": "other-project",
        "backup_id": "old",
    }
    d = tmp_path / "backups" / "project-a"
    d.mkdir(parents=True)
    (d / "old.json").write_text(json.dumps(receipt) + "\n", encoding="utf-8")
    meta = {"id": "project-a", "last_backup_id": "old", "slug": "project-a"}

    class FakeCtx:
        pass

    ctx = FakeCtx()
    ctx.meta = meta
    ctx.root = tmp_path
    ctx.slug = "project-a"
    ctx.operation_id = "op"
    ctx.deployment = tmp_path / "deployment"
    ctx.compose_project = "cp"
    ctx.deployment.mkdir()

    with mock.patch("sbfleet.authority.authorize_mutation") as am:
        cm = mock.MagicMock()
        cm.__enter__.return_value = ctx
        cm.__exit__.return_value = False
        am.return_value = cm
        with mock.patch.object(pr, "stop_project") as stop:
            code = pr.remove_project(tmp_path, "project-a", yes=True, no_backup=False)
    assert code != 0
    stop.assert_not_called()
