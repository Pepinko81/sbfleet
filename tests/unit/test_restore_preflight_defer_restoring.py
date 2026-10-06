"""Restore preflight defer restoring."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from sbfleet import backup as bak
from sbfleet import registry as reg
from sbfleet.backup_recovery import RecoveryVerificationResult
from sbfleet.cli import EXIT_BACKUP, EXIT_FAILURE


def _fleet_with_project(tmp_path: Path) -> tuple[Path, str, Path]:
    root = reg.ensure_root(tmp_path / "fleet")
    slug = "qa-restore"
    pid = str(uuid.uuid4())
    fid = reg.fleet_id(root)
    meta = {
        "format_version": 1,
        "id": pid,
        "fleet_id": fid,
        "slug": slug,
        "display_name": "QA Restore",
        "profile": "standard",
        "compose_project": reg.compose_project_name(fid, pid),
        "creation_complete": True,
        "ports": {
            "gateway": 54321,
            "db_direct": 54322,
            "pooler_session": 54323,
            "pooler_transaction": 54324,
        },
        "upstream": {"ref": "v1.0.0", "sha": "a" * 40},
        "public_url": "http://127.0.0.1:54321",
    }
    reg.write_project(root, meta)
    deployment = reg.project_dir(root, slug) / "deployment"
    deployment.mkdir(parents=True)
    (deployment / "volumes" / "db" / "data").mkdir(parents=True)
    sentinel = deployment / "volumes" / "db" / "data" / "PG_VERSION"
    sentinel.write_text("15\n", encoding="utf-8")
    return root, slug, sentinel


def _ctx_for(root: Path, slug: str) -> Any:
    meta = reg.read_project(root, slug)
    ctx = mock.Mock()
    ctx.meta = meta
    ctx.deployment = reg.project_dir(root, slug) / "deployment"
    ctx.root = root
    ctx.slug = slug
    ctx.operation_id = "op-preflight-" + uuid.uuid4().hex[:8]
    ctx.compose_project = str(meta["compose_project"])
    ctx.compose_env = {}
    ctx.fleet_id = str(meta["fleet_id"])
    ctx.project_id = str(meta["id"])
    ctx.intent = "restore"
    return ctx


def _authorize_cm(ctx: Any) -> Any:
    cm = mock.MagicMock()
    cm.__enter__.return_value = ctx
    cm.__exit__.return_value = False
    return cm


def _patch_common_preflight(
    monkeypatch: pytest.MonkeyPatch,
    *,
    root: Path,
    ctx: Any,
    identity: Path,
    archive: Path,
    prevalidate_ok: bool = True,
    decrypt_ok: bool = True,
    verify_ok: bool = True,
    verify_error: str = "postgres not ready",
) -> list[str]:
    calls: list[str] = []
    monkeypatch.setattr("sbfleet.authority.authorize_mutation", lambda *a, **k: _authorize_cm(ctx))
    monkeypatch.setattr(bak, "_require_age", lambda: "age")
    monkeypatch.setattr(bak, "_resolve_identity", lambda *a, **k: identity)

    def _wipe_ok(staging: Path) -> None:
        import shutil

        if staging.exists():
            shutil.rmtree(staging)

    monkeypatch.setattr(bak, "_wipe_staging", _wipe_ok)
    monkeypatch.setattr(bak, "disk_preflight", lambda *a, **k: None)

    class AgeResult:
        ok = decrypt_ok

    monkeypatch.setattr(bak, "run", lambda *a, **k: AgeResult())

    if prevalidate_ok:

        def _prevalidate(**k: Any) -> tuple[dict[str, Any], dict[str, str], str]:
            calls.append("prevalidate")
            return (
                {
                    "backup_id": "b1",
                    "project_id": str(ctx.meta["id"]),
                    "source_facts": {"databases": "postgres"},
                    "source_crypto": {"name": "x"},
                    "images": {"db": {"image_id": "sha256:" + "a" * 64}},
                },
                {"POSTGRES_PASSWORD": "x"},
                "m" * 64,
            )

        monkeypatch.setattr(bak, "prevalidate_restore_archive", _prevalidate)
    else:
        from sbfleet.backup_manifest import ManifestError

        def _bad_pre(**k: Any) -> None:
            calls.append("prevalidate")
            raise ManifestError("wrong project identity")

        monkeypatch.setattr(bak, "prevalidate_restore_archive", _bad_pre)

    def fake_rv(**kwargs: Any) -> RecoveryVerificationResult:
        calls.append("requested_verify")
        return RecoveryVerificationResult(
            ok=verify_ok,
            verifier_id="rv-test",
            operation_id=ctx.operation_id,
            error=None if verify_ok else verify_error,
            assertions=[],
        )

    monkeypatch.setattr(bak, "run_disposable_recovery_verification", fake_rv)
    return calls


@pytest.mark.parametrize(
    "case",
    [
        "wrong_identity",
        "missing_archive",
        "corrupt_prevalidate",
        "wrong_project",
        "recovery_verify_fail",
    ],
)
def test_premutation_refusal_does_not_wedge_restoring_journal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    root, slug, sentinel = _fleet_with_project(tmp_path)
    before = sentinel.read_bytes()
    prior = reg.read_operation_journal(root, slug)
    assert prior is None or prior.get("state") != reg.OP_STATE_FAILED

    identity = tmp_path / "id"
    identity.write_text("AGE-SECRET-KEY-1\n", encoding="utf-8")
    archive = root / "arch.tar.age"
    archive.write_bytes(b"ciphertext" * 8)
    ctx = _ctx_for(root, slug)

    begin_calls: list[str] = []
    fail_calls: list[str] = []

    def begin(*a: Any, **k: Any) -> None:
        begin_calls.append(k.get("phase") or "begin")
        reg.write_operation_journal(
            root,
            slug,
            reg.new_operation_journal(
                intent="RESTORING",
                phase=str(k.get("phase") or "run"),
                state=reg.OP_STATE_IN_PROGRESS,
                operation_id=ctx.operation_id,
            ),
        )

    def fail(*a: Any, **k: Any) -> None:
        fail_calls.append(str(k.get("error") or "fail"))
        reg.write_operation_journal(
            root,
            slug,
            reg.new_operation_journal(
                intent="RESTORING",
                phase="failed",
                state=reg.OP_STATE_FAILED,
                operation_id=ctx.operation_id,
                error=str(k.get("error") or "fail")[:200],
            ),
        )

    monkeypatch.setattr("sbfleet.authority.begin_operation", begin)
    monkeypatch.setattr("sbfleet.authority.fail_operation", fail)
    monkeypatch.setattr("sbfleet.authority.record_operation_phase", lambda *a, **k: None)
    monkeypatch.setattr("sbfleet.authority.complete_operation", lambda *a, **k: None)

    decrypt_ok = case != "wrong_identity"
    prevalidate_ok = case not in {"corrupt_prevalidate", "wrong_project"}
    verify_ok = case != "recovery_verify_fail"
    if case == "missing_archive":
        archive.unlink()

    calls = _patch_common_preflight(
        monkeypatch,
        root=root,
        ctx=ctx,
        identity=identity,
        archive=archive,
        prevalidate_ok=prevalidate_ok,
        decrypt_ok=decrypt_ok,
        verify_ok=verify_ok,
    )

    def boom_backup(*a: Any, **k: Any) -> None:
        raise AssertionError("pre-restore must not run on preflight refusal")

    def boom_quiesce(*a: Any, **k: Any) -> None:
        raise AssertionError("quiesce must not run on preflight refusal")

    monkeypatch.setattr(bak, "_create_backup_locked", boom_backup)
    monkeypatch.setattr(bak, "_quiesce_ordered", boom_quiesce)

    code = bak.restore_backup(
        root,
        slug,
        str(archive if archive.exists() else root / "missing.tar.age"),
        yes=True,
        identity=str(identity),
    )
    assert code != 0
    assert begin_calls == []
    assert fail_calls == []
    journal = reg.read_operation_journal(root, slug)
    assert journal is None or not reg.journal_blocks_ordinary_start(journal)
    assert sentinel.read_bytes() == before
    if case == "recovery_verify_fail":
        assert "requested_verify" in calls

    # Subsequent ordinary mutations must not be blocked by this preflight refusal.
    from sbfleet import authority as auth

    monkeypatch.setattr(
        "sbfleet.authority.authorize_mutation",
        auth.authorize_mutation,
    )
    # Pin/vendor checks may refuse in a bare fixture; journal blocking must not.
    try:
        with auth.authorize_mutation(
            root, slug, intent="backup", invent_live=False, validate_compose=False
        ):
            pass
    except auth.AuthorityError as exc:
        assert "unresolved" not in str(exc).lower()
        assert "RESTORING" not in str(exc)


def test_post_begin_failure_still_blocks_with_restoring_journal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Negative control: failure at/after begin leaves blocking RESTORING."""
    root, slug, sentinel = _fleet_with_project(tmp_path)
    identity = tmp_path / "id"
    identity.write_text("AGE-SECRET-KEY-1\n", encoding="utf-8")
    archive = root / "arch.tar.age"
    archive.write_bytes(b"ciphertext" * 8)
    ctx = _ctx_for(root, slug)

    def begin(*a: Any, **k: Any) -> None:
        reg.write_operation_journal(
            root,
            slug,
            reg.new_operation_journal(
                intent="RESTORING",
                phase=str(k.get("phase") or "creating_pre_restore_backup"),
                state=reg.OP_STATE_IN_PROGRESS,
                operation_id=ctx.operation_id,
            ),
        )

    def fail(*a: Any, **k: Any) -> None:
        reg.write_operation_journal(
            root,
            slug,
            reg.new_operation_journal(
                intent="RESTORING",
                phase="failed",
                state=reg.OP_STATE_FAILED,
                operation_id=ctx.operation_id,
                error=str(k.get("error") or "fail")[:200],
            ),
        )

    monkeypatch.setattr("sbfleet.authority.begin_operation", begin)
    monkeypatch.setattr("sbfleet.authority.fail_operation", fail)
    monkeypatch.setattr("sbfleet.authority.record_operation_phase", lambda *a, **k: None)
    _patch_common_preflight(
        monkeypatch,
        root=root,
        ctx=ctx,
        identity=identity,
        archive=archive,
        verify_ok=True,
    )

    def boom_pre(*a: Any, **k: Any) -> None:
        raise bak.BackupError("injected post-begin failure", code=EXIT_FAILURE)

    monkeypatch.setattr(bak, "_create_backup_locked", boom_pre)
    monkeypatch.setattr(
        bak, "_quiesce_ordered", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no"))
    )

    code = bak.restore_backup(root, slug, str(archive), yes=True, identity=str(identity))
    assert code != 0
    journal = reg.read_operation_journal(root, slug)
    assert journal is not None
    assert journal.get("intent") == "RESTORING"
    assert journal.get("state") == reg.OP_STATE_FAILED
    assert reg.journal_blocks_ordinary_start(journal)
    # Target not quiesced/quarantined in this injected path.
    assert sentinel.exists()


def test_preflight_cleanup_residuals_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root, slug, _sentinel = _fleet_with_project(tmp_path)
    identity = tmp_path / "id"
    identity.write_text("AGE-SECRET-KEY-1\n", encoding="utf-8")
    archive = root / "arch.tar.age"
    archive.write_bytes(b"ciphertext" * 8)
    ctx = _ctx_for(root, slug)

    monkeypatch.setattr("sbfleet.authority.begin_operation", lambda *a, **k: None)
    monkeypatch.setattr("sbfleet.authority.fail_operation", lambda *a, **k: None)
    monkeypatch.setattr("sbfleet.authority.record_operation_phase", lambda *a, **k: None)
    _patch_common_preflight(
        monkeypatch,
        root=root,
        ctx=ctx,
        identity=identity,
        archive=archive,
        decrypt_ok=False,
    )

    def wipe_fail(staging: Path) -> None:
        staging.mkdir(parents=True, exist_ok=True)
        (staging / "leftover.bin").write_bytes(b"x")
        raise bak.BackupError("docker staging wipe failed", code=5)

    monkeypatch.setattr(bak, "_wipe_staging", wipe_fail)

    code = bak.restore_backup(root, slug, str(archive), yes=True, identity=str(identity))
    assert code == EXIT_BACKUP
    err = capsys.readouterr().err
    assert "staging cleanup incomplete" in err
    assert "residuals:" in err
    assert "quarantine retained" not in err
    journal = reg.read_operation_journal(root, slug)
    assert journal is None or not reg.journal_blocks_ordinary_start(journal)
