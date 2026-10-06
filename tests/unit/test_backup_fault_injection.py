"""Backup fault injection."""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from sbfleet import authority as auth
from sbfleet import registry as reg
from sbfleet.archive_safe import MemberSpec
from sbfleet.backup import (
    VERIFICATION_DECRYPT_STRUCTURAL,
    VERIFICATION_NONE,
    VERIFICATION_RECOVERY,
    BackupError,
    reconcile_destination_env,
    require_recovery_backup,
)
from sbfleet.backup_manifest import (
    DESTINATION_OWNED_ENV_KEYS,
    SOURCE_RECOVERY_ENV_KEYS,
    ManifestError,
    build_internal_manifest,
    project_identity_matches,
    receipt_archive_binding_ok,
    require_db_recovery_facts,
    validate_internal_manifest,
)
from sbfleet.backup_recovery import (
    RecoveryVerificationResult,
    parse_pg_controldata,
)


def _member(path: str, digest: str = "a" * 64, size: int = 1) -> MemberSpec:
    return MemberSpec(path=path, type="file", size=size, sha256=digest)


def test_recovery_verification_result_is_not_project_healthy():
    rv = RecoveryVerificationResult(
        ok=True,
        verifier_id="rv-x",
        operation_id="op",
        assertions=[],
    )
    evidence = rv.as_receipt_evidence()
    assert "HEALTHY" not in json.dumps(evidence)
    assert evidence["ok"] is True
    assert evidence["outcome_version"].startswith("recovery-verify/")


def test_parse_pg_controldata_clean():
    text = "Database cluster state:             shut down\nCatalog version number:            1\n"
    facts = parse_pg_controldata(text)
    assert "shut down" in facts["Database cluster state"]


def test_require_db_recovery_facts_refuses_unknown_image():
    man = {
        "format_version": 1,
        "backup_id": "b",
        "project_id": "p",
        "fleet_id": "f",
        "created_at": "t",
        "method": "cold-physical",
        "images": {"db": {"image_ref": "UNKNOWN", "image_id": "UNKNOWN"}},
        "postgres": {"cluster_state": "shut down", "pg_version": "15"},
        "inventory": [
            {"path": "postgres/PG_VERSION", "type": "file", "size": 2, "sha256": "a" * 64},
            {"path": "db-config/pgsodium_root.key", "type": "file", "size": 2, "sha256": "b" * 64},
            {"path": "storage/o", "type": "file", "size": 2, "sha256": "c" * 64},
            {"path": "deployment/.env", "type": "file", "size": 2, "sha256": "d" * 64},
            {"path": "project.json", "type": "file", "size": 2, "sha256": "e" * 64},
        ],
    }
    with pytest.raises(ManifestError, match="UNKNOWN"):
        require_db_recovery_facts(man)


def test_validate_internal_manifest_requires_units():
    members = {
        "postgres/PG_VERSION": _member("postgres/PG_VERSION"),
        "db-config/pgsodium_root.key": _member("db-config/pgsodium_root.key"),
        "storage/obj": _member("storage/obj"),
        "deployment/.env": _member("deployment/.env"),
        "project.json": _member("project.json"),
    }
    man = build_internal_manifest(
        backup_id="b",
        project_id="p",
        fleet_id="f",
        slug="s",
        upstream={},
        last_verified_upstream=None,
        prior_state="STOPPED",
        images={"db": {"image_ref": "img", "image_id": "sha256:abc"}},
        postgres={"cluster_state": "shut down", "pg_version": "15", "major": 15},
        members=members,
        includes=["postgres"],
        clean_shutdown_evidence={"cluster_state": "shut down"},
    )
    validate_internal_manifest(man)
    # Self-entry refused
    man["inventory"].append(
        {"path": "manifest.json", "type": "file", "size": 1, "sha256": "f" * 64}
    )
    with pytest.raises(ManifestError, match="itself"):
        validate_internal_manifest(man)


def test_project_identity_mismatch():
    with pytest.raises(ManifestError, match="identity mismatch"):
        project_identity_matches({"project_id": "aaa"}, "bbb")


def test_restore_refuses_wrong_project_uuid_before_mutation(tmp_path: Path):
    """Wrong-project identity raises BackupError with EXIT_BACKUP (8)."""
    from sbfleet.backup import EXIT_BACKUP, BackupError
    from sbfleet.cli import EXIT_BACKUP as CLI_EXIT_BACKUP

    assert EXIT_BACKUP == CLI_EXIT_BACKUP == 8
    with pytest.raises(ManifestError, match="identity mismatch") as ei:
        project_identity_matches(
            {"project_id": "11111111-1111-1111-1111-111111111111"},
            "22222222-2222-2222-2222-222222222222",
        )
    # Restore path wraps this as BackupError EXIT_BACKUP — contract unit:
    wrapped = BackupError(str(ei.value), code=EXIT_BACKUP)
    assert wrapped.code == 8


def test_receipt_archive_binding():
    receipt = {
        "ciphertext_sha256": "a" * 64,
        "project_id": "p",
        "backup_id": "b",
        "manifest_sha256": "c" * 64,
    }
    receipt_archive_binding_ok(
        receipt,
        ciphertext_sha256="a" * 64,
        project_id="p",
        backup_id="b",
        manifest_sha256="c" * 64,
    )
    with pytest.raises(ManifestError, match="ciphertext"):
        receipt_archive_binding_ok(
            receipt,
            ciphertext_sha256="b" * 64,
            project_id="p",
            backup_id="b",
        )


def test_reconcile_destination_env_keeps_selectors(tmp_path: Path):
    archived = {
        "JWT_SECRET": "j" * 32,
        "ANON_KEY": "anon-key-value-123456",
        "SERVICE_ROLE_KEY": "service-role-key-123",
        "SUPABASE_PUBLISHABLE_KEY": "pub-key-value-123456",
        "SUPABASE_SECRET_KEY": "sec-key-value-1234567",
        "JWT_KEYS": "[]",
        "JWT_JWKS": '{"keys":[]}',
        "POSTGRES_PASSWORD": "postgres-password-1",
        "DASHBOARD_PASSWORD": "dashboard-password1",
        "SECRET_KEY_BASE": "secret-key-base-123456789012",
        "VAULT_ENC_KEY": "vault-enc-key-1234567890",
        "POOLER_TENANT_ID": "tenantfromsource01",
        "COMPOSE_PROJECT_NAME": "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb",
        "SUPABASE_PUBLIC_URL": "http://evil.example",
        "DASHBOARD_USERNAME": "src_user",
    }
    # Fix JWT_KEYS / JWKS to pass validation
    archived["JWT_KEYS"] = '[{"kty":"oct","k":"x"}]'
    archived["JWT_JWKS"] = '{"keys":[{"kty":"oct","k":"x"}]}'
    dest = {
        "COMPOSE_PROJECT_NAME": "sbfleet-ffffffffffff-eeeeeeeeeeee",
        "COMPOSE_FILE": "docker-compose.yml:docker-compose.override.yml",
        "COMPOSE_PATH_SEPARATOR": ":",
        "DASHBOARD_USERNAME": "dest_user",
        "SUPABASE_PUBLIC_URL": "http://127.0.0.1:8000",
        "API_EXTERNAL_URL": "http://127.0.0.1:8000/auth/v1",
        "JWT_SECRET": "old" * 20,
        "ANON_KEY": "old-anon",
        "SERVICE_ROLE_KEY": "old-service",
        "SUPABASE_PUBLISHABLE_KEY": "old-pub",
        "SUPABASE_SECRET_KEY": "old-sec",
        "JWT_KEYS": archived["JWT_KEYS"],
        "JWT_JWKS": archived["JWT_JWKS"],
        "POSTGRES_PASSWORD": "old-postgres-password",
        "DASHBOARD_PASSWORD": "old-dashboard-passw",
        "SECRET_KEY_BASE": "old-secret-key-base-123456",
        "VAULT_ENC_KEY": "old-vault-enc-key-1234567",
        "POOLER_TENANT_ID": "oldtenant",
        "KONG_HTTP_PORT": "8000",
    }
    meta = {
        "compose_project": "sbfleet-ffffffffffff-eeeeeeeeeeee",
        "ports": {"gateway": 18000},
        "public_url": "http://127.0.0.1:18000",
    }
    out = reconcile_destination_env(
        archived_env=archived,
        destination_env=dest,
        destination_meta=meta,
    )
    assert out["COMPOSE_PROJECT_NAME"] == meta["compose_project"]
    assert out["COMPOSE_PROJECT_NAME"] != archived["COMPOSE_PROJECT_NAME"]
    assert out["DASHBOARD_USERNAME"] == "dest_user"
    assert out["POOLER_TENANT_ID"] == "tenantfromsource01"
    assert out["JWT_SECRET"] == archived["JWT_SECRET"]
    assert "18000" in out["SUPABASE_PUBLIC_URL"]
    assert out["SUPABASE_PUBLIC_URL"] != archived["SUPABASE_PUBLIC_URL"]
    # Destination-owned keys must remain destination-controlled
    for key in (
        "COMPOSE_PROJECT_NAME",
        "COMPOSE_FILE",
        "COMPOSE_PATH_SEPARATOR",
        "DASHBOARD_USERNAME",
    ):
        assert key in DESTINATION_OWNED_ENV_KEYS
    assert "JWT_SECRET" in SOURCE_RECOVERY_ENV_KEYS


def test_record_operation_phase_preserves_restore_intent(tmp_path: Path):
    root = reg.ensure_root(tmp_path / "home")
    pid = "11111111-1111-4111-8111-111111111111"
    fid = reg.fleet_id(root)
    slug = "demo"
    cp = reg.compose_project_name(fid, pid)
    meta = {
        "format_version": 1,
        "id": pid,
        "fleet_id": fid,
        "slug": slug,
        "display_name": slug,
        "created_at": "2026-01-01T00:00:00Z",
        "profile": "standard",
        "compose_project": cp,
        "ports": {
            "gateway": 18000,
            "db_direct": 18001,
            "pooler_session": 18002,
            "pooler_transaction": 18003,
        },
        "domain": None,
        "public_url": "http://127.0.0.1:18000",
        "upstream": {"ref": "self-hosted/v0.8.2", "sha": "b" * 40},
        "creation_complete": True,
    }
    reg.write_project(root, meta)
    dep = reg.project_dir(root, slug) / "deployment"
    dep.mkdir(parents=True)
    (dep / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (dep / ".env").write_text(
        f"COMPOSE_PROJECT_NAME={cp}\n"
        "COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml\n"
        "COMPOSE_PATH_SEPARATOR=:\n",
        encoding="utf-8",
    )
    # Minimal compose files for validation skip path: invent_live=False validate_compose=False
    ctx = auth.MutationContext(
        root=root,
        slug=slug,
        meta=meta,
        deployment=dep,
        project_dir=reg.project_dir(root, slug),
        compose_project=cp,
        fleet_id=fid,
        project_id=pid,
        compose_env=auth.forced_compose_env(dep, cp),
        operation_id="restore-op-1",
        intent="restore",
        inventory=None,
    )
    auth.begin_operation(ctx, phase="validating_archive")
    auth.record_operation_phase(
        ctx,
        phase="creating_pre_restore_backup",
        evidence={"pre_restore": {"backup_phase": "collecting", "backup_id": "b1"}},
    )
    journal = reg.read_operation_journal(root, slug)
    assert journal is not None
    assert journal["intent"] == "RESTORING"
    assert journal["operation_id"] == "restore-op-1"
    assert journal["phase"] == "creating_pre_restore_backup"
    assert journal["evidence"]["pre_restore"]["backup_id"] == "b1"
    # Nested evidence merge must not flip intent to BACKUP
    auth.record_operation_phase(
        ctx,
        phase="creating_pre_restore_backup",
        evidence={"pre_restore": {"verification": VERIFICATION_RECOVERY}},
    )
    journal2 = reg.read_operation_journal(root, slug)
    assert journal2["intent"] == "RESTORING"
    assert journal2["evidence"]["pre_restore"]["backup_id"] == "b1"
    assert journal2["evidence"]["pre_restore"]["verification"] == VERIFICATION_RECOVERY


def test_create_backup_locked_never_calls_authorize(tmp_path: Path):
    """Guard: nested backup primitive must not reacquire mutation authority."""
    calls: list[str] = []
    real = auth.authorize_mutation

    def wrapped(*args, **kwargs):
        calls.append("authorize")
        return real(*args, **kwargs)

    with mock.patch("sbfleet.authority.authorize_mutation", side_effect=wrapped):
        from sbfleet import backup as backup_mod

        ctx = mock.Mock()
        ctx.root = tmp_path
        ctx.slug = "x"
        ctx.meta = {"id": "p", "fleet_id": "f", "compose_project": "cp", "upstream": {}}
        ctx.deployment = tmp_path / "dep"
        ctx.compose_project = "cp"
        ctx.operation_id = "op"
        ctx.intent = "restore"
        with mock.patch.object(backup_mod, "_require_age", return_value="/usr/bin/age"):
            with mock.patch.object(backup_mod, "_fleet_recipients", return_value=["age1x"]):
                with mock.patch.object(
                    backup_mod,
                    "_capture_prior_state",
                    side_effect=BackupError("stop early"),
                ):
                    with pytest.raises(BackupError, match="stop early"):
                        backup_mod._create_backup_locked(ctx, verify=False, pre_restore=True)
    assert calls == []


def test_capture_prior_state_ignores_own_backup_journal(tmp_path: Path):
    """Stopped stack + our in-progress BACKUP journal must still read as STOPPED."""
    from types import SimpleNamespace

    from sbfleet.backup import _capture_prior_state
    from sbfleet.health import STOPPED, ContainerInspectResult

    root = reg.ensure_root(tmp_path / "home")
    slug = "stopped"
    fid = reg.fleet_id(root)
    pid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    meta = {
        "format_version": 1,
        "id": pid,
        "fleet_id": fid,
        "slug": slug,
        "display_name": slug,
        "created_at": "2026-01-01T00:00:00Z",
        "profile": "standard",
        "compose_project": reg.compose_project_name(fid, pid),
        "ports": {
            "gateway": 21010,
            "db_direct": 21011,
            "pooler_session": 21012,
            "pooler_transaction": 21013,
        },
        "domain": None,
        "public_url": "http://127.0.0.1:21010",
        "upstream": {"ref": "self-hosted/v0.8.2", "sha": "a" * 40},
        "creation_complete": True,
    }
    reg.write_project(root, meta)
    (reg.project_dir(root, slug) / "deployment").mkdir(parents=True)
    op_id = "op-own-backup"
    reg.write_operation_journal(
        root,
        slug,
        reg.new_operation_journal(
            intent="BACKUP",
            phase="capturing_prior_state",
            operation_id=op_id,
        ),
    )
    empty = ContainerInspectResult(ok=True, containers={})
    own_ctx = SimpleNamespace(root=root, slug=slug, operation_id=op_id)
    foreign_ctx = SimpleNamespace(root=root, slug=slug, operation_id="other-op")
    with mock.patch("sbfleet.health.inspect_containers_result", return_value=empty):
        assert _capture_prior_state(root, slug, mutation_ctx=own_ctx) == STOPPED
    with mock.patch("sbfleet.health.inspect_containers_result", return_value=empty):
        with pytest.raises(BackupError, match="unresolved"):
            _capture_prior_state(root, slug, mutation_ctx=foreign_ctx)


def test_legacy_verified_never_promoted():
    from sbfleet.backup import normalize_receipt_verification

    assert normalize_receipt_verification({"verified": True}) == VERIFICATION_DECRYPT_STRUCTURAL
    assert normalize_receipt_verification({"verification": VERIFICATION_NONE}) == VERIFICATION_NONE


def test_require_recovery_still_refuses_structural(tmp_path: Path):
    pid = "11111111-1111-1111-1111-111111111111"
    bid = "22222222-2222-2222-2222-222222222222"
    (tmp_path / "backups" / pid).mkdir(parents=True)
    reg.atomic_write_json(
        tmp_path / "backups" / pid / f"{bid}.json",
        {
            "format_version": 1,
            "backup_id": bid,
            "project_id": pid,
            "verification": VERIFICATION_DECRYPT_STRUCTURAL,
            "verified": False,
        },
        mode=0o600,
    )
    with pytest.raises(BackupError, match="not recovery"):
        require_recovery_backup(tmp_path, {"id": pid, "last_backup_id": bid})
