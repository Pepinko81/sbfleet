"""Lifecycle safety regression."""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from sbfleet import upstream as up
from sbfleet.backup import (
    VERIFICATION_DECRYPT_STRUCTURAL,
    VERIFICATION_NONE,
    VERIFICATION_RECOVERY,
    BackupError,
    is_recovery_verified_receipt,
    normalize_receipt_verification,
    require_recovery_backup,
)
from sbfleet.health import (
    HEALTHY,
    STARTING,
    STOPPED,
    UNHEALTHY,
    UNKNOWN,
    StatusReport,
    _container_probe,
    _http_probe,
    collect_status,
    lifecycle_op_succeeded,
)
from sbfleet.process import Redactor


def test_receipt_levels_never_upgrade_legacy_verified():
    assert normalize_receipt_verification({"verified": True}) == VERIFICATION_DECRYPT_STRUCTURAL
    assert normalize_receipt_verification({"verification": VERIFICATION_NONE}) == VERIFICATION_NONE
    assert (
        normalize_receipt_verification({"verification": VERIFICATION_RECOVERY, "verified": True})
        == VERIFICATION_RECOVERY
    )
    assert not is_recovery_verified_receipt({"verified": True})
    assert is_recovery_verified_receipt({"verification": VERIFICATION_RECOVERY})


def test_require_recovery_backup_refuses_weak(tmp_path: Path):
    root = tmp_path
    pid = "11111111-1111-1111-1111-111111111111"
    bid = "22222222-2222-2222-2222-222222222222"
    (root / "backups" / pid).mkdir(parents=True)
    receipt = {
        "format_version": 1,
        "backup_id": bid,
        "project_id": pid,
        "verification": VERIFICATION_DECRYPT_STRUCTURAL,
        "verified": False,
    }
    from sbfleet import registry as reg

    reg.atomic_write_json(root / "backups" / pid / f"{bid}.json", receipt, mode=0o600)
    meta = {"id": pid, "last_backup_id": bid}
    with pytest.raises(BackupError, match="not recovery"):
        require_recovery_backup(root, meta)
    # Legacy verified=True also refused
    legacy = {
        "format_version": 1,
        "backup_id": bid,
        "project_id": pid,
        "verified": True,
    }
    reg.atomic_write_json(root / "backups" / pid / f"{bid}.json", legacy, mode=0o600)
    with pytest.raises(BackupError, match="not recovery"):
        require_recovery_backup(root, meta)


def test_redactor_password_urls_and_secrets():
    r = Redactor()
    r.add("super-secret-token")
    text = "postgres://user:hunter2@127.0.0.1:5432/db super-secret-token"
    out = r.redact_text(text)
    assert "hunter2" not in out
    assert "super-secret-token" not in out
    assert "[REDACTED]" in out


def test_container_starting_is_starting_not_unknown():
    p = _container_probe("db", {"Health": "starting", "State": "running"})
    assert p.status == STARTING


def test_studio_timeout_not_auth_required():
    with mock.patch("sbfleet.health.urllib.request.build_opener") as build:
        opener = mock.Mock()
        build.return_value = opener
        opener.open.side_effect = TimeoutError("timed out")
        probe = _http_probe("http://127.0.0.1:9/project/default", expect_status={401})
    assert probe.status == UNHEALTHY
    assert "auth required" not in probe.detail.lower()


def test_lifecycle_success_helper():
    ok = StatusReport("x", HEALTHY, enum_ok=True)
    bad = StatusReport("x", STARTING, enum_ok=True)
    stopped = StatusReport("x", STOPPED, enum_ok=True)
    unknown_enum = StatusReport("x", STOPPED, enum_ok=False)
    assert lifecycle_op_succeeded(ok, expect=HEALTHY)
    assert not lifecycle_op_succeeded(bad, expect=HEALTHY)
    assert lifecycle_op_succeeded(stopped, expect=STOPPED)
    assert not lifecycle_op_succeeded(unknown_enum, expect=STOPPED)


def test_dotenv_rejects_unmatched_quote_and_escapes_dollar():
    with pytest.raises(up.UpstreamError, match="unmatched quote"):
        up.parse_dotenv('FOO="bar\n')
    dumped = up.dump_dotenv({"X": "a$b"})
    assert 'X="a$$b"' in dumped
    parsed = up.parse_dotenv(dumped)
    assert parsed["X"] == "a$b"


def test_dotenv_rejects_controls_interpolation_and_newlines():
    with pytest.raises(up.UpstreamError, match="control character"):
        up.parse_dotenv("FOO=bar\x01baz\n")
    with pytest.raises(up.UpstreamError, match="unsupported interpolation"):
        up.parse_dotenv("FOO=${HOME}\n")
    with pytest.raises(up.UpstreamError, match="newline"):
        up.parse_dotenv('FOO="a\\nb"\n')
    with pytest.raises(up.UpstreamError, match="unsupported escape"):
        up.parse_dotenv('FOO="a\\t"\n')
    with pytest.raises(up.UpstreamError, match="trailing backslash"):
        up.parse_dotenv('FOO="a\\"\n')


def test_dotenv_supported_double_quote_escapes():
    parsed = up.parse_dotenv('A="say \\"hi\\""\nB="c:\\\\tmp"\nC="a$$b"\n')
    assert parsed["A"] == 'say "hi"'
    assert parsed["B"] == "c:\\tmp"
    assert parsed["C"] == "a$b"


def test_pooler_username_uses_tenant(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from sbfleet import connection as conn
    from sbfleet import registry as reg

    root = tmp_path
    reg.ensure_root(root)
    slug = "poola"
    pid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    meta = {
        "format_version": 1,
        "id": pid,
        "fleet_id": reg.fleet_id(root),
        "slug": slug,
        "display_name": slug,
        "created_at": "2026-01-01T00:00:00Z",
        "profile": "standard",
        "compose_project": "sb_test",
        "ports": {
            "gateway": 18000,
            "db_direct": 18001,
            "pooler_session": 18002,
            "pooler_transaction": 18003,
        },
        "domain": None,
        "public_url": "http://127.0.0.1:18000",
        "upstream": {"ref": up.PINNED_REF, "sha": up.PINNED_SHA},
        "creation_complete": True,
    }
    reg.write_project(root, meta)
    dep = reg.project_dir(root, slug) / "deployment"
    dep.mkdir(parents=True)
    env = {
        "POSTGRES_PASSWORD": "x" * 20,
        "POSTGRES_DB": "postgres",
        "POOLER_TENANT_ID": "tenant123",
        "ANON_KEY": "a" * 40,
        "SERVICE_ROLE_KEY": "b" * 40,
        "SUPABASE_PUBLISHABLE_KEY": "a" * 40,
        "SUPABASE_SECRET_KEY": "b" * 40,
        "JWT_SECRET": "j" * 32,
        "JWT_KEYS": "[]",
        "JWT_JWKS": '{"keys":[]}',
        "DASHBOARD_PASSWORD": "d" * 20,
        "SECRET_KEY_BASE": "s" * 32,
        "VAULT_ENC_KEY": "v" * 32,
    }
    # validate_generated_env needs proper JWT — bypass by writing and mocking validate
    (dep / ".env").write_text(
        up.dump_dotenv({**env, "JWT_KEYS": "[{}]", "JWT_JWKS": '{"keys":[{}]}'}), encoding="utf-8"
    )
    (dep / ".env").chmod(0o600)
    cred = root / "cred.json"
    cred.write_text(json.dumps({"role": "authenticated", "password": "pw"}), encoding="utf-8")
    cred.chmod(0o600)

    captured = {}

    def fake_run(argv, **kwargs):
        captured["env"] = kwargs.get("env")
        from sbfleet.process import ProcessResult

        return ProcessResult(list(argv), 0, "", "")

    monkeypatch.setattr(conn, "run", fake_run)
    monkeypatch.setattr(up, "validate_generated_env", lambda e: None)
    monkeypatch.setattr(
        up, "parse_dotenv", lambda t: {**env, "JWT_KEYS": "[{}]", "JWT_JWKS": '{"keys":[{}]}'}
    )

    rc = conn.run_with_env(
        root, slug, ["true"], admin=False, credentials_file=str(cred), service_role=False
    )
    assert rc == 0
    assert captured["env"]["PGUSER"] == "authenticated.tenant123"
    assert "authenticated.tenant123" in captured["env"]["DATABASE_URL"]


def test_cli_rejects_start_and_no_start():
    from sbfleet.cli import main

    assert main(["create", "x", "--start", "--no-start"]) == 2


def test_cli_home_alone_opens_shell(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    from sbfleet import cli as cli_mod

    called = {}

    def fake_shell(*, home=None):
        called["home"] = home
        return 0

    monkeypatch.setattr(cli_mod.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli_mod.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr("sbfleet.shell.run_interactive_shell", fake_shell)
    assert cli_mod.main(["--home", str(tmp_path)]) == 0
    assert called["home"] == str(tmp_path)


def test_shell_help_includes_parser_options():
    from sbfleet.shell import topic_help

    text = topic_help("create")
    assert "--start" in text
    assert "--no-start" in text


def test_collect_status_docker_fail_is_unknown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from sbfleet import health as health_mod
    from sbfleet import registry as reg

    root = tmp_path
    reg.ensure_root(root)
    slug = "stata"
    meta = {
        "format_version": 1,
        "id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "fleet_id": reg.fleet_id(root),
        "slug": slug,
        "display_name": slug,
        "created_at": "2026-01-01T00:00:00Z",
        "profile": "standard",
        "compose_project": "sb_stat",
        "ports": {
            "gateway": 19000,
            "db_direct": 19001,
            "pooler_session": 19002,
            "pooler_transaction": 19003,
        },
        "domain": None,
        "public_url": "http://127.0.0.1:19000",
        "upstream": {"ref": up.PINNED_REF, "sha": up.PINNED_SHA},
        "creation_complete": True,
    }
    reg.write_project(root, meta)
    (reg.project_dir(root, slug) / "deployment").mkdir(parents=True)

    monkeypatch.setattr(
        health_mod,
        "inspect_containers_result",
        lambda *a, **k: health_mod.ContainerInspectResult(ok=False, error="boom"),
    )
    report = collect_status(root, slug)
    assert report.lifecycle == UNKNOWN
    assert not report.enum_ok
