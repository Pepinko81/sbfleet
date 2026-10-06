"""Diagnostic handler redaction."""

from __future__ import annotations

import io
import json
import os
import uuid
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from sbfleet import registry as reg
from sbfleet.cli import EXIT_FAILURE, EXIT_SAFETY
from sbfleet.doctor import run_doctor
from sbfleet.process import (
    CREDENTIAL_SAFE_RENDERING_UNAVAILABLE,
    sanitize_configured_diagnostic,
)
from sbfleet.sandbox import sandbox_cmd
from sbfleet.sandbox_adoption import SandboxLocks, commit_adoption_pair, new_adoption
from sbfleet.sandbox_authority import SandboxAuthorityError
from sbfleet.sandbox_config import parse_sandbox_config

SYN_SMTP = "SmtpSecretValue99XYZ"
SYN_PROVIDER = "OauthProviderSecret88ABC"
SYN_PASS = "DbPasswordValue77DEF"
SYN_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.synjwtclaimssubjectpayload"
SYN_SERVICE = "ServiceRoleKeyValue66GHI"
SYN_ADMIN = "DashboardPassword55JKL"
SYN_URL_PASS = "UrlEmbeddedPass44MNO"


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    return reg.ensure_root(tmp_path / "home")


def _seed_project(home: Path, *, slug: str = "v4002proj") -> Path:
    fid = reg.fleet_id(home)
    pid = str(uuid.uuid4())
    pdir = reg.project_dir(home, slug)
    pdir.mkdir(parents=True)
    meta = {
        "format_version": 1,
        "slug": slug,
        "id": pid,
        "fleet_id": fid,
        "display_name": slug,
        "creation_complete": True,
        "ports": {
            "gateway": 18000,
            "db_direct": 15432,
            "pooler_session": 15433,
            "pooler_transaction": 15434,
        },
        "upstream": {"ref": "v1.25.04", "sha": "deadbeef"},
        "image_digests": {},
    }
    reg.atomic_write_json(pdir / "project.json", meta, mode=0o600)
    dep = pdir / "deployment"
    dep.mkdir(exist_ok=True)
    env_path = dep / ".env"
    env_path.write_text(
        f"SMTP_PASS={SYN_SMTP}\n"
        f"GOTRUE_EXTERNAL_GOOGLE_SECRET={SYN_PROVIDER}\n"
        f"POSTGRES_PASSWORD={SYN_PASS}\n"
        f"JWT_SECRET={SYN_JWT}\n"
        f"SERVICE_ROLE_KEY={SYN_SERVICE}\n"
        f"DASHBOARD_PASSWORD={SYN_ADMIN}\n"
        f"DATABASE_URL=postgres://u:{SYN_URL_PASS}@127.0.0.1:5432/postgres\n",
        encoding="utf-8",
    )
    os.chmod(env_path, 0o600)
    return dep


def _ns(**kwargs):  # noqa: ANN003
    base = {
        "action": "start",
        "path": "/tmp/x",
        "yes": False,
        "revalidate": False,
        "migration_mode": None,
        "cmd": [],
        "json": False,
        "home": None,
    }
    base.update(kwargs)
    return SimpleNamespace(**base)


def test_doctor_190_prefix_plus_secret_redacted_human_json(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dep = _seed_project(home)
    monkeypatch.setattr("sbfleet.doctor.shutil.which", lambda n: f"/usr/bin/{n}")
    monkeypatch.setattr("sbfleet.doctor.require_local_node", lambda: None)

    class FakeUsage:
        free = 50 * 1024**3

    monkeypatch.setattr("sbfleet.doctor.shutil.disk_usage", lambda p: FakeUsage())
    monkeypatch.setattr(
        "sbfleet.doctor.run",
        lambda argv, **kwargs: MagicMock(ok=True, stdout="ok\n", stderr="", returncode=0),
    )
    monkeypatch.setattr("sbfleet.doctor.PINNED_REF", "v1.25.04")
    monkeypatch.setattr("sbfleet.upstream.verify_deployment_vendor", lambda *a, **k: None)
    monkeypatch.setattr("sbfleet.upstream.verify_stamp_matches_meta", lambda *a, **k: None)
    monkeypatch.setattr("sbfleet.branding.doctor_auth_checks", lambda *a, **k: [])
    monkeypatch.setattr("sbfleet.registry.assert_secret_file", lambda *a, **k: None)
    monkeypatch.setattr("sbfleet.authority.build_project_contract", lambda *a, **k: object())
    monkeypatch.setattr("sbfleet.authority._validate_effective_compose", lambda *a, **k: None)

    leak = ("x" * 190) + SYN_SMTP

    def boom(*_a, **_k):  # noqa: ANN002, ANN003
        raise RuntimeError(leak)

    monkeypatch.setattr("sbfleet.authority.invent_owned_resources", boom)

    out_json = io.StringIO()
    err_json = io.StringIO()
    with redirect_stdout(out_json), redirect_stderr(err_json):
        code_json = run_doctor(home, project="v4002proj", sandbox=None, as_json=True)
    payload = json.loads(out_json.getvalue())
    blob_json = json.dumps(payload) + err_json.getvalue()
    assert code_json == EXIT_SAFETY
    assert SYN_SMTP not in blob_json
    assert SYN_SMTP[:10] not in blob_json

    out_h = io.StringIO()
    err_h = io.StringIO()
    with redirect_stdout(out_h), redirect_stderr(err_h):
        code_h = run_doctor(home, project="v4002proj", sandbox=None, as_json=False)
    blob_h = out_h.getvalue() + err_h.getvalue()
    assert code_h == EXIT_SAFETY
    assert SYN_SMTP not in blob_h
    assert SYN_SMTP[:10] not in blob_h
    assert dep.is_dir()


def test_update_planner_exception_redacts_secret(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_project(home, slug="updproj")
    monkeypatch.setattr(
        "sbfleet.update.build_plan",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError(f"planner boom {SYN_SMTP}")),
    )
    from sbfleet.update import update_project

    err = io.StringIO()
    with redirect_stderr(err):
        code = update_project(
            home,
            "updproj",
            to_ref="self-hosted/v0.8.2",
            yes=True,
            dry_run=False,
            reconcile=False,
            operation_id=None,
        )
    text = err.getvalue()
    assert code == EXIT_FAILURE
    assert SYN_SMTP not in text
    assert SYN_SMTP[:10] not in text
    assert "[REDACTED]" in text or "credential-safe" in text.lower()


def test_sandbox_observer_docker_error_redacts_env_local(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    app = tmp_path / "app"
    (app / "supabase").mkdir(parents=True)
    (app / "supabase" / "config.toml").write_text(
        'project_id = "sbfleet-test-v4002"\n[api]\nport = 54321\n[db]\nport = 54322\n',
        encoding="utf-8",
    )
    (app / ".env.local").write_text(f"SMTP_PASS={SYN_SMTP}\n", encoding="utf-8")
    cfg = parse_sandbox_config(app.resolve())
    rec = new_adoption(
        canonical=app.resolve(),
        cli_project_id=cfg.project_id,
        config_fingerprint=cfg.fingerprint,
        fingerprint_fields=cfg.fingerprint_fields,
        cli_version="2.118.0",
        migration_mode="supabase",
        network_id="netv4002abcd",
        owned_resources={"volumes": [], "containers": []},
    )
    with SandboxLocks(home, app.resolve()):
        commit_adoption_pair(home, rec)

    monkeypatch.setattr("sbfleet.sandbox.require_pinned_cli", lambda: "supabase")
    dispatched: list[list[str]] = []
    monkeypatch.setattr(
        "sbfleet.sandbox.run",
        lambda argv, **kwargs: (
            dispatched.append(list(argv)) or MagicMock(ok=True, stdout="", stderr="", returncode=0)
        ),
    )

    def boom_observe(*_a, **_k):  # noqa: ANN002, ANN003
        raise SandboxAuthorityError(
            f"docker inspect failed: secret leak {SYN_SMTP} from .env.local"
        )

    monkeypatch.setattr("sbfleet.sandbox.observe_sandbox_live", boom_observe)

    err = io.StringIO()
    with redirect_stderr(err):
        code = sandbox_cmd(_ns(action="start", path=str(app), home=str(home)))
    text = err.getvalue()
    assert code == EXIT_SAFETY
    assert SYN_SMTP not in text
    assert SYN_SMTP[:10] not in text
    assert not any(a and a[0] == "supabase" and "start" in a for a in dispatched)


def test_synthetic_secret_matrix_redacted(tmp_path: Path) -> None:
    dep = tmp_path / "deployment"
    dep.mkdir()
    (dep / ".env").write_text(
        f"SMTP_PASS={SYN_SMTP}\n"
        f"GOTRUE_EXTERNAL_GOOGLE_SECRET={SYN_PROVIDER}\n"
        f"POSTGRES_PASSWORD={SYN_PASS}\n"
        f"JWT_SECRET={SYN_JWT}\n"
        f"SERVICE_ROLE_KEY={SYN_SERVICE}\n"
        f"DASHBOARD_PASSWORD={SYN_ADMIN}\n"
        f"DATABASE_URL=postgres://u:{SYN_URL_PASS}@127.0.0.1:5432/postgres\n",
        encoding="utf-8",
    )
    secrets = [SYN_SMTP, SYN_PROVIDER, SYN_PASS, SYN_JWT, SYN_SERVICE, SYN_ADMIN]
    for secret in secrets:
        raw = f"operation failed near {secret} trailing"
        out = sanitize_configured_diagnostic(raw, deployment=dep, max_len=240)
        assert secret not in out
        assert secret[:10] not in out
        assert "[REDACTED]" in out
    # Password-bearing URL: userinfo always masked.
    url_raw = f"connect failed postgres://u:{SYN_URL_PASS}@127.0.0.1:5432/postgres"
    url_out = sanitize_configured_diagnostic(url_raw, deployment=dep, max_len=240)
    assert SYN_URL_PASS not in url_out
    assert "[REDACTED]" in url_out
    # Short/common diagnostic remains useful.
    short = sanitize_configured_diagnostic("docker daemon unavailable", deployment=dep, max_len=240)
    assert "docker daemon unavailable" in short


def test_fail_safe_unreadable_source_suppresses_raw(tmp_path: Path) -> None:
    dep = tmp_path / "deployment"
    dep.mkdir()
    env = dep / ".env"
    env.write_text(f"SMTP_PASS={SYN_SMTP}\n", encoding="utf-8")
    env.chmod(0o000)
    try:
        out = sanitize_configured_diagnostic(
            f"boom {SYN_SMTP}",
            deployment=dep,
            max_len=200,
        )
        assert SYN_SMTP not in out
        assert "credential-safe" in out.lower() or CREDENTIAL_SAFE_RENDERING_UNAVAILABLE[:20] in out
    finally:
        env.chmod(0o600)


def test_doctor_early_docker_info_secret_redacted(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: docker info stderr before redactor must still redact configured SMTP."""
    _seed_project(home)
    leak = ("x" * 190) + SYN_SMTP
    monkeypatch.setattr("sbfleet.doctor.shutil.which", lambda n: f"/usr/bin/{n}")
    monkeypatch.setattr("sbfleet.doctor.require_local_node", lambda: None)

    class FakeUsage:
        free = 50 * 1024**3

    monkeypatch.setattr("sbfleet.doctor.shutil.disk_usage", lambda p: FakeUsage())

    def fake_run(argv, **kwargs):  # noqa: ANN001, ANN003
        if list(argv[:2]) == ["docker", "info"]:
            return MagicMock(ok=False, stdout="", stderr=leak, returncode=1)
        return MagicMock(ok=True, stdout="ok\n", stderr="", returncode=0)

    monkeypatch.setattr("sbfleet.doctor.run", fake_run)
    monkeypatch.setattr("sbfleet.doctor.PINNED_REF", "v1.25.04")
    monkeypatch.setattr("sbfleet.upstream.verify_deployment_vendor", lambda *a, **k: None)
    monkeypatch.setattr("sbfleet.upstream.verify_stamp_matches_meta", lambda *a, **k: None)
    monkeypatch.setattr("sbfleet.branding.doctor_auth_checks", lambda *a, **k: [])
    monkeypatch.setattr("sbfleet.registry.assert_secret_file", lambda *a, **k: None)
    monkeypatch.setattr("sbfleet.authority.build_project_contract", lambda *a, **k: object())
    monkeypatch.setattr("sbfleet.authority._validate_effective_compose", lambda *a, **k: None)
    monkeypatch.setattr(
        "sbfleet.authority.invent_owned_resources",
        lambda *a, **k: MagicMock(containers=[], networks=[], volumes=[]),
    )

    out_json = io.StringIO()
    err_json = io.StringIO()
    with redirect_stdout(out_json), redirect_stderr(err_json):
        code_json = run_doctor(home, project="v4002proj", sandbox=None, as_json=True)
    blob_json = out_json.getvalue() + err_json.getvalue()
    assert code_json in {EXIT_SAFETY, 4}
    assert SYN_SMTP not in blob_json
    assert SYN_SMTP[:10] not in blob_json

    out_h = io.StringIO()
    err_h = io.StringIO()
    with redirect_stdout(out_h), redirect_stderr(err_h):
        code_h = run_doctor(home, project="v4002proj", sandbox=None, as_json=False)
    blob_h = out_h.getvalue() + err_h.getvalue()
    assert code_h in {EXIT_SAFETY, 4}
    assert SYN_SMTP not in blob_h
    assert SYN_SMTP[:10] not in blob_h


def test_reconcile_staging_rebind_json_reason_redacts_secret(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: reconcile JSON reason must pass configured diagnostic boundary."""
    import uuid

    from sbfleet import update as upd
    from sbfleet.update import UpdateError

    slug = "v4002rec"
    dep = _seed_project(home, slug=slug)
    fid = reg.fleet_id(home)
    meta = reg.read_project(home, slug)
    op_id = uuid.uuid4().hex
    backup_id = "bk-synth-" + uuid.uuid4().hex[:8]
    staging = home / "staging" / f"update-{op_id}"
    staging.mkdir(parents=True)
    (staging / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    live = dep
    quarantine = home / "staging" / f"update-quarantine-{op_id}"
    quarantine.mkdir(parents=True)
    rels = ["docker-compose.yml"]
    (live / "docker-compose.yml").write_text("services: {old: {}}\n", encoding="utf-8")
    record = upd.build_promote_record(
        operation_id=op_id,
        from_ref="self-hosted/v0.8.1",
        from_sha="1" * 40,
        to_ref="self-hosted/v0.8.2",
        to_sha="2" * 40,
        backup_id=backup_id,
        staging=staging,
        deployment=live,
        quarantine=quarantine,
        relpaths=rels,
    )
    upd.write_promote_record(staging, record)
    journal = {
        "format_version": 1,
        "operation_id": op_id,
        "intent": "UPDATING",
        "status": "in_progress",
        "phase": "promoting",
        "evidence": {
            "backup_id": backup_id,
            "promote_record_path": str(upd.promote_record_path(staging)),
        },
    }
    reg.atomic_write_json(reg.project_dir(home, slug) / "operation.json", journal, mode=0o600)

    class FakeCtx:
        def __init__(self) -> None:
            self.root = home
            self.slug = slug
            self.deployment = dep
            self.meta = meta
            self.operation_id = op_id
            self.inventory = None

    monkeypatch.setattr(
        "sbfleet.authority.authorize_mutation",
        lambda *a, **k: __import__("contextlib").nullcontext(FakeCtx()),
    )
    monkeypatch.setattr("sbfleet.authority.record_operation_phase", lambda *a, **k: {})
    monkeypatch.setattr(
        "sbfleet.update.bind_staging_to_approved_target",
        lambda *a, **k: (_ for _ in ()).throw(UpdateError(f"ordinary bind error {SYN_SMTP}")),
    )

    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = upd.reconcile_interrupted_update(home, slug, operation_id=op_id, yes=True)
    blob = out.getvalue() + err.getvalue()
    assert code == EXIT_SAFETY
    assert SYN_SMTP not in blob
    assert SYN_SMTP[:10] not in blob
    payload = json.loads(out.getvalue())
    assert payload.get("operation_id") == op_id
    assert payload.get("reconcile") is True
    assert SYN_SMTP not in str(payload.get("reason", ""))
    # Journal must not contain the configured secret either.
    jpath = reg.project_dir(home, slug) / "operation.json"
    if jpath.is_file():
        assert SYN_SMTP not in jpath.read_text(encoding="utf-8")
    assert fid == reg.fleet_id(home)
