"""Configured diagnostic boundary."""

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

from sbfleet import authority as auth
from sbfleet import registry as reg
from sbfleet.cli import EXIT_FAILURE, EXIT_SAFETY
from sbfleet.doctor import run_doctor
from sbfleet.process import (
    DiagnosticRedactorUnavailable,
    Redactor,
    StreamingRedactor,
    project_diagnostic_redactor,
    redactor_from_dotenv_paths,
    sandbox_diagnostic_redactor,
    sanitize_configured_diagnostic,
    sanitize_diagnostic,
)
from sbfleet.sandbox import _emit_status, sandbox_cmd
from sbfleet.sandbox_adoption import SandboxLocks, commit_adoption_pair, new_adoption
from sbfleet.sandbox_authority import ClassObservation, SandboxLiveAuthority
from sbfleet.sandbox_config import parse_sandbox_config

SYN_SMTP = "SmtpSecretValue99XYZ"
SYN_PROVIDER = "OauthProviderSecret88ABC"
SYN_PASS = "DbPasswordValue77DEF"
SYN_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.synjwtclaimssubjectpayload"


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    return reg.ensure_root(tmp_path / "home")


def _seed_project(home: Path, *, slug: str = "diagproj") -> Path:
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
        f"DATABASE_URL=postgres://u:{SYN_PASS}@127.0.0.1:5432/postgres\n",
        encoding="utf-8",
    )
    os.chmod(env_path, 0o600)
    return dep


def test_sandbox_redactor_includes_env_local(tmp_path: Path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / ".env.local").write_text(f"SMTP_PASS={SYN_SMTP}\n", encoding="utf-8")
    r = sandbox_diagnostic_redactor(app)
    out = sanitize_diagnostic(f"fail containing {SYN_SMTP}", redactor=r)
    assert SYN_SMTP not in out
    assert "[REDACTED]" in out


def test_fail_safe_unreadable_dotenv_raises(tmp_path: Path) -> None:
    dep = tmp_path / "deployment"
    dep.mkdir()
    env = dep / ".env"
    env.write_text(f"SMTP_PASS={SYN_SMTP}\n", encoding="utf-8")
    env.chmod(0o000)
    try:
        with pytest.raises(DiagnosticRedactorUnavailable):
            project_diagnostic_redactor(dep)
    finally:
        env.chmod(0o600)


def test_fail_safe_unsupported_grammar(tmp_path: Path) -> None:
    dep = tmp_path / "deployment"
    dep.mkdir()
    (dep / ".env").write_text("SMTP_PASS=foo$$barsecret99\n", encoding="utf-8")
    with pytest.raises(DiagnosticRedactorUnavailable):
        redactor_from_dotenv_paths([dep / ".env"])


def test_sanitize_configured_suppresses_raw_when_source_bad(tmp_path: Path) -> None:
    dep = tmp_path / "deployment"
    dep.mkdir()
    (dep / ".env").write_text("SMTP_PASS=foo$$barsecret99\n", encoding="utf-8")
    out = sanitize_configured_diagnostic(
        f"compose failed with leak {SYN_SMTP}",
        deployment=dep,
        max_len=200,
    )
    assert SYN_SMTP not in out
    assert "credential-safe" in out


def test_doctor_compose_failure_redacts_smtp(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_project(home)
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

    def boom(*_a, **_k):  # noqa: ANN002, ANN003
        raise RuntimeError(f"compose contract failed smtp={SYN_SMTP}")

    monkeypatch.setattr("sbfleet.authority.build_project_contract", boom)
    monkeypatch.setattr("sbfleet.authority._validate_effective_compose", boom)
    monkeypatch.setattr("sbfleet.compose.compose_config_json", boom)
    monkeypatch.setattr("sbfleet.compose.vendor_expected_images", boom)
    monkeypatch.setattr("sbfleet.compose.validate_resolved_config", boom)

    class Inv:
        residuals: list = []
        containers: list = []

    monkeypatch.setattr("sbfleet.authority.invent_owned_resources", lambda **k: Inv())

    class Report:
        lifecycle = "STOPPED"
        probes: list = []

    monkeypatch.setattr("sbfleet.health.collect_status", lambda *a, **k: Report())

    buf = io.StringIO()
    with redirect_stdout(buf):
        code = run_doctor(home, project="diagproj", sandbox=None, as_json=True)
    payload = json.loads(buf.getvalue())
    blob = json.dumps(payload)
    assert SYN_SMTP not in blob
    assert code == EXIT_SAFETY
    assert any(
        c["id"] == "compose-contract" and c["status"] == "fail" for c in payload["data"]["checks"]
    )


def test_sandbox_start_failure_redacts_env_local(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    app = tmp_path / "app"
    (app / "supabase").mkdir(parents=True)
    (app / "supabase" / "config.toml").write_text(
        'project_id = "sbfleet-test-v3c06"\n[api]\nport = 54321\n[db]\nport = 54322\n',
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
        network_id="net06",
    )
    with SandboxLocks(home, app.resolve()):
        commit_adoption_pair(home, rec)

    monkeypatch.setattr("sbfleet.sandbox.require_pinned_cli", lambda: "supabase")
    monkeypatch.setattr(
        "sbfleet.sandbox.observe_sandbox_live",
        lambda *_a, **_k: SandboxLiveAuthority(
            containers=ClassObservation(status="CONFIRMED_ABSENT"),
            network=ClassObservation(status="PRESENT_AND_OWNED", ids=["net06"]),
            volumes=ClassObservation(status="CONFIRMED_ABSENT"),
        ),
    )
    monkeypatch.setattr("sbfleet.sandbox.ensure_owned_network", lambda a: "net06")
    monkeypatch.setattr("sbfleet.sandbox.prove_network_owned", lambda *a, **k: {})
    monkeypatch.setattr(
        "sbfleet.sandbox.run",
        lambda argv, **kwargs: MagicMock(
            ok=False,
            stdout="",
            stderr=f"start failed smtp={SYN_SMTP}",
            returncode=1,
        ),
    )
    err = io.StringIO()
    with redirect_stderr(err):
        code = sandbox_cmd(
            SimpleNamespace(
                action="start",
                path=str(app),
                yes=False,
                revalidate=False,
                migration_mode=None,
                cmd=[],
                json=False,
                home=str(home),
            )
        )
    assert code == EXIT_FAILURE
    assert SYN_SMTP not in err.getvalue()
    assert "[REDACTED]" in err.getvalue()


def test_sandbox_fail_safe_unreadable_env_local(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When redactor construction fails, ordinary emit must not leak raw subprocess text."""
    home = tmp_path / "home"
    home.mkdir()
    app = tmp_path / "app"
    (app / "supabase").mkdir(parents=True)
    (app / "supabase" / "config.toml").write_text(
        'project_id = "sbfleet-test-v3c06b"\n[api]\nport = 54321\n[db]\nport = 54322\n',
        encoding="utf-8",
    )
    cfg = parse_sandbox_config(app.resolve())
    rec = new_adoption(
        canonical=app.resolve(),
        cli_project_id=cfg.project_id,
        config_fingerprint=cfg.fingerprint,
        fingerprint_fields=cfg.fingerprint_fields,
        cli_version="2.118.0",
        migration_mode="supabase",
        network_id="net06b",
    )
    with SandboxLocks(home, app.resolve()):
        commit_adoption_pair(home, rec)
    monkeypatch.setattr("sbfleet.sandbox.require_pinned_cli", lambda: "supabase")
    monkeypatch.setattr(
        "sbfleet.sandbox._sandbox_redactor",
        lambda *_a, **_k: (_ for _ in ()).throw(
            DiagnosticRedactorUnavailable("supported dotenv source unreadable")
        ),
    )
    monkeypatch.setattr(
        "sbfleet.sandbox.observe_sandbox_live",
        lambda *_a, **_k: SandboxLiveAuthority(
            containers=ClassObservation(status="CONFIRMED_ABSENT"),
            network=ClassObservation(status="PRESENT_AND_OWNED", ids=["net06b"]),
            volumes=ClassObservation(status="CONFIRMED_ABSENT"),
        ),
    )
    monkeypatch.setattr("sbfleet.sandbox.ensure_owned_network", lambda a: "net06b")
    monkeypatch.setattr("sbfleet.sandbox.prove_network_owned", lambda *a, **k: {})
    monkeypatch.setattr(
        "sbfleet.sandbox.run",
        lambda argv, **kwargs: MagicMock(
            ok=False,
            stdout="",
            stderr=f"raw leak {SYN_SMTP}",
            returncode=1,
        ),
    )
    err = io.StringIO()
    with redirect_stderr(err):
        code = sandbox_cmd(
            SimpleNamespace(
                action="start",
                path=str(app),
                yes=False,
                revalidate=False,
                migration_mode=None,
                cmd=[],
                json=False,
                home=str(home),
            )
        )
    text = err.getvalue()
    assert code == EXIT_FAILURE
    assert SYN_SMTP not in text
    assert "credential-safe" in text


def test_password_url_and_truncate() -> None:
    r = Redactor()
    r.add(SYN_PASS)
    out = sanitize_diagnostic(f"postgres://u:{SYN_PASS}@127.0.0.1/db", redactor=r)
    assert SYN_PASS not in out
    assert ":[REDACTED]@" in sanitize_diagnostic(
        f"postgres://u:{SYN_PASS}@host/db", redactor=Redactor()
    )
    long = ("x" * 100) + SYN_PASS + ("y" * 100)
    trunc = sanitize_diagnostic(long, redactor=r, max_len=50)
    assert SYN_PASS not in trunc
    assert len(trunc) <= 50


def test_streaming_chunk_split_secret() -> None:
    r = Redactor()
    r.add(SYN_SMTP)
    stream = StreamingRedactor(redactor=r)
    emitted = stream.feed(SYN_SMTP[:6]) + stream.feed(SYN_SMTP[6:]) + stream.flush()
    assert SYN_SMTP not in emitted
    assert "[REDACTED]" in emitted


def test_emit_status_redacts() -> None:
    r = Redactor()
    r.add(SYN_SMTP)
    result = MagicMock(ok=False, returncode=1, stderr=f"status boom {SYN_SMTP}", stdout="")
    err = io.StringIO()
    with redirect_stderr(err):
        code = _emit_status(
            SimpleNamespace(json=False),
            "pid",
            result,
            redactor=r,
            redactor_ok=True,
        )
    assert code == EXIT_FAILURE
    assert SYN_SMTP not in err.getvalue()


def test_short_common_words_remain_readable() -> None:
    r = Redactor()
    r.add(SYN_SMTP)
    msg = "error: start failed container unhealthy postgres localhost"
    out = sanitize_diagnostic(msg, redactor=r)
    assert "postgres" in out
    assert "localhost" in out
    assert "unhealthy" in out


def test_journal_fail_operation_redacts(home: Path) -> None:
    dep = _seed_project(home, slug="jproj")
    meta = reg.read_project(home, "jproj")
    ctx = auth.MutationContext(
        root=home,
        slug="jproj",
        meta=meta,
        deployment=dep,
        project_dir=reg.project_dir(home, "jproj"),
        compose_project="sbfleet_ff_aa",
        fleet_id=str(meta["fleet_id"]),
        project_id=str(meta["id"]),
        compose_env={},
        intent="backup",
        operation_id="op-test-006",
    )
    auth.fail_operation(ctx, error=f"backup failed smtp={SYN_SMTP} provider={SYN_PROVIDER}")
    journal = reg.read_operation_journal(home, "jproj")
    assert journal is not None
    err = str(journal.get("error") or "")
    assert SYN_SMTP not in err
    assert SYN_PROVIDER not in err
