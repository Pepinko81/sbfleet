"""Presentation configure: dual-file write, rollback, CONFIGURED vs APPLIED."""

from __future__ import annotations

import os
import stat
import uuid
from pathlib import Path
from typing import Any

import pytest

from sbfleet import configure as cfg
from sbfleet import registry as reg
from sbfleet import upstream as up
from sbfleet.cli import (
    EXIT_NOT_FOUND,
    EXIT_OK,
    EXIT_USAGE,
    build_parser,
    dispatch_namespace,
)


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    return reg.ensure_root(tmp_path / "home")


def _meta(root: Path, slug: str, **extra: Any) -> dict[str, Any]:
    fid = reg.fleet_id(root)
    pid = str(uuid.uuid4())
    data = {
        "format_version": 1,
        "id": pid,
        "fleet_id": fid,
        "slug": slug,
        "display_name": slug.title(),
        "created_at": "2026-10-04T00:00:00Z",
        "profile": "standard",
        "compose_project": reg.compose_project_name(fid, pid),
        "ports": {
            "gateway": 54321,
            "db_direct": 54322,
            "pooler_session": 54323,
            "pooler_transaction": 54324,
        },
        "domain": None,
        "public_url": "http://127.0.0.1:54321",
        "upstream": {"ref": up.PINNED_REF, "sha": up.PINNED_SHA},
        "last_verified_upstream": None,
        "image_digests": {},
        "creation_complete": True,
        "branding": {
            "organization_name": "Default Organization",
            "project_name": "Default Project",
        },
    }
    data.update(extra)
    return data


def _seed_project(root: Path, slug: str = "myapp", **extra: Any) -> dict[str, Any]:
    meta = _meta(root, slug, **extra)
    pdir = reg.project_dir(root, slug)
    dep = pdir / "deployment"
    dep.mkdir(parents=True)
    (dep / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    os.chmod(dep / "run.sh", 0o700)
    env = {
        "JWT_SECRET": "j" * 32,
        "ANON_KEY": "anon-secret-value",
        "SERVICE_ROLE_KEY": "svc-secret-value",
        "POSTGRES_PASSWORD": "p" * 32,
        "DASHBOARD_PASSWORD": "d" * 32,
        "COMPOSE_PROJECT_NAME": str(meta["compose_project"]),
        "COMPOSE_FILE": "docker-compose.yml:docker-compose.override.yml",
        "COMPOSE_PATH_SEPARATOR": ":",
        "STUDIO_DEFAULT_ORGANIZATION": "Default Organization",
        "STUDIO_DEFAULT_PROJECT": "Default Project",
        "GATEWAY_PORT": "54321",
    }
    env_path = dep / ".env"
    env_path.write_text(up.dump_dotenv(env), encoding="utf-8")
    os.chmod(env_path, 0o600)
    reg.write_project(root, meta)
    return meta


def test_atomic_write_dotenv_preserves_mode(home: Path, tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("A=1\n", encoding="utf-8")
    os.chmod(path, 0o640)
    up.atomic_write_dotenv(path, {"A": "2", "B": "x"})
    st = path.stat()
    assert st.st_mode & 0o777 == 0o640
    assert up.parse_dotenv(path.read_text(encoding="utf-8"))["A"] == "2"


def test_atomic_write_failure_leaves_original(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / ".env"
    path.write_text(up.dump_dotenv({"KEEP": "yes"}), encoding="utf-8")
    os.chmod(path, 0o600)
    original = path.read_text(encoding="utf-8")

    def boom(*_a: Any, **_k: Any) -> None:
        raise OSError("inject replace failure")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        up.atomic_write_dotenv(path, {"KEEP": "no"})
    assert path.read_text(encoding="utf-8") == original


def test_read_mode_and_name_only(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    meta = _seed_project(home)
    monkeypatch.setattr(cfg, "_probe_studio_env", lambda *_a, **_k: {})
    result = cfg.configure_project(home, "myapp")
    assert result.mutated is False
    assert result.snapshot.slug == "myapp"
    assert "immutable" in cfg.format_configure_human(result)
    assert result.applied.status == "pending_start"

    result2 = cfg.configure_project(home, "myapp", display_name="Orders App")
    assert result2.mutated is True
    assert any("display_name" in c for c in result2.changed)
    meta2 = reg.read_project(home, "myapp")
    assert meta2["display_name"] == "Orders App"
    assert meta2["slug"] == meta["slug"]
    assert meta2["id"] == meta["id"]
    assert meta2["compose_project"] == meta["compose_project"]
    assert meta2["ports"] == meta["ports"]
    env = up.parse_dotenv((reg.project_dir(home, "myapp") / "deployment" / ".env").read_text())
    assert env["JWT_SECRET"] == "j" * 32
    assert env["ANON_KEY"] == "anon-secret-value"


def test_organization_project_both(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    meta = _seed_project(home)
    monkeypatch.setattr(cfg, "_probe_studio_env", lambda *_a, **_k: {})
    secrets_before = up.parse_dotenv(
        (reg.project_dir(home, "myapp") / "deployment" / ".env").read_text()
    )

    cfg.configure_project(home, "myapp", organization_name_value="Acme")
    env = up.parse_dotenv((reg.project_dir(home, "myapp") / "deployment" / ".env").read_text())
    assert env["STUDIO_DEFAULT_ORGANIZATION"] == "Acme"
    assert env["STUDIO_DEFAULT_PROJECT"] == "Default Project"
    meta1 = reg.read_project(home, "myapp")
    assert meta1["branding"]["organization_name"] == "Acme"
    assert meta1["branding"]["project_name"] == "Default Project"

    cfg.configure_project(home, "myapp", studio_project_value="Orders")
    env = up.parse_dotenv((reg.project_dir(home, "myapp") / "deployment" / ".env").read_text())
    assert env["STUDIO_DEFAULT_ORGANIZATION"] == "Acme"
    assert env["STUDIO_DEFAULT_PROJECT"] == "Orders"

    cfg.configure_project(
        home,
        "myapp",
        organization_name_value="Corp",
        studio_project_value="Billing",
    )
    env = up.parse_dotenv((reg.project_dir(home, "myapp") / "deployment" / ".env").read_text())
    assert env["STUDIO_DEFAULT_ORGANIZATION"] == "Corp"
    assert env["STUDIO_DEFAULT_PROJECT"] == "Billing"
    for key in (
        "JWT_SECRET",
        "ANON_KEY",
        "SERVICE_ROLE_KEY",
        "POSTGRES_PASSWORD",
        "DASHBOARD_PASSWORD",
    ):
        assert env[key] == secrets_before[key]
    meta2 = reg.read_project(home, "myapp")
    assert meta2["id"] == meta["id"]
    assert meta2["slug"] == "myapp"
    assert meta2["compose_project"] == meta["compose_project"]
    assert meta2["ports"] == meta["ports"]


def test_malformed_input(home: Path) -> None:
    _seed_project(home)
    with pytest.raises(cfg.ConfigureError) as exc:
        cfg.configure_project(home, "myapp", organization_name_value="bad\nname")
    assert exc.value.code == 2
    with pytest.raises(cfg.ConfigureError) as exc2:
        cfg.configure_project(home, "myapp", display_name="x" * 101)
    assert exc2.value.code == 2


def test_nonexistent_project(home: Path) -> None:
    with pytest.raises(cfg.ConfigureError) as exc:
        cfg.configure_project(home, "missing")
    assert exc.value.code == 3


def test_second_project_unaffected(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_project(home, "alpha")
    meta_b = _seed_project(home, "beta")
    monkeypatch.setattr(cfg, "_probe_studio_env", lambda *_a, **_k: {})
    cfg.configure_project(home, "alpha", organization_name_value="OnlyA")
    env_b = up.parse_dotenv((reg.project_dir(home, "beta") / "deployment" / ".env").read_text())
    assert env_b["STUDIO_DEFAULT_ORGANIZATION"] == "Default Organization"
    meta_b2 = reg.read_project(home, "beta")
    assert meta_b2["id"] == meta_b["id"]
    assert meta_b2["display_name"] == meta_b["display_name"]


def test_dual_file_rollback_success(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    meta = _seed_project(home)
    env_path = reg.project_dir(home, "myapp") / "deployment" / ".env"
    before_env = env_path.read_text(encoding="utf-8")
    before_meta = reg.read_project(home, "myapp")

    def fail_env(_path: Path, _values: dict[str, str]) -> None:
        raise OSError("inject env write failure")

    monkeypatch.setattr(cfg, "_env_write", fail_env)
    with pytest.raises(cfg.ConfigureError) as exc:
        cfg.configure_project(home, "myapp", organization_name_value="ShouldFail")
    assert exc.value.code == 5
    assert "rolled back" in str(exc.value).lower()
    assert env_path.read_text(encoding="utf-8") == before_env
    after = reg.read_project(home, "myapp")
    assert after["branding"] == before_meta["branding"]
    assert after["id"] == meta["id"]


def test_dual_file_rollback_failure_reports_drift(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_project(home)
    calls = {"n": 0}
    original_write = reg.write_project

    def flaky_write(root: Path, data: Any) -> Path:
        calls["n"] += 1
        if calls["n"] == 1:
            return original_write(root, data)
        raise OSError("inject rollback failure")

    monkeypatch.setattr(reg, "write_project", flaky_write)

    def fail_env(_path: Path, _values: dict[str, str]) -> None:
        raise OSError("inject env write failure")

    monkeypatch.setattr(cfg, "_env_write", fail_env)
    with pytest.raises(cfg.ConfigureError) as exc:
        cfg.configure_project(home, "myapp", organization_name_value="DriftOrg")
    assert exc.value.code == 5
    assert "drift" in str(exc.value).lower() or "inconsistency" in str(exc.value).lower()
    # Meta may have new value (first write succeeded); never claim success via return.
    meta = reg.read_project(home, "myapp")
    assert meta["branding"]["organization_name"] == "DriftOrg"


def test_read_detects_meta_env_drift(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_project(home)
    env_path = reg.project_dir(home, "myapp") / "deployment" / ".env"
    env = up.parse_dotenv(env_path.read_text(encoding="utf-8"))
    env["STUDIO_DEFAULT_ORGANIZATION"] = "EnvOnly"
    env_path.write_text(up.dump_dotenv(env), encoding="utf-8")
    os.chmod(env_path, 0o600)
    monkeypatch.setattr(cfg, "_probe_studio_env", lambda *_a, **_k: {})
    result = cfg.configure_project(home, "myapp")
    assert result.snapshot.drift
    text = cfg.format_configure_human(result)
    assert "drift" in text.lower()


def test_applied_no_while_running(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_project(home)
    monkeypatch.setattr(
        cfg,
        "_probe_studio_env",
        lambda *_a, **_k: {
            "STUDIO_DEFAULT_ORGANIZATION": "Default Organization",
            "STUDIO_DEFAULT_PROJECT": "Default Project",
        },
    )
    cfg.configure_project(
        home,
        "myapp",
        organization_name_value="Acme",
        studio_project_value="Orders",
    )
    # Probe still returns old Env (stale containers).
    result = cfg.configure_project(home, "myapp")
    assert result.applied.status == "no"
    text = cfg.format_configure_human(result)
    assert "stop" in text and "start" in text
    assert "restart does not refresh" in text.lower()


def test_project_json_mode_contract(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_project(home)
    meta_path = reg.project_json_path(home, "myapp")
    before_mode = meta_path.stat().st_mode & 0o777
    monkeypatch.setattr(cfg, "_probe_studio_env", lambda *_a, **_k: {})
    cfg.configure_project(home, "myapp", display_name="Renamed")
    after_mode = meta_path.stat().st_mode & 0o777
    assert after_mode == before_mode
    assert not stat.S_ISLNK(meta_path.lstat().st_mode)


def test_lock_released_before_probe(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_project(home)
    order: list[str] = []

    def probe(*_a: Any, **_k: Any) -> dict[str, str]:
        order.append("probe")
        return {}

    def released() -> None:
        order.append("released")

    monkeypatch.setattr(cfg, "_probe_studio_env", probe)
    monkeypatch.setattr(cfg, "_lock_released_hook", released)
    cfg.configure_project(home, "myapp", organization_name_value="Acme")
    assert order == ["released", "probe"]


def test_cli_dispatch_configure(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_project(home)
    monkeypatch.setattr(cfg, "_probe_studio_env", lambda *_a, **_k: {})
    monkeypatch.setenv("SBFLEET_HOME", str(home))
    parser = build_parser()
    args = parser.parse_args(
        ["--home", str(home), "configure", "myapp", "--organization-name", "Acme"]
    )
    assert dispatch_namespace(args) == EXIT_OK
    args2 = parser.parse_args(["--home", str(home), "configure", "missing"])
    assert dispatch_namespace(args2) == EXIT_NOT_FOUND
    with pytest.raises(SystemExit) as se:
        parser.parse_args(["configure"])  # missing project
    assert se.value.code == EXIT_USAGE or se.value.code == 2


def test_cli_malformed_returns_usage(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_project(home)
    monkeypatch.setattr(cfg, "_probe_studio_env", lambda *_a, **_k: {})
    parser = build_parser()
    args = parser.parse_args(
        ["--home", str(home), "configure", "myapp", "--organization-name", "bad\nline"]
    )
    code = dispatch_namespace(args)
    assert code == EXIT_USAGE


def test_env_mode_preserved_on_configure(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_project(home)
    env_path = reg.project_dir(home, "myapp") / "deployment" / ".env"
    os.chmod(env_path, 0o600)
    monkeypatch.setattr(cfg, "_probe_studio_env", lambda *_a, **_k: {})
    cfg.configure_project(home, "myapp", studio_project_value="X")
    assert env_path.stat().st_mode & 0o777 == 0o600
    assert env_path.stat().st_uid == os.getuid()
