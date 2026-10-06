"""Process tests for sandbox authority (regression suite)."""

from __future__ import annotations

import argparse
from pathlib import Path
from unittest import mock

import pytest

from sbfleet import sandbox as sb
from sbfleet.cli import EXIT_SAFETY, EXIT_USAGE
from sbfleet.sandbox_adoption import (
    SandboxLocks,
    canonicalize_app_root,
    commit_adoption_pair,
    new_adoption,
    reconcile_adoption_index,
    update_record_fields,
)
from sbfleet.sandbox_authority import SandboxAuthorityError
from sbfleet.sandbox_config import parse_sandbox_config


def _ns(**kwargs):
    defaults = {
        "action": "status",
        "path": ".",
        "cmd": [],
        "yes": False,
        "json": False,
        "revalidate": False,
        "migration_mode": None,
        "home": None,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


@pytest.fixture
def adopted_app(tmp_path: Path):
    app = tmp_path / "app"
    app.mkdir()
    (app / "supabase").mkdir()
    (app / "supabase" / "config.toml").write_text(
        'project_id = "sbfleet-test-proc1"\n[api]\nport = 54321\n[db]\nport = 54322\n'
        "major_version = 15\n[db.migrations]\nenabled = true\n[db.seed]\nenabled = true\n"
        "[studio]\nport = 54323\n",
        encoding="utf-8",
    )
    home = tmp_path / "home"
    home.mkdir()
    canonical = canonicalize_app_root(app, fleet_home=home)
    cfg = parse_sandbox_config(canonical)
    rec = new_adoption(
        canonical=canonical,
        cli_project_id=cfg.project_id,
        config_fingerprint=cfg.fingerprint,
        fingerprint_fields=cfg.fingerprint_fields,
        cli_version="2.118.0",
        migration_mode="supabase",
    )
    with SandboxLocks(home, canonical):
        commit_adoption_pair(home, rec)
    return app, home, cfg


def test_remainder_preserves_env_child_flags() -> None:
    args = _ns(action="env", cmd=["--", "echo", "--yes", "--json"])
    cmd = sb._parse_remainder_flags(args)
    assert cmd == ["echo", "--yes", "--json"]
    assert args.yes is False


def test_revalidate_only_on_start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sb, "require_pinned_cli", lambda: "supabase")
    args = _ns(action="reset", path=str(tmp_path), revalidate=True, yes=True)
    rc = sb.sandbox_cmd(args)
    assert rc == EXIT_USAGE


def test_env_refuses_when_status_fails(adopted_app, monkeypatch: pytest.MonkeyPatch) -> None:
    app, home, _cfg = adopted_app
    monkeypatch.setattr(sb, "require_pinned_cli", lambda: "supabase")

    class R:
        ok = False
        stdout = ""
        stderr = "boom"
        returncode = 1

    monkeypatch.setattr(sb, "run", lambda *a, **k: R())
    args = _ns(action="env", path=str(app), home=str(home), cmd=["--", "true"])
    rc = sb.sandbox_cmd(args)
    assert rc == EXIT_SAFETY


def test_fingerprint_drift_refuses_start_without_revalidate(
    adopted_app, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, home, _cfg = adopted_app
    text = (app / "supabase" / "config.toml").read_text(encoding="utf-8")
    (app / "supabase" / "config.toml").write_text(
        text.replace("port = 54321", "port = 54329"),
        encoding="utf-8",
    )
    monkeypatch.setattr(sb, "require_pinned_cli", lambda: "supabase")
    args = _ns(action="start", path=str(app), home=str(home))
    rc = sb.sandbox_cmd(args)
    assert rc == EXIT_SAFETY


def test_malformed_docker_inspect_fail_closed() -> None:
    from sbfleet import sandbox_authority as auth

    with mock.patch("sbfleet.sandbox_authority.run") as m:
        m.return_value = mock.Mock(ok=True, stdout="not-json", stderr="")
        with pytest.raises(SandboxAuthorityError, match="malformed"):
            auth._docker_json(["docker", "network", "inspect", "x"])


def test_start_argv_uses_workdir_and_network(adopted_app, monkeypatch: pytest.MonkeyPatch) -> None:
    app, home, cfg = adopted_app
    monkeypatch.setattr(sb, "require_pinned_cli", lambda: "/usr/bin/supabase")
    captured: dict = {}

    monkeypatch.setattr(sb, "ensure_owned_network", lambda record: "netiddeadbeef")
    monkeypatch.setattr(sb, "prove_network_owned", lambda *a, **k: {})
    monkeypatch.setattr(
        sb,
        "invent_owned_resources",
        lambda **k: {
            "containers": [{"id": "c1", "name": "n", "labels": {}}],
            "volumes": [],
            "network_id": "netiddeadbeef",
            "labels_expected": {},
            "published_bindings": [
                {
                    "container_id": "c1",
                    "port": "54321/tcp",
                    "host_ip": "127.0.0.1",
                    "host_port": "54321",
                }
            ],
        },
    )
    monkeypatch.setattr(sb, "assert_effective_bindings", lambda inv: None)

    def fake_run(argv, **kwargs):
        captured["argv"] = list(argv)
        return mock.Mock(ok=True, stdout="{}", stderr="", returncode=0)

    monkeypatch.setattr(sb, "run", fake_run)

    canonical = canonicalize_app_root(app, fleet_home=home)
    with SandboxLocks(home, canonical):
        rec = reconcile_adoption_index(home, canonical, cli_project_id=cfg.project_id)
        assert rec
        rec = update_record_fields(rec, network_id="netiddeadbeef")
        commit_adoption_pair(home, rec)

    args = _ns(action="start", path=str(app), home=str(home))
    rc = sb.sandbox_cmd(args)
    assert rc == 0
    assert captured["argv"][0] == "/usr/bin/supabase"
    assert "--workdir" in captured["argv"]
    assert str(app.resolve()) in captured["argv"]
    assert "--network-id" in captured["argv"]
    assert "start" in captured["argv"]
    assert "--linked" not in captured["argv"]
