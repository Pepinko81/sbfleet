"""Host application connection contract — ports, env injection, restart stability."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sbfleet import connection as conn
from sbfleet import registry as reg
from sbfleet import upstream as up
from sbfleet.connection import connection_info, format_connection_human


def _project(root: Path, slug: str, ports: dict[str, int], pid: str) -> dict:
    reg.ensure_root(root)
    meta = {
        "format_version": 1,
        "id": pid,
        "fleet_id": reg.fleet_id(root),
        "slug": slug,
        "display_name": slug,
        "created_at": "2026-01-01T00:00:00Z",
        "profile": "standard",
        "compose_project": f"sbfleet-{pid.replace('-', '')[:24]}",
        "ports": ports,
        "domain": None,
        "public_url": f"http://127.0.0.1:{ports['gateway']}",
        "upstream": {"ref": up.PINNED_REF, "sha": up.PINNED_SHA},
        "creation_complete": True,
    }
    reg.write_project(root, meta)
    dep = reg.project_dir(root, slug) / "deployment"
    dep.mkdir(parents=True, exist_ok=True)
    env = {
        "POSTGRES_PASSWORD": "p" * 20,
        "POSTGRES_DB": "postgres",
        "POOLER_TENANT_ID": "tenant",
        "ANON_KEY": "a" * 40,
        "SERVICE_ROLE_KEY": "b" * 40,
        "SUPABASE_PUBLISHABLE_KEY": "a" * 40,
        "SUPABASE_SECRET_KEY": "b" * 40,
        "JWT_SECRET": "j" * 32,
        "JWT_KEYS": "[{}]",
        "JWT_JWKS": '{"keys":[{}]}',
        "DASHBOARD_PASSWORD": "d" * 20,
        "SECRET_KEY_BASE": "s" * 32,
        "VAULT_ENC_KEY": "v" * 32,
    }
    (dep / ".env").write_text(up.dump_dotenv(env), encoding="utf-8")
    (dep / ".env").chmod(0o600)
    return meta


def test_two_projects_distinct_connection_and_admin_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ports_a = {
        "gateway": 22000,
        "db_direct": 22001,
        "pooler_session": 22002,
        "pooler_transaction": 22003,
    }
    ports_b = {
        "gateway": 22100,
        "db_direct": 22101,
        "pooler_session": 22102,
        "pooler_transaction": 22103,
    }
    _project(tmp_path, "alpha", ports_a, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    _project(tmp_path, "beta", ports_b, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

    info_a = connection_info(tmp_path, "alpha")
    info_b = connection_info(tmp_path, "beta")
    assert info_a["db_port"] != info_b["db_port"]
    assert info_a["db_port"] == "22001"
    assert info_b["db_port"] == "22101"
    assert "22001" in format_connection_human(info_a)
    assert "22101" in format_connection_human(info_b)

    captured: dict[str, dict] = {}

    def fake_run(argv, **kwargs):  # noqa: ANN001
        captured[kwargs.get("env", {}).get("PGPORT", "?")] = kwargs.get("env") or {}
        from sbfleet.process import ProcessResult

        return ProcessResult(list(argv), 0, "", "")

    monkeypatch.setattr(conn, "run", fake_run)
    monkeypatch.setattr(up, "validate_generated_env", lambda e: None)

    assert (
        conn.run_with_env(
            tmp_path,
            "alpha",
            ["true"],
            admin=True,
            credentials_file=None,
            service_role=False,
        )
        == 0
    )
    assert (
        conn.run_with_env(
            tmp_path,
            "beta",
            ["true"],
            admin=True,
            credentials_file=None,
            service_role=False,
        )
        == 0
    )
    assert captured["22001"]["PGHOST"] == "127.0.0.1"
    assert captured["22001"]["PGPORT"] == "22001"
    assert ":22001/" in captured["22001"]["DATABASE_URL"]
    assert captured["22101"]["PGPORT"] == "22101"
    assert captured["22001"]["PGPASSWORD"] != ""  # injected, not empty

    # Restart-preserving contract: ports in metadata unchanged after re-read
    assert reg.read_project(tmp_path, "alpha")["ports"] == ports_a
    assert reg.read_project(tmp_path, "beta")["ports"] == ports_b


def test_cli_connection_human_not_json_kv(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from sbfleet.cli import main

    ports = {
        "gateway": 23000,
        "db_direct": 23001,
        "pooler_session": 23002,
        "pooler_transaction": 23003,
    }
    _project(tmp_path, "demo", ports, "cccccccc-cccc-cccc-cccc-cccccccccccc")
    code = main(["--home", str(tmp_path), "connection", "demo"])
    assert code == 0
    out = capsys.readouterr().out
    assert "Host application (supported)" in out
    assert "Not supported by V1" in out
    code = main(["--home", str(tmp_path), "connection", "demo", "--json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["data"]["db_port"] == "23001"
