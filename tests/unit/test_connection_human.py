"""Human connection formatting — support labels without JSON schema change."""

from __future__ import annotations

from pathlib import Path

from sbfleet import registry as reg
from sbfleet import upstream as up
from sbfleet.connection import connection_info, format_connection_human


def _meta(root: Path, slug: str, ports: dict[str, int]) -> None:
    reg.ensure_root(root)
    meta = {
        "format_version": 1,
        "id": "11111111-1111-1111-1111-111111111111",
        "fleet_id": reg.fleet_id(root),
        "slug": slug,
        "display_name": slug,
        "created_at": "2026-01-01T00:00:00Z",
        "profile": "standard",
        "compose_project": "sbfleet-111111111111-111111111111",
        "ports": ports,
        "domain": None,
        "public_url": f"http://127.0.0.1:{ports['gateway']}",
        "upstream": {"ref": up.PINNED_REF, "sha": up.PINNED_SHA},
        "creation_complete": True,
    }
    reg.write_project(root, meta)


def test_human_labels_host_and_unsupported(tmp_path: Path) -> None:
    ports = {
        "gateway": 20000,
        "db_direct": 20001,
        "pooler_session": 20002,
        "pooler_transaction": 20003,
    }
    _meta(tmp_path, "myapp", ports)
    info = connection_info(tmp_path, "myapp")
    assert info["db_port"] == "20001"
    text = format_connection_human(info)
    assert "Host application (supported)" in text
    assert "127.0.0.1:20001" in text
    assert "Container application" in text
    assert "Not supported by V1" in text
    assert "not exposed remotely by default" in text
    assert "Never assume host PostgreSQL port 5432" in text


def test_json_data_contract_unchanged(tmp_path: Path) -> None:
    ports = {
        "gateway": 21000,
        "db_direct": 21001,
        "pooler_session": 21002,
        "pooler_transaction": 21003,
    }
    _meta(tmp_path, "app", ports)
    info = connection_info(tmp_path, "app")
    assert set(info) >= {
        "api_url",
        "studio_url",
        "db_host",
        "db_port",
        "pooler_session_port",
        "pooler_transaction_port",
        "db_name",
        "admin_role",
        "pooler_username_pattern",
        "note",
    }
    assert "container" not in info
