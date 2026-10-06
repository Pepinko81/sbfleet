"""Mutation ownership."""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest

from sbfleet import authority as auth
from sbfleet import compose as c
from sbfleet import registry as reg
from sbfleet.health import FAILED, collect_status


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    return reg.ensure_root(tmp_path / "home")


def _minimal_meta(home: Path, slug: str = "alpha") -> dict:
    fid = reg.fleet_id(home)
    pid = str(uuid.uuid4())
    cp = reg.compose_project_name(fid, pid)
    return {
        "format_version": 1,
        "id": pid,
        "fleet_id": fid,
        "slug": slug,
        "display_name": slug,
        "created_at": "2026-01-01T00:00:00Z",
        "profile": "standard",
        "compose_project": cp,
        "ports": {
            "gateway": 21010,
            "db_direct": 21011,
            "pooler_session": 21012,
            "pooler_transaction": 21013,
        },
        "domain": None,
        "public_url": "http://127.0.0.1:21010",
        "upstream": {"ref": "self-hosted/v0.8.2", "sha": "a" * 40},
        "last_verified_upstream": None,
        "image_digests": {},
        "creation_complete": True,
    }


def _seed_project(home: Path, slug: str = "alpha") -> dict:
    meta = _minimal_meta(home, slug)
    reg.write_project(home, meta)
    pdir = reg.project_dir(home, slug)
    dep = pdir / "deployment"
    dep.mkdir(parents=True)
    (dep / "run.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chmod(dep / "run.sh", 0o700)
    (dep / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    override = c.render_override(
        compose_project=str(meta["compose_project"]),
        fleet_id=str(meta["fleet_id"]),
        project_id=str(meta["id"]),
        gateway_port=int(meta["ports"]["gateway"]),
        db_direct_port=int(meta["ports"]["db_direct"]),
        pooler_session_port=int(meta["ports"]["pooler_session"]),
        pooler_transaction_port=int(meta["ports"]["pooler_transaction"]),
    )
    c.write_override(dep, override)
    (dep / ".env").write_text(
        "\n".join(
            [
                f"COMPOSE_PROJECT_NAME={meta['compose_project']}",
                "COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml",
                "COMPOSE_PATH_SEPARATOR=:",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    os.chmod(dep / ".env", 0o600)
    (dep / "volumes").mkdir()
    return meta


def test_lock_refuses_symlink(home: Path, tmp_path: Path) -> None:
    target = tmp_path / "victim.txt"
    target.write_text("secret\n", encoding="utf-8")
    before = target.read_text(encoding="utf-8")
    lock_path = home / "locks" / "evil.lock"
    lock_path.symlink_to(target)
    with pytest.raises(reg.OwnershipError):
        with reg.FileLock(lock_path, timeout=0.5):
            pass
    assert target.read_text(encoding="utf-8") == before


def test_lock_refuses_directory(home: Path) -> None:
    lock_path = home / "locks" / "dir.lock"
    lock_path.mkdir()
    with pytest.raises(reg.OwnershipError):
        with reg.FileLock(lock_path, timeout=0.5):
            pass


def test_assert_managed_entry_symlink_and_escape(home: Path, tmp_path: Path) -> None:
    under = home / "projects" / "alpha"
    under.mkdir(parents=True)
    link = under / "escape"
    link.symlink_to(tmp_path)
    with pytest.raises(reg.OwnershipError):
        reg.assert_managed_entry(link, under=under, expect_dir=True)
    outside = tmp_path / "out"
    outside.mkdir()
    with pytest.raises(reg.OwnershipError):
        reg.assert_managed_entry(outside, under=under, expect_dir=True)


def test_mountpoint_authority_fail_closed_without_mountinfo(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    under = home / "projects" / "alpha"
    under.mkdir(parents=True)
    target = under / "data"
    target.mkdir()
    monkeypatch.setattr(reg, "_mountinfo_points", lambda: None)
    with pytest.raises(reg.OwnershipError, match="cannot establish mountpoint authority"):
        reg.assert_managed_entry(target, under=under, expect_dir=True, refuse_mountpoint=True)


def test_compose_project_mismatch_refused(home: Path) -> None:
    meta = _minimal_meta(home)
    meta["compose_project"] = "sbfleet-ffffffffffff-eeeeeeeeeeee"
    reg.write_project(home, meta)
    with pytest.raises(reg.OwnershipError, match="compose_project mismatch"):
        reg.validate_project_identity(home, reg.read_project(home, "alpha"))


def test_env_selector_attack_refused(home: Path) -> None:
    meta_a = _seed_project(home, "alpha")
    meta_b = _seed_project(home, "beta")
    dep_a = reg.project_dir(home, "alpha") / "deployment"
    # Tamper A's .env to point at B
    (dep_a / ".env").write_text(
        "\n".join(
            [
                f"COMPOSE_PROJECT_NAME={meta_b['compose_project']}",
                "COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml",
                "COMPOSE_PATH_SEPARATOR=:",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    os.chmod(dep_a / ".env", 0o600)
    with pytest.raises(auth.AuthorityError, match="disagrees with metadata"):
        with auth.authorize_mutation(
            home,
            "alpha",
            intent="stop",
            validate_compose=False,
            invent_live=False,
        ):
            pass
    # B metadata untouched
    assert reg.read_project(home, "beta")["id"] == meta_b["id"]
    assert meta_a["id"] != meta_b["id"]


def test_forced_compose_env_ignores_dotenv(home: Path) -> None:
    meta = _seed_project(home)
    dep = reg.project_dir(home, "alpha") / "deployment"
    (dep / ".env").write_text("COMPOSE_PROJECT_NAME=evil\n", encoding="utf-8")
    env = auth.forced_compose_env(dep, str(meta["compose_project"]))
    assert env["COMPOSE_PROJECT_NAME"] == meta["compose_project"]
    assert env["COMPOSE_FILE"] == auth.COMPOSE_FILE_VALUE


def test_unresolved_journal_blocks_start(home: Path) -> None:
    _seed_project(home)
    reg.write_operation_journal(
        home,
        "alpha",
        reg.new_operation_journal(
            intent="UPDATING",
            phase="promoting",
            state=reg.OP_STATE_IN_PROGRESS,
        ),
    )
    with pytest.raises(auth.AuthorityError, match="unresolved operation"):
        with auth.authorize_mutation(
            home,
            "alpha",
            intent="start",
            validate_compose=False,
            invent_live=False,
        ):
            pass


def test_unresolved_journal_not_stopped_status(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_project(home)
    reg.write_operation_journal(
        home,
        "alpha",
        reg.new_operation_journal(
            intent="RESTORING",
            phase="extract",
            state=reg.OP_STATE_FAILED,
        ),
    )

    class FakeInspect:
        ok = True
        containers: dict = {}
        error = ""

    monkeypatch.setattr(
        "sbfleet.health.inspect_containers_result",
        lambda *a, **k: FakeInspect(),
    )
    report = collect_status(home, "alpha")
    assert report.lifecycle == FAILED
    assert report.lifecycle != "STOPPED"


def test_completed_backup_journal_allows_stopped(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sbfleet.health import STOPPED

    _seed_project(home)
    reg.write_operation_journal(
        home,
        "alpha",
        reg.new_operation_journal(
            intent="BACKUP",
            phase="completed",
            state=reg.OP_STATE_COMPLETED,
        ),
    )

    class FakeInspect:
        ok = True
        containers: dict = {}
        error = ""

    monkeypatch.setattr(
        "sbfleet.health.inspect_containers_result",
        lambda *a, **k: FakeInspect(),
    )
    report = collect_status(home, "alpha")
    assert report.lifecycle == STOPPED


def test_validate_bind_escape() -> None:
    config = {
        "services": {
            svc: {
                "container_name": f"sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb-{svc}",
                "image": "alpine:3.20",
                "labels": {
                    "io.sbfleet.fleet": "11111111-1111-1111-1111-111111111111",
                    "io.sbfleet.project": "22222222-2222-2222-2222-222222222222",
                },
                "volumes": [],
                "ports": [],
            }
            for svc in c.STANDARD_SERVICES
        },
        "networks": {
            "default": {
                "name": "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb_default",
                "labels": {
                    "io.sbfleet.fleet": "11111111-1111-1111-1111-111111111111",
                    "io.sbfleet.project": "22222222-2222-2222-2222-222222222222",
                },
            }
        },
        "volumes": {
            "db-config": {
                "name": "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb_db-config",
                "labels": {
                    "io.sbfleet.fleet": "11111111-1111-1111-1111-111111111111",
                    "io.sbfleet.project": "22222222-2222-2222-2222-222222222222",
                },
            },
            "deno-cache": {
                "name": "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb_deno-cache",
                "labels": {
                    "io.sbfleet.fleet": "11111111-1111-1111-1111-111111111111",
                    "io.sbfleet.project": "22222222-2222-2222-2222-222222222222",
                },
            },
        },
    }
    # ports
    config["services"]["api-gw"]["ports"] = [
        {"published": 20001, "target": 8000, "host_ip": "127.0.0.1"}
    ]
    config["services"]["db"]["ports"] = [
        {"published": 20002, "target": 5432, "host_ip": "127.0.0.1"}
    ]
    config["services"]["supavisor"]["ports"] = [
        {"published": 20003, "target": 5432, "host_ip": "127.0.0.1"},
        {"published": 20004, "target": 6543, "host_ip": "127.0.0.1"},
    ]
    config["services"]["realtime"]["networks"] = {"default": {"aliases": [c.REALTIME_ALIAS]}}
    # Inject escaping bind
    config["services"]["db"]["volumes"] = [
        {"type": "bind", "source": "/etc/passwd", "target": "/evil"}
    ]
    with pytest.raises(c.ComposeError, match="escapes"):
        c.validate_resolved_config(
            config,
            compose_project="sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb",
            fleet_id="11111111-1111-1111-1111-111111111111",
            project_id="22222222-2222-2222-2222-222222222222",
            gateway_port=20001,
            db_direct_port=20002,
            pooler_session_port=20003,
            pooler_transaction_port=20004,
            deployment=Path("/tmp/sbfleet-project-dep"),
            allowed_bind_roots=[Path("/tmp/sbfleet-project-dep")],
        )


def test_validate_extra_wildcard_port_refused() -> None:
    config = {
        "services": {
            svc: {
                "container_name": f"sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb-{svc}",
                "image": "alpine:3.20",
                "labels": {
                    "io.sbfleet.fleet": "11111111-1111-1111-1111-111111111111",
                    "io.sbfleet.project": "22222222-2222-2222-2222-222222222222",
                },
                "volumes": [],
                "ports": [],
            }
            for svc in c.STANDARD_SERVICES
        },
        "networks": {
            "default": {
                "name": "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb_default",
                "labels": {
                    "io.sbfleet.fleet": "11111111-1111-1111-1111-111111111111",
                    "io.sbfleet.project": "22222222-2222-2222-2222-222222222222",
                },
            }
        },
        "volumes": {
            "db-config": {
                "name": "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb_db-config",
                "labels": {
                    "io.sbfleet.fleet": "11111111-1111-1111-1111-111111111111",
                    "io.sbfleet.project": "22222222-2222-2222-2222-222222222222",
                },
            },
            "deno-cache": {
                "name": "sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb_deno-cache",
                "labels": {
                    "io.sbfleet.fleet": "11111111-1111-1111-1111-111111111111",
                    "io.sbfleet.project": "22222222-2222-2222-2222-222222222222",
                },
            },
        },
    }
    config["services"]["api-gw"]["ports"] = [
        {"published": 20001, "target": 8000, "host_ip": "127.0.0.1"}
    ]
    config["services"]["db"]["ports"] = [
        {"published": 20002, "target": 5432, "host_ip": "127.0.0.1"}
    ]
    config["services"]["supavisor"]["ports"] = [
        {"published": 20003, "target": 5432, "host_ip": "0.0.0.0"},
        {"published": 20004, "target": 6543, "host_ip": "127.0.0.1"},
        {"published": 20005, "target": 5432, "host_ip": "127.0.0.1"},
    ]
    config["services"]["realtime"]["networks"] = {"default": {"aliases": [c.REALTIME_ALIAS]}}
    with pytest.raises(c.ComposeError):
        c.validate_resolved_config(
            config,
            compose_project="sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb",
            fleet_id="11111111-1111-1111-1111-111111111111",
            project_id="22222222-2222-2222-2222-222222222222",
            gateway_port=20001,
            db_direct_port=20002,
            pooler_session_port=20003,
            pooler_transaction_port=20004,
        )


def test_remove_argv_has_no_remove_orphans() -> None:
    src = Path("src/sbfleet/projects_remove.py").read_text(encoding="utf-8")
    assert "--remove-orphans" not in src
    assert "invent_owned_resources" in src


def test_new_operation_journal_fields(home: Path) -> None:
    (home / "projects" / "j").mkdir(parents=True)
    journal = reg.new_operation_journal(intent="BACKUP", phase="copy")
    assert journal["state"] == reg.OP_STATE_IN_PROGRESS
    assert journal["operation_id"]
    assert journal["started_at"]
    reg.write_operation_journal(home, "j", journal)
    loaded = reg.read_operation_journal(home, "j")
    assert loaded is not None
    assert loaded["operation_id"] == journal["operation_id"]
