"""Authority compose."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from sbfleet import authority as auth
from sbfleet import compose as c
from sbfleet import registry as reg
from sbfleet.process import ProcessResult


def _minimal_contract(meta: dict, deployment: Path) -> c.ApprovedProfileContract:
    cp = str(meta["compose_project"])
    fleet = str(meta["fleet_id"])
    project = str(meta["id"])
    services = {
        name: c.ServiceContract(
            service=name,
            container_name=f"{cp}-{name}",
            image_ref=f"example/{name}:1",
            mounts=(),
            networks=frozenset({f"{cp}_default"}),
            required_labels=frozenset(
                {
                    ("io.sbfleet.fleet", fleet),
                    ("io.sbfleet.project", project),
                    ("com.docker.compose.project", cp),
                    ("com.docker.compose.service", name),
                }
            ),
        )
        for name in c.STANDARD_SERVICES
    }
    return c.ApprovedProfileContract(
        compose_project=cp,
        fleet_id=fleet,
        project_id=project,
        services=services,
        expected_network=f"{cp}_default",
        expected_volumes=frozenset({f"{cp}_db-config", f"{cp}_deno-cache"}),
    )


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    return reg.ensure_root(tmp_path / "home")


def _seed_minimal(home: Path, slug: str = "alpha") -> dict:
    import os
    import uuid

    fid = reg.fleet_id(home)
    pid = str(uuid.uuid4())
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
    reg.write_project(home, meta)
    pdir = reg.project_dir(home, slug)
    dep = pdir / "deployment"
    dep.mkdir(parents=True)
    (dep / "run.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chmod(dep / "run.sh", 0o700)
    (dep / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    override = c.render_override(
        compose_project=cp,
        fleet_id=fid,
        project_id=pid,
        gateway_port=21010,
        db_direct_port=21011,
        pooler_session_port=21012,
        pooler_transaction_port=21013,
    )
    c.write_override(dep, override)
    (dep / ".env").write_text(
        "\n".join(
            [
                f"COMPOSE_PROJECT_NAME={cp}",
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


def test_inspect_daemon_failure_is_unknown_not_absent() -> None:
    with mock.patch.object(
        auth,
        "run",
        return_value=ProcessResult(
            argv=["docker"],
            returncode=1,
            stdout="",
            stderr="Cannot connect to the Docker daemon",
        ),
    ):
        obs = auth._docker_inspect_observation(["inspect", "x"])
    assert obs.state == "UNKNOWN"


def test_inspect_malformed_json_is_failed() -> None:
    with mock.patch.object(
        auth,
        "run",
        return_value=ProcessResult(
            argv=["docker"],
            returncode=0,
            stdout="not-json{",
            stderr="",
        ),
    ):
        obs = auth._docker_inspect_observation(["inspect", "x"])
    assert obs.state == "FAILED"


def test_inspect_exact_missing_is_absent() -> None:
    with mock.patch.object(
        auth,
        "run",
        return_value=ProcessResult(
            argv=["docker"],
            returncode=1,
            stdout="",
            stderr="Error: No such object: sbfleet-abc-db",
        ),
    ):
        obs = auth._docker_inspect_observation(["inspect", "sbfleet-abc-db"])
    assert obs.state == "ABSENT"


def test_invent_refuses_daemon_failure(home: Path) -> None:
    meta = _seed_minimal(home)
    dep = reg.project_dir(home, "alpha") / "deployment"

    def fake_run(argv: list[str], **kwargs: Any) -> ProcessResult:
        return ProcessResult(
            argv=argv,
            returncode=1,
            stdout="",
            stderr="Cannot connect to the Docker daemon",
        )

    with mock.patch.object(auth, "run", side_effect=fake_run):
        with pytest.raises(auth.AuthorityError, match="UNKNOWN|refusing"):
            auth.invent_owned_resources(
                compose_project=str(meta["compose_project"]),
                fleet_id=str(meta["fleet_id"]),
                project_id=str(meta["id"]),
                deployment=dep,
                contract=_minimal_contract(meta, dep),
            )


def test_invent_refuses_malformed_ps_json(home: Path) -> None:
    meta = _seed_minimal(home)
    dep = reg.project_dir(home, "alpha") / "deployment"

    def fake_run(argv: list[str], **kwargs: Any) -> ProcessResult:
        # list ok empty; inspect of expected name returns malformed on success path
        if "ps" in argv:
            return ProcessResult(argv, 0, "", "")
        if "network" in argv and "ls" in argv:
            return ProcessResult(argv, 0, "", "")
        if "volume" in argv and "ls" in argv:
            return ProcessResult(argv, 0, "", "")
        if "inspect" in argv:
            return ProcessResult(argv, 0, "{bad", "")
        return ProcessResult(argv, 1, "", "No such object: x")

    with mock.patch.object(auth, "run", side_effect=fake_run):
        with pytest.raises(auth.AuthorityError, match="FAILED|malformed|refusing"):
            auth.invent_owned_resources(
                compose_project=str(meta["compose_project"]),
                fleet_id=str(meta["fleet_id"]),
                project_id=str(meta["id"]),
                deployment=dep,
                contract=_minimal_contract(meta, dep),
            )


def test_invent_absent_never_started_ok(home: Path) -> None:
    meta = _seed_minimal(home)
    dep = reg.project_dir(home, "alpha") / "deployment"
    cp = str(meta["compose_project"])

    def fake_run(argv: list[str], **kwargs: Any) -> ProcessResult:
        if (
            "ps" in argv
            or ("network" in argv and "ls" in argv)
            or ("volume" in argv and "ls" in argv)
        ):
            return ProcessResult(argv, 0, "", "")
        # inspect expected names → exact missing
        return ProcessResult(argv, 1, "", "Error: No such object: missing")

    with mock.patch.object(auth, "run", side_effect=fake_run):
        inv = auth.invent_owned_resources(
            compose_project=cp,
            fleet_id=str(meta["fleet_id"]),
            project_id=str(meta["id"]),
            deployment=dep,
            contract=_minimal_contract(meta, dep),
        )
    assert inv.containers == []
    assert inv.networks == []
    assert inv.volumes == []


def test_foreign_default_network_name_refused() -> None:
    config = {
        "services": {
            svc: {
                "container_name": f"sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb-{svc}",
                "image": f"example/{svc}:1",
                "labels": {
                    "io.sbfleet.fleet": "11111111-1111-1111-1111-111111111111",
                    "io.sbfleet.project": "22222222-2222-2222-2222-222222222222",
                },
                "volumes": [],
                "ports": [],
                "networks": {"default": {"aliases": [c.REALTIME_ALIAS]}}
                if svc == "realtime"
                else {},
            }
            for svc in c.STANDARD_SERVICES
        },
        "networks": {
            "default": {
                "name": "foreign",
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
    # Fix ports for published services
    config["services"]["api-gw"]["ports"] = [
        {"published": 21010, "target": 8000, "host_ip": "127.0.0.1"}
    ]
    config["services"]["db"]["ports"] = [
        {"published": 21011, "target": 5432, "host_ip": "127.0.0.1"}
    ]
    config["services"]["supavisor"]["ports"] = [
        {"published": 21012, "target": 5432, "host_ip": "127.0.0.1"},
        {"published": 21013, "target": 6543, "host_ip": "127.0.0.1"},
    ]
    with pytest.raises(c.ComposeError, match="unexpected network name"):
        c.validate_resolved_config(
            config,
            compose_project="sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb",
            fleet_id="11111111-1111-1111-1111-111111111111",
            project_id="22222222-2222-2222-2222-222222222222",
            gateway_port=21010,
            db_direct_port=21011,
            pooler_session_port=21012,
            pooler_transaction_port=21013,
        )


def test_network_mode_container_refused() -> None:
    config = {
        "services": {
            svc: {
                "container_name": f"sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb-{svc}",
                "image": f"example/{svc}:1",
                "labels": {
                    "io.sbfleet.fleet": "11111111-1111-1111-1111-111111111111",
                    "io.sbfleet.project": "22222222-2222-2222-2222-222222222222",
                },
                "volumes": [],
                "ports": [],
                "network_mode": "container:foreign" if svc == "db" else None,
                "networks": {"default": {"aliases": [c.REALTIME_ALIAS]}}
                if svc == "realtime"
                else {},
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
        {"published": 21010, "target": 8000, "host_ip": "127.0.0.1"}
    ]
    config["services"]["db"]["ports"] = [
        {"published": 21011, "target": 5432, "host_ip": "127.0.0.1"}
    ]
    config["services"]["supavisor"]["ports"] = [
        {"published": 21012, "target": 5432, "host_ip": "127.0.0.1"},
        {"published": 21013, "target": 6543, "host_ip": "127.0.0.1"},
    ]
    with pytest.raises(c.ComposeError, match="network_mode"):
        c.validate_resolved_config(
            config,
            compose_project="sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb",
            fleet_id="11111111-1111-1111-1111-111111111111",
            project_id="22222222-2222-2222-2222-222222222222",
            gateway_port=21010,
            db_direct_port=21011,
            pooler_session_port=21012,
            pooler_transaction_port=21013,
        )


def test_expected_images_mismatch_refused() -> None:
    images = {svc: f"example/{svc}:1" for svc in c.STANDARD_SERVICES}
    wrong = dict(images)
    wrong["db"] = "evil/db:hacked"
    config = {
        "services": {
            svc: {
                "container_name": f"sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb-{svc}",
                "image": wrong[svc],
                "labels": {
                    "io.sbfleet.fleet": "11111111-1111-1111-1111-111111111111",
                    "io.sbfleet.project": "22222222-2222-2222-2222-222222222222",
                },
                "volumes": [],
                "ports": [],
                "networks": {"default": {"aliases": [c.REALTIME_ALIAS]}}
                if svc == "realtime"
                else {},
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
        {"published": 21010, "target": 8000, "host_ip": "127.0.0.1"}
    ]
    config["services"]["db"]["ports"] = [
        {"published": 21011, "target": 5432, "host_ip": "127.0.0.1"}
    ]
    config["services"]["supavisor"]["ports"] = [
        {"published": 21012, "target": 5432, "host_ip": "127.0.0.1"},
        {"published": 21013, "target": 6543, "host_ip": "127.0.0.1"},
    ]
    with pytest.raises(c.ComposeError, match="image mismatch"):
        c.validate_resolved_config(
            config,
            compose_project="sbfleet-aaaaaaaaaaaa-bbbbbbbbbbbb",
            fleet_id="11111111-1111-1111-1111-111111111111",
            project_id="22222222-2222-2222-2222-222222222222",
            gateway_port=21010,
            db_direct_port=21011,
            pooler_session_port=21012,
            pooler_transaction_port=21013,
            expected_images=images,
        )


def test_invent_includes_residual_network_without_containers(home: Path) -> None:
    meta = _seed_minimal(home)
    dep = reg.project_dir(home, "alpha") / "deployment"
    cp = str(meta["compose_project"])
    net_id = "a" * 64
    net_name = f"{cp}_default"

    def fake_run(argv: list[str], **kwargs: Any) -> ProcessResult:
        if "ps" in argv and "-aq" in argv:
            return ProcessResult(argv, 0, "", "")
        if "network" in argv and "ls" in argv:
            return ProcessResult(argv, 0, f"{net_id}\n", "")
        if "volume" in argv and "ls" in argv:
            return ProcessResult(argv, 0, "", "")
        if "network" in argv and "inspect" in argv:
            payload = {
                "Id": net_id,
                "Name": net_name,
                "Labels": {
                    "io.sbfleet.fleet": meta["fleet_id"],
                    "io.sbfleet.project": meta["id"],
                    "com.docker.compose.project": cp,
                },
            }
            return ProcessResult(argv, 0, json.dumps(payload), "")
        return ProcessResult(argv, 1, "", "Error: No such object: x")

    with mock.patch.object(auth, "run", side_effect=fake_run):
        inv = auth.invent_owned_resources(
            compose_project=cp,
            fleet_id=str(meta["fleet_id"]),
            project_id=str(meta["id"]),
            deployment=dep,
            contract=_minimal_contract(meta, dep),
        )
    assert len(inv.networks) == 1
    assert inv.networks[0].resource_id == net_id
    assert inv.containers == []
