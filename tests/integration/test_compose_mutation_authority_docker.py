"""Compose mutation authority docker."""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

import pytest

from sbfleet import authority as auth
from sbfleet import compose as c
from sbfleet import registry as reg
from sbfleet.process import run

pytestmark = pytest.mark.docker


def _docker_ok() -> bool:
    if shutil.which("docker") is None:
        return False
    r = run(
        ["docker", "info"],
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        timeout=30.0,
        check=False,
    )
    return r.ok


def _run(argv: list[str]):
    return run(
        argv,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        timeout=60.0,
        check=False,
    )


def _minimal_contract(meta: dict, deployment: Path) -> c.ApprovedProfileContract:
    cp = str(meta["compose_project"])
    fleet = str(meta["fleet_id"])
    project = str(meta["id"])
    services = {
        name: c.ServiceContract(
            service=name,
            container_name=f"{cp}-{name}",
            image_ref="alpine:3.20" if name == "db" else f"example/{name}:1",
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


def _seed(root: Path, slug: str) -> dict:
    fid = reg.fleet_id(root)
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
            "gateway": 24100,
            "db_direct": 24101,
            "pooler_session": 24102,
            "pooler_transaction": 24103,
        },
        "domain": None,
        "public_url": "http://127.0.0.1:24100",
        "upstream": {"ref": "self-hosted/v0.8.2", "sha": "a" * 40},
        "creation_complete": True,
        "image_digests": {},
    }
    reg.write_project(root, meta)
    (reg.project_dir(root, slug) / "deployment").mkdir(parents=True)
    return meta


@pytest.mark.docker
def test_v3_001_foreign_network_refuses_and_sentinel_untouched(tmp_path: Path) -> None:
    if not _docker_ok():
        pytest.skip("docker unavailable")

    root = reg.ensure_root(tmp_path / f"sbfleet-v3a-{uuid.uuid4().hex[:10]}")
    meta = _seed(root, "v3a")
    dep = reg.project_dir(root, "v3a") / "deployment"
    cp = str(meta["compose_project"])
    fid = str(meta["fleet_id"])
    pid = str(meta["id"])
    tag = uuid.uuid4().hex[:8]
    sentinel = f"sbfleet-v3a-sentinel-{tag}"
    owned_net = f"{cp}_default"
    foreign_net = f"sbfleet-v3a-foreign-{tag}"
    cname = f"{cp}-db"

    assert _run(["docker", "run", "-d", "--name", sentinel, "alpine:3.20", "sleep", "120"]).ok
    sentinel_id = _run(["docker", "inspect", "--format", "{{.Id}}", sentinel]).stdout.strip()
    try:
        assert _run(
            [
                "docker",
                "network",
                "create",
                "--label",
                f"io.sbfleet.fleet={fid}",
                "--label",
                f"io.sbfleet.project={pid}",
                "--label",
                f"com.docker.compose.project={cp}",
                owned_net,
            ]
        ).ok
        assert _run(["docker", "network", "create", foreign_net]).ok
        assert _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                cname,
                "--network",
                owned_net,
                "--label",
                f"io.sbfleet.fleet={fid}",
                "--label",
                f"io.sbfleet.project={pid}",
                "--label",
                f"com.docker.compose.project={cp}",
                "--label",
                "com.docker.compose.service=db",
                "alpine:3.20",
                "sleep",
                "120",
            ]
        ).ok
        assert _run(["docker", "network", "connect", foreign_net, cname]).ok
        with pytest.raises(auth.AuthorityError, match="network attachment|ownership"):
            auth.invent_owned_resources(
                compose_project=cp,
                fleet_id=fid,
                project_id=pid,
                deployment=dep,
                contract=_minimal_contract(meta, dep),
            )
        after = _run(["docker", "inspect", "--format", "{{.Id}}", sentinel]).stdout.strip()
        assert after == sentinel_id
    finally:
        _run(["docker", "rm", "-f", cname])
        _run(["docker", "rm", "-f", sentinel])
        _run(["docker", "network", "rm", owned_net])
        _run(["docker", "network", "rm", foreign_net])
