"""Compose authority adversarial docker.

Unique fixtures only. Sentinel IDs captured before/after. No prune / no --remove-orphans.
"""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path
from unittest import mock

import pytest

from sbfleet import authority as auth
from sbfleet import compose as c
from sbfleet import registry as reg
from sbfleet.process import ProcessResult, run


def _minimal_contract(
    meta: dict, deployment: Path, *, image_ref: str = "alpine:3.20"
) -> c.ApprovedProfileContract:
    cp = str(meta["compose_project"])
    fleet = str(meta["fleet_id"])
    project = str(meta["id"])
    services = {
        name: c.ServiceContract(
            service=name,
            container_name=f"{cp}-{name}",
            image_ref=image_ref if name == "db" else f"example/{name}:1",
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


def _inspect_id(kind: str, name: str) -> str | None:
    if kind == "container":
        argv = ["docker", "inspect", "--format", "{{.Id}}", name]
    elif kind == "network":
        argv = ["docker", "network", "inspect", "--format", "{{.Id}}", name]
    else:
        argv = ["docker", "volume", "inspect", "--format", "{{.Name}}", name]
    r = _run(argv)
    if not r.ok:
        return None
    return (r.stdout or "").strip() or None


@pytest.fixture()
def disposable_root(tmp_path: Path) -> Path:
    return reg.ensure_root(tmp_path / f"sbfleet-v2a-{uuid.uuid4().hex[:12]}")


def _seed(root: Path, slug: str, *, port_base: int) -> dict:
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
            "gateway": port_base,
            "db_direct": port_base + 1,
            "pooler_session": port_base + 2,
            "pooler_transaction": port_base + 3,
        },
        "domain": None,
        "public_url": f"http://127.0.0.1:{port_base}",
        "upstream": {"ref": "self-hosted/v0.8.2", "sha": "b" * 40},
        "image_digests": {},
        "creation_complete": True,
    }
    reg.write_project(root, meta)
    dep = reg.project_dir(root, slug) / "deployment"
    dep.mkdir(parents=True)
    (dep / "run.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chmod(dep / "run.sh", 0o700)
    (dep / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    c.write_override(
        dep,
        c.render_override(
            compose_project=cp,
            fleet_id=fid,
            project_id=pid,
            gateway_port=port_base,
            db_direct_port=port_base + 1,
            pooler_session_port=port_base + 2,
            pooler_transaction_port=port_base + 3,
        ),
    )
    (dep / ".env").write_text(
        f"COMPOSE_PROJECT_NAME={cp}\n"
        "COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml\n"
        "COMPOSE_PATH_SEPARATOR=:\n",
        encoding="utf-8",
    )
    os.chmod(dep / ".env", 0o600)
    (dep / "volumes").mkdir()
    return meta


def _create_sentinel(tag: str) -> dict[str, str]:
    suffix = uuid.uuid4().hex[:8]
    cname = f"sbfleet-v2a-sent-c-{suffix}"
    nname = f"sbfleet-v2a-sent-n-{suffix}"
    vname = f"sbfleet-v2a-sent-v-{suffix}"
    assert _run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            cname,
            "--label",
            f"io.sbfleet.v2a={tag}",
            "alpine:3.20",
            "sleep",
            "180",
        ]
    ).ok
    assert _run(["docker", "network", "create", "--label", f"io.sbfleet.v2a={tag}", nname]).ok
    assert _run(["docker", "volume", "create", "--label", f"io.sbfleet.v2a={tag}", vname]).ok
    return {
        "container": _inspect_id("container", cname) or "",
        "network": _inspect_id("network", nname) or "",
        "volume": _inspect_id("volume", vname) or "",
        "container_name": cname,
        "network_name": nname,
        "volume_name": vname,
    }


def _cleanup_sentinel(ids: dict[str, str]) -> None:
    _run(["docker", "rm", "-f", ids["container_name"]])
    _run(["docker", "network", "rm", ids["network_name"]])
    _run(["docker", "volume", "rm", ids["volume_name"]])


def _assert_sentinel_unchanged(before: dict[str, str]) -> None:
    assert _inspect_id("container", before["container_name"]) == before["container"]
    assert _inspect_id("network", before["network_name"]) == before["network"]
    assert _inspect_id("volume", before["volume_name"]) == before["volume"]


@pytest.mark.docker
def test_v2a_live_authority_adversarial(disposable_root: Path) -> None:
    if not _docker_ok():
        pytest.skip("docker unavailable")

    root = disposable_root
    tag = f"v2a-{uuid.uuid4().hex[:8]}"
    sentinel = _create_sentinel(tag)
    owned: list[str] = []
    try:
        meta = _seed(root, "v2a", port_base=23100)
        dep = reg.project_dir(root, "v2a") / "deployment"
        cp = str(meta["compose_project"])
        fid = str(meta["fleet_id"])
        pid = str(meta["id"])
        before = dict(sentinel)

        # 1) Never-started confirmed-absent invent succeeds; sentinels untouched.
        inv = auth.invent_owned_resources(
            compose_project=cp,
            fleet_id=fid,
            project_id=pid,
            deployment=dep,
            contract=_minimal_contract(meta, dep),
        )
        assert inv.containers == []
        _assert_sentinel_unchanged(before)

        # 2) Renamed Compose-labelled owned container still inventoried by label.
        real_name = f"{cp}-db"
        renamed = f"{cp}-db-renamed-{uuid.uuid4().hex[:6]}"
        expected_net = f"{cp}_default"
        _run(
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
                expected_net,
            ]
        )
        r = _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                real_name,
                "--network",
                expected_net,
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
                "180",
            ]
        )
        assert r.ok, r.stderr
        owned.append(real_name)
        assert _run(["docker", "rename", real_name, renamed]).ok
        owned = [renamed]
        inv2 = auth.invent_owned_resources(
            compose_project=cp,
            fleet_id=fid,
            project_id=pid,
            deployment=dep,
            contract=_minimal_contract(meta, dep),
        )
        assert len(inv2.containers) >= 1
        assert any(
            c.name == renamed
            or renamed in c.name
            or c.labels.get("com.docker.compose.service") == "db"
            for c in inv2.containers
        )
        _assert_sentinel_unchanged(before)

        # 3) Wrong-label lookalike on expected name refused.
        lookalike = f"{cp}-auth"
        r = _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                lookalike,
                "--label",
                "io.sbfleet.fleet=11111111-1111-1111-1111-111111111111",
                "--label",
                "io.sbfleet.project=22222222-2222-2222-2222-222222222222",
                "--label",
                f"com.docker.compose.project={cp}",
                "--label",
                "com.docker.compose.service=auth",
                "alpine:3.20",
                "sleep",
                "120",
            ]
        )
        assert r.ok, r.stderr
        owned.append(lookalike)
        with pytest.raises(auth.AuthorityError, match="ownership|mislabeled|foreign"):
            auth.invent_owned_resources(
                compose_project=cp,
                fleet_id=fid,
                project_id=pid,
                deployment=dep,
                contract=_minimal_contract(meta, dep),
            )
        _assert_sentinel_unchanged(before)
        _run(["docker", "rm", "-f", lookalike])
        owned.remove(lookalike)

        # 4) Foreign named volume with compose project label but wrong fleet/project.
        foreign_vol = f"{cp}_db-config"
        # May already exist from nothing; create with wrong labels if absent.
        existing = _inspect_id("volume", foreign_vol)
        created_vol = False
        if existing is None:
            r = _run(
                [
                    "docker",
                    "volume",
                    "create",
                    "--label",
                    f"com.docker.compose.project={cp}",
                    "--label",
                    "io.sbfleet.fleet=11111111-1111-1111-1111-111111111111",
                    "--label",
                    "io.sbfleet.project=22222222-2222-2222-2222-222222222222",
                    foreign_vol,
                ]
            )
            assert r.ok, r.stderr
            created_vol = True
        try:
            with pytest.raises(auth.AuthorityError, match="ownership|mislabeled|foreign"):
                auth.invent_owned_resources(
                    compose_project=cp,
                    fleet_id=fid,
                    project_id=pid,
                    deployment=dep,
                    contract=_minimal_contract(meta, dep),
                )
            _assert_sentinel_unchanged(before)
        finally:
            if created_vol:
                _run(["docker", "volume", "rm", foreign_vol])

        # 5) Foreign network with compose project label + wrong fleet.
        # Step 2 created {cp}_default with correct labels for attachment proof;
        # detach/remove owned containers, replace the network with a
        # wrong-fleet lookalike of the expected name, then invent must refuse.
        foreign_net = f"{cp}_default"
        for name in list(owned):
            _run(["docker", "rm", "-f", name])
            owned.remove(name)
        if _inspect_id("network", foreign_net) is not None:
            assert _run(["docker", "network", "rm", foreign_net]).ok
        r = _run(
            [
                "docker",
                "network",
                "create",
                "--label",
                f"com.docker.compose.project={cp}",
                "--label",
                "io.sbfleet.fleet=11111111-1111-1111-1111-111111111111",
                "--label",
                "io.sbfleet.project=22222222-2222-2222-2222-222222222222",
                foreign_net,
            ]
        )
        assert r.ok, r.stderr
        created_net = True
        try:
            with pytest.raises(auth.AuthorityError, match="ownership|mislabeled|foreign"):
                auth.invent_owned_resources(
                    compose_project=cp,
                    fleet_id=fid,
                    project_id=pid,
                    deployment=dep,
                    contract=_minimal_contract(meta, dep),
                )
            _assert_sentinel_unchanged(before)
        finally:
            if created_net:
                _run(["docker", "network", "rm", foreign_net])

        # 6) Malformed/failed inspection at production observation boundary.
        real_run = auth.run

        def failing_run(argv, **kwargs):
            if argv[:1] == ["docker"] and "ps" in argv:
                return ProcessResult(list(argv), 1, "", "Cannot connect to the Docker daemon")
            return real_run(argv, **kwargs)

        with mock.patch.object(auth, "run", side_effect=failing_run):
            with pytest.raises(auth.AuthorityError, match="UNKNOWN|refusing"):
                auth.invent_owned_resources(
                    compose_project=cp,
                    fleet_id=fid,
                    project_id=pid,
                    deployment=dep,
                    contract=_minimal_contract(meta, dep),
                )
        _assert_sentinel_unchanged(before)

        # Cleanup renamed owned container
        for name in list(owned):
            _run(["docker", "rm", "-f", name])
        owned.clear()
        _assert_sentinel_unchanged(before)
    finally:
        for name in owned:
            _run(["docker", "rm", "-f", name])
        try:
            _run(["docker", "network", "rm", f"{cp}_default"])
        except Exception:
            pass
        _cleanup_sentinel(sentinel)
