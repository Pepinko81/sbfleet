"""Module tests."""

from __future__ import annotations

import json
import os
import shutil
import uuid
from pathlib import Path

import pytest

from sbfleet import authority as auth
from sbfleet import compose as c
from sbfleet import registry as reg
from sbfleet.process import run


def _minimal_contract(meta: dict, deployment: Path) -> c.ApprovedProfileContract:
    from sbfleet import compose as c

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


def _run(argv: list[str], **kwargs: object):
    return run(
        argv,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        timeout=60.0,
        check=False,
        **kwargs,  # type: ignore[arg-type]
    )


def _inspect_id(kind: str, name: str) -> str | None:
    if kind == "container":
        argv = ["docker", "inspect", "--format", "{{.Id}}", name]
    elif kind == "network":
        argv = ["docker", "network", "inspect", "--format", "{{.Id}}", name]
    elif kind == "volume":
        argv = ["docker", "volume", "inspect", "--format", "{{.Name}}", name]
    else:
        raise ValueError(kind)
    r = _run(argv)
    if not r.ok:
        return None
    return (r.stdout or "").strip() or None


@pytest.fixture()
def disposable_root(tmp_path: Path) -> Path:
    run_id = uuid.uuid4().hex[:12]
    root = reg.ensure_root(tmp_path / f"sbfleet-test-{run_id}")
    return root


def _seed_minimal_project(root: Path, slug: str, *, port_base: int) -> dict:
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
        "last_verified_upstream": None,
        "image_digests": {},
        "creation_complete": True,
    }
    reg.write_project(root, meta)
    dep = reg.project_dir(root, slug) / "deployment"
    dep.mkdir(parents=True)
    (dep / "run.sh").write_text(
        '#!/bin/sh\ncase "$1" in start|stop|restart) exit 0;; *) exit 0;; esac\n'
    )
    os.chmod(dep / "run.sh", 0o700)
    # Minimal compose that still exercises labels/network/volumes for ownership tests
    (dep / "docker-compose.yml").write_text(
        "services:\n  marker:\n    image: alpine:3.20\n    command: ['sleep', '30']\n",
        encoding="utf-8",
    )
    # Full override still rendered for standard contract tests that need it;
    # for adversarial selector tests we only need .env + metadata identity.
    override = c.render_override(
        compose_project=cp,
        fleet_id=fid,
        project_id=pid,
        gateway_port=port_base,
        db_direct_port=port_base + 1,
        pooler_session_port=port_base + 2,
        pooler_transaction_port=port_base + 3,
    )
    c.write_override(dep, override)
    # Stub deployment for focused authority-path attacks (POINTER/HELPER evidence for
    # selector/identity refusal). Full Compose+live invent paths are covered by live
    # G10/integration cases that use production authorize_mutation defaults.
    # Replace vendor compose with a stub that satisfies inventory for mutations
    # that intentionally skip full compose validate (validate_compose=False).
    (dep / ".env").write_text(
        f"COMPOSE_PROJECT_NAME={cp}\n"
        "COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml\n"
        "COMPOSE_PATH_SEPARATOR=:\n",
        encoding="utf-8",
    )
    os.chmod(dep / ".env", 0o600)
    (dep / "volumes").mkdir()
    return meta


def _create_sentinel(label: str) -> dict[str, str]:
    """Create unrelated Docker resources with lookalike / partial labels."""
    suffix = uuid.uuid4().hex[:8]
    cname = f"sbfleet-sentinel-{suffix}"
    nname = f"sbfleet-sentinel-net-{suffix}"
    vname = f"sbfleet-sentinel-vol-{suffix}"
    # Container with misleading name + partial label
    r = _run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            cname,
            "--label",
            f"io.sbfleet.sentinel={label}",
            "--label",
            "io.sbfleet.fleet=00000000-0000-0000-0000-000000000000",
            "alpine:3.20",
            "sleep",
            "120",
        ]
    )
    assert r.ok, r.stderr
    r = _run(["docker", "network", "create", "--label", f"io.sbfleet.sentinel={label}", nname])
    assert r.ok, r.stderr
    r = _run(["docker", "volume", "create", "--label", f"io.sbfleet.sentinel={label}", vname])
    assert r.ok, r.stderr
    ids = {
        "container": _inspect_id("container", cname) or "",
        "network": _inspect_id("network", nname) or "",
        "volume": _inspect_id("volume", vname) or "",
        "container_name": cname,
        "network_name": nname,
        "volume_name": vname,
    }
    assert all(ids[k] for k in ("container", "network", "volume"))
    return ids


def _cleanup_sentinel(ids: dict[str, str]) -> None:
    _run(["docker", "rm", "-f", ids["container_name"]])
    _run(["docker", "network", "rm", ids["network_name"]])
    _run(["docker", "volume", "rm", ids["volume_name"]])


def _assert_sentinel_unchanged(before: dict[str, str]) -> None:
    assert _inspect_id("container", before["container_name"]) == before["container"]
    assert _inspect_id("network", before["network_name"]) == before["network"]
    assert _inspect_id("volume", before["volume_name"]) == before["volume"]


@pytest.mark.docker
def test_adversarial_ownership_harness(disposable_root: Path) -> None:
    if not _docker_ok():
        pytest.skip("docker unavailable")

    root = disposable_root
    sentinel = _create_sentinel(f"run2a-{uuid.uuid4().hex[:8]}")
    try:
        meta_a = _seed_minimal_project(root, "proj-a", port_base=22100)
        meta_b = _seed_minimal_project(root, "proj-b", port_base=22110)
        dep_a = reg.project_dir(root, "proj-a") / "deployment"
        dep_b = reg.project_dir(root, "proj-b") / "deployment"

        before_b_env = (dep_b / ".env").read_bytes()
        before_b_meta = json.dumps(reg.read_project(root, "proj-b"), sort_keys=True)
        before_sentinel = dict(sentinel)

        # 1) Cross-project selector attack
        (dep_a / ".env").write_text(
            f"COMPOSE_PROJECT_NAME={meta_b['compose_project']}\n"
            "COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml\n"
            "COMPOSE_PATH_SEPARATOR=:\n",
            encoding="utf-8",
        )
        os.chmod(dep_a / ".env", 0o600)
        with pytest.raises(auth.AuthorityError, match="disagrees"):
            with auth.authorize_mutation(
                root, "proj-a", intent="stop", validate_compose=False, invent_live=False
            ):
                pass
        assert (dep_b / ".env").read_bytes() == before_b_env
        assert json.dumps(reg.read_project(root, "proj-b"), sort_keys=True) == before_b_meta
        _assert_sentinel_unchanged(before_sentinel)

        # Restore A's .env for subsequent cases
        (dep_a / ".env").write_text(
            f"COMPOSE_PROJECT_NAME={meta_a['compose_project']}\n"
            "COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml\n"
            "COMPOSE_PATH_SEPARATOR=:\n",
            encoding="utf-8",
        )
        os.chmod(dep_a / ".env", 0o600)

        # 2) Copied identity — alter compose_project in metadata
        bad = dict(reg.read_project(root, "proj-a"))
        bad["compose_project"] = meta_b["compose_project"]
        # write bypassing validate by atomic write directly
        reg.atomic_write_json(reg.project_json_path(root, "proj-a"), bad, mode=0o600)
        with pytest.raises((reg.OwnershipError, auth.AuthorityError)):
            with auth.authorize_mutation(
                root, "proj-a", intent="stop", validate_compose=False, invent_live=False
            ):
                pass
        _assert_sentinel_unchanged(before_sentinel)
        # Restore valid metadata
        reg.write_project(root, meta_a)

        # 3) Foreign/labeled sentinels remain untouched (already asserted)
        _assert_sentinel_unchanged(before_sentinel)

        # 4) Renamed owned-looking resource: create container with expected name but wrong labels
        lookalike = f"{meta_a['compose_project']}-db"
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
                "alpine:3.20",
                "sleep",
                "60",
            ]
        )
        assert r.ok, r.stderr
        lookalike_id = _inspect_id("container", lookalike)
        try:
            with pytest.raises(auth.AuthorityError, match="ownership"):
                auth.invent_owned_resources(
                    compose_project=str(meta_a["compose_project"]),
                    fleet_id=str(meta_a["fleet_id"]),
                    project_id=str(meta_a["id"]),
                    deployment=dep_a,
                    contract=_minimal_contract(meta_a, dep_a),
                )
            # No broad cleanup — lookalike still present
            assert _inspect_id("container", lookalike) == lookalike_id
            _assert_sentinel_unchanged(before_sentinel)
        finally:
            _run(["docker", "rm", "-f", lookalike])

        # 5) Bind escape — mutate override is hard; exercise path helper + authority path check
        escape = dep_a / "volumes" / "escape"
        escape.symlink_to("/tmp")
        with pytest.raises((reg.OwnershipError, auth.AuthorityError)):
            reg.assert_managed_entry(
                escape, under=dep_a / "volumes", expect_dir=True, refuse_mountpoint=True
            )
        escape.unlink()
        _assert_sentinel_unchanged(before_sentinel)

        # 6) Nested symlink path escape on deployment
        # Replace deployment with symlink to B's deployment
        shutil.move(str(dep_a), str(reg.project_dir(root, "proj-a") / "deployment.real"))
        (reg.project_dir(root, "proj-a") / "deployment").symlink_to(
            reg.project_dir(root, "proj-b") / "deployment"
        )
        with pytest.raises((reg.OwnershipError, auth.AuthorityError)):
            with auth.authorize_mutation(
                root, "proj-a", intent="stop", validate_compose=False, invent_live=False
            ):
                pass
        (reg.project_dir(root, "proj-a") / "deployment").unlink()
        shutil.move(
            str(reg.project_dir(root, "proj-a") / "deployment.real"),
            str(dep_a),
        )
        assert (dep_b / ".env").read_bytes() == before_b_env
        _assert_sentinel_unchanged(before_sentinel)

        # 7) Lock-file safety
        victim = root / "locks" / "victim-data"
        victim.write_text("do-not-truncate\n", encoding="utf-8")
        before_victim = victim.read_bytes()
        lock_path = root / "locks" / f"{meta_a['id']}.lock"
        if lock_path.exists():
            lock_path.unlink()
        lock_path.symlink_to(victim)
        with pytest.raises(reg.OwnershipError):
            with reg.project_lock(root, str(meta_a["id"]), timeout=0.5):
                pass
        assert victim.read_bytes() == before_victim
        lock_path.unlink()
        _assert_sentinel_unchanged(before_sentinel)

        # 8) Concurrency: held project lock blocks start authorization
        with reg.locked_registry_then_project(root, str(meta_a["id"]), timeout=2.0):
            with pytest.raises(reg.LockTimeoutError):
                with auth.authorize_mutation(
                    root,
                    "proj-a",
                    intent="start",
                    timeout=0.4,
                    validate_compose=False,
                    invent_live=False,
                ):
                    pass
        _assert_sentinel_unchanged(before_sentinel)

        # 9) Unresolved maintenance refuses ordinary start; failed journal ≠ STOPPED
        reg.write_operation_journal(
            root,
            "proj-a",
            reg.new_operation_journal(
                intent="UPDATING",
                phase="promoting",
                state=reg.OP_STATE_IN_PROGRESS,
            ),
        )
        with pytest.raises(auth.AuthorityError, match="unresolved"):
            with auth.authorize_mutation(
                root, "proj-a", intent="start", validate_compose=False, invent_live=False
            ):
                pass
        reg.write_operation_journal(
            root,
            "proj-a",
            reg.new_operation_journal(
                intent="UPDATING",
                phase="promoting",
                state=reg.OP_STATE_FAILED,
            ),
        )
        from sbfleet.health import FAILED, collect_status

        class FakeInspect:
            ok = True
            containers: dict = {}
            error = ""

        import sbfleet.health as health_mod

        orig = health_mod.inspect_containers_result
        health_mod.inspect_containers_result = lambda *a, **k: FakeInspect()  # type: ignore[assignment]
        try:
            report = collect_status(root, "proj-a")
            assert report.lifecycle == FAILED
        finally:
            health_mod.inspect_containers_result = orig  # type: ignore[assignment]
        _assert_sentinel_unchanged(before_sentinel)

        # Clear journal for next case
        reg.write_operation_journal(
            root,
            "proj-a",
            reg.new_operation_journal(
                intent="STOPPED",
                phase="done",
                state=reg.OP_STATE_COMPLETED,
            ),
        )

        # 10) Wrong namespace in .env toward B
        (dep_a / ".env").write_text(
            f"COMPOSE_PROJECT_NAME={meta_b['compose_project']}\n"
            "COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml\n"
            "COMPOSE_PATH_SEPARATOR=:\n",
            encoding="utf-8",
        )
        os.chmod(dep_a / ".env", 0o600)
        with pytest.raises(auth.AuthorityError):
            with auth.authorize_mutation(
                root, "proj-a", intent="remove", validate_compose=False, invent_live=False
            ):
                pass
        assert (dep_b / ".env").read_bytes() == before_b_env
        _assert_sentinel_unchanged(before_sentinel)

        # Production remove source never uses --remove-orphans
        remove_src = Path("src/sbfleet/projects_remove.py").read_text(encoding="utf-8")
        assert "--remove-orphans" not in remove_src

    finally:
        _cleanup_sentinel(sentinel)
        _assert_sentinel_unchanged  # noqa: B018 — cleanup best-effort
        # Final sentinel check if still present
        if _inspect_id("container", sentinel["container_name"]):
            _assert_sentinel_unchanged(sentinel)
            _cleanup_sentinel(sentinel)
