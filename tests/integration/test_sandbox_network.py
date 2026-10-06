"""Docker integration tests for sandbox network ownership (regression suite)."""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest

from sbfleet.process import run
from sbfleet.sandbox_authority import (
    HOST_BINDING_OPT,
    SBFLEET_SANDBOX_LABEL,
    SBFLEET_UUID_LABEL,
    SandboxAuthorityError,
    create_owned_network,
    prove_network_owned,
)

DOCKER_ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}

pytestmark = pytest.mark.docker


def _docker_ok() -> bool:
    r = run(["docker", "info"], env=DOCKER_ENV, check=False, timeout=30.0)
    return bool(r.ok)


@pytest.fixture
def require_docker():
    if not _docker_ok():
        pytest.skip("Docker daemon unavailable")


def test_owned_network_create_and_prove(require_docker, tmp_path: Path) -> None:
    phash = uuid.uuid4().hex[:16]
    suuid = str(uuid.uuid4())
    name = f"sbfleet-sb-itest-{phash}"
    net_id = create_owned_network(name=name, path_hash=phash, sandbox_uuid=suuid)
    try:
        net = prove_network_owned(net_id, path_hash=phash, sandbox_uuid=suuid)
        assert net["Driver"] == "bridge"
        assert net["Options"][HOST_BINDING_OPT] == "127.0.0.1"
        assert net["Labels"][SBFLEET_SANDBOX_LABEL] == phash
        assert net["Labels"][SBFLEET_UUID_LABEL] == suuid
    finally:
        run(["docker", "network", "rm", net_id], env=DOCKER_ENV, check=False)


def test_foreign_same_name_network_refused(require_docker) -> None:
    phash = uuid.uuid4().hex[:16]
    suuid = str(uuid.uuid4())
    name = f"sbfleet-sb-itest-foreign-{phash}"
    # Create foreign network without ownership labels
    created = run(
        ["docker", "network", "create", name],
        env=DOCKER_ENV,
        check=False,
    )
    assert created.ok
    net_id = (created.stdout or "").strip()
    try:
        with pytest.raises(SandboxAuthorityError):
            prove_network_owned(net_id, path_hash=phash, sandbox_uuid=suuid)
        with pytest.raises(SandboxAuthorityError, match="refuse takeover"):
            create_owned_network(name=name, path_hash=phash, sandbox_uuid=suuid)
    finally:
        run(["docker", "network", "rm", net_id], env=DOCKER_ENV, check=False)


def test_wrong_host_binding_option_refused(require_docker) -> None:
    phash = uuid.uuid4().hex[:16]
    suuid = str(uuid.uuid4())
    name = f"sbfleet-sb-itest-badopt-{phash}"
    created = run(
        [
            "docker",
            "network",
            "create",
            "--label",
            f"{SBFLEET_SANDBOX_LABEL}={phash}",
            "--label",
            f"{SBFLEET_UUID_LABEL}={suuid}",
            "-o",
            f"{HOST_BINDING_OPT}=0.0.0.0",
            name,
        ],
        env=DOCKER_ENV,
        check=False,
    )
    assert created.ok
    net_id = (created.stdout or "").strip()
    try:
        with pytest.raises(SandboxAuthorityError, match="host_binding"):
            prove_network_owned(net_id, path_hash=phash, sandbox_uuid=suuid)
    finally:
        run(["docker", "network", "rm", net_id], env=DOCKER_ENV, check=False)


def test_sentinel_network_survives_unrelated_rm_attempt(require_docker) -> None:
    """Prove we never prune; sentinel network remains when we only rm owned id."""
    sent = run(
        ["docker", "network", "create", f"sbfleet-sentinel-{uuid.uuid4().hex[:8]}"],
        env=DOCKER_ENV,
        check=False,
    )
    assert sent.ok
    sentinel_id = (sent.stdout or "").strip()
    phash = uuid.uuid4().hex[:16]
    suuid = str(uuid.uuid4())
    owned = create_owned_network(
        name=f"sbfleet-sb-itest-own-{phash}", path_hash=phash, sandbox_uuid=suuid
    )
    try:
        run(["docker", "network", "rm", owned], env=DOCKER_ENV, check=False)
        insp = run(["docker", "network", "inspect", sentinel_id], env=DOCKER_ENV, check=False)
        assert insp.ok, "sentinel network must survive owned network removal"
    finally:
        run(["docker", "network", "rm", sentinel_id], env=DOCKER_ENV, check=False)
        run(["docker", "network", "rm", owned], env=DOCKER_ENV, check=False)
