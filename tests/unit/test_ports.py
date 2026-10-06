"""Module tests."""

from __future__ import annotations

import multiprocessing
import socket
from pathlib import Path

import pytest

from sbfleet import registry as reg


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    return reg.ensure_root(tmp_path / "home")


def test_allocate_four_distinct(home: Path) -> None:
    with reg.registry_lock(home):
        ports, held = reg.allocate_ports(home, port_range=(30100, 30200))
        reg.release_held_sockets(held)
    assert len(set(ports.values())) == 4
    assert set(ports) == {
        "gateway",
        "db_direct",
        "pooler_session",
        "pooler_transaction",
    }


def test_exhausted_range(home: Path) -> None:
    # Occupy the only candidate.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 30500))
    try:
        with reg.registry_lock(home):
            with pytest.raises(reg.ValidationError, match="exhausted"):
                reg.allocate_ports(home, port_range=(30500, 30500))
    finally:
        sock.close()


def test_wildcard_listener_blocks(home: Path) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", 30600))
    try:
        with reg.registry_lock(home):
            with pytest.raises(reg.ValidationError, match="exhausted"):
                reg.allocate_ports(home, port_range=(30600, 30600))
    finally:
        sock.close()


def _alloc_worker(root_s: str, q: multiprocessing.Queue) -> None:
    root = Path(root_s)
    with reg.registry_lock(root, timeout=10):
        ports, held = reg.allocate_ports(root, port_range=(31000, 32000))
        # Persist fake project so reserved_ports sees it.
        import uuid
        from datetime import datetime, timezone

        fid = reg.fleet_id(root)
        pid = str(uuid.uuid4())
        reg.write_project(
            root,
            {
                "format_version": 1,
                "id": pid,
                "fleet_id": fid,
                "slug": f"p{pid[:8]}",
                "display_name": "P",
                "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "profile": "standard",
                "compose_project": reg.compose_project_name(fid, pid),
                "ports": ports,
                "domain": None,
                "public_url": f"http://127.0.0.1:{ports['gateway']}",
                "upstream": {"ref": "r", "sha": "s"},
                "last_verified_upstream": None,
                "image_digests": {},
                "creation_complete": False,
            },
        )
        reg.release_held_sockets(held)
        q.put(sorted(ports.values()))


def test_multiprocess_no_overlap(home: Path) -> None:
    q: multiprocessing.Queue = multiprocessing.Queue()
    procs = [multiprocessing.Process(target=_alloc_worker, args=(str(home), q)) for _ in range(3)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=30)
        assert p.exitcode == 0
    all_ports: list[int] = []
    while not q.empty():
        all_ports.extend(q.get())
    assert len(all_ports) == 12
    assert len(set(all_ports)) == 12


def test_invalid_range() -> None:
    with pytest.raises(reg.ValidationError):
        reg.port_range_from_env({"SBFLEET_PORT_RANGE": "80-90"})
