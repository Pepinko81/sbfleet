"""Module tests."""

from __future__ import annotations

import multiprocessing
import time
from pathlib import Path

import pytest

from sbfleet import registry as reg


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    return reg.ensure_root(tmp_path / "lock-home")


def _hold_registry(
    root_s: str,
    ready: multiprocessing.Event,
    release: multiprocessing.Event,
) -> None:
    root = Path(root_s)
    lock = reg.registry_lock(root, timeout=5.0)
    lock.acquire()
    ready.set()
    release.wait(timeout=10)
    lock.release()


def test_concurrent_registry_lock_blocks(home: Path) -> None:
    ready = multiprocessing.Event()
    release = multiprocessing.Event()
    proc = multiprocessing.Process(target=_hold_registry, args=(str(home), ready, release))
    proc.start()
    assert ready.wait(timeout=5)
    with pytest.raises(reg.LockTimeoutError):
        with reg.registry_lock(home, timeout=0.3):
            pass
    release.set()
    proc.join(timeout=5)
    assert proc.exitcode == 0
    # Lock file remains after unlock.
    assert (home / "locks" / "registry.lock").exists()
    with reg.registry_lock(home, timeout=2.0):
        pass
    assert (home / "locks" / "registry.lock").exists()


def test_lock_releases_on_process_death(home: Path) -> None:
    ready = multiprocessing.Event()

    def crash(root_s: str, ready_ev: multiprocessing.Event) -> None:
        root = Path(root_s)
        lock = reg.registry_lock(root, timeout=5.0)
        lock.acquire()
        ready_ev.set()
        time.sleep(60)

    proc = multiprocessing.Process(target=crash, args=(str(home), ready))
    proc.start()
    assert ready.wait(timeout=5)
    proc.terminate()
    proc.join(timeout=5)
    # Kernel releases flock; new acquire succeeds; lock file still present.
    with reg.registry_lock(home, timeout=2.0):
        assert (home / "locks" / "registry.lock").exists()


def test_registry_before_project_order(home: Path) -> None:
    pid = "11111111-1111-4111-8111-111111111111"
    with reg.locked_registry_then_project(home, pid, timeout=2.0) as (rlock, plock):
        assert rlock._fd is not None
        assert plock._fd is not None
    assert (home / "locks" / "registry.lock").exists()
    assert (home / "locks" / f"{pid}.lock").exists()
