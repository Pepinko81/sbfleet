"""Sandbox lock release on failure."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from sbfleet.registry import FileLock, LockTimeoutError, OwnershipError
from sbfleet.sandbox_adoption import SandboxAdoptionError, SandboxLocks, sandboxes_root


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    h = tmp_path / "home"
    h.mkdir()
    return h


@pytest.fixture()
def canonical(tmp_path: Path) -> Path:
    app = tmp_path / "app"
    app.mkdir()
    return app.resolve()


def _inject_second_acquire(exc: BaseException):
    """Patch FileLock so first acquire (registry) succeeds; second raises exc."""
    real_init = FileLock.__init__
    instances: list[FileLock] = []

    def tracking_init(self: FileLock, path: Path, *, timeout: float = 30.0) -> None:
        real_init(self, path, timeout=timeout)
        instances.append(self)

    call_n = {"n": 0}
    real_acquire = FileLock.acquire

    def selective_acquire(self: FileLock) -> None:
        call_n["n"] += 1
        if call_n["n"] == 1:
            return real_acquire(self)
        raise exc

    return tracking_init, selective_acquire, instances, call_n


@pytest.mark.parametrize(
    "exc",
    [
        LockTimeoutError("sandbox lock timeout"),
        OwnershipError("lock not owned"),
        OSError("EIO"),
        RuntimeError("unexpected"),
    ],
)
def test_second_lock_failure_releases_registry(
    home: Path, canonical: Path, exc: BaseException
) -> None:
    tracking_init, selective_acquire, _instances, _call_n = _inject_second_acquire(exc)
    with (
        patch.object(FileLock, "__init__", tracking_init),
        patch.object(FileLock, "acquire", selective_acquire),
    ):
        locks = SandboxLocks(home, canonical, timeout=1.0)
        with pytest.raises((SandboxAdoptionError, type(exc))):
            locks.__enter__()
        assert locks._reg is None
        assert locks._sb is None

    # Contender can acquire the registry lock after the failed attempt.
    from sbfleet.sandbox_adoption import registry_lock_path

    contender = FileLock(registry_lock_path(home), timeout=2.0)
    contender.acquire()
    contender.release()


def test_normal_nested_lifetime_serialized(home: Path, canonical: Path) -> None:
    with SandboxLocks(home, canonical, timeout=2.0) as held:
        assert held._reg is not None
        assert held._sb is not None
        from sbfleet.sandbox_adoption import registry_lock_path

        contender = FileLock(registry_lock_path(home), timeout=0.2)
        with pytest.raises(LockTimeoutError):
            contender.acquire()
    # After exit, contender succeeds.
    from sbfleet.sandbox_adoption import registry_lock_path

    contender = FileLock(registry_lock_path(home), timeout=2.0)
    contender.acquire()
    contender.release()
    assert sandboxes_root(home).is_dir()
