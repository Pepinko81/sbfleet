"""Authority reread under lock."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from sbfleet.cli import EXIT_SAFETY
from sbfleet.registry import FileLock
from sbfleet.sandbox import sandbox_cmd
from sbfleet.sandbox_adoption import (
    SandboxLocks,
    commit_adoption_pair,
    new_adoption,
    sandbox_lock_path,
)


def _write_cfg(app: Path, project_id: str, *, extra: str = "") -> None:
    (app / "supabase").mkdir(parents=True, exist_ok=True)
    (app / "supabase" / "config.toml").write_text(
        f'project_id = "{project_id}"\n[api]\nport = 54321\n[db]\nport = 54322\n'
        f"[db.migrations]\nenabled = true\n{extra}",
        encoding="utf-8",
    )


def _adopt(home: Path, app: Path, pid: str):
    from sbfleet.sandbox_config import parse_sandbox_config

    cfg = parse_sandbox_config(app.resolve())
    rec = new_adoption(
        canonical=app.resolve(),
        cli_project_id=cfg.project_id,
        config_fingerprint=cfg.fingerprint,
        fingerprint_fields=cfg.fingerprint_fields,
        cli_version="2.118.0",
        migration_mode="supabase",
        network_id="netlocktest01",
    )
    with SandboxLocks(home, app.resolve()):
        commit_adoption_pair(home, rec)
    return rec


def _ns(action: str, path: str, home: str, **kwargs):  # noqa: ANN003
    base = {
        "action": action,
        "path": path,
        "yes": True,
        "revalidate": False,
        "migration_mode": None,
        "cmd": [],
        "json": False,
        "home": home,
    }
    base.update(kwargs)
    return SimpleNamespace(**base)


def test_project_id_edit_while_lock_waits_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    app = tmp_path / "app"
    app.mkdir()
    _write_cfg(app, "sbfleet-test-toctou1")
    _adopt(home, app, "sbfleet-test-toctou1")

    monkeypatch.setattr("sbfleet.sandbox.require_pinned_cli", lambda: "supabase")
    dispatched: list[list[str]] = []

    def fake_run(argv, **kwargs):  # noqa: ANN001, ANN003
        dispatched.append(list(argv))
        return MagicMock(ok=True, stdout="{}", stderr="", returncode=0)

    monkeypatch.setattr("sbfleet.sandbox.run", fake_run)
    # Avoid real Docker ownership for this TOCTOU unit: force live authority after lock.
    from sbfleet.sandbox_authority import ClassObservation, SandboxLiveAuthority

    monkeypatch.setattr(
        "sbfleet.sandbox.observe_sandbox_live",
        lambda *_a, **_k: SandboxLiveAuthority(
            containers=ClassObservation(status="PRESENT_AND_OWNED", ids=["c1"], runtime="RUNNING"),
            network=ClassObservation(status="PRESENT_AND_OWNED", ids=["netlocktest01"]),
            volumes=ClassObservation(status="PRESENT_AND_OWNED", names=["v1"]),
        ),
    )

    # Hold sandbox lock so the command waits; mutate project_id during wait.
    lock = FileLock(sandbox_lock_path(home, app.resolve()), timeout=5.0)
    lock.acquire()
    ready = threading.Event()
    done_code: list[int] = []

    def waiter() -> None:
        ready.set()
        code = sandbox_cmd(_ns("reset", str(app), str(home)))
        done_code.append(code)

    t = threading.Thread(target=waiter)
    t.start()
    assert ready.wait(2)
    time.sleep(0.15)
    _write_cfg(app, "sbfleet-test-CHANGED")
    lock.release()
    t.join(timeout=10)
    assert done_code and done_code[0] == EXIT_SAFETY
    assert not any("db" in a and "reset" in a for a in dispatched)


def test_linked_marker_while_lock_waits_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    app = tmp_path / "app"
    app.mkdir()
    _write_cfg(app, "sbfleet-test-toctou2")
    _adopt(home, app, "sbfleet-test-toctou2")
    monkeypatch.setattr("sbfleet.sandbox.require_pinned_cli", lambda: "supabase")
    monkeypatch.setattr(
        "sbfleet.sandbox.run",
        lambda *a, **k: MagicMock(ok=True, stdout="{}", stderr="", returncode=0),
    )
    from sbfleet.sandbox_authority import ClassObservation, SandboxLiveAuthority

    monkeypatch.setattr(
        "sbfleet.sandbox.observe_sandbox_live",
        lambda *_a, **_k: SandboxLiveAuthority(
            containers=ClassObservation(status="PRESENT_AND_OWNED", ids=["c1"], runtime="RUNNING"),
            network=ClassObservation(status="PRESENT_AND_OWNED", ids=["n1"]),
            volumes=ClassObservation(status="CONFIRMED_ABSENT"),
        ),
    )

    lock = FileLock(sandbox_lock_path(home, app.resolve()), timeout=5.0)
    lock.acquire()
    ready = threading.Event()
    codes: list[int] = []

    def waiter() -> None:
        ready.set()
        codes.append(sandbox_cmd(_ns("reset", str(app), str(home))))

    t = threading.Thread(target=waiter)
    t.start()
    assert ready.wait(2)
    time.sleep(0.15)
    temp = app / "supabase" / ".temp"
    temp.mkdir(parents=True, exist_ok=True)
    (temp / "project-ref").write_text("abcdef123456", encoding="utf-8")
    lock.release()
    t.join(timeout=10)
    assert codes and codes[0] == EXIT_SAFETY
