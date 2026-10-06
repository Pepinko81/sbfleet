"""Health status process death."""

from __future__ import annotations

import os
import signal
import time
import uuid
from pathlib import Path

import pytest

from sbfleet import registry as reg
from sbfleet.health import FAILED, STOPPED, collect_status, status_exit_code, status_json
from sbfleet.process import ProcessResult


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    return reg.ensure_root(tmp_path / "home")


def _seed(home: Path, slug: str = "crash") -> dict:
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
            "gateway": 22010,
            "db_direct": 22011,
            "pooler_session": 22012,
            "pooler_transaction": 22013,
        },
        "domain": None,
        "public_url": "http://127.0.0.1:22010",
        "upstream": {"ref": "self-hosted/v0.8.2", "sha": "a" * 40},
        "creation_complete": True,
        "image_digests": {},
    }
    reg.write_project(home, meta)
    (reg.project_dir(home, slug) / "deployment").mkdir(parents=True)
    return meta


def _child_write_journal_and_die(home: Path, slug: str, intent: str, ready_path: Path) -> None:
    """Child: acquire nothing special; write durable in-progress journal; SIGKILL self."""
    op_id = uuid.uuid4().hex
    reg.write_operation_journal(
        home,
        slug,
        reg.new_operation_journal(
            intent=intent,
            phase="killed-mid-flight",
            state=reg.OP_STATE_IN_PROGRESS,
            operation_id=op_id,
        ),
    )
    ready_path.write_text(op_id, encoding="utf-8")
    # Ensure parent can observe durable write before death.
    time.sleep(0.05)
    os.kill(os.getpid(), signal.SIGKILL)


@pytest.mark.parametrize("intent", ["RESTORING", "UPDATING"])
def test_sigkill_after_journal_ordinary_status_failed(
    home: Path, intent: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    slug = "crash"
    _seed(home, slug)
    ready = home / f"ready-{intent}.txt"
    pid = os.fork()
    if pid == 0:
        try:
            _child_write_journal_and_die(home, slug, intent, ready)
        finally:
            os._exit(1)
    # Parent waits for durable journal marker then reaps killed child.
    deadline = time.time() + 5.0
    while time.time() < deadline and not ready.exists():
        time.sleep(0.02)
    assert ready.exists(), "child did not write journal before death"
    _pid, status = os.waitpid(pid, 0)
    assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL

    journal = reg.read_operation_journal(home, slug) or {}
    assert journal.get("intent") == intent
    assert journal.get("state") == reg.OP_STATE_IN_PROGRESS

    monkeypatch.setattr(
        "sbfleet.health.run",
        lambda *a, **k: ProcessResult(["docker"], 0, "", ""),
    )
    report = collect_status(home, slug)
    assert report.lifecycle == FAILED
    assert report.lifecycle != STOPPED
    assert status_exit_code(report) == 1
    payload = status_json(report)
    assert payload["ok"] is False
    assert payload["data"]["lifecycle"] == FAILED


@pytest.mark.parametrize("intent", ["RESTORING", "UPDATING"])
def test_sigkill_with_healthy_looking_runtime_still_failed(
    home: Path, intent: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from unittest import mock

    from sbfleet.compose import STANDARD_SERVICES
    from sbfleet.health import HEALTHY, ProbeResult

    slug = "crash"
    meta = _seed(home, slug)
    ready = home / f"ready-healthy-{intent}.txt"
    pid = os.fork()
    if pid == 0:
        try:
            _child_write_journal_and_die(home, slug, intent, ready)
        finally:
            os._exit(1)
    deadline = time.time() + 5.0
    while time.time() < deadline and not ready.exists():
        time.sleep(0.02)
    assert ready.exists()
    os.waitpid(pid, 0)

    rows = {
        svc: {
            "Service": svc,
            "State": "running",
            "Health": "healthy",
            "Name": f"{meta['compose_project']}-{svc}",
        }
        for svc in STANDARD_SERVICES
    }

    def ok_probe(*a, name=None, **k):
        return ProbeResult(name or "p", HEALTHY, "ok")

    with (
        mock.patch(
            "sbfleet.health.inspect_containers_result",
            return_value=mock.Mock(ok=True, containers=rows, error=""),
        ),
        mock.patch("sbfleet.health._http_probe", side_effect=ok_probe),
        mock.patch(
            "sbfleet.health._sql_readiness",
            return_value=ProbeResult("sql", HEALTHY, "ok"),
        ),
    ):
        report = collect_status(home, slug)
    assert report.lifecycle == FAILED
    assert status_exit_code(report) == 1


def test_stop_does_not_erase_operation(home: Path) -> None:
    from sbfleet import authority as auth

    slug = "crash"
    meta = _seed(home, slug)
    op_id = "op-preserve-stop"
    reg.write_operation_journal(
        home,
        slug,
        reg.new_operation_journal(
            intent="RESTORING",
            phase="installing",
            state=reg.OP_STATE_IN_PROGRESS,
            operation_id=op_id,
        ),
    )
    # Simulate subordinate stop evidence under parent journal.
    ctx = auth.MutationContext(
        root=home,
        slug=slug,
        meta=meta,
        deployment=reg.project_dir(home, slug) / "deployment",
        project_dir=reg.project_dir(home, slug),
        compose_project=str(meta["compose_project"]),
        fleet_id=str(meta["fleet_id"]),
        project_id=str(meta["id"]),
        compose_env={},
        operation_id=op_id,
        intent="restore",
    )
    auth.record_subordinate_stop_evidence(ctx, detail="nested stop")
    journal = reg.read_operation_journal(home, slug) or {}
    assert journal.get("operation_id") == op_id
    assert journal.get("intent") == "RESTORING"
    assert journal.get("state") == reg.OP_STATE_IN_PROGRESS
