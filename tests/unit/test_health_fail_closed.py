"""Health fail closed."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from unittest import mock

import pytest

from sbfleet import registry as reg
from sbfleet.health import (
    FAILED,
    HEALTHY,
    STARTING,
    STOPPED,
    UNKNOWN,
    StatusReport,
    collect_status,
    inspect_containers_result,
    status_exit_code,
    status_ok_flag,
)
from sbfleet.process import ProcessResult


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    return reg.ensure_root(tmp_path / "home")


def _seed(home: Path) -> dict:
    fid = reg.fleet_id(home)
    pid = str(uuid.uuid4())
    cp = reg.compose_project_name(fid, pid)
    meta = {
        "format_version": 1,
        "id": pid,
        "fleet_id": fid,
        "slug": "alpha",
        "display_name": "alpha",
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
        "creation_complete": True,
        "image_digests": {},
    }
    reg.write_project(home, meta)
    dep = reg.project_dir(home, "alpha") / "deployment"
    dep.mkdir(parents=True)
    return meta


def test_malformed_compose_ps_not_stopped(home: Path) -> None:
    meta = _seed(home)
    dep = reg.project_dir(home, "alpha") / "deployment"
    with mock.patch(
        "sbfleet.health.run",
        return_value=ProcessResult(["docker"], 0, "not-json\n", ""),
    ):
        result = inspect_containers_result(dep, str(meta["compose_project"]))
    assert result.ok is False
    report = collect_status(home, "alpha") if False else None
    with mock.patch(
        "sbfleet.health.run",
        return_value=ProcessResult(["docker"], 0, "not-json\n", ""),
    ):
        report = collect_status(home, "alpha")
    assert report.lifecycle != STOPPED
    assert report.enum_ok is False
    assert status_exit_code(report) != 0


def test_mixed_valid_and_malformed_rows_fail_closed(home: Path) -> None:
    meta = _seed(home)
    dep = reg.project_dir(home, "alpha") / "deployment"
    stdout = (
        json.dumps({"Service": "db", "State": "running", "Name": f"{meta['compose_project']}-db"})
        + "\nnot-json\n"
    )
    with mock.patch(
        "sbfleet.health.run",
        return_value=ProcessResult(["docker"], 0, stdout, ""),
    ):
        result = inspect_containers_result(dep, str(meta["compose_project"]))
    assert result.ok is False


def test_unresolved_with_empty_containers_is_failed(home: Path) -> None:
    _seed(home)
    reg.write_operation_journal(
        home,
        "alpha",
        reg.new_operation_journal(
            intent="RESTORING",
            phase="install",
            state=reg.OP_STATE_FAILED,
            operation_id="op1",
        ),
    )
    with mock.patch(
        "sbfleet.health.run",
        return_value=ProcessResult(["docker"], 0, "", ""),
    ):
        report = collect_status(home, "alpha")
    assert report.lifecycle == FAILED
    assert report.lifecycle != STOPPED
    assert status_exit_code(report) == 1
    assert status_ok_flag(report) is False


def test_in_progress_backup_forces_failed_for_ordinary_status(home: Path) -> None:
    """Ordinary observers must see durable in-progress BACKUP as FAILED (V3-004)."""
    _seed(home)
    reg.write_operation_journal(
        home,
        "alpha",
        reg.new_operation_journal(
            intent="BACKUP",
            phase="restoring_prior_state",
            state=reg.OP_STATE_IN_PROGRESS,
            operation_id="op-backup",
        ),
    )
    with mock.patch(
        "sbfleet.health.run",
        return_value=ProcessResult(["docker"], 0, "", ""),
    ):
        report = collect_status(home, "alpha")
    assert report.lifecycle == FAILED
    assert report.lifecycle != STOPPED
    assert status_exit_code(report) == 1
    assert status_ok_flag(report) is False


def test_unresolved_with_healthy_looking_containers_is_failed(home: Path) -> None:
    meta = _seed(home)
    reg.write_operation_journal(
        home,
        "alpha",
        reg.new_operation_journal(
            intent="UPDATING",
            phase="promote",
            state=reg.OP_STATE_FAILED,
            operation_id="op2",
        ),
    )
    rows = []
    for svc in (
        "studio",
        "api-gw",
        "auth",
        "rest",
        "realtime",
        "storage",
        "imgproxy",
        "meta",
        "functions",
        "db",
        "supavisor",
    ):
        rows.append(
            {
                "Service": svc,
                "State": "running",
                "Health": "healthy",
                "Name": f"{meta['compose_project']}-{svc}",
            }
        )
    with (
        mock.patch(
            "sbfleet.health.inspect_containers_result",
            return_value=mock.Mock(ok=True, containers={r["Service"]: r for r in rows}, error=""),
        ),
        mock.patch(
            "sbfleet.health._http_probe",
            return_value=mock.Mock(status=HEALTHY, detail="HTTP 200", name="x"),
        ),
        mock.patch(
            "sbfleet.health._sql_readiness",
            return_value=mock.Mock(status=HEALTHY, detail="ok", name="sql"),
        ),
    ):
        # _http_probe returns ProbeResult-like; collect_status expects ProbeResult fields
        from sbfleet.health import ProbeResult

        def ok_probe(*a, name=None, **k):
            return ProbeResult(name or "p", HEALTHY, "HTTP 200")

        with (
            mock.patch("sbfleet.health._http_probe", side_effect=ok_probe),
            mock.patch(
                "sbfleet.health._sql_readiness",
                return_value=ProbeResult("sql", HEALTHY, "SELECT 1"),
            ),
        ):
            report = collect_status(home, "alpha")
    assert report.lifecycle == FAILED
    assert report.lifecycle != HEALTHY
    assert any(p.name == "operation" for p in report.probes)
    assert status_exit_code(report) == 1
    assert report.ok is False


@pytest.mark.parametrize(
    ("lifecycle", "exit_code", "ok"),
    [
        (HEALTHY, 0, True),
        (STOPPED, 0, False),
        (STARTING, 0, False),
        (UNKNOWN, 7, False),
        (FAILED, 1, False),
        ("DEGRADED", 7, False),
        ("UNHEALTHY", 7, False),
    ],
)
def test_status_exit_and_ok_matrix(lifecycle: str, exit_code: int, ok: bool) -> None:
    report = StatusReport(slug="alpha", lifecycle=lifecycle, probes=[], meta={})
    assert status_exit_code(report) == exit_code
    assert status_ok_flag(report) is ok
    assert report.ok is ok
