"""Crash aware status."""

from __future__ import annotations

import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from sbfleet import registry as reg
from sbfleet.health import (
    FAILED,
    HEALTHY,
    STOPPED,
    collect_status,
    collect_status_for_mutation,
    status_exit_code,
    status_ok_flag,
)
from sbfleet.process import ProcessResult


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    return reg.ensure_root(tmp_path / "home")


def _seed(home: Path, slug: str = "alpha") -> dict:
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
    (reg.project_dir(home, slug) / "deployment").mkdir(parents=True)
    return meta


def _write_in_progress(home: Path, slug: str, *, intent: str, op_id: str) -> None:
    reg.write_operation_journal(
        home,
        slug,
        reg.new_operation_journal(
            intent=intent,
            phase="mid",
            state=reg.OP_STATE_IN_PROGRESS,
            operation_id=op_id,
        ),
    )


def test_ordinary_status_restoring_in_progress_empty_is_failed(home: Path) -> None:
    _seed(home)
    _write_in_progress(home, "alpha", intent="RESTORING", op_id="op-restore")
    with mock.patch(
        "sbfleet.health.run",
        return_value=ProcessResult(["docker"], 0, "", ""),
    ):
        report = collect_status(home, "alpha")
    assert report.lifecycle == FAILED
    assert report.lifecycle != STOPPED
    assert status_exit_code(report) == 1
    assert status_ok_flag(report) is False
    assert any(p.name == "operation" for p in report.probes)


def test_ordinary_status_updating_in_progress_healthy_looking_is_failed(home: Path) -> None:
    meta = _seed(home)
    _write_in_progress(home, "alpha", intent="UPDATING", op_id="op-update")
    from sbfleet.compose import STANDARD_SERVICES
    from sbfleet.health import ProbeResult

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
        report = collect_status(home, "alpha")
    assert report.lifecycle == FAILED
    assert report.lifecycle != HEALTHY
    assert status_exit_code(report) == 1


def test_raw_operation_id_cannot_suppress_via_ordinary_api(home: Path) -> None:
    """collect_status has no operation-id suppression parameter."""
    import inspect

    sig = inspect.signature(collect_status)
    assert "ignore_journal_operation_id" not in sig.parameters


def test_mutation_ctx_may_observe_runtime(home: Path) -> None:
    _seed(home)
    op_id = "op-owner"
    _write_in_progress(home, "alpha", intent="BACKUP", op_id=op_id)
    ctx = SimpleNamespace(root=home, slug="alpha", operation_id=op_id)
    with mock.patch(
        "sbfleet.health.run",
        return_value=ProcessResult(["docker"], 0, "", ""),
    ):
        report = collect_status_for_mutation(ctx)  # type: ignore[arg-type]
    assert report.lifecycle == STOPPED
    assert report.lifecycle != FAILED


def test_foreign_mutation_ctx_cannot_suppress(home: Path) -> None:
    _seed(home)
    _write_in_progress(home, "alpha", intent="RESTORING", op_id="op-real")
    ctx = SimpleNamespace(root=home, slug="alpha", operation_id="op-forged")
    with mock.patch(
        "sbfleet.health.run",
        return_value=ProcessResult(["docker"], 0, "", ""),
    ):
        report = collect_status_for_mutation(ctx)  # type: ignore[arg-type]
    assert report.lifecycle == FAILED
