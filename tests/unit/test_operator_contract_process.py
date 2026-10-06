"""Operator contract process."""

from __future__ import annotations

import signal
import uuid
from pathlib import Path
from unittest import mock

from sbfleet import registry as reg
from sbfleet.health import STOPPED, StatusReport
from sbfleet.studio import maybe_open, open_studio


def test_maybe_open_false_warns(capsys):
    with mock.patch("sbfleet.studio.webbrowser.open", return_value=False):
        maybe_open("http://127.0.0.1:9/project/default")
    out = capsys.readouterr().out
    assert "warning" in out.lower()


def test_maybe_open_exception_warns(capsys):
    with mock.patch("sbfleet.studio.webbrowser.open", side_effect=RuntimeError("no display")):
        maybe_open("http://127.0.0.1:9/project/default")
    out = capsys.readouterr().out
    assert "warning" in out.lower()
    assert "no display" in out


def test_stopped_url_only_prints_url(tmp_path: Path, monkeypatch, capsys):
    home = reg.ensure_root(tmp_path / "home")
    slug = "stu"
    pid = str(uuid.uuid4())
    fid = reg.fleet_id(home)
    pdir = reg.project_dir(home, slug)
    pdir.mkdir(parents=True)
    meta = {
        "format_version": 1,
        "slug": slug,
        "id": pid,
        "fleet_id": fid,
        "display_name": "S",
        "creation_complete": True,
        "ports": {
            "gateway": 18000,
            "db_direct": 15432,
            "pooler_session": 15433,
            "pooler_transaction": 15434,
        },
        "upstream": {"ref": "x", "sha": "y"},
    }
    reg.atomic_write_json(pdir / "project.json", meta, mode=0o600)

    report = StatusReport(slug=slug, lifecycle=STOPPED, probes=[], meta=meta)
    monkeypatch.setattr("sbfleet.studio.collect_status", lambda *a, **k: report)
    code = open_studio(home, slug, url_only=True, offer_start=False)
    out = capsys.readouterr().out
    assert "18000" in out
    assert "/project/default" in out
    assert code == 7


def test_child_signal_exit_mapping():
    from sbfleet.process import ProcessResult

    result = ProcessResult(["x"], -signal.SIGTERM, "", "", signal=signal.SIGTERM)
    assert result.returncode < 0
    mapped = 128 + (-result.returncode)
    assert mapped == 128 + signal.SIGTERM
