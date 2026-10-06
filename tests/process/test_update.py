"""Module tests."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

from sbfleet import update as upd
from sbfleet.cli import EXIT_SAFETY
from sbfleet.process import ProcessResult


def test_run_official_updater_argv_and_timeout(tmp_path: Path):
    staging = tmp_path / "stage"
    staging.mkdir(mode=0o700)
    (staging / "update.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    captured: dict = {}

    def fake_run(argv, *, cwd=None, env=None, timeout=None, **kwargs):
        captured["argv"] = list(argv)
        captured["cwd"] = str(cwd)
        captured["timeout"] = timeout
        captured["env"] = dict(env or {})
        return ProcessResult(argv=list(argv), returncode=0, stdout="", stderr="")

    with mock.patch.object(upd, "run", side_effect=fake_run):
        upd.run_official_updater(staging, to_ref="self-hosted/v0.8.2", timeout=12.5)

    assert captured["argv"] == ["sh", "update.sh", "--to", "self-hosted/v0.8.2"]
    assert captured["cwd"] == str(staging)
    assert captured["timeout"] == 12.5
    assert "SUPABASE_REPO_URL" in captured["env"]
    # Must not invent --yes.
    assert "--yes" not in captured["argv"]
    assert "--dry-run" not in captured["argv"]


def test_update_missing_to_is_safety():
    code = upd.update_project(
        Path("/tmp"),
        "x",
        to_ref=None,
        dry_run=False,
        yes=True,
    )
    assert code == EXIT_SAFETY


def test_updater_timeout_fails_closed(tmp_path: Path):
    staging = tmp_path / "stage"
    staging.mkdir()
    (staging / ".supabase-version").write_text("ref=self-hosted/v0.8.1\n", encoding="utf-8")
    result = ProcessResult(
        argv=["sh", "update.sh", "--to", "self-hosted/v0.8.2"],
        returncode=-1,
        stdout="",
        stderr="",
        timed_out=True,
    )
    try:
        upd.inspect_updater_result(
            staging,
            result,
            to_ref="self-hosted/v0.8.2",
            to_sha="564eab8ad7840b13324f68b1bfac074ef8d51c21",
        )
        raise AssertionError("expected timeout UpdateError")
    except upd.UpdateError as exc:
        assert "timed out" in str(exc)
