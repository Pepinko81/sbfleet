"""Immutable project id."""

from __future__ import annotations

from pathlib import Path

import pytest

from sbfleet.sandbox_adoption import (
    SandboxAdoptionError,
    SandboxLocks,
    commit_adoption_pair,
    index_path_for,
    new_adoption,
    reconcile_adoption_index,
    update_record_fields,
)


def _adopt(home: Path, canonical: Path, pid: str):
    rec = new_adoption(
        canonical=canonical,
        cli_project_id=pid,
        config_fingerprint="fp1",
        fingerprint_fields={"project_id": pid},
        cli_version="2.118.0",
        migration_mode="supabase",
    )
    with SandboxLocks(home, canonical):
        commit_adoption_pair(home, rec)
    return rec


def test_revalidate_cannot_change_project_id(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    ca = tmp_path / "app-a"
    cb = tmp_path / "app-b"
    ca.mkdir()
    cb.mkdir()
    _adopt(home, ca, "sbfleet-test-aaa")
    _adopt(home, cb, "sbfleet-test-bbb")
    with SandboxLocks(home, ca):
        with pytest.raises(SandboxAdoptionError, match="immutable|differs"):
            reconcile_adoption_index(home, ca, cli_project_id="sbfleet-test-bbb")


def test_missing_index_fail_closed(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    app = tmp_path / "app"
    app.mkdir()
    rec = _adopt(home, app, "sbfleet-test-miss")
    index_path_for(home, rec.cli_project_id).unlink()
    with SandboxLocks(home, app):
        with pytest.raises(SandboxAdoptionError, match="index missing"):
            reconcile_adoption_index(home, app, cli_project_id=rec.cli_project_id)


def test_conflicting_index_fail_closed(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    app = tmp_path / "app"
    app.mkdir()
    rec = _adopt(home, app, "sbfleet-test-conf")
    idx = index_path_for(home, rec.cli_project_id)
    # Point index at a different sandbox UUID
    data = __import__("json").loads(idx.read_text(encoding="utf-8"))
    data["sandbox_uuid"] = "00000000-0000-4000-8000-000000000099"
    idx.write_text(__import__("json").dumps(data), encoding="utf-8")
    with SandboxLocks(home, app):
        with pytest.raises(SandboxAdoptionError, match="disagree"):
            reconcile_adoption_index(home, app, cli_project_id=rec.cli_project_id)


def test_fingerprint_revalidate_keeps_same_id(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    app = tmp_path / "app"
    app.mkdir()
    rec = _adopt(home, app, "sbfleet-test-fp")
    updated = update_record_fields(
        rec,
        config_fingerprint="fp2",
        fingerprint_fields={"project_id": "sbfleet-test-fp", "api.port": 1},
    )
    assert updated.cli_project_id == "sbfleet-test-fp"
    with SandboxLocks(home, app):
        commit_adoption_pair(home, updated)
        loaded = reconcile_adoption_index(home, app, cli_project_id="sbfleet-test-fp")
    assert loaded is not None
    assert loaded.cli_project_id == "sbfleet-test-fp"
    assert loaded.config_fingerprint == "fp2"


def test_interrupted_journal_refuses(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    app = tmp_path / "app"
    app.mkdir()
    from sbfleet.sandbox_adoption import journal_path, sandboxes_root

    sandboxes_root(home).mkdir(parents=True, exist_ok=True)
    journal_path(home).write_text('{"phase":"commit"}', encoding="utf-8")
    with SandboxLocks(home, app):
        with pytest.raises(SandboxAdoptionError, match="journal"):
            reconcile_adoption_index(home, app, cli_project_id="sbfleet-test-j")
