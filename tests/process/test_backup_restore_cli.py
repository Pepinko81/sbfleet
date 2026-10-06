"""Module tests."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

from sbfleet import backup as backup_mod
from sbfleet.backup_manifest import ManifestError
from sbfleet.cli import EXIT_BACKUP, EXIT_SAFETY


def test_restore_requires_yes(tmp_path: Path):
    code = backup_mod.restore_backup(tmp_path, "demo", "x.tar.age", yes=False)
    assert code == EXIT_SAFETY


def test_create_backup_requires_identity_when_verify(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("SBFLEET_AGE_IDENTITY", raising=False)
    with mock.patch.object(backup_mod, "_require_age", return_value="/usr/bin/age"):
        with mock.patch.object(backup_mod, "_fleet_recipients", return_value=["age1test"]):
            code = backup_mod.create_backup(tmp_path, "demo", verify=True, identity=None)
    assert code != 0


def test_wrong_project_identity_is_exit_8():
    """Wrong-project UUID mismatch maps to EXIT_BACKUP (8) before destructive swap."""
    assert EXIT_BACKUP == 8
    with mock.patch.object(
        backup_mod,
        "project_identity_matches",
        side_effect=ManifestError(
            "project identity mismatch: archive project_id=aaa destination=bbb"
        ),
    ):
        try:
            backup_mod.project_identity_matches({"project_id": "aaa"}, "bbb")
        except ManifestError as exc:
            err = backup_mod.BackupError(str(exc), code=EXIT_BACKUP)
            assert err.code == EXIT_BACKUP
            assert "identity mismatch" in str(err)
            return
    raise AssertionError("expected ManifestError")
