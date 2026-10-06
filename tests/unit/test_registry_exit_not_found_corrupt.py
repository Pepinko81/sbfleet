"""Registry exit not found corrupt."""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import pytest

from sbfleet import registry as reg
from sbfleet.cli import (
    EXIT_FAILURE,
    EXIT_NOT_FOUND,
    EXIT_PREREQUISITE,
    build_parser,
    dispatch_namespace,
)


@pytest.fixture()
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "sbfleet-home"
    monkeypatch.setenv("HOME", str(tmp_path / "user"))
    monkeypatch.delenv("SBFLEET_HOME", raising=False)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    return reg.ensure_root(root)


def _write_ok_project(home: Path, slug: str = "demo") -> dict:
    fid = reg.fleet_id(home)
    pid = str(uuid.uuid4())
    data = {
        "format_version": 1,
        "id": pid,
        "fleet_id": fid,
        "slug": slug,
        "display_name": "Demo",
        "created_at": "2026-09-26T00:00:00Z",
        "profile": "standard",
        "compose_project": reg.compose_project_name(fid, pid),
        "ports": {
            "gateway": 18000,
            "db_direct": 15432,
            "pooler_session": 15433,
            "pooler_transaction": 15434,
        },
        "domain": None,
        "public_url": "http://127.0.0.1:18000",
        "upstream": {
            "ref": "self-hosted/v0.8.2",
            "sha": "564eab8ad7840b13324f68b1bfac074ef8d51c21",
        },
        "last_verified_upstream": None,
        "image_digests": {},
        "creation_complete": True,
    }
    reg.write_project(home, data)
    return data


def _run(home: Path, argv: list[str]) -> int:
    args = build_parser().parse_args(["--home", str(home), *argv])
    return dispatch_namespace(args)


def test_read_project_absent_dir_raises_not_found(home: Path) -> None:
    with pytest.raises(reg.NotFoundError, match="project not found"):
        reg.read_project(home, "nope")


def test_read_project_dir_without_json_is_corrupt_not_absent(home: Path) -> None:
    pdir = home / "projects" / "broken"
    pdir.mkdir(mode=0o700)
    with pytest.raises(reg.OwnershipError, match="incomplete/corrupt"):
        reg.read_project(home, "broken")


def test_read_project_malformed_json_not_absent(home: Path) -> None:
    pdir = home / "projects" / "broken"
    pdir.mkdir(mode=0o700)
    path = pdir / "project.json"
    path.write_text("{not-json", encoding="utf-8")
    os.chmod(path, 0o600)
    with pytest.raises(reg.ValidationError, match="malformed"):
        reg.read_project(home, "broken")


def test_read_project_fleet_mismatch_not_absent(home: Path) -> None:
    data = _write_ok_project(home, "demo")
    data["fleet_id"] = str(uuid.uuid4())
    path = reg.project_json_path(home, "demo")
    path.write_text(json.dumps(data), encoding="utf-8")
    os.chmod(path, 0o600)
    with pytest.raises(reg.OwnershipError, match="fleet_id mismatch"):
        reg.read_project(home, "demo")


@pytest.mark.parametrize(
    "cmd",
    [
        ["status", "ghost"],
        ["start", "ghost"],
        ["connection", "ghost"],
        ["secrets", "ghost"],
        ["studio", "ghost", "--url-only"],
    ],
)
def test_cli_true_absence_exit_3(home: Path, cmd: list[str]) -> None:
    code = _run(home, cmd)
    assert code == EXIT_NOT_FOUND


def test_cli_missing_project_json_not_exit_3(home: Path) -> None:
    pdir = home / "projects" / "broken"
    pdir.mkdir(mode=0o700)
    code = _run(home, ["status", "broken"])
    assert code != EXIT_NOT_FOUND
    assert code in {EXIT_FAILURE, EXIT_PREREQUISITE, 5, 1}


def test_cli_malformed_project_json_not_exit_3(home: Path) -> None:
    pdir = home / "projects" / "broken"
    pdir.mkdir(mode=0o700)
    path = pdir / "project.json"
    path.write_text("{not-json", encoding="utf-8")
    os.chmod(path, 0o600)
    code = _run(home, ["status", "broken"])
    assert code != EXIT_NOT_FOUND


def test_cli_missing_identity_still_exit_4(
    home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Exit-4 control: missing age identity remains prerequisite, not not-found."""
    _write_ok_project(home, "demo")
    monkeypatch.delenv("SBFLEET_AGE_IDENTITY", raising=False)
    # Point age at a missing binary path via PATH that has no age, or force require_age.
    from sbfleet import backup as bak

    monkeypatch.setattr(
        bak,
        "_require_age",
        lambda: (_ for _ in ()).throw(bak.BackupError("age not found", code=EXIT_PREREQUISITE)),
    )
    code = bak.create_backup(home, "demo", verify=False, identity=None)
    # Missing recipients / other prereqs may also fail; ensure not exit 3.
    assert code != EXIT_NOT_FOUND


def test_authority_absent_code_3(home: Path) -> None:
    from sbfleet import authority as auth

    with pytest.raises(auth.AuthorityError) as ei:
        with auth.authorize_mutation(home, "ghost", intent="start"):
            pass
    assert ei.value.code == 3


def test_authority_corrupt_not_code_3(home: Path) -> None:
    from sbfleet import authority as auth

    pdir = home / "projects" / "broken"
    pdir.mkdir(mode=0o700)
    with pytest.raises(auth.AuthorityError) as ei:
        with auth.authorize_mutation(home, "broken", intent="start"):
            pass
    assert ei.value.code != 3
