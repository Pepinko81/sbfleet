"""Module tests."""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import pytest

from sbfleet import registry as reg


@pytest.fixture()
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "sbfleet-home"
    monkeypatch.setenv("HOME", str(tmp_path / "user"))
    monkeypatch.delenv("SBFLEET_HOME", raising=False)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    return reg.ensure_root(root)


def test_resolve_home_precedence(tmp_path: Path) -> None:
    explicit = tmp_path / "explicit"
    assert reg.resolve_home(explicit) == explicit.resolve()
    env = {"SBFLEET_HOME": str(tmp_path / "envhome"), "HOME": str(tmp_path / "h")}
    assert reg.resolve_home(None, environ=env) == (tmp_path / "envhome").resolve()
    env2 = {"XDG_DATA_HOME": str(tmp_path / "xdg"), "HOME": str(tmp_path / "h")}
    assert reg.resolve_home(None, environ=env2) == (tmp_path / "xdg" / "sbfleet").resolve()
    env3 = {"HOME": str(tmp_path / "h")}
    assert (
        reg.resolve_home(None, environ=env3)
        == (tmp_path / "h" / ".local" / "share" / "sbfleet").resolve()
    )


def test_relative_home_rejected(tmp_path: Path) -> None:
    with pytest.raises(reg.ValidationError):
        reg.resolve_home("relative")


@pytest.mark.parametrize(
    "slug",
    ["a", "app1", "my-app", "a" + "b" * 30],
)
def test_valid_slugs(slug: str) -> None:
    assert reg.validate_slug(slug) == slug


@pytest.mark.parametrize(
    "slug",
    [
        "all",
        "Bad",
        "-bad",
        "bad-",
        "has space",
        "üni",
        "../x",
        "a/b",
        "--opt",
        "-o",
        "",
        "a" * 33,
    ],
)
def test_invalid_slugs(slug: str) -> None:
    with pytest.raises(reg.ValidationError):
        reg.validate_slug(slug)


def test_atomic_write_preserves_old_on_failure(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = home / "fleet.json"
    original = path.read_text(encoding="utf-8")

    def boom(*_a: object, **_k: object) -> None:
        raise OSError("simulated failure after write")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        reg.atomic_write_json(path, {"format_version": 1, "fleet_id": str(uuid.uuid4())})
    assert path.read_text(encoding="utf-8") == original


def test_write_and_list_project(home: Path) -> None:
    fid = reg.fleet_id(home)
    pid = str(uuid.uuid4())
    data = {
        "format_version": 1,
        "id": pid,
        "fleet_id": fid,
        "slug": "demo",
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
        "creation_complete": False,
    }
    reg.write_project(home, data)
    loaded = reg.read_project(home, "demo")
    assert loaded["id"] == pid
    rows = reg.list_projects(home)
    assert len(rows) == 1
    assert rows[0].ok
    assert rows[0].slug == "demo"


def test_malformed_row_remains_visible(home: Path) -> None:
    bad = home / "projects" / "broken"
    bad.mkdir(mode=0o700)
    (bad / "project.json").write_text("{not-json", encoding="utf-8")
    os.chmod(bad / "project.json", 0o600)
    rows = reg.list_projects(home)
    assert len(rows) == 1
    assert not rows[0].ok
    assert bad.exists()


def test_unknown_schema_preserved(home: Path) -> None:
    path = home / "projects" / "x" / "project.json"
    path.parent.mkdir(parents=True, mode=0o700)
    path.write_text(json.dumps({"format_version": 99, "slug": "x"}), encoding="utf-8")
    os.chmod(path, 0o600)
    rows = reg.list_projects(home)
    assert len(rows) == 1
    assert not rows[0].ok
    assert path.exists()


def test_symlink_project_refused(home: Path, tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.mkdir()
    link = home / "projects" / "linked"
    link.symlink_to(target)
    rows = reg.list_projects(home)
    assert len(rows) == 1
    assert not rows[0].ok
    with pytest.raises(reg.OwnershipError):
        reg.read_project(home, "linked")


def test_foreign_fleet_id_rejected(home: Path) -> None:
    fid = reg.fleet_id(home)
    pid = str(uuid.uuid4())
    data = {
        "format_version": 1,
        "id": pid,
        "fleet_id": str(uuid.uuid4()),
        "slug": "foreign",
        "display_name": "Foreign",
        "created_at": "2026-09-26T00:00:00Z",
        "profile": "standard",
        "compose_project": reg.compose_project_name(fid, pid),
        "ports": {
            "gateway": 1,
            "db_direct": 2,
            "pooler_session": 3,
            "pooler_transaction": 4,
        },
        "domain": None,
        "public_url": "http://127.0.0.1:1",
        "upstream": {
            "ref": "self-hosted/v0.8.2",
            "sha": "564eab8ad7840b13324f68b1bfac074ef8d51c21",
        },
        "last_verified_upstream": None,
        "image_digests": {},
        "creation_complete": True,
    }
    # Write without going through read_project ownership check.
    dest = home / "projects" / "foreign"
    dest.mkdir(mode=0o700)
    reg.atomic_write_json(dest / "project.json", data)
    with pytest.raises(reg.OwnershipError):
        reg.read_project(home, "foreign")
    rows = reg.list_projects(home)
    assert any(not r.ok for r in rows)


def test_operation_journal(home: Path) -> None:
    fid = reg.fleet_id(home)
    pid = str(uuid.uuid4())
    reg.write_project(
        home,
        {
            "format_version": 1,
            "id": pid,
            "fleet_id": fid,
            "slug": "j",
            "display_name": "J",
            "created_at": "2026-09-26T00:00:00Z",
            "profile": "standard",
            "compose_project": reg.compose_project_name(fid, pid),
            "ports": {
                "gateway": 1,
                "db_direct": 2,
                "pooler_session": 3,
                "pooler_transaction": 4,
            },
            "domain": None,
            "public_url": "http://127.0.0.1:1",
            "upstream": {"ref": "r", "sha": "s"},
            "last_verified_upstream": None,
            "image_digests": {},
            "creation_complete": False,
        },
    )
    reg.write_operation_journal(home, "j", {"intent": "CREATING", "phase": "ports"})
    journal = reg.read_operation_journal(home, "j")
    assert journal is not None
    assert journal["intent"] == "CREATING"


def test_display_name_controls_rejected() -> None:
    with pytest.raises(reg.ValidationError):
        reg.validate_display_name("bad\nname")
