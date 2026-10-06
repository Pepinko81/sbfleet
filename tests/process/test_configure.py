"""Process-level configure CLI wiring."""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest

from sbfleet import registry as reg
from sbfleet import upstream as up
from sbfleet.cli import main


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    return reg.ensure_root(tmp_path / "home")


def _seed(root: Path, slug: str = "myapp") -> None:
    fid = reg.fleet_id(root)
    pid = str(uuid.uuid4())
    meta = {
        "format_version": 1,
        "id": pid,
        "fleet_id": fid,
        "slug": slug,
        "display_name": "My App",
        "created_at": "2026-10-04T00:00:00Z",
        "profile": "standard",
        "compose_project": reg.compose_project_name(fid, pid),
        "ports": {
            "gateway": 54321,
            "db_direct": 54322,
            "pooler_session": 54323,
            "pooler_transaction": 54324,
        },
        "domain": None,
        "public_url": "http://127.0.0.1:54321",
        "upstream": {"ref": up.PINNED_REF, "sha": up.PINNED_SHA},
        "last_verified_upstream": None,
        "image_digests": {},
        "creation_complete": True,
        "branding": {
            "organization_name": "Default Organization",
            "project_name": "Default Project",
        },
    }
    pdir = reg.project_dir(root, slug)
    dep = pdir / "deployment"
    dep.mkdir(parents=True)
    (dep / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    os.chmod(dep / "run.sh", 0o700)
    env = {
        "JWT_SECRET": "j" * 32,
        "ANON_KEY": "anon",
        "SERVICE_ROLE_KEY": "svc",
        "POSTGRES_PASSWORD": "p" * 32,
        "DASHBOARD_PASSWORD": "d" * 32,
        "COMPOSE_PROJECT_NAME": str(meta["compose_project"]),
        "COMPOSE_FILE": "docker-compose.yml:docker-compose.override.yml",
        "COMPOSE_PATH_SEPARATOR": ":",
        "STUDIO_DEFAULT_ORGANIZATION": "Default Organization",
        "STUDIO_DEFAULT_PROJECT": "Default Project",
    }
    env_path = dep / ".env"
    env_path.write_text(up.dump_dotenv(env), encoding="utf-8")
    os.chmod(env_path, 0o600)
    reg.write_project(root, meta)


def test_direct_configure_read_and_mutate(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import sbfleet.configure as cfg

    _seed(home)
    monkeypatch.setattr(cfg, "_probe_studio_env", lambda *_a, **_k: {})
    assert main(["--home", str(home), "configure", "myapp"]) == 0
    assert (
        main(
            [
                "--home",
                str(home),
                "configure",
                "myapp",
                "--organization-name",
                "Acme",
                "--studio-project",
                "Orders",
                "--name",
                "Orders App",
            ]
        )
        == 0
    )
    meta = reg.read_project(home, "myapp")
    assert meta["display_name"] == "Orders App"
    assert meta["slug"] == "myapp"
    env_vals = up.parse_dotenv(
        (reg.project_dir(home, "myapp") / "deployment" / ".env").read_text(encoding="utf-8")
    )
    assert env_vals["STUDIO_DEFAULT_ORGANIZATION"] == "Acme"
    assert env_vals["STUDIO_DEFAULT_PROJECT"] == "Orders"


def test_configure_missing_project(home: Path) -> None:
    assert main(["--home", str(home), "configure", "nope"]) == 3
