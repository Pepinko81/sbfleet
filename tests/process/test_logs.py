"""Module tests."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from sbfleet import projects as proj
from sbfleet import registry as reg


def test_unknown_service_rejected(tmp_path: Path) -> None:
    home = reg.ensure_root(tmp_path / "home")
    fid = reg.fleet_id(home)
    pid = str(uuid.uuid4())
    slug = "lg"
    reg.write_project(
        home,
        {
            "format_version": 1,
            "id": pid,
            "fleet_id": fid,
            "slug": slug,
            "display_name": "L",
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
            "upstream": {"ref": "self-hosted/v0.8.2", "sha": "a" * 40},
            "last_verified_upstream": None,
            "image_digests": {},
            "creation_complete": True,
        },
    )
    dep = reg.project_dir(home, slug) / "deployment"
    dep.mkdir(parents=True)
    (dep / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    with pytest.raises(proj.ProjectError, match="unknown service"):
        proj.project_logs(home, slug, service="not-a-service")
