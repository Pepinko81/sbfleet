"""Module tests."""

from __future__ import annotations

import uuid
from pathlib import Path

from sbfleet import health as h
from sbfleet import registry as reg


def test_stopped_when_no_containers(tmp_path: Path, monkeypatch) -> None:
    home = reg.ensure_root(tmp_path / "home")
    fid = reg.fleet_id(home)
    pid = str(uuid.uuid4())
    slug = "st"
    reg.write_project(
        home,
        {
            "format_version": 1,
            "id": pid,
            "fleet_id": fid,
            "slug": slug,
            "display_name": "S",
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
    monkeypatch.setattr(
        h,
        "inspect_containers_result",
        lambda *a, **k: h.ContainerInspectResult(ok=True, containers={}),
    )
    report = h.collect_status(home, slug)
    assert report.lifecycle == h.STOPPED
