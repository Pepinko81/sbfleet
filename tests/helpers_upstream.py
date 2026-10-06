"""Shared test helpers for upstream materialization in tests."""

from __future__ import annotations

import json
from pathlib import Path

from sbfleet import upstream as up


def ensure_critical_vendor_files(docker: Path) -> None:
    docker = Path(docker)
    docker.mkdir(parents=True, exist_ok=True)
    for rel in up.CRITICAL_VENDOR_FILES:
        path = docker / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            continue
        if rel.endswith(".sh"):
            path.write_text("#!/bin/sh\n", encoding="utf-8")
        else:
            path.write_text("services: {}\n" + ("x" * 120), encoding="utf-8")


def write_cache_marker(
    cache: Path,
    *,
    sha: str = up.PINNED_SHA,
    ref: str = up.PINNED_REF,
    repo: str = up.OFFICIAL_REPO,
) -> None:
    docker = Path(cache) / "docker"
    ensure_critical_vendor_files(docker)
    digests = up.critical_vendor_digests(docker)
    (Path(cache) / ".sbfleet-cache.json").write_text(
        json.dumps(
            {
                "format_version": 1,
                "ref": ref,
                "sha": sha,
                "repo": repo,
                "critical_digests": digests,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
