"""Shared pin-cache fixture helpers for tests that exercise mutation authority."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from sbfleet import upstream as up


def ensure_pin_cache(root: Path) -> Path:
    """Ensure ``cache/upstream/<PINNED_SHA>`` exists (symlink host cache or materialize)."""
    dest = up.cache_dir(root, up.PINNED_SHA)
    if dest.is_dir() and (dest / "docker" / "docker-compose.yml").is_file():
        return dest
    candidates = [
        Path.home() / ".local/share/sbfleet/cache/upstream" / up.PINNED_SHA,
        Path.home() / ".cache/sbfleet/acceptance-home/cache/upstream" / up.PINNED_SHA,
    ]
    dest.parent.mkdir(parents=True, exist_ok=True)
    for src in candidates:
        if src.is_dir() and (src / "docker" / "docker-compose.yml").is_file():
            if dest.exists() or dest.is_symlink():
                if dest.is_symlink() or dest.is_file():
                    dest.unlink()
                else:
                    shutil.rmtree(dest)
            os.symlink(src, dest)
            return dest
    return up.materialize_cache(root, ref=up.PINNED_REF, sha=up.PINNED_SHA)


def install_vendor_deployment(
    root: Path, deployment: Path, *, instrument_run_sh: str | None = None
) -> None:
    """Copy pinned vendor docker/ into deployment and refresh critical digest marker."""
    cache = ensure_pin_cache(root)
    docker_src = cache / "docker"
    deployment.mkdir(parents=True, exist_ok=True)
    for rel in up.CRITICAL_VENDOR_FILES:
        src = docker_src / rel
        dest = deployment / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
    # Also need full compose tree mounts/volumes for compose config — copy docker contents.
    for item in docker_src.iterdir():
        target = deployment / item.name
        if target.exists() or target.is_symlink():
            continue
        if item.is_dir():
            shutil.copytree(item, target, symlinks=False)
        else:
            shutil.copy2(item, target)
    if instrument_run_sh is not None:
        run_sh = deployment / "run.sh"
        run_sh.write_text(instrument_run_sh, encoding="utf-8")
        os.chmod(run_sh, 0o700)
        digests = up.critical_vendor_digests(deployment)
        marker = {
            "format_version": 1,
            "ref": up.PINNED_REF,
            "sha": up.PINNED_SHA,
            "repo": up.OFFICIAL_REPO,
            "critical_digests": digests,
        }
        # Write a *test-local* marker beside the symlink target when possible; if cache
        # is a symlink to shared host cache, write digests into a wrapper by replacing
        # symlink with a private copy of the marker only via a local overlay.
        if cache.is_symlink():
            # Private cache copy of marker: break symlink into directory copy of docker + marker.
            real = cache.resolve()
            cache.unlink()
            shutil.copytree(real, cache, symlinks=False)
        (cache / ".sbfleet-cache.json").write_text(
            json.dumps(marker, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.chmod(cache / ".sbfleet-cache.json", 0o600)
    up.write_version_stamp(deployment, ref=up.PINNED_REF, sha=up.PINNED_SHA)
