"""Module tests."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from sbfleet import upstream as up


def _fake_cache(root: Path, *, sha: str = up.PINNED_SHA, ref: str = up.PINNED_REF) -> Path:
    cache = root / "cache" / "upstream" / sha
    docker = cache / "docker"
    docker.mkdir(parents=True)
    (docker / "docker-compose.yml").write_text("services: {}\n" + ("x" * 120), encoding="utf-8")
    (docker / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    os.chmod(docker / "run.sh", 0o700)
    (docker / "utils").mkdir(parents=True, exist_ok=True)
    (docker / "utils" / "generate-keys.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (docker / "utils" / "add-new-auth-keys.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (cache / "LICENSE").write_text("MIT\n", encoding="utf-8")
    digests = up.critical_vendor_digests(docker)
    (cache / ".sbfleet-cache.json").write_text(
        json.dumps(
            {
                "format_version": 1,
                "ref": ref,
                "sha": sha,
                "repo": up.OFFICIAL_REPO,
                "critical_digests": digests,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return cache


def test_reject_master_latest() -> None:
    for bad in ("master", "main", "latest", "self-hosted/latest", "self-hosted/v0.8"):
        with pytest.raises(up.UpstreamError):
            up.validate_ref(bad)


def test_accept_numeric_tag() -> None:
    assert up.validate_ref("self-hosted/v0.8.2") == "self-hosted/v0.8.2"


def test_reject_repo_override(tmp_path: Path) -> None:
    with pytest.raises(up.UpstreamError):
        up.materialize_cache(
            tmp_path,
            repo_url="https://evil.example/supabase.git",
        )


def test_corrupt_cache_detected(tmp_path: Path) -> None:
    cache = _fake_cache(tmp_path)
    (cache / "docker" / "docker-compose.yml").write_text("tiny\n", encoding="utf-8")
    with pytest.raises(up.UpstreamError):
        up.verify_cache(cache)


def test_copy_vendor_preserves_bytes_and_no_share(tmp_path: Path) -> None:
    cache = _fake_cache(tmp_path)
    dep_a = tmp_path / "a"
    dep_b = tmp_path / "b"
    up.copy_vendor_docker(cache, dep_a)
    up.copy_vendor_docker(cache, dep_b)
    a = dep_a / "docker-compose.yml"
    b = dep_b / "docker-compose.yml"
    assert a.read_bytes() == b.read_bytes()
    assert a.stat().st_ino != b.stat().st_ino
    assert (dep_a / ".supabase-version").read_text(encoding="utf-8").startswith("ref=")
    assert up.PINNED_SHA in (dep_a / ".sbfleet-upstream").read_text(encoding="utf-8")


def test_copy_refuses_nonempty_deployment(tmp_path: Path) -> None:
    cache = _fake_cache(tmp_path)
    dep = tmp_path / "dep"
    dep.mkdir()
    (dep / "stale").write_text("x", encoding="utf-8")
    with pytest.raises(up.UpstreamError):
        up.copy_vendor_docker(cache, dep)


def test_symlink_in_vendor_refused(tmp_path: Path) -> None:
    cache = _fake_cache(tmp_path)
    link = cache / "docker" / "evil"
    link.symlink_to("/etc/passwd")
    with pytest.raises(up.UpstreamError):
        up.copy_vendor_docker(cache, tmp_path / "dep")


def test_wrong_sha_marker(tmp_path: Path) -> None:
    cache = _fake_cache(tmp_path, sha=up.PINNED_SHA)
    marker = json.loads((cache / ".sbfleet-cache.json").read_text(encoding="utf-8"))
    marker["sha"] = "0" * 40
    (cache / ".sbfleet-cache.json").write_text(json.dumps(marker), encoding="utf-8")
    with pytest.raises(up.UpstreamError):
        up.verify_cache(cache, sha=up.PINNED_SHA)


def test_verify_stamp_matches_meta_ok(tmp_path: Path) -> None:
    dep = tmp_path / "dep"
    dep.mkdir()
    up.write_version_stamp(dep, ref=up.PINNED_REF, sha=up.PINNED_SHA)
    meta = {"upstream": {"ref": up.PINNED_REF, "sha": up.PINNED_SHA}}
    up.verify_stamp_matches_meta(dep, meta)


def test_verify_stamp_matches_meta_refuses_mismatch(tmp_path: Path) -> None:
    dep = tmp_path / "dep"
    dep.mkdir()
    up.write_version_stamp(dep, ref=up.PINNED_REF, sha=up.PINNED_SHA)
    meta = {"upstream": {"ref": "self-hosted/v0.8.1", "sha": up.PINNED_SHA}}
    with pytest.raises(up.UpstreamError, match="ref mismatch"):
        up.verify_stamp_matches_meta(dep, meta)


def test_verify_deployment_vendor_detects_drift(tmp_path: Path) -> None:
    cache = _fake_cache(tmp_path)
    dep = tmp_path / "dep"
    up.copy_vendor_docker(cache, dep)
    (dep / "docker-compose.yml").write_text("services: {}\n" + ("y" * 120), encoding="utf-8")
    with pytest.raises(up.UpstreamError, match="vendor drift"):
        up.verify_deployment_vendor(dep, sha=up.PINNED_SHA, root=tmp_path)


def test_verify_deployment_vendor_requires_cache(tmp_path: Path) -> None:
    dep = tmp_path / "dep"
    dep.mkdir()
    (dep / "docker-compose.yml").write_text("services: {}\n" + ("x" * 120), encoding="utf-8")
    with pytest.raises(up.UpstreamError, match="cache unavailable"):
        up.verify_deployment_vendor(dep, sha=up.PINNED_SHA, root=tmp_path)
