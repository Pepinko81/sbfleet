"""Module tests."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

from sbfleet import upstream as up
from sbfleet.process import ProcessResult


def test_fetch_failure_fail_closed(tmp_path: Path) -> None:
    def fake_run(argv, **kwargs):  # type: ignore[no-untyped-def]
        return ProcessResult(argv=list(argv), returncode=1, stdout="", stderr="network down")

    with mock.patch("sbfleet.upstream.run", side_effect=fake_run):
        with pytest.raises(up.UpstreamError):
            up.materialize_cache(tmp_path, force=True)


def test_tag_movement_sha_mismatch(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(list(argv))
        if argv[:2] == ["git", "init"] or (len(argv) >= 2 and argv[0] == "git" and "init" in argv):
            # upstream._git uses ["git", *argv] where argv starts with init/--quiet
            pass
        if "rev-parse" in argv:
            return ProcessResult(
                argv=list(argv),
                returncode=0,
                stdout="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
                stderr="",
            )
        return ProcessResult(argv=list(argv), returncode=0, stdout="", stderr="")

    # Create docker dir when checkout would have happened: intercept after git calls
    # by making materialize use a prebuilt staging via monkeypatch of tempfile.
    real_mkdtemp = __import__("tempfile").mkdtemp

    def mkdtemp(*a, **k):  # type: ignore[no-untyped-def]
        d = Path(real_mkdtemp(*a, **k))
        (d / "docker").mkdir(exist_ok=True)
        (d / "docker" / "docker-compose.yml").write_text("services: {}\n" + ("y" * 120))
        return str(d)

    with (
        mock.patch("sbfleet.upstream.run", side_effect=fake_run),
        mock.patch("tempfile.mkdtemp", side_effect=mkdtemp),
    ):
        with pytest.raises(up.UpstreamError, match="does not match"):
            up.materialize_cache(tmp_path, force=True)


def test_interrupted_copy_leaves_no_partial_success(tmp_path: Path) -> None:
    cache = tmp_path / "cache" / "upstream" / up.PINNED_SHA
    docker = cache / "docker"
    docker.mkdir(parents=True)
    (docker / "docker-compose.yml").write_text("services: {}\n" + ("z" * 120))
    (docker / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    from helpers_upstream import write_cache_marker

    write_cache_marker(cache)
    dep = tmp_path / "dep"
    real_copy = __import__("shutil").copy2

    def boom(src, dst, *a, **k):  # type: ignore[no-untyped-def]
        if str(src).endswith("run.sh"):
            raise OSError("simulated interrupt")
        return real_copy(src, dst, *a, **k)

    with mock.patch("shutil.copy2", side_effect=boom):
        with pytest.raises(OSError):
            up.copy_vendor_docker(cache, dep)
    assert not (dep / ".supabase-version").exists()
