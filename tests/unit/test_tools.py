"""Managed tool resolution — absolute paths, node_modules refusal, PATH policy."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from sbfleet import tools as t


def _fake_bin(path: Path, version_line: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f'#!/bin/sh\necho "{version_line}"\n',
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def test_managed_supabase_preferred(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    prefix = tmp_path / "current"
    managed = _fake_bin(
        prefix / "tools" / "supabase" / t.PINNED_SUPABASE_CLI / "supabase",
        t.PINNED_SUPABASE_CLI,
    )
    (prefix / "install.json").write_text("{}", encoding="utf-8")
    bad = _fake_bin(tmp_path / "node_modules" / "supabase" / "bin" / "supabase", "2.70.5")
    monkeypatch.setenv("SBFLEET_SOFTWARE_ROOT", str(prefix))
    monkeypatch.setenv("PATH", str(bad.parent) + os.pathsep + "/usr/bin:/bin")
    monkeypatch.delenv("SBFLEET_ALLOW_PATH_TOOLS", raising=False)
    path, detail = t.resolve_supabase()
    assert path == str(managed)
    assert "managed" in detail


def test_node_modules_rejected_on_path_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SBFLEET_SOFTWARE_ROOT", raising=False)
    # Ensure no default current under HOME
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    nm = _fake_bin(
        tmp_path / "proj" / "node_modules" / "supabase" / "bin" / "supabase",
        t.PINNED_SUPABASE_CLI,
    )
    monkeypatch.setenv("PATH", str(nm.parent))
    monkeypatch.setenv("SBFLEET_ALLOW_PATH_TOOLS", "1")
    path, detail = t.resolve_supabase()
    assert path is None
    assert "not found" in detail


def test_wrong_version_on_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("SBFLEET_SOFTWARE_ROOT", raising=False)
    wrong = _fake_bin(tmp_path / "bin" / "supabase", "2.70.5")
    monkeypatch.setenv("PATH", str(wrong.parent))
    monkeypatch.setenv("SBFLEET_ALLOW_PATH_TOOLS", "1")
    path, detail = t.resolve_supabase()
    assert path is None
    assert "2.70.5" in detail


def test_managed_prefix_blocks_path_without_allow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix = tmp_path / "current"
    prefix.mkdir()
    (prefix / "install.json").write_text("{}", encoding="utf-8")
    good = _fake_bin(tmp_path / "bin" / "supabase", t.PINNED_SUPABASE_CLI)
    monkeypatch.setenv("SBFLEET_SOFTWARE_ROOT", str(prefix))
    monkeypatch.setenv("PATH", str(good.parent))
    monkeypatch.delenv("SBFLEET_ALLOW_PATH_TOOLS", raising=False)
    path, _ = t.resolve_supabase()
    assert path is None


def test_sandbox_unavailable_reason(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("SBFLEET_SOFTWARE_ROOT", raising=False)
    monkeypatch.delenv("SBFLEET_ALLOW_PATH_TOOLS", raising=False)
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    reason = t.sandbox_unavailable_reason()
    assert reason is not None
    assert "2.118.0" in reason


def test_require_age_managed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    prefix = tmp_path / "current"
    managed = _fake_bin(prefix / "tools" / "age" / t.PINNED_AGE / "age", f"v{t.PINNED_AGE}")
    (prefix / "install.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("SBFLEET_SOFTWARE_ROOT", str(prefix))
    assert t.require_age() == str(managed)
