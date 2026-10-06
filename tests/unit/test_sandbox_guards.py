"""Module tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from sbfleet import sandbox as sb


def test_forbidden_dotenv(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("SUPABASE_ACCESS_TOKEN=realtoken\n", encoding="utf-8")
    with pytest.raises(sb.SandboxError):
        sb.audit_dotenv(tmp_path)


def test_cli_pin_refusal(monkeypatch) -> None:
    monkeypatch.setattr(sb, "_cli_version", lambda: "2.54.11")
    with pytest.raises(sb.SandboxError, match="incompatible"):
        sb.require_pinned_cli()


def test_path_hash_stable(tmp_path: Path) -> None:
    assert sb.path_hash(tmp_path) == sb.path_hash(tmp_path)
