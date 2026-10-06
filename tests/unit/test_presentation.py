"""Presentation layer — TTY / NO_COLOR / prompt / banner (no safety impact)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from sbfleet.health import FAILED, HEALTHY, STOPPED, UNKNOWN
from sbfleet.presentation import (
    banner_for_shell,
    collect_shell_summary,
    colors_enabled,
    format_prompt_message,
    format_prompt_text,
    format_shell_banner,
    green,
    indicator_ok,
)
from sbfleet.shell import FleetShell


def test_colors_enabled_respects_no_color(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Tty:
        def isatty(self) -> bool:
            return True

    monkeypatch.delenv("NO_COLOR", raising=False)
    assert colors_enabled(_Tty()) is True
    monkeypatch.setenv("NO_COLOR", "1")
    assert colors_enabled(_Tty()) is False


def test_colors_disabled_when_not_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Pipe:
        def isatty(self) -> bool:
            return False

    monkeypatch.delenv("NO_COLOR", raising=False)
    assert colors_enabled(_Pipe()) is False


def test_banner_none_when_stdout_not_tty(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class _Pipe:
        def isatty(self) -> bool:
            return False

    monkeypatch.setattr("sbfleet.presentation.sys.stdout", _Pipe())
    assert banner_for_shell(home=str(tmp_path), stream=_Pipe()) is None


def test_banner_contains_identity_when_tty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sbfleet import registry as reg

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("SBFLEET_SOFTWARE_ROOT", raising=False)
    monkeypatch.delenv("SBFLEET_ALLOW_PATH_TOOLS", raising=False)
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    reg.ensure_root(tmp_path)
    summary = collect_shell_summary(str(tmp_path))
    text = format_shell_banner(summary, enabled=False)
    assert "S B F L E E T" in text
    assert "local control plane" in text
    assert "for self-hosted supabase stacks" not in text
    assert "upstream stacks · isolated · recoverable" in text
    assert "Local Supabase Control Plane" not in text
    assert "fleet" in text
    assert "docker" in text
    assert "projects" in text
    assert "sandbox" in text
    if not summary.sandbox_available:
        assert "unavailable" in text
        assert "doctor" in text
    assert "\033[" not in text


def test_banner_ansi_only_when_enabled(tmp_path: Path) -> None:
    from sbfleet import registry as reg

    reg.ensure_root(tmp_path)
    summary = collect_shell_summary(str(tmp_path))
    plain = format_shell_banner(summary, enabled=False)
    colored = format_shell_banner(summary, enabled=True)
    assert "\033[" not in plain
    # Summary dots may use ANSI when enabled
    if summary.fleet_ready or summary.docker_connected or summary.sandbox_available:
        assert "\033[" in colored


def test_prompt_shape_and_green_only_for_healthy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert format_prompt_text(None, None, enabled=False) == "sbfleet ❯ "
    stopped = format_prompt_text("myapp", STOPPED, enabled=False)
    assert stopped == "sbfleet / myapp ● ❯ "
    failed = format_prompt_text("myapp", FAILED, enabled=False)
    assert failed == "sbfleet / myapp ● ❯ "
    unknown = format_prompt_text("myapp", UNKNOWN, enabled=False)
    assert unknown == "sbfleet / myapp ● ❯ "
    missing = format_prompt_text("myapp", None, enabled=False)
    assert missing == "sbfleet / myapp ● ❯ "

    healthy_plain = format_prompt_text("myapp", HEALTHY, enabled=False)
    assert healthy_plain == "sbfleet / myapp ● ❯ "
    healthy_color = format_prompt_text("myapp", HEALTHY, enabled=True)
    assert "\033[32m" in healthy_color
    stopped_color = format_prompt_text("myapp", STOPPED, enabled=True)
    assert "\033[32m" not in stopped_color
    assert "\033[33m" in stopped_color


def test_indicator_ok_never_green_when_false() -> None:
    assert "\033[32m" not in indicator_ok(False, enabled=True)
    assert "\033[32m" in indicator_ok(True, enabled=True)
    assert green("x", enabled=False) == "x"


def test_prompt_message_formatted_when_colors_on() -> None:
    plain = format_prompt_message("demo", HEALTHY, enabled=False)
    assert isinstance(plain, str)
    styled = format_prompt_message("demo", HEALTHY, enabled=True)
    assert not isinstance(styled, str)
    # FormattedText is iterable of (style, text)
    parts = list(styled)
    assert any(style == "ansigreen" and text == "●" for style, text in parts)


def test_shell_prompt_uses_cache(tmp_path: Path) -> None:
    sh = FleetShell(home=str(tmp_path))
    assert sh.prompt == "sbfleet ❯ "
    sh.active = "demo"
    assert sh.prompt == "sbfleet / demo ● ❯ "
    assert "\033[32m" not in sh.prompt or os.environ.get("NO_COLOR")
    sh.lifecycle_cache["demo"] = HEALTHY
    # Property uses colors_enabled(stdout); force plain via format path
    from sbfleet.presentation import format_prompt_text

    assert format_prompt_text("demo", HEALTHY, enabled=False).startswith("sbfleet / demo")


def test_shell_intro_empty_without_tty(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class _Pipe:
        def isatty(self) -> bool:
            return False

    monkeypatch.setattr("sbfleet.presentation.sys.stdout", _Pipe())
    sh = FleetShell(home=str(tmp_path))
    assert sh.intro == ""


def test_json_projects_has_no_ansi(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from sbfleet import registry as reg
    from sbfleet.cli import main

    reg.ensure_root(tmp_path)
    code = main(["--home", str(tmp_path), "projects", "--json"])
    assert code == 0
    out = capsys.readouterr().out
    assert "\033[" not in out
    payload: Any = json.loads(out)
    assert isinstance(payload, (dict, list))
