"""TTY-aware CLI presentation (banner, prompt, summary). Presentational only."""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from typing import TextIO

from sbfleet.health import HEALTHY

# ANSI — applied only when colors_enabled() is true.
_RESET = "\033[0m"
_GREEN = "\033[32m"
_DIM = "\033[2m"
_YELLOW = "\033[33m"

_SB_MARK = """\
             ░██████╗ ██████╗
            ██╔════╝ ██╔══██╗
            ╚█████╗  ██████╔╝
             ╚═══██╗ ██╔══██╗
            ██████╔╝ ██████╔╝
            ╚═════╝  ╚═════╝"""

_SUBTITLE = "S B F L E E T"
_TAGLINE = "local control plane"
_PILLARS = "upstream stacks · isolated · recoverable"


@dataclass(frozen=True)
class ShellSummary:
    """Cheap read-only shell startup summary."""

    fleet_ready: bool
    docker_connected: bool
    project_count: int
    sandbox_available: bool
    fleet_detail: str = "ready"
    docker_detail: str = "connected"
    sandbox_detail: str = "available"
    sandbox_hint: str = ""


def colors_enabled(stream: TextIO | None = None) -> bool:
    """True only for TTY stdout with NO_COLOR unset/empty."""
    out = stream if stream is not None else sys.stdout
    if os.environ.get("NO_COLOR", "") != "":
        return False
    try:
        return bool(out.isatty())
    except Exception:  # noqa: BLE001 — defensive for odd streams
        return False


def _paint(text: str, code: str, *, enabled: bool) -> str:
    if not enabled or not text:
        return text
    return f"{code}{text}{_RESET}"


def green(text: str, *, enabled: bool | None = None) -> str:
    on = colors_enabled() if enabled is None else enabled
    return _paint(text, _GREEN, enabled=on)


def neutral(text: str, *, enabled: bool | None = None) -> str:
    on = colors_enabled() if enabled is None else enabled
    return _paint(text, _YELLOW, enabled=on)


def dim(text: str, *, enabled: bool | None = None) -> str:
    on = colors_enabled() if enabled is None else enabled
    return _paint(text, _DIM, enabled=on)


def indicator_ok(ok: bool, *, enabled: bool | None = None) -> str:
    """Success green only when ok is true; never decorative."""
    on = colors_enabled() if enabled is None else enabled
    if ok:
        return green("●", enabled=on)
    return neutral("●", enabled=on)


def format_shell_banner(summary: ShellSummary, *, enabled: bool | None = None) -> str:
    """Full startup identity + summary. Plain text when colors disabled."""
    on = colors_enabled() if enabled is None else enabled
    lines = [
        _SB_MARK,
        "",
        f"                {_SUBTITLE}",
        f"         {_TAGLINE}",
        "",
        f"    {_PILLARS}",
        "",
        _format_summary_lines(summary, enabled=on),
        "",
        dim("type / for commands, /help <cmd> for topics, Ctrl-D to exit", enabled=on),
    ]
    if not summary.sandbox_available:
        hint = summary.sandbox_hint or "run /doctor for remediation"
        lines.append(dim(f"sandbox: {hint}", enabled=on))
    lines.append("")
    return "\n".join(lines)


def _format_summary_lines(summary: ShellSummary, *, enabled: bool) -> str:
    fleet_dot = indicator_ok(summary.fleet_ready, enabled=enabled)
    docker_dot = indicator_ok(summary.docker_connected, enabled=enabled)
    sandbox_dot = indicator_ok(summary.sandbox_available, enabled=enabled)
    fleet_label = summary.fleet_detail if summary.fleet_ready else "unavailable"
    docker_label = summary.docker_detail if summary.docker_connected else "unavailable"
    if summary.sandbox_available:
        sandbox_label = summary.sandbox_detail
    elif summary.sandbox_detail != "unavailable":
        sandbox_label = summary.sandbox_detail
    else:
        sandbox_label = "unavailable"
    return "\n".join(
        [
            f"    fleet      {fleet_dot} {fleet_label}",
            f"    docker     {docker_dot} {docker_label}",
            f"    projects   {summary.project_count}",
            f"    sandbox    {sandbox_dot} {sandbox_label}",
        ]
    )


def format_prompt_text(
    active: str | None,
    lifecycle: str | None,
    *,
    enabled: bool | None = None,
) -> str:
    """Plain (possibly ANSI) prompt string for tests and fallbacks."""
    on = colors_enabled() if enabled is None else enabled
    if not active:
        return "sbfleet ❯ "
    healthy = lifecycle == HEALTHY
    dot = indicator_ok(healthy, enabled=on)
    return f"sbfleet / {active} {dot} ❯ "


def format_prompt_message(
    active: str | None,
    lifecycle: str | None,
    *,
    enabled: bool | None = None,
):
    """prompt_toolkit message: FormattedText when colors on, else plain str."""
    on = colors_enabled() if enabled is None else enabled
    if not on:
        return format_prompt_text(active, lifecycle, enabled=False)
    from prompt_toolkit.formatted_text import FormattedText

    if not active:
        return FormattedText([("", "sbfleet ❯ ")])
    healthy = lifecycle == HEALTHY
    style = "ansigreen" if healthy else "ansiyellow"
    return FormattedText(
        [
            ("", "sbfleet / "),
            ("", active),
            ("", " "),
            (style, "●"),
            ("", " ❯ "),
        ]
    )


def collect_shell_summary(home: str | None = None) -> ShellSummary:
    """Cheap one-shot read-only probes for shell startup. Never mutates."""
    fleet_ready = False
    project_count = 0
    try:
        from sbfleet import registry as reg

        root = reg.resolve_home(home)
        fleet_json = root / "fleet.json"
        if root.is_dir() and fleet_json.is_file():
            fleet_ready = True
            try:
                project_count = sum(1 for r in reg.list_projects(root) if not r.error)
            except Exception:  # noqa: BLE001
                project_count = 0
        elif root.is_dir():
            # Root exists but not initialized — still a resolvable home.
            fleet_ready = False
    except Exception:  # noqa: BLE001
        fleet_ready = False

    docker_connected = _probe_docker()
    sandbox_available, sandbox_detail, sandbox_hint = _probe_sandbox_cli()

    return ShellSummary(
        fleet_ready=fleet_ready,
        docker_connected=docker_connected,
        project_count=project_count,
        sandbox_available=sandbox_available,
        fleet_detail="ready" if fleet_ready else "unavailable",
        docker_detail="connected" if docker_connected else "unavailable",
        sandbox_detail=sandbox_detail,
        sandbox_hint=sandbox_hint,
    )


def _path_env() -> dict[str, str]:
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}


def _probe_docker() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        from sbfleet.process import run

        result = run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            env=_path_env(),
            check=False,
            timeout=5.0,
        )
        return bool(result.ok) and bool((result.stdout or "").strip())
    except Exception:  # noqa: BLE001
        return False


def _probe_sandbox_cli() -> tuple[bool, str, str]:
    """Return (available, detail_label, remediation_hint)."""
    try:
        from sbfleet.tools import resolve_supabase, sandbox_unavailable_reason

        path, detail = resolve_supabase()
        if path:
            return True, "available", ""
        reason = sandbox_unavailable_reason() or detail
        label = f"unavailable — {reason}"
        return False, label, "run /doctor for remediation"
    except Exception:  # noqa: BLE001
        return False, "unavailable — CLI probe failed", "run /doctor for remediation"


def banner_for_shell(*, home: str | None = None, stream: TextIO | None = None) -> str | None:
    """Return banner text for interactive shell, or None when stdout is not a TTY."""
    out = stream if stream is not None else sys.stdout
    if not out.isatty():
        return None
    summary = collect_shell_summary(home)
    return format_shell_banner(summary, enabled=colors_enabled(out))
