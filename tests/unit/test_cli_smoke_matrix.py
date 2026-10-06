"""Module tests."""

from __future__ import annotations

import subprocess
import sys

import pytest

from sbfleet.cli import EXIT_USAGE, build_parser, main

PUBLIC_COMMANDS = (
    "projects",
    "create",
    "start",
    "stop",
    "restart",
    "status",
    "studio",
    "logs",
    "doctor",
    "connection",
    "env",
    "secrets",
    "backup",
    "restore",
    "update",
    "remove",
    "nginx",
    "sandbox",
)


def _help(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sbfleet.cli", *argv],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize("command", PUBLIC_COMMANDS)
def test_public_command_parser_and_help(command: str) -> None:
    parser = build_parser()
    # Ensure subparser exists by parsing a minimal valid argv shape without executing.
    actions = {a.dest: a for a in parser._subparsers._group_actions}  # noqa: SLF001
    assert "command" in actions or parser._subparsers is not None  # noqa: SLF001
    choices = parser._subparsers._group_actions[0].choices  # noqa: SLF001
    assert command in choices

    proc = _help([command, "--help"])
    assert proc.returncode == 0, (command, proc.stderr)
    text = (proc.stdout + proc.stderr).lower()
    assert "usage" in text or command in text


def test_top_level_help_and_unsupported_option() -> None:
    assert main(["--help"]) == 0
    proc = _help(["--not-a-real-global-flag"])
    assert proc.returncode == EXIT_USAGE
    assert "traceback" not in (proc.stderr + proc.stdout).lower()


def test_update_requires_to_flag_usage() -> None:
    """Without --to or --reconcile, update fails closed (safety), not argparse usage."""
    from sbfleet.cli import EXIT_SAFETY

    proc = _help(["update", "demo"])
    assert proc.returncode == EXIT_SAFETY
    assert "--to" in (proc.stderr or "").lower() or "reconcile" in (proc.stderr or "").lower()
    assert "traceback" not in (proc.stderr + proc.stdout).lower()


def test_create_rejects_unknown_option() -> None:
    proc = _help(["create", "demo", "--not-a-flag"])
    assert proc.returncode == EXIT_USAGE
    assert "traceback" not in (proc.stderr + proc.stdout).lower()


def test_nginx_surface_matches_parser() -> None:
    """Implemented nginx CLI: generate|validate|install + project + --json only."""
    parser = build_parser()
    args = parser.parse_args(["nginx", "generate", "demo", "--json"])
    assert args.action == "generate"
    assert args.project == "demo"
    assert args.json is True
    assert not hasattr(args, "certificate")
    assert not hasattr(args, "output")


def test_sandbox_help_lists_actions() -> None:
    proc = _help(["sandbox", "--help"])
    assert proc.returncode == 0
    text = (proc.stdout + proc.stderr).lower()
    for action in ("start", "stop", "status", "reset", "destroy", "env", "studio"):
        assert action in text
