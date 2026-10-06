"""Module tests."""

from __future__ import annotations

import subprocess
import sys

import pytest

from sbfleet.cli import EXIT_OK, EXIT_USAGE, main


def test_help_exits_zero() -> None:
    assert main(["--help"]) == 0
    proc = subprocess.run(
        [sys.executable, "-m", "sbfleet.cli", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    combined = (proc.stdout + proc.stderr).lower()
    assert "sbfleet" in combined


def test_version() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "sbfleet.cli", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert "1.0.0" in proc.stdout


def test_unknown_command_exit_2() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "sbfleet.cli", "not-a-real-command"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == EXIT_USAGE


def test_projects_empty_ok(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "user"))
    code = main(["--home", str(tmp_path / "fleet"), "projects"])
    assert code == EXIT_OK


def test_non_tty_no_args_help_exit_2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    code = main([])
    assert code == EXIT_USAGE


def test_home_option_accepted_without_docker(tmp_path) -> None:
    code = main(["--home", str(tmp_path / "fleet"), "projects"])
    assert code == EXIT_OK


def test_python310_import() -> None:
    assert sys.version_info >= (3, 10)
    import sbfleet  # noqa: F401
    from sbfleet import cli  # noqa: F401

    assert cli.EXIT_OK == 0
