"""Module tests."""

from __future__ import annotations

import os
import signal
import stat
import time
from pathlib import Path

import pytest

from sbfleet.process import ProcessError, Redactor, run


@pytest.fixture()
def fake_bin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))
    return bin_dir


def _write_exec(path: Path, body: str) -> Path:
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def test_nonzero_is_not_success(fake_bin: Path) -> None:
    _write_exec(fake_bin / "failtool", "echo err >&2; exit 7\n")
    result = run(["failtool"], env={"PATH": str(fake_bin)}, check=False)
    assert not result.ok
    assert result.returncode == 7
    with pytest.raises(ProcessError):
        run(["failtool"], env={"PATH": str(fake_bin)}, check=True)


def test_timeout_reaps_hanging_child(fake_bin: Path) -> None:
    _write_exec(fake_bin / "hang", "while true; do :; done\n")
    start = time.monotonic()
    result = run(
        ["hang"],
        env={"PATH": str(fake_bin) + os.pathsep + "/bin:/usr/bin"},
        timeout=0.3,
    )
    assert result.timed_out
    assert not result.ok
    assert time.monotonic() - start < 5


def test_child_receives_only_intended_env(fake_bin: Path) -> None:
    _write_exec(fake_bin / "envdump", 'printf "%s" "$SECRET::$LEAK"\n')
    result = run(
        ["envdump"],
        env={"PATH": str(fake_bin), "SECRET": "only"},
        check=True,
    )
    assert result.stdout == "only::"


def test_secret_stderr_redaction(fake_bin: Path) -> None:
    secret = "super-secret-token-xyz"
    _write_exec(fake_bin / "gen", f'echo "generated {secret}" >&2; exit 0\n')
    result = run(["gen"], env={"PATH": str(fake_bin)}, check=True)
    redactor = Redactor()
    redactor.add(secret)
    cleaned = redactor.redact_text(result.stderr)
    assert secret not in cleaned
    assert "[REDACTED]" in cleaned


def test_spaces_and_metacharacters_not_shell_expanded(fake_bin: Path) -> None:
    _write_exec(fake_bin / "echoer", 'printf "%s" "$1"\n')
    result = run(
        ["echoer", "a b; rm -rf /"],
        env={"PATH": str(fake_bin)},
        check=True,
    )
    assert result.stdout == "a b; rm -rf /"


def test_output_flood_truncated(fake_bin: Path) -> None:
    _write_exec(
        fake_bin / "flood",
        "python3 -c \"print('x'*50000)\"\n",
    )
    result = run(
        ["flood"],
        env={"PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", "")},
        max_capture_bytes=1000,
        check=True,
    )
    assert "[truncated]" in result.stdout


def test_redact_recursive_mapping() -> None:
    r = Redactor()
    r.add("sekrit-token-value")
    data = {
        "token": "sekrit-token-value",
        "nested": {"url": "postgres://user:pw@127.0.0.1/db"},
        "list": ["sekrit-token-value", "ok"],
    }
    out = r.redact(data)
    assert out == {
        "token": "[REDACTED]",
        "nested": {"url": "postgres://user:[REDACTED]@127.0.0.1/db"},
        "list": ["[REDACTED]", "ok"],
    }


def test_signal_failure_not_success(fake_bin: Path) -> None:
    _write_exec(fake_bin / "die", "kill -s TERM $$\n")
    result = run(["die"], env={"PATH": str(fake_bin)})
    assert not result.ok
    assert result.signal in (signal.SIGTERM, None) or result.returncode != 0


def test_json_stderr_separated(fake_bin: Path) -> None:
    _write_exec(fake_bin / "both", "echo '{\"ok\":true}'; echo secret-line >&2\n")
    result = run(["both"], env={"PATH": str(fake_bin)}, check=True)
    assert '{"ok":true}' in result.stdout
    assert "secret-line" in result.stderr
    assert "secret-line" not in result.stdout
