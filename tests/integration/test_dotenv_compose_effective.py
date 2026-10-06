"""Module tests."""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

import pytest

from sbfleet import upstream as up
from sbfleet.process import run

pytestmark = pytest.mark.docker


def _docker_ok() -> bool:
    if shutil.which("docker") is None:
        return False
    r = run(
        ["docker", "info"],
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        timeout=30.0,
        check=False,
    )
    return r.ok


def _compose_printenv(work: Path, key: str, *, run_id: str) -> str:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(work / ".home"),
        "COMPOSE_PROJECT_NAME": f"sbfleet_dotenv_{run_id}",
    }
    (work / ".home").mkdir(mode=0o700, exist_ok=True)
    r = run(
        ["docker", "compose", "run", "--rm", "--no-deps", "probe", "printenv", key],
        cwd=work,
        env=env,
        timeout=120.0,
        check=False,
    )
    assert r.ok, (key, (r.stderr or r.stdout or "")[:400])
    return (r.stdout or "").strip()


def _write_probe(work: Path, env_text: str, keys: list[str]) -> None:
    (work / ".env").write_text(env_text, encoding="utf-8")
    keys_yaml = "\n".join(f"      {k}: ${{{k}}}" for k in keys)
    (work / "docker-compose.yml").write_text(
        f"services:\n  probe:\n    image: alpine:3.20\n    environment:\n{keys_yaml}\n",
        encoding="utf-8",
    )


@pytest.mark.docker
def test_compose_effective_dotenv_matches_parse_dotenv(tmp_path: Path) -> None:
    """Write fleet dotenv → compose run printenv → compare to parse_dotenv.

    Note: ``docker compose config`` may still show ``$$`` literally; runtime
    interpolation yields the effective single ``$`` (proven here).
    """
    if not _docker_ok():
        pytest.skip("docker unavailable")

    run_id = uuid.uuid4().hex[:8]
    work = tmp_path / f"dotenv-eff-{run_id}"
    work.mkdir()
    values = {
        "JWT_SECRET": "plain",
        "DOLLAR_VAL": "pre$post",
        "QUOTED": 'say "hi"',
        "PATH_LIKE": "c:\\tmp",
        "JSONISH": '{"k":"v$1"}',
    }
    env_text = up.dump_dotenv(values)
    parsed = up.parse_dotenv(env_text)
    assert parsed == values

    _write_probe(work, env_text, list(values))
    for key, expect in values.items():
        got = _compose_printenv(work, key, run_id=run_id)
        assert got == expect, f"{key}: compose_runtime={got!r} parse={expect!r}"


@pytest.mark.docker
def test_compose_effective_single_quoted_literal_not_expanded(tmp_path: Path) -> None:
    """Single-quoted $HOME must be identical for parse_dotenv and Compose runtime."""
    if not _docker_ok():
        pytest.skip("docker unavailable")

    run_id = uuid.uuid4().hex[:8]
    work = tmp_path / f"dotenv-sq-{run_id}"
    work.mkdir()
    (work / ".env").write_text("X='$HOME'\n", encoding="utf-8")
    parsed = up.parse_dotenv((work / ".env").read_text(encoding="utf-8"))
    assert parsed["X"] == "$HOME"
    _write_probe(work, "X='$HOME'\n", ["X"])
    got = _compose_printenv(work, "X", run_id=run_id)
    assert got == "$HOME"


@pytest.mark.docker
def test_compose_effective_accepted_manual_forms(tmp_path: Path) -> None:
    """Every accepted *manual* form must match Compose printenv ()."""
    if not _docker_ok():
        pytest.skip("docker unavailable")

    run_id = uuid.uuid4().hex[:8]
    work = tmp_path / f"dotenv-manual-{run_id}"
    work.mkdir()
    env_text = (
        "\n".join(
            [
                "PLAIN=abc",
                'DQ="pre$$post"',
                "SQ='$HOME'",
                'JSON={"k":"v"}',
                'ESC="say \\"hi\\""',
                "# comment line",
                "TRAIL=ok # inline",
            ]
        )
        + "\n"
    )
    parsed = up.parse_dotenv(env_text)
    expect = {
        "PLAIN": "abc",
        "DQ": "pre$post",
        "SQ": "$HOME",
        "JSON": '{"k":"v"}',
        "ESC": 'say "hi"',
        "TRAIL": "ok",
    }
    assert parsed == expect
    _write_probe(work, env_text, list(expect))
    for key, want in expect.items():
        got = _compose_printenv(work, key, run_id=run_id)
        assert got == want, f"{key}: compose={got!r} parse={want!r}"


@pytest.mark.docker
def test_compose_refused_manual_forms_never_reach_runtime(tmp_path: Path) -> None:
    """Unsupported manual forms fail in parse_dotenv before Compose mutation."""
    if not _docker_ok():
        pytest.skip("docker unavailable")
    for text in ("X=foo$$bar\n", "X= abc\n", "X=$NAME\n", "X=${NAME}\n", "A=1\nA=2\n"):
        with pytest.raises(up.UpstreamError):
            up.parse_dotenv(text)
