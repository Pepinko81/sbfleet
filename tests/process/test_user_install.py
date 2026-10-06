"""User install script — disposable HOME, quoting, transactional promote."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
INSTALL = REPO / "scripts" / "install-user.sh"
UNINSTALL = REPO / "scripts" / "uninstall-user.sh"


def _run(
    argv: list[str],
    *,
    env: dict[str, str],
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=str(cwd or REPO),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


@pytest.fixture()
def disposable_home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    return home


def test_install_skip_tools_fresh_shell_and_outside_cwd(
    disposable_home: Path, tmp_path: Path
) -> None:
    env = {
        "HOME": str(disposable_home),
        "USER": "tester",
        "PATH": "/usr/bin:/bin",
        "SBFLEET_SOFTWARE_ROOT_BASE": str(disposable_home / ".local" / "lib" / "sbfleet"),
        "LANG": "C",
    }
    # May exit 4 (not FULL V1 READY without docker/tools) but must install CLI.
    result = _run(["bash", str(INSTALL), "--skip-tools"], env=env)
    combined = result.stdout + result.stderr
    assert "INSTALLATION ARTIFACTS READY: YES" in combined
    assert "SBFLEET CLI READY: YES" in combined
    assert "CURRENT SHELL sbfleet: PENDING" in combined
    assert "FULL V1 READY: YES" not in combined
    assert 'export PATH="$HOME/.local/bin:$PATH"' in combined
    shim = disposable_home / ".local" / "bin" / "sbfleet"
    assert shim.is_symlink()
    target = shim.resolve()
    assert str(disposable_home / ".local" / "lib" / "sbfleet") in str(target)
    # No age/supabase PATH shims
    assert not (disposable_home / ".local" / "bin" / "supabase").exists()
    assert not (disposable_home / ".local" / "bin" / "age").exists()

    outside = tmp_path / "outside"
    outside.mkdir()
    probe = _run(
        [
            "env",
            "-i",
            f"HOME={disposable_home}",
            "USER=tester",
            f"PATH=/usr/bin:/bin:{disposable_home / '.local' / 'bin'}",
            "/bin/sh",
            "-c",
            "command -v sbfleet && sbfleet --version",
        ],
        env=os.environ.copy(),
        cwd=outside,
    )
    assert probe.returncode == 0
    assert "sbfleet" in probe.stdout


def test_install_artifacts_ready_current_shell_path_pending(
    disposable_home: Path,
) -> None:
    """Managed install succeeds while operator PATH lacks ~/.local/bin."""
    env = {
        "HOME": str(disposable_home),
        "USER": "tester",
        # Reproduce production: installer inherits a PATH without ~/.local/bin.
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "SBFLEET_SOFTWARE_ROOT_BASE": str(disposable_home / ".local" / "lib" / "sbfleet"),
        "SBFLEET_TOOL_CACHE": "/tmp/sbfleet-pin-dl",
        "LANG": "C",
    }
    cache = Path("/tmp/sbfleet-pin-dl")
    args = ["bash", str(INSTALL)]
    if not (cache / "supabase_2.118.0_linux_amd64.tar.gz").is_file():
        args.append("--skip-tools")
        env.pop("SBFLEET_TOOL_CACHE", None)

    result = _run(args, env=env)
    combined = result.stdout + result.stderr
    assert result.returncode == 4
    assert "INSTALLATION ARTIFACTS READY: YES" in combined
    assert "CURRENT SHELL sbfleet: PENDING" in combined
    assert "FULL V1 READY: YES" not in combined
    assert 'export PATH="$HOME/.local/bin:$PATH"' in combined
    if (
        "BACKUP READY: YES" in combined
        and "SANDBOX READY: YES" in combined
        and "DOCKER READY: YES" in combined
    ):
        assert "current-shell command availability is PENDING" in combined
    # Absolute managed entrypoint still works without PATH.
    shim = disposable_home / ".local" / "bin" / "sbfleet"
    assert shim.is_file() or shim.is_symlink()
    direct = _run([str(shim.resolve()), "--version"], env=env)
    assert direct.returncode == 0
    assert "sbfleet" in direct.stdout


def test_install_source_path_with_spaces(disposable_home: Path, tmp_path: Path) -> None:
    spaced = tmp_path / "Project X" / "sbfleet"
    spaced.parent.mkdir(parents=True)
    # Lightweight copy of packaging + pyproject + src for installability is heavy;
    # instead verify the installer quotes by pointing --source at a symlink path with spaces
    # that resolves to the real repo.
    spaced.symlink_to(REPO)
    env = {
        "HOME": str(disposable_home),
        "USER": "tester",
        "PATH": "/usr/bin:/bin",
        "SBFLEET_SOFTWARE_ROOT_BASE": str(disposable_home / ".local" / "lib" / "sbfleet"),
        "LANG": "C",
    }
    result = _run(
        ["bash", str(INSTALL), "--source", str(spaced), "--skip-tools"],
        env=env,
        cwd=tmp_path,
    )
    combined = result.stdout + result.stderr
    assert "SBFLEET CLI READY: YES" in combined or result.returncode in {0, 4}
    assert (disposable_home / ".local" / "bin" / "sbfleet").exists()


def test_uninstall_containment(disposable_home: Path) -> None:
    soft = disposable_home / ".local" / "lib" / "sbfleet"
    soft.mkdir(parents=True)
    current = soft / "current"
    current.mkdir()
    (current / "install.json").write_text("{}", encoding="utf-8")
    bin_dir = disposable_home / ".local" / "bin"
    bin_dir.mkdir(parents=True)
    managed = current / "venv" / "bin"
    managed.mkdir(parents=True)
    fake = managed / "sbfleet"
    fake.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    fake.chmod(0o755)
    shim = bin_dir / "sbfleet"
    shim.symlink_to(fake)
    foreign = bin_dir / "othertool"
    foreign.write_text("keep\n", encoding="utf-8")
    sentinel = disposable_home / "sentinel.txt"
    sentinel.write_text("untouched\n", encoding="utf-8")
    fleet = disposable_home / ".local" / "share" / "sbfleet"
    fleet.mkdir(parents=True)
    (fleet / "fleet.json").write_text("{}\n", encoding="utf-8")

    env = {
        "HOME": str(disposable_home),
        "PATH": "/usr/bin:/bin",
        "SBFLEET_SOFTWARE_ROOT_BASE": str(soft),
    }
    result = _run(["bash", str(UNINSTALL)], env=env)
    assert result.returncode == 0
    assert not soft.exists()
    assert not shim.exists()
    assert foreign.exists()
    assert sentinel.read_text(encoding="utf-8") == "untouched\n"
    assert (fleet / "fleet.json").exists()


def test_uninstall_refuses_foreign_shim(disposable_home: Path) -> None:
    soft = disposable_home / ".local" / "lib" / "sbfleet"
    soft.mkdir(parents=True)
    bin_dir = disposable_home / ".local" / "bin"
    bin_dir.mkdir(parents=True)
    foreign_target = disposable_home / "elsewhere" / "sbfleet"
    foreign_target.parent.mkdir(parents=True)
    foreign_target.write_text("#!/bin/sh\n", encoding="utf-8")
    foreign_target.chmod(0o755)
    shim = bin_dir / "sbfleet"
    shim.symlink_to(foreign_target)
    env = {
        "HOME": str(disposable_home),
        "PATH": "/usr/bin:/bin",
        "SBFLEET_SOFTWARE_ROOT_BASE": str(soft),
    }
    _run(["bash", str(UNINSTALL)], env=env)
    assert shim.exists()  # left alone


def test_transactional_failed_stage_keeps_previous(disposable_home: Path) -> None:
    soft = disposable_home / ".local" / "lib" / "sbfleet"
    soft.mkdir(parents=True)
    old_gen = soft / "staging-old"
    old_gen.mkdir()
    (old_gen / "install.json").write_text(
        '{"package":"sbfleet","marker":"old"}\n',
        encoding="utf-8",
    )
    venv_bin = old_gen / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    old = venv_bin / "sbfleet"
    old.write_text("#!/bin/sh\necho sbfleet old\n", encoding="utf-8")
    old.chmod(0o755)
    current = soft / "current"
    current.symlink_to("staging-old")
    bin_dir = disposable_home / ".local" / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "sbfleet").symlink_to(old)

    # Break pip by using a non-checkout source
    bogus = disposable_home / "not-a-checkout"
    bogus.mkdir()
    env = {
        "HOME": str(disposable_home),
        "USER": "tester",
        "PATH": "/usr/bin:/bin",
        "SBFLEET_SOFTWARE_ROOT_BASE": str(soft),
        "LANG": "C",
    }
    result = _run(["bash", str(INSTALL), "--source", str(bogus), "--skip-tools"], env=env)
    assert result.returncode != 0
    assert current.is_symlink()
    assert current.resolve() == old_gen.resolve()
    assert (old_gen / "install.json").read_text(encoding="utf-8").find("old") >= 0
    assert (bin_dir / "sbfleet").resolve() == old.resolve()


def test_tool_cache_install_with_pins(disposable_home: Path) -> None:
    cache = Path("/tmp/sbfleet-pin-dl")
    if not (cache / "supabase_2.118.0_linux_amd64.tar.gz").is_file():
        pytest.skip("pin cache archives not present")
    if shutil.which("docker") is None:
        pytest.skip("docker not available for FULL readiness context")
    env = {
        "HOME": str(disposable_home),
        "USER": "tester",
        "PATH": "/usr/bin:/bin:" + os.environ.get("PATH", ""),
        "SBFLEET_SOFTWARE_ROOT_BASE": str(disposable_home / ".local" / "lib" / "sbfleet"),
        "SBFLEET_TOOL_CACHE": str(cache),
        "LANG": "C",
    }
    result = _run(["bash", str(INSTALL)], env=env)
    combined = result.stdout + result.stderr
    assert "BACKUP READY: YES" in combined
    assert "SANDBOX READY: YES" in combined or "Node" in combined
    age = (
        disposable_home
        / ".local"
        / "lib"
        / "sbfleet"
        / "current"
        / "tools"
        / "age"
        / "1.3.2"
        / "age"
    )
    assert age.is_file()
    assert stat.S_IXUSR & age.stat().st_mode
    assert not (disposable_home / ".local" / "bin" / "age").exists()
