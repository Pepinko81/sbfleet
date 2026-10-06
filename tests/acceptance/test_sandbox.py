"""Module tests."""

from __future__ import annotations

import json
import os
import shutil
import uuid
from pathlib import Path

import pytest

from sbfleet.cli import EXIT_OK, EXIT_SAFETY
from sbfleet.process import run

pytestmark = [pytest.mark.docker, pytest.mark.sandbox]

DOCKER_ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
PINNED = "2.118.0"


def _cli_version() -> str | None:
    which = shutil.which("supabase")
    if not which:
        return None
    r = run(
        [which, "--version"], env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")}, check=False
    )
    text = (r.stdout or r.stderr or "").strip()
    import re

    m = re.search(r"(\d+\.\d+\.\d+)", text)
    return m.group(1) if m else None


@pytest.fixture(scope="module")
def require_sandbox_runtime():
    if not shutil.which("docker"):
        pytest.skip("docker missing")
    di = run(["docker", "info"], env=DOCKER_ENV, check=False, timeout=30)
    if not di.ok:
        pytest.skip("docker daemon unavailable")
    ver = _cli_version()
    if ver != PINNED:
        pytest.skip(f"pinned supabase CLI {PINNED} required (have {ver})")


def _sbfleet(*argv: str, home: Path, check: bool = False):
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "SBFLEET_HOME": str(home),
    }
    import sys

    py = sys.executable
    # Prefer console script next to the test interpreter; fall back to -m.
    script = Path(py).resolve().parent / "sbfleet"
    if script.is_file():
        cmd = [str(script), "--home", str(home), *argv]
    else:
        cmd = [py, "-m", "sbfleet.cli", "--home", str(home), *argv]
    return run(cmd, env=env, check=check, timeout=600.0)


def _init_app(app: Path, project_id: str, *, api_port: int = 54321, db_port: int = 54322) -> None:
    app.mkdir(parents=True, exist_ok=True)
    cli_home = app / ".cli-home-init"
    cli_home.mkdir(exist_ok=True)
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(cli_home),
        "SUPABASE_HOME": str(cli_home),
        "SUPABASE_NO_KEYRING": "1",
        "SUPABASE_TELEMETRY_DISABLED": "1",
        "DO_NOT_TRACK": "1",
        "SUPABASE_EXPERIMENTAL_STACK": "0",
        "SUPABASE_ACCESS_TOKEN": "invalid-token-sentinel",
        "SUPABASE_AUTH_TOKEN": "invalid-token-sentinel",
        "SUPABASE_API_URL": "http://127.0.0.1:9",
    }
    init = run(["supabase", "init"], cwd=app, env=env, check=False)
    assert init.ok, init.stderr or init.stdout
    cfg = app / "supabase" / "config.toml"
    text = cfg.read_text(encoding="utf-8")
    import re

    text = re.sub(
        r'(?m)^project_id\s*=\s*".*"',
        f'project_id = "{project_id}"',
        text,
        count=1,
    )
    # Unique ports to avoid collision with other local stacks
    text = re.sub(r"(?m)^port\s*=\s*54321\s*$", f"port = {api_port}", text, count=1)
    text = re.sub(r"(?m)^port\s*=\s*54322\s*$", f"port = {db_port}", text, count=1)
    # studio often 54323
    text = re.sub(r"(?m)^port\s*=\s*54323\s*$", f"port = {api_port + 2}", text, count=1)
    cfg.write_text(text, encoding="utf-8")


def test_g8_adoption_lifecycle_and_collisions(require_sandbox_runtime, tmp_path: Path) -> None:
    """
    G8: adopt → start → local endpoints → SQL → status → reset → destroy;
    duplicate-ID / copy collision; sentinels survive; no Cloud auth required.
    """
    op = tmp_path / f"g8-{uuid.uuid4().hex[:10]}"
    home = op / "sbfleet-home"
    home.mkdir(parents=True)
    app = op / "app-a"
    pid = f"sbfleet-test-{uuid.uuid4().hex[:12]}"
    # Use high unique ports
    base = 55000 + (uuid.uuid4().int % 500)
    _init_app(app, pid, api_port=base, db_port=base + 1)

    # Sentinels
    sent_net = run(
        ["docker", "network", "create", f"sbfleet-g8-sentinel-net-{uuid.uuid4().hex[:8]}"],
        env=DOCKER_ENV,
        check=False,
    )
    assert sent_net.ok
    sentinel_net = (sent_net.stdout or "").strip()
    sent_vol = run(
        ["docker", "volume", "create", f"sbfleet-g8-sentinel-vol-{uuid.uuid4().hex[:8]}"],
        env=DOCKER_ENV,
        check=False,
    )
    assert sent_vol.ok
    sentinel_vol = (sent_vol.stdout or "").strip()
    sent_ctr = run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            f"sbfleet-g8-sentinel-ctr-{uuid.uuid4().hex[:8]}",
            "alpine:3.20",
            "sleep",
            "3600",
        ],
        env=DOCKER_ENV,
        check=False,
    )
    # alpine may need pull
    if not sent_ctr.ok:
        run(["docker", "pull", "alpine:3.20"], env=DOCKER_ENV, check=False, timeout=120)
        sent_ctr = run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                f"sbfleet-g8-sentinel-ctr-{uuid.uuid4().hex[:8]}",
                "alpine:3.20",
                "sleep",
                "3600",
            ],
            env=DOCKER_ENV,
            check=False,
        )
    assert sent_ctr.ok, sent_ctr.stderr
    sentinel_ctr = (sent_ctr.stdout or "").strip()

    marker = app / "APP_SOURCE_MARKER.txt"
    marker.write_text("preserve-me\n", encoding="utf-8")

    try:
        # 1–4 adopt + start (no Cloud token)
        start = _sbfleet("sandbox", "start", str(app), home=home)
        assert start.returncode == EXIT_OK, start.stderr or start.stdout

        # 5 local loopback endpoints via status json
        status = _sbfleet("sandbox", "status", str(app), "--json", home=home)
        assert status.returncode == EXIT_OK, status.stderr
        payload = json.loads(status.stdout or "{}")
        assert payload.get("ok") is True

        # Direct status for URLs (env path locality)
        env_sql = _sbfleet(
            "sandbox",
            "env",
            str(app),
            "--",
            "python3",
            "-c",
            "import os; u=os.environ['DATABASE_URL']; assert u.startswith('postgresql://'); "
            "assert '127.0.0.1' in u or 'localhost' in u; print('db-ok')",
            home=home,
        )
        assert env_sql.returncode == 0, env_sql.stderr or env_sql.stdout

        # Stateful SQL via production sandbox env (/G8 strengthen):
        # write → query → reset → query-absent. Not SELECT 1 / URL print alone.
        marker_val = f"g8mark-{uuid.uuid4().hex[:10]}"
        sql_helper = (
            "import os,subprocess,sys\n"
            "url=os.environ['DATABASE_URL']\n"
            "assert '127.0.0.1' in url or 'localhost' in url\n"
            "cmd=sys.argv[1]\n"
            "sql=sys.argv[2]\n"
            "r=subprocess.run(\n"
            " ['docker','run','--rm','--network','host','postgres:15-alpine',"
            "  'psql',url,'-v','ON_ERROR_STOP=1','-tAc',sql],\n"
            " capture_output=True,text=True,\n"
            ")\n"
            "sys.stdout.write(r.stdout or '')\n"
            "sys.stderr.write(r.stderr or '')\n"
            "raise SystemExit(r.returncode)\n"
        )
        write = _sbfleet(
            "sandbox",
            "env",
            str(app),
            "--",
            "python3",
            "-c",
            sql_helper,
            "write",
            "create table if not exists g8_stateful(k text primary key, v text);"
            f"insert into g8_stateful(k,v) values ('probe','{marker_val}') "
            "on conflict (k) do update set v=excluded.v;",
            home=home,
        )
        assert write.returncode == 0, write.stderr or write.stdout

        read_back = _sbfleet(
            "sandbox",
            "env",
            str(app),
            "--",
            "python3",
            "-c",
            sql_helper,
            "read",
            "select v from g8_stateful where k='probe';",
            home=home,
        )
        assert read_back.returncode == 0, read_back.stderr or read_back.stdout
        assert marker_val in (read_back.stdout or ""), read_back.stdout

        # Stop → start again as existing adoption (V3-005 / Run C G8)
        stop = _sbfleet("sandbox", "stop", str(app), home=home)
        assert stop.returncode == EXIT_OK, stop.stderr or stop.stdout
        restart = _sbfleet("sandbox", "start", str(app), home=home)
        assert restart.returncode == EXIT_OK, restart.stderr or restart.stdout
        read_after_restart = _sbfleet(
            "sandbox",
            "env",
            str(app),
            "--",
            "python3",
            "-c",
            sql_helper,
            "read2",
            "select v from g8_stateful where k='probe';",
            home=home,
        )
        assert read_after_restart.returncode == 0, (
            read_after_restart.stderr or read_after_restart.stdout
        )
        assert marker_val in (read_after_restart.stdout or ""), read_after_restart.stdout

        # Migration file + reset on same adopted sandbox
        mig = app / "supabase" / "migrations"
        mig.mkdir(exist_ok=True)
        (mig / "20260101000000_g8.sql").write_text(
            "create table if not exists g8_probe(id int primary key);\n"
            "insert into g8_probe(id) values (1) on conflict do nothing;\n",
            encoding="utf-8",
        )
        reset = _sbfleet("sandbox", "reset", str(app), "--yes", home=home)
        assert reset.returncode == EXIT_OK, reset.stderr or reset.stdout

        status2 = _sbfleet("sandbox", "status", str(app), home=home)
        assert status2.returncode == EXIT_OK

        after_reset = _sbfleet(
            "sandbox",
            "env",
            str(app),
            "--",
            "python3",
            "-c",
            sql_helper,
            "after",
            "select count(*) from information_schema.tables "
            "where table_schema='public' and table_name='g8_stateful';",
            home=home,
        )
        assert after_reset.returncode == 0, after_reset.stderr or after_reset.stdout
        assert (after_reset.stdout or "").strip() == "0", (
            f"disposable marker must be gone after reset, got {after_reset.stdout!r}"
        )

        # Duplicate ID collision (scenario A)
        app_b = op / "app-b"
        _init_app(app_b, pid, api_port=base + 10, db_port=base + 11)
        dup = _sbfleet("sandbox", "start", str(app_b), home=home)
        assert dup.returncode == EXIT_SAFETY, "duplicate project_id must refuse"
        assert (
            "already adopted" in (dup.stderr or "").lower()
            or "refuse" in (dup.stderr or "").lower()
        )

        # Revalidation must not adopt another sandbox's project ID ().
        # Adopt a second root without a second full Docker stack (stopped identity).
        app_c = op / "app-c"
        pid_c = f"sbfleet-test-{uuid.uuid4().hex[:12]}"
        _init_app(app_c, pid_c, api_port=base + 50, db_port=base + 51)
        from sbfleet.sandbox_adoption import (
            SandboxLocks,
            commit_adoption_pair,
            new_adoption,
            reconcile_adoption_index,
        )
        from sbfleet.sandbox_config import parse_sandbox_config

        cfg_c = parse_sandbox_config(app_c.resolve())
        with SandboxLocks(home, app_c.resolve()):
            commit_adoption_pair(
                home,
                new_adoption(
                    canonical=app_c.resolve(),
                    cli_project_id=cfg_c.project_id,
                    config_fingerprint=cfg_c.fingerprint,
                    fingerprint_fields=cfg_c.fingerprint_fields,
                    cli_version=PINNED,
                    migration_mode="supabase",
                ),
            )
        cfg_a = app / "supabase" / "config.toml"
        cfg_a.write_text(
            cfg_a.read_text(encoding="utf-8").replace(
                f'project_id = "{pid}"', f'project_id = "{pid_c}"'
            ),
            encoding="utf-8",
        )
        collide = _sbfleet("sandbox", "start", str(app), "--revalidate", home=home)
        assert collide.returncode == EXIT_SAFETY, collide.stderr
        assert (
            "immutable" in (collide.stderr or "").lower()
            or "differs" in (collide.stderr or "").lower()
        )
        with SandboxLocks(home, app_c.resolve()):
            still = reconcile_adoption_index(home, app_c.resolve(), cli_project_id=pid_c)
        assert still is not None and still.cli_project_id == pid_c
        # Restore A's project_id for later destroy
        cfg_a.write_text(
            cfg_a.read_text(encoding="utf-8").replace(
                f'project_id = "{pid_c}"', f'project_id = "{pid}"'
            ),
            encoding="utf-8",
        )

        # Copied repository (scenario B)
        app_copy = op / "app-copy"
        shutil.copytree(app, app_copy, symlinks=True)
        # ensure same project id
        copy_start = _sbfleet("sandbox", "start", str(app_copy), home=home)
        assert copy_start.returncode == EXIT_SAFETY

        # Symlink alias (scenario C) — same identity should work (not double-adopt)
        alias = op / "app-alias"
        alias.symlink_to(app.resolve())
        alias_status = _sbfleet("sandbox", "status", str(alias), home=home)
        assert alias_status.returncode == EXIT_OK

        # Linked-state refusal (scenario G)
        linked = op / "app-linked"
        _init_app(
            linked, f"sbfleet-test-{uuid.uuid4().hex[:12]}", api_port=base + 20, db_port=base + 21
        )
        temp = linked / "supabase" / ".temp"
        temp.mkdir(parents=True, exist_ok=True)
        (temp / "project-ref").write_text("abcdefghijklmnopqrst\n", encoding="utf-8")
        linked_start = _sbfleet("sandbox", "start", str(linked), home=home)
        assert linked_start.returncode == EXIT_SAFETY

        # Dangerous dotenv (scenario H)
        bad_env = op / "app-dotenv"
        _init_app(
            bad_env, f"sbfleet-test-{uuid.uuid4().hex[:12]}", api_port=base + 30, db_port=base + 31
        )
        (bad_env / ".env").write_text(
            'export SUPABASE_ACCESS_TOKEN="cloud-tok"\n', encoding="utf-8"
        )
        dotenv_start = _sbfleet("sandbox", "start", str(bad_env), home=home)
        assert dotenv_start.returncode == EXIT_SAFETY

        # Studio URL locality
        studio = _sbfleet("sandbox", "studio", str(app), home=home)
        assert studio.returncode == EXIT_OK
        url = (studio.stdout or "").strip()
        assert url.startswith("http://127.0.0.1") or url.startswith("http://localhost")

        # 11 destroy
        destroy = _sbfleet("sandbox", "destroy", str(app), "--yes", home=home)
        assert destroy.returncode == EXIT_OK, destroy.stderr or destroy.stdout

        # 12 app source survives
        assert marker.is_file()
        assert marker.read_text(encoding="utf-8") == "preserve-me\n"

        # 13 sentinels survive
        assert run(["docker", "network", "inspect", sentinel_net], env=DOCKER_ENV, check=False).ok
        assert run(["docker", "volume", "inspect", sentinel_vol], env=DOCKER_ENV, check=False).ok
        assert run(["docker", "inspect", sentinel_ctr], env=DOCKER_ENV, check=False).ok

        # Fingerprint drift refuses without --revalidate
        app2 = op / "app-drift"
        pid2 = f"sbfleet-test-{uuid.uuid4().hex[:12]}"
        _init_app(app2, pid2, api_port=base + 40, db_port=base + 41)
        assert _sbfleet("sandbox", "start", str(app2), home=home).returncode == EXIT_OK
        cfg = app2 / "supabase" / "config.toml"
        cfg.write_text(
            cfg.read_text(encoding="utf-8").replace(f"port = {base + 40}", f"port = {base + 42}"),
            encoding="utf-8",
        )
        drift = _sbfleet("sandbox", "status", str(app2), home=home)
        assert drift.returncode == EXIT_SAFETY
        # cleanup app2
        # revalidate then destroy
        assert (
            _sbfleet("sandbox", "start", str(app2), "--revalidate", home=home).returncode == EXIT_OK
        )
        _sbfleet("sandbox", "destroy", str(app2), "--yes", home=home)

    finally:
        # Best-effort cleanup of primary app if still running
        _sbfleet("sandbox", "destroy", str(app), "--yes", home=home)
        run(["docker", "rm", "-f", sentinel_ctr], env=DOCKER_ENV, check=False)
        run(["docker", "volume", "rm", sentinel_vol], env=DOCKER_ENV, check=False)
        run(["docker", "network", "rm", sentinel_net], env=DOCKER_ENV, check=False)


def test_g8_foreign_network_refused(require_sandbox_runtime, tmp_path: Path) -> None:
    """Scenario D/E: foreign / wrong-option networks cannot be adopted via name."""
    from sbfleet.sandbox_authority import (
        HOST_BINDING_OPT,
        SandboxAuthorityError,
        create_owned_network,
        prove_network_owned,
    )

    phash = uuid.uuid4().hex[:16]
    suuid = str(uuid.uuid4())
    foreign_name = f"sbfleet-sb-{phash}"
    created = run(["docker", "network", "create", foreign_name], env=DOCKER_ENV, check=False)
    assert created.ok
    fid = (created.stdout or "").strip()
    try:
        with pytest.raises(SandboxAuthorityError):
            prove_network_owned(fid, path_hash=phash, sandbox_uuid=suuid)
        with pytest.raises(SandboxAuthorityError, match="refuse takeover"):
            create_owned_network(name=foreign_name, path_hash=phash, sandbox_uuid=suuid)
    finally:
        run(["docker", "network", "rm", fid], env=DOCKER_ENV, check=False)

    # Wrong options
    bad = run(
        [
            "docker",
            "network",
            "create",
            "--label",
            f"io.sbfleet.sandbox={phash}",
            "--label",
            f"io.sbfleet.sandbox_uuid={suuid}",
            "-o",
            f"{HOST_BINDING_OPT}=0.0.0.0",
            f"sbfleet-sb-bad-{phash}",
        ],
        env=DOCKER_ENV,
        check=False,
    )
    assert bad.ok
    bid = (bad.stdout or "").strip()
    try:
        with pytest.raises(SandboxAuthorityError, match="host_binding"):
            prove_network_owned(bid, path_hash=phash, sandbox_uuid=suuid)
    finally:
        run(["docker", "network", "rm", bid], env=DOCKER_ENV, check=False)


def test_g8_adopted_start_refuses_foreign_live_container(
    require_sandbox_runtime, tmp_path: Path
) -> None:
    """Existing adoption + foreign live container: zero unproven start/stop dispatch (V3-005)."""
    from sbfleet.sandbox_adoption import SandboxLocks, commit_adoption_pair, new_adoption
    from sbfleet.sandbox_config import parse_sandbox_config

    op = tmp_path / f"g8-foreign-{uuid.uuid4().hex[:8]}"
    home = op / "home"
    home.mkdir(parents=True)
    app = op / "app"
    pid = f"sbfleet-test-{uuid.uuid4().hex[:12]}"
    base = 56000 + (uuid.uuid4().int % 400)
    _init_app(app, pid, api_port=base, db_port=base + 1)
    sentinel_file = op / "sentinel.txt"
    sentinel_file.write_text("sentinel-data\n", encoding="utf-8")
    marker = app / "APP_SOURCE_MARKER.txt"
    marker.write_text("preserve-me\n", encoding="utf-8")

    # Seed adoption without starting a real stack.
    cfg = parse_sandbox_config(app.resolve())
    with SandboxLocks(home, app.resolve()):
        commit_adoption_pair(
            home,
            new_adoption(
                canonical=app.resolve(),
                cli_project_id=cfg.project_id,
                config_fingerprint=cfg.fingerprint,
                fingerprint_fields=cfg.fingerprint_fields,
                cli_version=PINNED,
                migration_mode="supabase",
                network_id="net-missing-for-foreign-test",
            ),
        )

    # Foreign container labeled with this project id but wrong workdir.
    foreign_name = f"sbfleet-g8-foreign-ctr-{uuid.uuid4().hex[:8]}"
    foreign = run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            foreign_name,
            "--label",
            f"com.supabase.cli.project={pid}",
            "--label",
            "com.supabase.cli.workdir=/tmp/not-this-sandbox",
            "alpine:3.20",
            "sleep",
            "120",
        ],
        env=DOCKER_ENV,
        check=False,
    )
    if not foreign.ok:
        run(["docker", "pull", "alpine:3.20"], env=DOCKER_ENV, check=False, timeout=120)
        foreign = run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                foreign_name,
                "--label",
                f"com.supabase.cli.project={pid}",
                "--label",
                "com.supabase.cli.workdir=/tmp/not-this-sandbox",
                "alpine:3.20",
                "sleep",
                "120",
            ],
            env=DOCKER_ENV,
            check=False,
        )
    assert foreign.ok, foreign.stderr
    foreign_id = (foreign.stdout or "").strip()
    try:
        before = run(["docker", "inspect", foreign_id], env=DOCKER_ENV, check=False)
        assert before.ok
        start = _sbfleet("sandbox", "start", str(app), home=home)
        assert start.returncode == EXIT_SAFETY, start.stderr or start.stdout
        assert (
            "foreign" in (start.stderr or "").lower()
            or "unknown" in (start.stderr or "").lower()
            or "ownership" in (start.stderr or "").lower()
        )
        after = run(["docker", "inspect", foreign_id], env=DOCKER_ENV, check=False)
        assert after.ok, "foreign container must remain untouched"
        assert marker.read_text(encoding="utf-8") == "preserve-me\n"
        assert sentinel_file.read_text(encoding="utf-8") == "sentinel-data\n"
        # Destroy must also refuse unproven cleanup when foreign/unknown
        destroy = _sbfleet("sandbox", "destroy", str(app), "--yes", home=home)
        assert destroy.returncode == EXIT_SAFETY
        still = run(["docker", "inspect", foreign_id], env=DOCKER_ENV, check=False)
        assert still.ok, "destroy must not remove foreign container"
    finally:
        run(["docker", "rm", "-f", foreign_id], env=DOCKER_ENV, check=False)
        # Exact absence check for test-owned foreign container
        gone = run(["docker", "inspect", foreign_id], env=DOCKER_ENV, check=False)
        assert not gone.ok
