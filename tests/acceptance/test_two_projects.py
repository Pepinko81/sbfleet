"""G5 disposable two simultaneous official projects (Audit Readiness).

Never targets user projects. Unique sbfleet-test-<uuid> roots and labeled sentinels.
No prune / no --remove-orphans.
"""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pytest

from sbfleet import registry as reg
from sbfleet.health import HEALTHY, STOPPED, collect_status, lifecycle_op_succeeded
from sbfleet.process import run
from sbfleet.projects import create_project, start_project, stop_project
from sbfleet.projects_remove import remove_project
from sbfleet.upstream import parse_dotenv


def _cleanup_remove(root, slug: str) -> None:
    """Disposable cleanup: clear unresolved journal then remove with --no-backup."""
    op = reg.project_dir(root, slug) / "operation.json"
    if op.exists() or op.is_symlink():
        op.unlink()
    return remove_project(root, slug, yes=True, no_backup=True)


pytestmark = pytest.mark.docker

SQL_A = "a-only-marker"
SQL_B = "b-only-marker"


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


def _run(argv: list[str], *, cwd: Path | None = None, timeout: float = 120.0):
    return run(
        argv,
        cwd=cwd,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        timeout=timeout,
        check=False,
    )


@pytest.fixture()
def disposable_home(tmp_path: Path):
    if not _docker_ok():
        pytest.skip("docker unavailable")
    run_id = uuid.uuid4().hex[:12]
    root = reg.ensure_root(tmp_path / f"sbfleet-test-{run_id}")
    fleet = reg.fleet_id(root)
    yield {"root": root, "run_id": run_id, "fleet_id": fleet}
    import fixture_cleanup

    fixture_cleanup.cleanup_labeled_fleet_resources(fleet_id=fleet)


def _sentinel(run_id: str) -> tuple[str, str]:
    name = f"sbfleet-sentinel-g5-{run_id}"
    r = _run(
        [
            "docker",
            "volume",
            "create",
            "--label",
            "io.sbfleet.role=sentinel",
            "--label",
            f"io.sbfleet.run={run_id}",
            name,
        ]
    )
    assert r.ok, r.stderr
    insp = _run(["docker", "volume", "inspect", "--format", "{{.Name}}|{{.CreatedAt}}", name])
    assert insp.ok
    return name, (insp.stdout or "").strip()


def _compose_exec(deployment: Path, compose_project: str, service: str, *cmd: str):
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(deployment / ".run-home"),
        "COMPOSE_PROJECT_NAME": compose_project,
        "COMPOSE_FILE": "docker-compose.yml:docker-compose.override.yml",
        "COMPOSE_PATH_SEPARATOR": ":",
    }
    return run(
        ["docker", "compose", "exec", "-T", service, *cmd],
        cwd=deployment,
        env=env,
        timeout=120.0,
        check=False,
    )


def _psql(deployment: Path, compose_project: str, sql: str) -> str:
    r = _compose_exec(
        deployment,
        compose_project,
        "db",
        "psql",
        "-U",
        "postgres",
        "-d",
        "postgres",
        "-v",
        "ON_ERROR_STOP=1",
        "-tAc",
        sql,
    )
    assert r.ok, (r.stderr or r.stdout or "")[:400]
    return (r.stdout or "").strip()


def _http(url: str, *, headers: dict[str, str] | None = None, timeout: float = 30.0):
    req = Request(url, headers=headers or {}, method="GET")
    try:
        with urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return resp.status, resp.read(2048)
    except HTTPError as exc:
        return exc.code, exc.read(2048) if exc.fp else b""
    except URLError as exc:
        return None, str(exc).encode()


def _secret_probe(env: dict[str, str]) -> dict[str, str]:
    keys = (
        "JWT_SECRET",
        "ANON_KEY",
        "SERVICE_ROLE_KEY",
        "POSTGRES_PASSWORD",
        "DASHBOARD_PASSWORD",
        "POOLER_TENANT_ID",
    )
    return {k: env[k] for k in keys}


def test_g5_two_simultaneous_projects(disposable_home: dict) -> None:
    root = disposable_home["root"]
    run_id = disposable_home["run_id"]
    slug_a = f"g5a{run_id[:5]}"
    slug_b = f"g5b{run_id[:5]}"
    sentinel_name, sentinel_before = _sentinel(run_id)
    meta_a = meta_b = None
    try:
        before_ids = set()
        ls = _run(["docker", "ps", "-aq", "--no-trunc"])
        if ls.ok:
            before_ids = {x for x in (ls.stdout or "").splitlines() if x}

        meta_a = create_project(root, slug_a, display_name="G5A", start=True)
        meta_b = create_project(root, slug_b, display_name="G5B", start=True)
        assert lifecycle_op_succeeded(collect_status(root, slug_a), expect=HEALTHY)
        assert lifecycle_op_succeeded(collect_status(root, slug_b), expect=HEALTHY)

        assert meta_a["id"] != meta_b["id"]
        assert meta_a["compose_project"] != meta_b["compose_project"]
        assert meta_a["ports"] != meta_b["ports"]

        dep_a = reg.project_dir(root, slug_a) / "deployment"
        dep_b = reg.project_dir(root, slug_b) / "deployment"
        env_a = parse_dotenv((dep_a / ".env").read_text(encoding="utf-8"))
        env_b = parse_dotenv((dep_b / ".env").read_text(encoding="utf-8"))
        sec_a = _secret_probe(env_a)
        sec_b = _secret_probe(env_b)
        # Compare booleans only — never print secrets.
        differ = {k: sec_a[k] != sec_b[k] for k in sec_a}
        assert all(differ.values()), f"secret independence failed: {differ}"

        cp_a = str(meta_a["compose_project"])
        cp_b = str(meta_b["compose_project"])
        _psql(
            dep_a,
            cp_a,
            "CREATE TABLE IF NOT EXISTS public.sbfleet_g5 "
            f"(k text PRIMARY KEY, v text); "
            f"INSERT INTO public.sbfleet_g5(k,v) VALUES ('m','{SQL_A}') "
            "ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v;",
        )
        _psql(
            dep_b,
            cp_b,
            "CREATE TABLE IF NOT EXISTS public.sbfleet_g5 "
            f"(k text PRIMARY KEY, v text); "
            f"INSERT INTO public.sbfleet_g5(k,v) VALUES ('m','{SQL_B}') "
            "ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v;",
        )
        assert _psql(dep_a, cp_a, "SELECT v FROM public.sbfleet_g5 WHERE k='m'") == SQL_A
        assert _psql(dep_b, cp_b, "SELECT v FROM public.sbfleet_g5 WHERE k='m'") == SQL_B

        # Host-loopback SQL via allocated ports (Mode A) — not compose exec.
        from sbfleet.connection import connection_info

        info_a = connection_info(root, slug_a)
        info_b = connection_info(root, slug_b)
        assert info_a["db_port"] != info_b["db_port"]
        assert info_a["db_port"] != "5432"
        assert info_b["db_port"] != "5432"

        def _host_psql(slug: str, sql: str) -> str:
            """Query via published 127.0.0.1:<db_direct> (host network client)."""
            info = connection_info(root, slug)
            port = info["db_port"]
            password = parse_dotenv(
                (reg.project_dir(root, slug) / "deployment" / ".env").read_text(encoding="utf-8")
            )["POSTGRES_PASSWORD"]
            r = run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    "host",
                    "-e",
                    f"PGPASSWORD={password}",
                    "postgres:17",
                    "psql",
                    "-h",
                    "127.0.0.1",
                    "-p",
                    port,
                    "-U",
                    "postgres",
                    "-d",
                    "postgres",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-t",
                    "-A",
                    "-c",
                    sql,
                ],
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                check=False,
                timeout=120.0,
            )
            assert r.ok, r.stderr
            return (r.stdout or "").strip()

        assert _host_psql(slug_a, "SELECT v FROM public.sbfleet_g5 WHERE k='m'") == SQL_A
        assert _host_psql(slug_b, "SELECT v FROM public.sbfleet_g5 WHERE k='m'") == SQL_B

        gw_b = int(meta_b["ports"]["gateway"])
        # Cross-project key rejected on B.
        code, _ = _http(
            f"http://127.0.0.1:{gw_b}/rest/v1/",
            headers={
                "apikey": env_a["ANON_KEY"],
                "Authorization": f"Bearer {env_a['ANON_KEY']}",
            },
        )
        assert code in {401, 403}, f"cross-key unexpectedly accepted: {code}"
        code_ok, _ = _http(
            f"http://127.0.0.1:{gw_b}/auth/v1/health",
            headers={"apikey": env_b["ANON_KEY"]},
        )
        assert code_ok == 200

        stop_project(root, slug_a)
        assert lifecycle_op_succeeded(collect_status(root, slug_a), expect=STOPPED)
        assert lifecycle_op_succeeded(collect_status(root, slug_b), expect=HEALTHY)
        assert _psql(dep_b, cp_b, "SELECT v FROM public.sbfleet_g5 WHERE k='m'") == SQL_B

        start_project(root, slug_a)
        assert lifecycle_op_succeeded(collect_status(root, slug_a), expect=HEALTHY)

        # Capture resource classes before removing A ( / Run D).
        def _compose_ids(compose_project: str) -> set[str]:
            r = _run(
                [
                    "docker",
                    "ps",
                    "-aq",
                    "--no-trunc",
                    "--filter",
                    f"label=com.docker.compose.project={compose_project}",
                ]
            )
            assert r.ok, (r.stderr or r.stdout or "")[:200]
            return {x for x in (r.stdout or "").splitlines() if x}

        a_ids = _compose_ids(cp_a)  # class A — expected to disappear
        b_ids = _compose_ids(cp_b)  # class B — required to remain
        assert a_ids, "project A must have live containers before remove"
        assert b_ids, "project B must have live containers before remove"
        assert a_ids.isdisjoint(b_ids)

        def _id_fingerprint(cid: str) -> str:
            r = _run(
                [
                    "docker",
                    "inspect",
                    "--format",
                    "{{.Id}}|{{.Created}}|{{.Name}}",
                    cid,
                ]
            )
            assert r.ok, f"missing B/sentinel resource {cid}: {(r.stderr or '')[:160]}"
            return (r.stdout or "").strip()

        b_before = {cid: _id_fingerprint(cid) for cid in b_ids}

        code = remove_project(root, slug_a, yes=True, no_backup=True)
        assert code == 0
        meta_a = None
        assert lifecycle_op_succeeded(collect_status(root, slug_b), expect=HEALTHY)
        assert _psql(dep_b, cp_b, "SELECT v FROM public.sbfleet_g5 WHERE k='m'") == SQL_B

        # Class A: expected A resources absent.
        for cid in a_ids:
            gone = _run(["docker", "inspect", cid])
            assert not gone.ok, f"A resource still present after remove: {cid[:12]}"

        # Class B: every expected B resource ID/data unchanged.
        for cid, fp in b_before.items():
            assert _id_fingerprint(cid) == fp, f"B resource changed: {cid[:12]}"

        # Unrelated sentinel: ID/data unchanged.
        after = _run(
            ["docker", "volume", "inspect", "--format", "{{.Name}}|{{.CreatedAt}}", sentinel_name]
        )
        assert after.ok, "sentinel volume missing after A removal"
        assert (after.stdout or "").strip() == sentinel_before
        # Keep before_ids used only as ambient inventory evidence (not mixed set-diff claim).
        assert isinstance(before_ids, set)
    finally:
        for slug, meta in ((slug_a, meta_a), (slug_b, meta_b)):
            if meta is None:
                continue
            try:
                stop_project(root, slug)
            except Exception:  # noqa: BLE001
                pass
            try:
                _cleanup_remove(root, slug)
            except Exception:  # noqa: BLE001
                pass
        after = _run(
            ["docker", "volume", "inspect", "--format", "{{.Name}}|{{.CreatedAt}}", sentinel_name]
        )
        if after.ok:
            assert (after.stdout or "").strip() == sentinel_before
            _run(["docker", "volume", "rm", sentinel_name])
