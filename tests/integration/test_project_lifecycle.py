"""G4 disposable single official project lifecycle acceptance (Audit Readiness).

Never targets user projects. Unique sbfleet-test-<uuid> roots and labeled sentinels.
No prune / no --remove-orphans.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pytest

from sbfleet import registry as reg
from sbfleet.doctor import run_doctor
from sbfleet.health import HEALTHY, STOPPED, collect_status, lifecycle_op_succeeded
from sbfleet.process import run
from sbfleet.projects import create_project, restart_project, start_project, stop_project
from sbfleet.projects_remove import remove_project
from sbfleet.upstream import parse_dotenv


def _cleanup_remove(root, slug: str) -> None:
    """Disposable cleanup: clear unresolved journal then remove with --no-backup."""
    op = reg.project_dir(root, slug) / "operation.json"
    if op.exists() or op.is_symlink():
        op.unlink()
    return remove_project(root, slug, yes=True, no_backup=True)


pytestmark = pytest.mark.docker

SQL_MARKER = "sbfleet-g4-sql-marker"
SQL_VALUE = "g4-persist-1"
STORAGE_BYTES = b"g4-object-bytes-audit-readiness"


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
    name = f"sbfleet-sentinel-{run_id}"
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
        with urlopen(req, timeout=timeout) as resp:  # noqa: S310 — loopback fixture only
            body = resp.read(4096)
            return resp.status, body
    except HTTPError as exc:
        return exc.code, exc.read(4096) if exc.fp else b""
    except URLError as exc:
        return None, str(exc).encode()


def test_g4_official_project_lifecycle(disposable_home: dict) -> None:
    root = disposable_home["root"]
    run_id = disposable_home["run_id"]
    slug = f"g4a{run_id[:6]}"
    sentinel_name, sentinel_before = _sentinel(run_id)
    meta = None
    try:
        meta = create_project(root, slug, display_name="G4A", start=False)
        assert meta.get("creation_complete") is True
        report = collect_status(root, slug)
        assert lifecycle_op_succeeded(report, expect=STOPPED), report.lifecycle

        start_project(root, slug)
        report = collect_status(root, slug)
        assert lifecycle_op_succeeded(report, expect=HEALTHY), report.lifecycle

        # Runtime image recording must be honest (RECORDED or UNKNOWN+reason).
        meta = reg.read_project(root, slug)
        images = meta.get("image_digests") or {}
        assert images, "image_digests missing after HEALTHY start"
        for svc, entry in images.items():
            if svc.startswith("_"):
                assert entry.get("status") == "UNKNOWN"
                assert entry.get("reason")
                continue
            assert entry.get("status") in {"RECORDED", "UNKNOWN"}
            if entry.get("status") == "UNKNOWN":
                assert entry.get("reason"), f"{svc} UNKNOWN without reason"

        deployment = reg.project_dir(root, slug) / "deployment"
        cp = str(meta["compose_project"])
        env = parse_dotenv((deployment / ".env").read_text(encoding="utf-8"))
        gateway = int(meta["ports"]["gateway"])
        base = f"http://127.0.0.1:{gateway}"
        anon = env["ANON_KEY"]
        dash_user = env["DASHBOARD_USERNAME"]
        dash_pass = env["DASHBOARD_PASSWORD"]

        code, _ = _http(f"{base}/auth/v1/health", headers={"apikey": anon})
        assert code == 200, f"auth health={code}"

        code, _ = _http(
            f"{base}/rest/v1/sbfleet_missing_table",
            headers={"apikey": anon, "Authorization": f"Bearer {anon}"},
        )
        assert code in {401, 404}, f"rest unexpected={code}"

        code, _ = _http(
            f"{base}/storage/v1/bucket",
            headers={"apikey": anon, "Authorization": f"Bearer {anon}"},
        )
        assert code == 200, f"storage={code}"

        code, _ = _http(f"{base}/")
        assert code == 401, f"studio unauth={code}"

        import base64

        token = base64.b64encode(f"{dash_user}:{dash_pass}".encode()).decode()
        code, body = _http(f"{base}/", headers={"Authorization": f"Basic {token}"})
        assert code == 200, f"studio auth={code}"
        assert body, "studio body empty"

        _psql(
            deployment,
            cp,
            "CREATE TABLE IF NOT EXISTS public.sbfleet_g4 "
            f"(k text PRIMARY KEY, v text); "
            f"INSERT INTO public.sbfleet_g4(k,v) VALUES ('{SQL_MARKER}','{SQL_VALUE}') "
            "ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v;",
        )
        got = _psql(
            deployment,
            cp,
            f"SELECT v FROM public.sbfleet_g4 WHERE k = '{SQL_MARKER}'",
        )
        assert got == SQL_VALUE

        storage_root = deployment / "volumes" / "storage"
        host_file = Path(f"/tmp/sbfleet-g4-{uuid.uuid4().hex}.bin")
        host_file.write_bytes(STORAGE_BYTES)
        try:
            r = _run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "-v",
                    f"{storage_root}:/to",
                    "-v",
                    f"{host_file}:/from/object.bin:ro",
                    "alpine:3.20",
                    "sh",
                    "-c",
                    "mkdir -p /to/stub/g4 && cp /from/object.bin /to/stub/g4/object.bin && "
                    "chown -R 1000:1000 /to/stub",
                ],
                timeout=120.0,
            )
            assert r.ok, (r.stderr or r.stdout or "")[:300]
        finally:
            host_file.unlink(missing_ok=True)
        # May not be readable as host user; verify via alpine
        r = _run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "-v",
                f"{storage_root}:/to:ro",
                "alpine:3.20",
                "sha256sum",
                "/to/stub/g4/object.bin",
            ]
        )
        assert r.ok, (r.stderr or "")[:200]
        assert hashlib.sha256(STORAGE_BYTES).hexdigest() in (r.stdout or "")

        stop_project(root, slug)
        assert lifecycle_op_succeeded(collect_status(root, slug), expect=STOPPED)
        start_project(root, slug)
        assert lifecycle_op_succeeded(collect_status(root, slug), expect=HEALTHY)
        got = _psql(
            deployment,
            cp,
            f"SELECT v FROM public.sbfleet_g4 WHERE k = '{SQL_MARKER}'",
        )
        assert got == SQL_VALUE

        restart_project(root, slug)
        assert lifecycle_op_succeeded(collect_status(root, slug), expect=HEALTHY)

        doc_code = run_doctor(root, project=slug, sandbox=None, as_json=True)
        assert doc_code == 0, f"doctor exit={doc_code} (expected exact 0 for healthy fixture)"

        report = collect_status(root, slug)
        assert report.lifecycle == HEALTHY

        stop_project(root, slug)
        code = _cleanup_remove(root, slug)
        assert code == 0
        meta = None
    finally:
        if meta is not None:
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
        assert after.ok, "sentinel volume missing"
        assert (after.stdout or "").strip() == sentinel_before
        _run(["docker", "volume", "rm", sentinel_name])
