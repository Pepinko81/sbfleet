"""Module tests."""

from __future__ import annotations

import hashlib
import os
import shutil
import uuid
from pathlib import Path

import pytest

from sbfleet import registry as reg
from sbfleet.backup import (
    VERIFICATION_RECOVERY,
    create_backup,
    load_backup_receipt,
    restore_backup,
    set_fleet_recipients,
)
from sbfleet.health import HEALTHY, STOPPED, collect_status, lifecycle_op_succeeded
from sbfleet.process import run
from sbfleet.projects import create_project, stop_project
from sbfleet.projects_remove import remove_project


def _cleanup_remove(root, slug: str) -> None:
    """Disposable cleanup: clear unresolved journal then remove with --no-backup."""
    op = reg.project_dir(root, slug) / "operation.json"
    if op.exists() or op.is_symlink():
        op.unlink()
    return remove_project(root, slug, yes=True, no_backup=True)


pytestmark = pytest.mark.docker

SQL_MARKER = "sbfleet-run2b-sql-marker-7f3a"
SQL_VALUE = "recovery-proof-value-7f3a"
AUTH_EMAIL = "run2b-auth@example.test"
STORAGE_BYTES = b"sbfleet-run2b-storage-object-bytes-v1"
VAULT_SECRET = "run2b-vault-secret-not-for-logs"
FUNCTION_BODY = "Deno.serve(() => new Response('run2b-fn'));\n"


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


def _age_ok() -> bool:
    return shutil.which("age") is not None and shutil.which("age-keygen") is not None


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
    if not _age_ok():
        pytest.skip("age/age-keygen unavailable")
    run_id = uuid.uuid4().hex[:12]
    root = reg.ensure_root(tmp_path / f"sbfleet-test-{run_id}")
    id_path = root / "age-identity.txt"
    gen = _run(["age-keygen", "-o", str(id_path)])
    assert gen.ok, gen.stderr
    os.chmod(id_path, 0o600)
    pub = ""
    for line in id_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("# public key:"):
            pub = line.split(":", 1)[1].strip()
            break
    assert pub.startswith("age1")
    set_fleet_recipients(root, [pub])
    fleet = reg.fleet_id(root)
    yield {"root": root, "identity": id_path, "run_id": run_id, "fleet_id": fleet}
    # Exact labeled cleanup even on setup/assertion failure (no prune).
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


def _psql(deployment: Path, compose_project: str, sql: str, *, db: str = "postgres") -> str:
    r = _compose_exec(
        deployment,
        compose_project,
        "db",
        "psql",
        "-U",
        "postgres",
        "-d",
        db,
        "-v",
        "ON_ERROR_STOP=1",
        "-tAc",
        sql,
    )
    assert r.ok, (r.stderr or r.stdout or "")[:400]
    return (r.stdout or "").strip()


def _docker_write_bytes(dest_dir: Path, filename: str, data: bytes, *, uid: int, gid: int) -> None:
    """Write into container-owned trees via alpine helper."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    # Host may not create nested dirs inside container-owned tree; use docker for all.
    parent = dest_dir
    try:
        # Write on a host-owned sibling then docker-cp into place.
        host_file = Path(f"/tmp/sbfleet-seed-{uuid.uuid4().hex}-{filename}")
        host_file.write_bytes(data)
        r = _run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "-v",
                f"{parent}:/to",
                "-v",
                f"{host_file}:/from/{filename}:ro",
                "alpine:3.20",
                "sh",
                "-c",
                f"mkdir -p /to/{dest_dir.name} && "
                f"cp /from/{filename} /to/{dest_dir.name}/{filename} && "
                f"chown -R {uid}:{gid} /to/{dest_dir.name}",
            ],
            timeout=120.0,
        )
        assert r.ok, (r.stderr or r.stdout or "")[:300]
    finally:
        try:
            host_file.unlink(missing_ok=True)
        except Exception:  # noqa: BLE001
            pass


def _seed_project(root: Path, slug: str, meta: dict) -> dict:
    """Seed SQL/Auth/Storage/function/Vault fixtures. Returns expected probes."""
    deployment = reg.project_dir(root, slug) / "deployment"
    cp = str(meta["compose_project"])
    _psql(
        deployment,
        cp,
        "CREATE TABLE IF NOT EXISTS public.sbfleet_run2b "
        f"(k text PRIMARY KEY, v text); "
        f"INSERT INTO public.sbfleet_run2b(k,v) VALUES ('{SQL_MARKER}','{SQL_VALUE}') "
        "ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v;",
    )
    email = AUTH_EMAIL
    uid = str(uuid.uuid4())
    _psql(
        deployment,
        cp,
        "INSERT INTO auth.users (instance_id, id, aud, role, email, "
        "encrypted_password, email_confirmed_at, created_at, updated_at, "
        "confirmation_token, recovery_token, email_change_token_new, email_change) "
        f"VALUES ('00000000-0000-0000-0000-000000000000', '{uid}', 'authenticated', "
        f"'authenticated', '{email}', crypt('not-a-real-pass', gen_salt('bf')), "
        "now(), now(), now(), '', '', '', '');",
    )
    storage_root = deployment / "volumes" / "storage"
    obj_rel = Path("stub") / "run2b" / "object.bin"
    # Write nested path via docker (storage is 1000:1000)
    host_file = Path(f"/tmp/sbfleet-seed-{uuid.uuid4().hex}.bin")
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
                "mkdir -p /to/stub/run2b && cp /from/object.bin /to/stub/run2b/object.bin && "
                "chown -R 1000:1000 /to/stub",
            ],
            timeout=120.0,
        )
        assert r.ok, (r.stderr or r.stdout or "")[:300]
    finally:
        host_file.unlink(missing_ok=True)
    storage_sha = hashlib.sha256(STORAGE_BYTES).hexdigest()

    fn_root = deployment / "volumes" / "functions"
    host_fn = Path(f"/tmp/sbfleet-seed-{uuid.uuid4().hex}.ts")
    host_fn.write_text(FUNCTION_BODY, encoding="utf-8")
    try:
        r = _run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "-v",
                f"{fn_root}:/to",
                "-v",
                f"{host_fn}:/from/index.ts:ro",
                "alpine:3.20",
                "sh",
                "-c",
                "mkdir -p /to/run2b && cp /from/index.ts /to/run2b/index.ts",
            ],
            timeout=120.0,
        )
        assert r.ok, (r.stderr or r.stdout or "")[:300]
    finally:
        host_fn.unlink(missing_ok=True)
    fn_sha = hashlib.sha256(FUNCTION_BODY.encode()).hexdigest()
    # Vault/pgsodium is mandatory for recovery-proven G6 evidence — no plaintext proxy.
    _psql(deployment, cp, "CREATE EXTENSION IF NOT EXISTS supabase_vault CASCADE;")
    _psql(
        deployment,
        cp,
        f"SELECT vault.create_secret('{VAULT_SECRET}', 'run2b-name', 'run2b-desc');",
    )
    got = _psql(
        deployment,
        cp,
        "SELECT decrypted_secret FROM vault.decrypted_secrets WHERE name = 'run2b-name' LIMIT 1;",
    )
    assert got == VAULT_SECRET, f"vault seed decrypt mismatch (got len={len(got)})"
    vault_sql = (
        "SELECT decrypted_secret FROM vault.decrypted_secrets WHERE name = 'run2b-name' LIMIT 1;"
    )

    return {
        "sql": {
            "fixture_id": SQL_MARKER,
            "query": f"SELECT v FROM public.sbfleet_run2b WHERE k = '{SQL_MARKER}'",
            "expect": SQL_VALUE,
            "database": "postgres",
        },
        "auth": {"email": email, "database": "postgres"},
        "storage_sha": storage_sha,
        "storage_rel": str(obj_rel),
        "functions": {"files": {"deployment/functions/run2b/index.ts": fn_sha}},
        "vault": {
            "ok": True,
            "expect": VAULT_SECRET,
            "sql_decrypt": vault_sql,
            "database": "postgres",
            "name": "run2b-name",
        },
    }


def test_g6_recovery_verified_backup_restore_roundtrip(
    disposable_home: dict, capsys: pytest.CaptureFixture[str]
):
    root = disposable_home["root"]
    run_id = disposable_home["run_id"]
    id_path = disposable_home["identity"]
    slug = f"g6a{run_id[:6]}"
    sentinel_name, sentinel_before = _sentinel(run_id)

    meta = None
    try:
        meta = create_project(root, slug, display_name="G6A", start=True)
        report = collect_status(root, slug)
        assert lifecycle_op_succeeded(report, expect=HEALTHY), report.lifecycle

        seeds = _seed_project(root, slug, meta)
        assert seeds["vault"]["ok"] is True
        expected_vault = seeds["vault"]
        assert expected_vault["expect"] == VAULT_SECRET

        code = create_backup(
            root,
            slug,
            verify=True,
            identity=str(id_path),
            expected_sql=seeds["sql"],
            expected_auth=seeds["auth"],
            expected_vault=expected_vault,
            expected_functions=seeds["functions"],
        )
        assert code == 0
        meta2 = reg.read_project(root, slug)
        bid = meta2["last_backup_id"]
        assert bid
        receipt = load_backup_receipt(root, str(meta2["id"]), str(bid))
        assert receipt is not None
        assert receipt["verification"] == VERIFICATION_RECOVERY
        assert receipt.get("verified") is True
        rec = receipt.get("recovery") or {}
        assert rec.get("outcome_version") == "recovery-verify/v3", rec
        archive = root / "backups" / str(meta2["id"]) / f"{bid}.tar.age"
        assert archive.is_file()
        blob = archive.read_bytes()
        assert VAULT_SECRET.encode() not in blob
        assert SQL_VALUE.encode() not in blob
        receipt_text = (root / "backups" / str(meta2["id"]) / f"{bid}.json").read_text(
            encoding="utf-8"
        )
        assert VAULT_SECRET not in receipt_text
        rec = receipt.get("recovery") or {}
        by_name = {a["name"]: a for a in (rec.get("assertions") or [])}
        assert "vault_decrypt" in by_name, sorted(by_name)
        assert by_name["vault_decrypt"]["ok"] is True
        assert by_name["vault_decrypt"]["detail"] == "match"
        # Capture operator output so far; secret must never appear.
        out1 = capsys.readouterr()
        assert VAULT_SECRET not in out1.out
        assert VAULT_SECRET not in out1.err

        deployment = reg.project_dir(root, slug) / "deployment"
        cp = str(meta2["compose_project"])
        _psql(
            deployment,
            cp,
            f"UPDATE public.sbfleet_run2b SET v = 'MUTATED' WHERE k = '{SQL_MARKER}';",
        )
        # Delete live vault secret so restore must recover the pre-backup value.
        _psql(
            deployment,
            cp,
            "DELETE FROM vault.secrets WHERE name = 'run2b-name';",
        )
        gone = _psql(
            deployment,
            cp,
            "SELECT count(*)::text FROM vault.decrypted_secrets WHERE name = 'run2b-name';",
        )
        assert gone == "0"
        # Mutate storage/functions via docker (container-owned trees)
        _run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "-v",
                f"{deployment / 'volumes' / 'storage'}:/to",
                "alpine:3.20",
                "sh",
                "-c",
                (
                    "printf mutated-storage >/to/stub/run2b/object.bin"
                    " && chown 1000:1000 /to/stub/run2b/object.bin"
                ),
            ],
            timeout=60.0,
        )
        _run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "-v",
                f"{deployment / 'volumes' / 'functions'}:/to",
                "alpine:3.20",
                "sh",
                "-c",
                "printf '// mutated\\n' >/to/run2b/index.ts",
            ],
            timeout=60.0,
        )

        code = restore_backup(
            root,
            slug,
            str(archive),
            yes=True,
            identity=str(id_path),
            expected_sql=seeds["sql"],
            expected_auth=seeds["auth"],
            expected_vault=expected_vault,
        )
        assert code == 0
        report2 = collect_status(root, slug)
        assert lifecycle_op_succeeded(report2, expect=HEALTHY), report2.lifecycle

        got_sql = _psql(deployment, cp, seeds["sql"]["query"])
        assert got_sql == SQL_VALUE
        auth_count = _psql(
            deployment,
            cp,
            f"SELECT count(*)::text FROM auth.users WHERE email = '{AUTH_EMAIL}'",
        )
        assert auth_count == "1"
        # Read via docker if host cannot read container-owned file
        r = _run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "-v",
                f"{deployment / 'volumes' / 'storage'}:/from:ro",
                "alpine:3.20",
                "sha256sum",
                f"/from/{seeds['storage_rel']}",
            ],
            timeout=60.0,
        )
        assert r.ok, (r.stderr or "")[:200]
        got_sha = (r.stdout or "").split()[0]
        assert got_sha == seeds["storage_sha"]
        r = _run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "-v",
                f"{deployment / 'volumes' / 'functions'}:/from:ro",
                "alpine:3.20",
                "cat",
                "/from/run2b/index.ts",
            ],
            timeout=60.0,
        )
        assert r.ok
        assert (r.stdout or "") == FUNCTION_BODY
        # Vault/pgsodium end-to-end after same-project restore (mandatory).
        got_vault = _psql(deployment, cp, expected_vault["sql_decrypt"])
        assert got_vault == VAULT_SECRET
        out2 = capsys.readouterr()
        assert VAULT_SECRET not in out2.out
        assert VAULT_SECRET not in out2.err

        after = _run(
            [
                "docker",
                "volume",
                "inspect",
                "--format",
                "{{.Name}}|{{.CreatedAt}}",
                sentinel_name,
            ]
        )
        assert after.ok
        assert (after.stdout or "").strip() == sentinel_before
    finally:
        try:
            if meta is not None:
                _cleanup_remove(root, slug)
        except Exception:  # noqa: BLE001
            pass
        _run(["docker", "volume", "rm", "-f", sentinel_name])


def test_g6_backup_from_stopped_leaves_stopped(disposable_home: dict):
    root = disposable_home["root"]
    run_id = disposable_home["run_id"]
    id_path = disposable_home["identity"]
    slug = f"g6s{run_id[:6]}"
    sentinel_name, sentinel_before = _sentinel(run_id + "s")
    try:
        create_project(root, slug, display_name="G6S", start=True)
        assert lifecycle_op_succeeded(collect_status(root, slug), expect=HEALTHY)
        stop_project(root, slug)
        assert lifecycle_op_succeeded(collect_status(root, slug), expect=STOPPED)
        code = create_backup(root, slug, verify=True, identity=str(id_path))
        assert code == 0, "STOPPED-source backup must succeed with exit 0"
        report = collect_status(root, slug)
        assert report.lifecycle == STOPPED
        after = _run(
            [
                "docker",
                "volume",
                "inspect",
                "--format",
                "{{.Name}}|{{.CreatedAt}}",
                sentinel_name,
            ]
        )
        assert after.ok
        assert (after.stdout or "").strip() == sentinel_before
        meta2 = reg.read_project(root, slug)
        assert meta2.get("last_backup_verification") == VERIFICATION_RECOVERY
        bid = meta2.get("last_backup_id")
        assert bid
        # Strong verifier contract: currently usable recovery archive bound to receipt.
        from sbfleet.backup import require_recovery_backup

        require_recovery_backup(root, meta2)
    finally:
        try:
            _cleanup_remove(root, slug)
        except Exception:  # noqa: BLE001
            pass
        _run(["docker", "volume", "rm", "-f", sentinel_name])


def test_gates_g6_points_here():
    """Pointer/helper evidence only — not a G6 capability claim."""
    from tests.acceptance import test_gates

    assert hasattr(test_gates, "test_backup_restore_g6")
