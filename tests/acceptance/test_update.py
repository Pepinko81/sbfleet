"""Module tests."""

from __future__ import annotations

import hashlib
import os
import shutil
import uuid
from pathlib import Path

import pytest

from sbfleet import registry as reg
from sbfleet import update as upd
from sbfleet import upstream as up
from sbfleet.backup import load_backup_receipt, set_fleet_recipients
from sbfleet.backup_manifest import VERIFICATION_RECOVERY, is_recovery_verified_receipt
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

SQL_MARKER = "sbfleet-run2c-sql-marker-9a1b"
SQL_VALUE = "update-proof-value-9a1b"
AUTH_EMAIL = "run2c-auth@example.test"
STORAGE_BYTES = b"sbfleet-run2c-storage-object-bytes-v1"
VAULT_SECRET = "run2c-vault-secret-not-for-logs"
FUNCTION_BODY = "Deno.serve(() => new Response('run2c-fn'));\n"

SOURCE_REF = "self-hosted/v0.8.1"
TARGET_REF = "self-hosted/v0.8.2"
SOURCE_SHA = up.KNOWN_REF_SHAS[SOURCE_REF]
TARGET_SHA = up.KNOWN_REF_SHAS[TARGET_REF]


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
    os.environ["SBFLEET_AGE_IDENTITY"] = str(id_path)
    fleet = reg.fleet_id(root)
    yield {"root": root, "identity": id_path, "run_id": run_id, "fleet_id": fleet}
    import fixture_cleanup

    fixture_cleanup.cleanup_labeled_fleet_resources(fleet_id=fleet)
    os.environ.pop("SBFLEET_AGE_IDENTITY", None)


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


def _seed_project(root: Path, slug: str, meta: dict) -> dict:
    deployment = reg.project_dir(root, slug) / "deployment"
    cp = str(meta["compose_project"])
    _psql(
        deployment,
        cp,
        "CREATE TABLE IF NOT EXISTS public.sbfleet_run2c (k text PRIMARY KEY, v text NOT NULL);",
    )
    _psql(
        deployment,
        cp,
        f"INSERT INTO public.sbfleet_run2c(k,v) VALUES ('{SQL_MARKER}','{SQL_VALUE}') "
        "ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v;",
    )
    email = AUTH_EMAIL
    uid = str(uuid.uuid4())
    _psql(
        deployment,
        cp,
        "INSERT INTO auth.users (instance_id, id, aud, role, email, encrypted_password, "
        "email_confirmed_at, created_at, updated_at, confirmation_token, recovery_token, "
        "email_change_token_new, email_change) "
        f"VALUES ('00000000-0000-0000-0000-000000000000', '{uid}', 'authenticated', "
        f"'authenticated', '{email}', crypt('not-a-real-pass', gen_salt('bf')), "
        "now(), now(), now(), '', '', '', '');",
    )
    storage_root = deployment / "volumes" / "storage"
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
                "mkdir -p /to/stub/run2c && cp /from/object.bin /to/stub/run2c/object.bin && "
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
                "mkdir -p /to/run2c && cp /from/index.ts /to/run2c/index.ts",
            ],
            timeout=120.0,
        )
        assert r.ok, (r.stderr or r.stdout or "")[:300]
    finally:
        host_fn.unlink(missing_ok=True)
    fn_sha = hashlib.sha256(FUNCTION_BODY.encode()).hexdigest()

    _psql(deployment, cp, "CREATE EXTENSION IF NOT EXISTS supabase_vault CASCADE;")
    _psql(
        deployment,
        cp,
        f"SELECT vault.create_secret('{VAULT_SECRET}', 'run2c-name', 'run2c-desc');",
    )
    got = _psql(
        deployment,
        cp,
        "SELECT decrypted_secret FROM vault.decrypted_secrets WHERE name = 'run2c-name' LIMIT 1;",
    )
    assert got == VAULT_SECRET

    env = up.parse_dotenv((deployment / ".env").read_text(encoding="utf-8"))
    secret_fp = {
        k: hashlib.sha256(env[k].encode()).hexdigest()[:16]
        for k in sorted(up.REQUIRED_ENV_KEYS)
        if k in env
    }
    return {
        "sql_expect": SQL_VALUE,
        "auth_email": email,
        "storage_sha": storage_sha,
        "fn_sha": fn_sha,
        "vault_expect": VAULT_SECRET,
        "secret_fp": secret_fp,
        "project_id": str(meta["id"]),
        "fleet_id": str(meta["fleet_id"]),
    }


def _assert_seeded_survived(root: Path, slug: str, meta: dict, seeds: dict) -> None:
    """Update-transition acceptance: seeded application state survives."""
    deployment = reg.project_dir(root, slug) / "deployment"
    cp = str(meta["compose_project"])
    got_sql = _psql(
        deployment,
        cp,
        f"SELECT v FROM public.sbfleet_run2c WHERE k = '{SQL_MARKER}'",
    )
    assert got_sql == seeds["sql_expect"]
    auth_count = _psql(
        deployment,
        cp,
        f"SELECT count(*) FROM auth.users WHERE email = '{seeds['auth_email']}'",
    )
    assert auth_count == "1"
    # Read via docker because of container ownership.
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
            "/from/stub/run2c/object.bin",
        ],
        timeout=60.0,
    )
    assert r.ok, (r.stderr or r.stdout or "")[:200]
    assert (r.stdout or "").split()[0] == seeds["storage_sha"]
    fn = deployment / "volumes" / "functions" / "run2c" / "index.ts"
    r = _run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{fn.parent}:/from:ro",
            "alpine:3.20",
            "sha256sum",
            "/from/index.ts",
        ],
        timeout=60.0,
    )
    assert r.ok
    assert (r.stdout or "").split()[0] == seeds["fn_sha"]
    vault = _psql(
        deployment,
        cp,
        "SELECT decrypted_secret FROM vault.decrypted_secrets WHERE name = 'run2c-name' LIMIT 1;",
    )
    assert vault == seeds["vault_expect"]


def test_g7_reviewed_transition_healthy_source(
    disposable_home: dict, capsys: pytest.CaptureFixture[str]
):
    root = disposable_home["root"]
    run_id = disposable_home["run_id"]
    id_path = disposable_home["identity"]
    slug = f"g7h{run_id[:6]}"
    sentinel_name, sentinel_before = _sentinel(run_id)
    meta = None
    try:
        meta = create_project(
            root,
            slug,
            display_name="G7H",
            start=True,
            upstream_ref=SOURCE_REF,
            upstream_sha=SOURCE_SHA,
        )
        report = collect_status(root, slug)
        assert lifecycle_op_succeeded(report, expect=HEALTHY), report.lifecycle
        assert meta["upstream"]["ref"] == SOURCE_REF

        seeds = _seed_project(root, slug, meta)
        dep = reg.project_dir(root, slug) / "deployment"
        live_before = upd.hash_authority_surface(dep)

        code = upd.update_project(
            root,
            slug,
            to_ref=TARGET_REF,
            dry_run=False,
            yes=True,
            identity=str(id_path),
        )
        out = capsys.readouterr()
        assert code == 0, out.err or out.out
        assert VAULT_SECRET not in out.out
        assert VAULT_SECRET not in out.err
        assert seeds["vault_expect"] not in out.out

        meta2 = reg.read_project(root, slug)
        assert meta2["upstream"]["ref"] == TARGET_REF
        assert meta2["upstream"]["sha"] == TARGET_SHA
        verified = meta2.get("last_verified_upstream") or {}
        assert verified.get("ref") == TARGET_REF
        assert verified.get("sha") == TARGET_SHA

        # Recovery receipt from within update transaction.
        bid = meta2.get("last_backup_id")
        assert bid
        receipt = load_backup_receipt(root, str(meta2["id"]), str(bid))
        assert receipt and is_recovery_verified_receipt(receipt)
        assert receipt.get("verification") == VERIFICATION_RECOVERY

        report2 = collect_status(root, slug)
        assert lifecycle_op_succeeded(report2, expect=HEALTHY), report2.lifecycle

        # Identity unchanged (generic runtime / ownership facts).
        assert meta2["id"] == seeds["project_id"]
        assert meta2["fleet_id"] == seeds["fleet_id"]

        env = up.parse_dotenv((dep / ".env").read_text(encoding="utf-8"))
        for k, fp in seeds["secret_fp"].items():
            assert hashlib.sha256(env[k].encode()).hexdigest()[:16] == fp

        # Seeded-data acceptance (distinct evidence class).
        _assert_seeded_survived(root, slug, meta2, seeds)

        # Private update staging removed after success (not quarantine evidence dirs).
        for p in (root / "staging").glob("update-*"):
            if "quarantine" in p.name:
                continue
            assert not p.exists() or not any(p.iterdir())

        # Authority surface after promote: must differ from pre-update when the
        # reviewed edge changes the deployment authority bytes (compose/pin).
        live_after = upd.hash_authority_surface(dep)
        assert live_after != live_before, (
            "reviewed promote must change authority surface hash "
            f"(before={live_before[:16]} after={live_after[:16]})"
        )

        insp = _run(
            ["docker", "volume", "inspect", "--format", "{{.Name}}|{{.CreatedAt}}", sentinel_name]
        )
        assert insp.ok
        assert (insp.stdout or "").strip() == sentinel_before
    finally:
        try:
            if meta is not None:
                _cleanup_remove(root, slug)
        except Exception:  # noqa: BLE001
            pass
        _run(["docker", "volume", "rm", "-f", sentinel_name])


def test_g7_reviewed_transition_stopped_source(disposable_home: dict):
    root = disposable_home["root"]
    run_id = disposable_home["run_id"]
    id_path = disposable_home["identity"]
    slug = f"g7s{run_id[:6]}"
    sentinel_name, sentinel_before = _sentinel(run_id)
    meta = None
    try:
        meta = create_project(
            root,
            slug,
            display_name="G7S",
            start=True,
            upstream_ref=SOURCE_REF,
            upstream_sha=SOURCE_SHA,
        )
        assert lifecycle_op_succeeded(collect_status(root, slug), expect=HEALTHY)
        seeds = _seed_project(root, slug, meta)
        stop_project(root, slug)
        assert collect_status(root, slug).lifecycle == STOPPED

        code = upd.update_project(
            root,
            slug,
            to_ref=TARGET_REF,
            dry_run=False,
            yes=True,
            identity=str(id_path),
        )
        assert code == 0

        meta2 = reg.read_project(root, slug)
        assert meta2["last_verified_upstream"]["ref"] == TARGET_REF
        # Must return to STOPPED after successful verification.
        assert collect_status(root, slug).lifecycle == STOPPED

        # Briefly start to assert seeded data, then leave stopped.
        from sbfleet.projects import start_project

        start_project(root, slug, timeout=600)
        _assert_seeded_survived(root, slug, meta2, seeds)
        stop_project(root, slug)
        assert collect_status(root, slug).lifecycle == STOPPED

        insp = _run(
            ["docker", "volume", "inspect", "--format", "{{.Name}}|{{.CreatedAt}}", sentinel_name]
        )
        assert (insp.stdout or "").strip() == sentinel_before
    finally:
        try:
            if meta is not None:
                _cleanup_remove(root, slug)
        except Exception:  # noqa: BLE001
            pass
        _run(["docker", "volume", "rm", "-f", sentinel_name])


def test_g7_dry_run_non_mutating(disposable_home: dict):
    root = disposable_home["root"]
    run_id = disposable_home["run_id"]
    slug = f"g7d{run_id[:6]}"
    meta = None
    try:
        meta = create_project(
            root,
            slug,
            display_name="G7D",
            start=False,
            upstream_ref=SOURCE_REF,
            upstream_sha=SOURCE_SHA,
        )
        dep = reg.project_dir(root, slug) / "deployment"
        before = upd.hash_authority_surface(dep)
        before_meta = reg.read_project(root, slug)
        code = upd.update_project(root, slug, to_ref=TARGET_REF, dry_run=True, yes=False)
        assert code == 0
        assert upd.hash_authority_surface(dep) == before
        after_meta = reg.read_project(root, slug)
        assert after_meta.get("last_verified_upstream") == before_meta.get("last_verified_upstream")
        assert after_meta.get("upstream") == before_meta.get("upstream")
        assert after_meta.get("last_backup_id") == before_meta.get("last_backup_id")
    finally:
        try:
            if meta is not None:
                _cleanup_remove(root, slug)
        except Exception:  # noqa: BLE001
            pass
