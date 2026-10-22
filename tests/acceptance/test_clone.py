"""Real disposable evidence: primitive first, then clone orchestration."""

import time

import pytest
from tests.acceptance.test_backup_restore import (
    _psql,
    _seed_project,
    disposable_home,
)

from sbfleet import authority as auth
from sbfleet import backup as bak
from sbfleet import registry as reg
from sbfleet import upstream as up
from sbfleet.archive_safe import sha256_file
from sbfleet.backup_recovery import _copy_tree_to_volume
from sbfleet.pooler_rebind import RebindError, rebind_pooler, sql, tenant_id, verify_pooler
from sbfleet.process import run
from sbfleet.projects import create_project, start_project, stop_project

__all__ = ["disposable_home"]
pytestmark = pytest.mark.docker


def _compose(ctx, *args):
    result = run(
        ["docker", "compose", *args],
        cwd=ctx.deployment,
        env=ctx.compose_env,
        timeout=180,
        check=False,
    )
    assert result.ok, "fixture Compose operation failed"


def _install_fixture_payload(ctx, extract, archived_env):
    """Test-only restore into a fresh disposable target, not public restore bypass."""
    env = bak.reconcile_destination_env(
        archived_env=archived_env,
        destination_env=up.parse_dotenv((ctx.deployment / ".env").read_text()),
        destination_meta=ctx.meta,
    )
    (ctx.deployment / ".env").write_text(up.dump_dotenv(env))
    for rel, dest, owner in (
        ("postgres", "db/data", "100:1000"),
        ("storage", "storage", "1000:1000"),
        ("deployment/functions", "functions", None),
        ("deployment/snippets", "snippets", None),
    ):
        bak._install_unit_from_extract(
            extract / rel, ctx.deployment / "volumes" / dest, chown=owner, label=rel
        )
    _copy_tree_to_volume(
        extract / "db-config",
        f"{ctx.compose_project}_db-config",
        uid=100,
        gid=101,
        mode_file="640",
        mode_path="pgsodium_root.key",
    )
    _compose(ctx, "up", "-d", "--no-deps", "db")
    for _ in range(60):
        try:
            if sql(ctx, "SELECT 1") == "1":
                return
        except RebindError:
            pass
        time.sleep(1)
    pytest.fail("fixture restored DB failed to start")


def test_rebind_verified_disposable_destination(disposable_home):
    root = disposable_home["root"]
    source = create_project(root, "source", start=True)
    seed = _seed_project(root, "source", source)
    dep = reg.project_dir(root, "source") / "deployment"
    source_env = (dep / ".env").read_bytes()
    assert (
        bak.create_backup(
            root,
            "source",
            identity=str(disposable_home["identity"]),
            expected_sql=seed["sql"],
            expected_auth=seed["auth"],
            expected_vault=seed["vault"],
        )
        == 0
    )
    source = reg.read_project(root, "source")
    receipt = bak.require_recovery_backup(root, source)
    bid = source["last_backup_id"]
    archive = root / "backups" / source["id"] / f"{bid}.tar.age"
    staging = root / "staging" / "primitive-fixture"
    staging.mkdir(mode=0o700)
    decrypted = staging / "payload.tar"
    result = run(
        [
            bak._require_age(),
            "-d",
            "-i",
            str(disposable_home["identity"]),
            "-o",
            str(decrypted),
            str(archive),
        ],
        check=False,
    )
    assert result.ok
    manifest, env, _ = bak.prevalidate_restore_archive(
        tar_path=decrypted,
        extract_dir=staging / "extract",
        destination_project_id=source["id"],
        destination_meta=source,
        deployment=dep,
        root=root,
        ciphertext_sha256=sha256_file(archive),
        filename_backup_id=bid,
        receipt=receipt,
    )
    target = create_project(root, "target", start=True)
    stop_project(root, "target")
    with auth.authorize_mutation(root, "target", intent="restore") as ctx:
        auth.begin_operation(ctx, phase="test_recovered_destination")
        _install_fixture_payload(ctx, staging / "extract", env)
        # Each malformed state refuses atomically, before the successful transition.
        for setup, undo in (
            (
                "UPDATE _supavisor.tenants SET db_host='foreign'",
                "UPDATE _supavisor.tenants SET db_host='db'",
            ),
            (
                "UPDATE _supavisor.users SET is_manager=false",
                "UPDATE _supavisor.users SET is_manager=true",
            ),
            (
                "ALTER TABLE _supavisor.tenants RENAME COLUMN db_host TO unexpected",
                "ALTER TABLE _supavisor.tenants RENAME COLUMN unexpected TO db_host",
            ),
        ):
            sql(ctx, setup)
            with pytest.raises(RebindError):
                rebind_pooler(ctx, source_project_id=source["id"], manifest=manifest)
            assert sql(ctx, "SELECT external_id FROM _supavisor.tenants") == tenant_id(source["id"])
            sql(ctx, undo)
        sql(
            ctx,
            "INSERT INTO _supavisor.tenants SELECT (jsonb_populate_record("
            "NULL::_supavisor.tenants, to_jsonb(t) || jsonb_build_object("
            "'id', gen_random_uuid(), 'external_id', 'unexpected'))).* FROM _supavisor.tenants t",
        )
        with pytest.raises(RebindError):
            rebind_pooler(ctx, source_project_id=source["id"], manifest=manifest)
        assert sql(ctx, "SELECT count(*) FROM _supavisor.tenants") == "2"
        sql(ctx, "DELETE FROM _supavisor.tenants WHERE external_id='unexpected'")
        sql(ctx, "UPDATE _supavisor.users SET tenant_external_id=NULL")
        with pytest.raises(RebindError):
            rebind_pooler(ctx, source_project_id=source["id"], manifest=manifest)
        sql(ctx, f"UPDATE _supavisor.users SET tenant_external_id='{tenant_id(source['id'])}'")
        sql(
            ctx,
            "CREATE TABLE public.rebind_reference (tenant varchar REFERENCES "
            "_supavisor.tenants(external_id) ON DELETE CASCADE)",
        )
        with pytest.raises(RebindError):
            rebind_pooler(ctx, source_project_id=source["id"], manifest=manifest)
        sql(ctx, "DROP TABLE public.rebind_reference")
        sql(
            ctx,
            "CREATE TABLE public.rebind_tenant AS TABLE _supavisor.tenants; "
            "CREATE TABLE public.rebind_user AS TABLE _supavisor.users; "
            "DELETE FROM _supavisor.users; DELETE FROM _supavisor.tenants",
        )
        with pytest.raises(RebindError):
            rebind_pooler(ctx, source_project_id=source["id"], manifest=manifest)
        assert sql(ctx, "SELECT count(*) FROM _supavisor.tenants") == "0"
        sql(
            ctx,
            "INSERT INTO _supavisor.tenants SELECT * FROM public.rebind_tenant; "
            "INSERT INTO _supavisor.users SELECT * FROM public.rebind_user; "
            "DROP TABLE public.rebind_tenant, public.rebind_user",
        )
        before = sql(ctx, "SELECT md5(db_pass_encrypted) FROM _supavisor.users")
        evidence = rebind_pooler(ctx, source_project_id=source["id"], manifest=manifest)
        assert evidence["destination_tenant"] == tenant_id(target["id"])
        assert sql(ctx, "SELECT md5(db_pass_encrypted) FROM _supavisor.users") == before
        with pytest.raises(RebindError):
            rebind_pooler(ctx, source_project_id=source["id"], manifest=manifest)
        reconciled = up.parse_dotenv((ctx.deployment / ".env").read_text())
        reconciled["POOLER_TENANT_ID"] = tenant_id(target["id"])
        (ctx.deployment / ".env").write_text(up.dump_dotenv(reconciled))
        start_project(root, "target", already_locked=True, manage_journal=False)
        verify_pooler(ctx, source_project_id=source["id"])
        assert sql(ctx, seed["sql"]["query"], database="postgres") == seed["sql"]["expect"]
        assert (
            sql(ctx, seed["vault"]["sql_decrypt"], database="postgres") == seed["vault"]["expect"]
        )
        stop_project(root, "target", already_locked=True, manage_journal=False)
        auth.complete_operation(ctx, phase="completed")
    assert (dep / ".env").read_bytes() == source_env
    assert _psql(
        dep, source["compose_project"], "SELECT external_id FROM _supavisor.tenants", db="_supabase"
    ) == tenant_id(source["id"])
    with auth.authorize_mutation(root, "source", intent="backup") as ctx:
        verify_pooler(ctx, source_project_id=target["id"])
    bak._wipe_staging(staging)


@pytest.mark.parametrize("fail_verification", [False, True])
def test_verified_clone_cli(disposable_home, capsys, monkeypatch, fail_verification):
    import asyncio
    import hashlib
    import json

    from tests.acceptance.test_backup_restore import _run, _sentinel

    from sbfleet import clone
    from sbfleet.cli import main
    from sbfleet.connection import connection_info
    from sbfleet.dashboard import render
    from sbfleet.fleet import collect_snapshot
    from sbfleet.health import collect_status
    from sbfleet.mcp_server import create_server

    root = disposable_home["root"]
    source = create_project(root, "source", start=True)
    seed = _seed_project(root, "source", source)
    dep = reg.project_dir(root, "source") / "deployment"
    env_before = (dep / ".env").read_bytes()
    source_env = up.parse_dotenv(env_before.decode())
    sentinel, sentinel_before = _sentinel(disposable_home["run_id"])
    if fail_verification:

        def fail(*args, **kwargs):
            raise RuntimeError(source_env["POSTGRES_PASSWORD"])

        monkeypatch.setattr(clone, "_verify_recovered", fail)
    try:
        capsys.readouterr()
        code = main(
            [
                "--home",
                str(root),
                "clone",
                "source",
                "target",
                "--identity",
                str(disposable_home["identity"]),
                "--json",
            ]
        )
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["schema_version"] == "sbfleet.clone.v1"
        assert source_env["POSTGRES_PASSWORD"] not in captured.out + captured.err
        assert source_env["JWT_SECRET"] not in captured.out + captured.err
        assert str(disposable_home["identity"]) not in captured.out
        assert (dep / ".env").read_bytes() == env_before
        after = reg.read_project(root, "source")
        for key in ("id", "fleet_id", "compose_project", "ports", "upstream", "public_url"):
            assert after[key] == source[key]
        assert _psql(dep, source["compose_project"], seed["sql"]["query"]) == seed["sql"]["expect"]
        assert collect_status(root, "source").lifecycle == "HEALTHY"
        assert (
            _run(
                ["docker", "volume", "inspect", "--format", "{{.Name}}|{{.CreatedAt}}", sentinel]
            ).stdout.strip()
            == sentinel_before
        )
        if fail_verification:
            assert code != 0 and not result["success"]
            assert result["attention"] == ["destination_verify_failed"]
            assert result["final_state"] == "REMOVED", result
            assert not reg.project_dir(root, "target").exists()
            return
        assert code == 0 and result["success"], result
        target = reg.read_project(root, "target")
        assert target["id"] != source["id"]
        assert target["compose_project"] != source["compose_project"]
        assert set(target["ports"].values()).isdisjoint(source["ports"].values())
        assert collect_status(root, "target").lifecycle == "STOPPED"
        assert result["final_state"] == "STOPPED" and result["verification"] == "VERIFIED"
        snapshot = collect_snapshot(root)
        assert next(p for p in snapshot.projects if p.slug == "target").state == "STOPPED"
        assert "target" in render(snapshot)
        assert "target" in str(asyncio.run(create_server(root).call_tool("list_projects", {})))
        info = connection_info(root, "target")
        assert info["pooler_username_pattern"] == f"<role>.{tenant_id(target['id'])}"
        assert info["pooler_transaction_port"] == str(target["ports"]["pooler_transaction"])
        start_project(root, "target")
        with auth.authorize_mutation(root, "target", intent="backup") as ctx:
            verify_pooler(ctx, source_project_id=source["id"])
            assert sql(ctx, seed["sql"]["query"], database="postgres") == seed["sql"]["expect"]
            assert (
                sql(ctx, seed["vault"]["sql_decrypt"], database="postgres")
                == seed["vault"]["expect"]
            )
            assert sql(ctx, "SELECT count(*) FROM auth.users", database="postgres") == "1"
            # Exercise the exact host-facing connection output, not only the bridge alias.
            target_env = up.parse_dotenv((ctx.deployment / ".env").read_text())
            db_image = run(
                ["docker", "compose", "images", "-q", "db"],
                cwd=ctx.deployment,
                env=ctx.compose_env,
                timeout=30,
                check=False,
            )
            assert db_image.ok and len(db_image.stdout.splitlines()) == 1
            for port_key in ("pooler_session_port", "pooler_transaction_port"):
                probe = run(
                    [
                        "docker",
                        "run",
                        "--rm",
                        "--network",
                        "host",
                        "-e",
                        "PGPASSWORD",
                        "-e",
                        "PGCONNECT_TIMEOUT=5",
                        db_image.stdout.strip(),
                        "psql",
                        "-X",
                        "-h",
                        info["db_host"],
                        "-p",
                        info[port_key],
                        "-U",
                        f"postgres.{tenant_id(target['id'])}",
                        "-d",
                        info["db_name"],
                        "-qAtc",
                        "SELECT 1",
                    ],
                    env={**ctx.compose_env, "PGPASSWORD": target_env["POSTGRES_PASSWORD"]},
                    timeout=30,
                    check=False,
                )
                assert probe.ok and probe.stdout.strip() == "1", "host pooler connection failed"
            obj = ctx.deployment / "volumes" / "storage" / seed["storage_rel"]
            assert hashlib.sha256(obj.read_bytes()).hexdigest() == seed["storage_sha"]
        with auth.authorize_mutation(root, "source", intent="backup") as ctx:
            verify_pooler(ctx, source_project_id=target["id"])
        stop_project(root, "target")
        target_env = up.parse_dotenv(
            (reg.project_dir(root, "target") / "deployment" / ".env").read_text()
        )
        assert target_env["DASHBOARD_PASSWORD"] != source_env["DASHBOARD_PASSWORD"]
        assert target_env["POOLER_TENANT_ID"] == tenant_id(target["id"])
    finally:
        _run(["docker", "volume", "rm", sentinel])
