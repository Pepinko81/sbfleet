"""Exact-pin pooler identity transition for a verified, private clone destination.

This is not a restore mode or public SQL execution interface. Caller holds the
new destination's mutation authority; only its DB may be running during rebinding.
"""

from __future__ import annotations

import json
import uuid
from importlib.resources import files

from sbfleet import authority as auth
from sbfleet import upstream as up
from sbfleet.process import run

SUPPORTED_PIN = {"ref": "self-hosted/v0.8.2", "sha": "564eab8ad7840b13324f68b1bfac074ef8d51c21"}


class RebindError(Exception):
    """Safe diagnostic: never carries database responses or credentials."""


def tenant_id(project_id: str) -> str:
    return uuid.UUID(project_id).hex


def sql(ctx: auth.MutationContext, statement: str, *, database: str = "_supabase") -> str:
    result = run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "db",
            "psql",
            "-X",
            "-U",
            "supabase_admin",
            "-d",
            database,
            "-v",
            "ON_ERROR_STOP=1",
            "-qAt",
        ],
        cwd=ctx.deployment,
        env=ctx.compose_env,
        input_data=statement,
        timeout=60,
        check=False,
    )
    if not result.ok:
        raise RebindError("pooler database operation refused or unavailable")
    return (result.stdout or "").strip()


# Stable catalog facts, not OIDs or a guessed Supavisor schema.
CATALOG_SQL = """
SELECT jsonb_build_object(
 'columns',(SELECT jsonb_agg(to_jsonb(x) ORDER BY table_name,ordinal_position) FROM (SELECT
table_name,column_name,ordinal_position,data_type,udt_name,is_nullable,column_default FROM
information_schema.columns WHERE table_schema='_supavisor') x),
 'relations',(SELECT
jsonb_agg(jsonb_build_array(c.relname,c.relkind,c.relrowsecurity,c.relforcerowsecurity) ORDER BY
c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE
n.nspname='_supavisor' AND c.relkind NOT IN ('i','I')),
 'constraints',(SELECT
jsonb_agg(jsonb_build_array(c.relname,k.conname,pg_get_constraintdef(k.oid)) ORDER BY
c.relname,k.conname) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace
n ON n.oid=c.relnamespace WHERE n.nspname='_supavisor'),
 'indexes',(SELECT jsonb_agg(jsonb_build_array(tablename,indexname,indexdef) ORDER BY
tablename,indexname) FROM pg_indexes WHERE schemaname='_supavisor'),
 'triggers',(SELECT coalesce(jsonb_agg(pg_get_triggerdef(t.oid) ORDER BY t.tgname),'[]'::jsonb)
FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='_supavisor' AND NOT t.tgisinternal),
 'incoming',(SELECT coalesce(jsonb_agg(jsonb_build_array(n.nspname,c.relname,k.conname,
 pg_get_constraintdef(k.oid)) ORDER BY n.nspname,c.relname,k.conname),'[]'::jsonb)
 FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid
 JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_class referenced ON referenced.oid=k.confrelid
 JOIN pg_namespace rn ON rn.oid=referenced.relnamespace
 WHERE rn.nspname='_supavisor' AND n.nspname<>'_supavisor'),
 'rules',(SELECT coalesce(jsonb_agg(definition ORDER BY rulename),'[]'::jsonb)
 FROM pg_rules WHERE schemaname='_supavisor'),
 'migrations',(SELECT jsonb_agg(version ORDER BY version) FROM _supavisor.schema_migrations)
)
"""


def rebind_pooler(ctx: auth.MutationContext, *, source_project_id: str, manifest: dict) -> dict:
    """Rebind once, or refuse atomically. Never silently accept repeat/partial state.

    The original source manifest is retained unchanged. Receipt verification and
    payload installation are the caller's responsibility. UUID equality remains
    mandatory for ordinary restore; this primitive cannot invoke restore.
    """
    source = tenant_id(source_project_id)
    target = tenant_id(ctx.project_id)
    if source == target or manifest.get("project_id") != source_project_id:
        raise RebindError("distinct source and destination identity required")
    if manifest.get("upstream") != SUPPORTED_PIN or ctx.meta.get("upstream") != SUPPORTED_PIN:
        raise RebindError("pooler rebinding supports only the exact reviewed pin")
    auth.revalidate_deployment_authority(ctx)
    from sbfleet.health import inspect_containers_result

    live = inspect_containers_result(ctx.deployment, ctx.compose_project)
    if not live.ok or set(live.containers) != {"db"}:
        raise RebindError("rebinding requires an isolated destination with only DB running")
    inventory = auth.invent_owned_resources(
        compose_project=ctx.compose_project,
        fleet_id=ctx.fleet_id,
        project_id=ctx.project_id,
        deployment=ctx.deployment,
        contract=ctx.contract,
    )
    if inventory.residuals:
        raise RebindError("destination live resource authority unknown")
    contract = json.loads(files("sbfleet").joinpath("pooler.schema.json").read_text())
    expected = json.dumps(contract).replace("'", "''")
    tenant_columns = [c["column_name"] for c in contract["columns"] if c["table_name"] == "tenants"]
    projection = ",".join(
        f"'{uuid.uuid4()}'::uuid"
        if c == "id"
        else f"'{target}'"
        if c == "external_id"
        else f'"{c}"'
        for c in tenant_columns
    )
    columns = ",".join(f'"{c}"' for c in tenant_columns)
    statement = f"""
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
SET LOCAL search_path = pg_catalog;
LOCK TABLE _supavisor.tenants, _supavisor.users, _supavisor.clusters,
 _supavisor.cluster_tenants, _supavisor.schema_migrations IN ACCESS EXCLUSIVE MODE;
DO $rebind$
DECLARE old_credential bytea;
BEGIN
 IF ({CATALOG_SQL}) IS DISTINCT FROM '{expected}'::jsonb THEN
  RAISE EXCEPTION 'unsupported pooler catalog';
 END IF;
 IF (SELECT count(*) FROM _supavisor.tenants) <> 1
 OR (SELECT count(*) FROM _supavisor.users) <> 1
 OR EXISTS (SELECT 1 FROM _supavisor.clusters)
 OR EXISTS (SELECT 1 FROM _supavisor.cluster_tenants) THEN
  RAISE EXCEPTION 'ambiguous pooler state';
 END IF;
 IF NOT EXISTS (SELECT 1 FROM _supavisor.tenants WHERE external_id='{source}'
  AND db_host='db' AND db_port=5432 AND db_database='postgres'
  AND require_user=false AND auth_query='SELECT * FROM pgbouncer.get_auth($1)'
  AND upstream_ssl=false AND upstream_verify IS NULL AND upstream_tls_ca IS NULL
  AND enforce_ssl=false AND sni_hostname IS NULL AND ip_version='auto'
  AND default_pool_size=20 AND default_max_clients=100 AND client_idle_timeout=0
  AND default_pool_strategy='fifo' AND client_heartbeat_interval=60
  AND allow_list=ARRAY['0.0.0.0/0','::/0']::varchar[] AND availability_zone IS NULL
  AND use_jit=false AND jit_api_url IS NULL AND feature_flags='{{}}'::jsonb
  AND banned_at IS NULL AND banned_until IS NULL AND ban_reason IS NULL
  AND default_parameter_status='{{"server_version":"17.6"}}'::jsonb) THEN
  RAISE EXCEPTION 'unsupported tenant configuration or repeated application';
 END IF;
 IF NOT EXISTS (SELECT 1 FROM _supavisor.users WHERE tenant_external_id='{source}'
  AND db_user='pgbouncer' AND db_user_alias='pgbouncer' AND is_manager=true
  AND mode_type='transaction' AND pool_size=20 AND pool_checkout_timeout=60000
  AND max_clients IS NULL AND octet_length(db_pass_encrypted)>16) THEN
  RAISE EXCEPTION 'unsupported manager credential state';
 END IF;
 SELECT db_pass_encrypted INTO STRICT old_credential FROM _supavisor.users;
 INSERT INTO _supavisor.tenants ({columns})
 SELECT {projection} FROM _supavisor.tenants WHERE external_id='{source}';
 UPDATE _supavisor.users SET tenant_external_id='{target}', id='{uuid.uuid4()}'::uuid
 WHERE tenant_external_id='{source}';
 DELETE FROM _supavisor.tenants WHERE external_id='{source}';
 IF (SELECT count(*) FROM _supavisor.tenants WHERE external_id='{target}')<>1
 OR (SELECT count(*) FROM _supavisor.users WHERE tenant_external_id='{target}'
     AND db_pass_encrypted=old_credential)<>1
 OR EXISTS (SELECT 1 FROM _supavisor.tenants WHERE external_id='{source}') THEN
  RAISE EXCEPTION 'rebind postcondition failed';
 END IF;
END $rebind$;
COMMIT;
SELECT 'rebound';
"""
    if sql(ctx, statement) != "rebound":
        raise RebindError("pooler rebind acknowledgement missing")
    return {
        "source_tenant_removed": True,
        "destination_tenant": target,
        "credential_preserved": True,
    }


def verify_pooler(ctx: auth.MutationContext, *, source_project_id: str) -> None:
    """Real TCP checks through both pooler modes; old tenant must not authenticate."""
    source, target = tenant_id(source_project_id), tenant_id(ctx.project_id)
    env = up.parse_dotenv((ctx.deployment / ".env").read_text())
    if env.get("POOLER_TENANT_ID") != target:
        raise RebindError("destination environment tenant mismatch")
    if sql(ctx, "SELECT external_id FROM _supavisor.tenants") != target:
        raise RebindError("destination database tenant mismatch")
    for port in (5432, 6543):
        for tenant in (target, source):
            result = run(
                [
                    "docker",
                    "compose",
                    "exec",
                    "-T",
                    "-e",
                    "PGPASSWORD",
                    "db",
                    "psql",
                    "-X",
                    "-h",
                    "supavisor",
                    "-p",
                    str(port),
                    "-U",
                    f"postgres.{tenant}",
                    "-d",
                    "postgres",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-qAtc",
                    "SELECT 1",
                ],
                cwd=ctx.deployment,
                env={
                    **ctx.compose_env,
                    "PGPASSWORD": env["POSTGRES_PASSWORD"],
                    "PGCONNECT_TIMEOUT": "5",
                },
                timeout=20,
                check=False,
            )
            if tenant == target:
                if not result.ok or (result.stdout or "").strip() != "1":
                    raise RebindError("destination pooler connection verification failed")
            elif result.ok:
                raise RebindError("source tenant unexpectedly accepted by destination pooler")
