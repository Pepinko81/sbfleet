"""Canonical read-only schema snapshots, diffs and preview classifications.

SOURCE is desired; TARGET is current. No caller-supplied SQL, lifecycle dispatch,
registry writes, lock files, persisted cache or automatic migration execution.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal

from pydantic import Field, JsonValue

from sbfleet import authority as auth
from sbfleet import compose, upstream
from sbfleet import registry as reg
from sbfleet.fleet import Model
from sbfleet.pooler_rebind import SUPPORTED_PIN
from sbfleet.process import project_diagnostic_redactor, run, sanitize_configured_diagnostic
from sbfleet.schema_catalog import READ_SQL

Kind = Literal[
    "SCHEMA",
    "TABLE",
    "COLUMN",
    "CONSTRAINT",
    "INDEX",
    "FUNCTION",
    "RLS",
    "POLICY",
    "VIEW",
    "MATERIALIZED_VIEW",
    "ENUM",
    "SEQUENCE",
    "TRIGGER",
    "EXTENSION",
    "UNSUPPORTED",
]
Classification = Literal["APPLICATION", "SUPABASE_MANAGED", "SYSTEM", "IGNORED"]
Risk = Literal["SAFE", "REVIEW_REQUIRED", "DESTRUCTIVE", "UNSUPPORTED"]
SAFE_COLUMN_TYPES = frozenset(
    {
        "bool",
        "int2",
        "int4",
        "int8",
        "float4",
        "float8",
        "numeric",
        "text",
        "varchar",
        "bpchar",
        "bytea",
        "date",
        "time",
        "timetz",
        "timestamp",
        "timestamptz",
        "interval",
        "uuid",
        "json",
        "jsonb",
        "inet",
        "cidr",
        "macaddr",
        "macaddr8",
        "bit",
        "varbit",
        "oid",
        "xml",
        "tsvector",
        "tsquery",
    }
)
MANAGED = frozenset(
    {
        "auth",
        "storage",
        "_realtime",
        "realtime",
        "supabase_functions",
        "pgbouncer",
        "vault",
        "net",
        "graphql",
        "graphql_public",
        "extensions",
        "_supavisor",
    }
)
LIMITATIONS = [
    "Expressions, defaults, enum labels and function/view/trigger definitions are SHA-256 "
    "fingerprints, not displayed SQL; equality is textual, not semantic.",
    "Owners, ACLs/grants, comments, security labels, publications/subscriptions, event triggers, "
    "collations, foreign servers, operator classes and database/role settings are not compared.",
    "Extension-owned objects are ignored; extension versions are inventory only and unsupported "
    "for planning. Custom types, aggregates, rewrite rules and partition/inheritance semantics "
    "are unsupported or partial.",
    "Snapshots are individually consistent, not an atomic snapshot across two databases. "
    "Data, sequence current values and external dependencies are not compared.",
]


class SchemaObject(Model):
    kind: Kind
    key: list[str]
    facts: dict[str, JsonValue]
    classification: Classification = "APPLICATION"


class Namespace(Model):
    name: str
    classification: Classification


class SchemaSnapshot(Model):
    schema_model_version: Literal["sbfleet-schema-v1"] = "sbfleet-schema-v1"
    project: str
    pin: dict[str, str] = Field(default_factory=dict)
    state: Literal["KNOWN", "UNKNOWN"] = "UNKNOWN"
    error: str | None = None
    namespaces: list[Namespace] = Field(default_factory=list)
    objects: list[SchemaObject] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=lambda: list(LIMITATIONS))


class Difference(Model):
    kind: Kind
    key: list[str]
    change: Literal["ADDED", "REMOVED", "CHANGED", "UNSUPPORTED"]
    classification: Classification
    before: dict[str, JsonValue] | None = None
    after: dict[str, JsonValue] | None = None
    changed_fields: list[str] = Field(default_factory=list)


class SchemaDiff(Model):
    schema_version: Literal["sbfleet.schema-diff.v1"] = "sbfleet.schema-diff.v1"
    schema_model_version: Literal["sbfleet-schema-v1"] = "sbfleet-schema-v1"
    source: str
    target: str
    direction: Literal["TARGET_TO_SOURCE"] = "TARGET_TO_SOURCE"
    source_pin: dict[str, str] = Field(default_factory=dict)
    target_pin: dict[str, str] = Field(default_factory=dict)
    pin_mismatch: bool = False
    state: Literal["KNOWN", "UNKNOWN"] = "UNKNOWN"
    error: str | None = None
    summary: dict[str, int] = Field(default_factory=dict)
    differences: list[Difference] = Field(default_factory=list)
    unsupported_objects: list[SchemaObject] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=lambda: list(LIMITATIONS))


class PlanItem(Model):
    difference: Difference
    classification: Risk
    reason: str


class MigrationPlan(Model):
    schema_version: Literal["sbfleet.migration-plan.v1"] = "sbfleet.migration-plan.v1"
    schema_model_version: Literal["sbfleet-schema-v1"] = "sbfleet-schema-v1"
    preview_only: Literal[True] = True
    sql_preview: Literal[False] = False
    diff: SchemaDiff
    items: list[PlanItem] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)


def namespace_class(name: str) -> Classification:
    if name.startswith("pg_") or name == "information_schema":
        return "SYSTEM"
    return "SUPABASE_MANAGED" if name in MANAGED else "APPLICATION"


def normalize(raw: dict, project: str, pin: dict) -> SchemaSnapshot:
    if raw["server_major"] != 17:
        raise ValueError("unsupported server")
    objects = [SchemaObject.model_validate(row) for row in raw["objects"]]
    seen = set()
    for obj in objects:
        if not obj.key or (obj.kind, tuple(obj.key)) in seen:
            raise ValueError("ambiguous identity")
        seen.add((obj.kind, tuple(obj.key)))
        obj.facts = json.loads(json.dumps(obj.facts, sort_keys=True))
        obj.classification = "IGNORED" if obj.kind == "EXTENSION" else namespace_class(obj.key[0])
    return SchemaSnapshot(
        project=project,
        pin=pin,
        state="KNOWN",
        objects=sorted(objects, key=lambda o: (o.kind, o.key)),
        namespaces=[
            Namespace(name=n, classification=namespace_class(n))
            for n in sorted(set(raw["namespaces"]))
        ],
    )


def _read_catalog(root: Path, slug: str, meta: dict) -> dict:
    """Prove ownership read-only, then address the exact proven DB container ID."""
    deployment = auth._validate_project_paths(root, slug, meta)
    cp = meta["compose_project"]
    auth._verify_env_selectors(deployment, cp)
    # Existing Compose helper creates .compose-home. This observation path must
    # not create directories, so resolve in memory with a deliberately absent HOME.
    env = upstream.parse_dotenv((deployment / ".env").read_text())
    interpolation = {
        key: value
        for key, value in env.items()
        if key
        in {
            "POSTGRES_PORT",
            "POOLER_PROXY_PORT_TRANSACTION",
            "API_GW_HTTP_PORT",
            "KONG_HTTP_PORT",
            "JWT_SECRET",
            "ANON_KEY",
            "SERVICE_ROLE_KEY",
            "JWT_KEYS",
            "JWT_JWKS",
            "POSTGRES_PASSWORD",
            "DASHBOARD_USERNAME",
            "DASHBOARD_PASSWORD",
            "SECRET_KEY_BASE",
            "VAULT_ENC_KEY",
            "SUPABASE_PUBLIC_URL",
            "API_EXTERNAL_URL",
            "SITE_URL",
            "ADDITIONAL_REDIRECT_URLS",
            "STUDIO_DEFAULT_ORGANIZATION",
            "STUDIO_DEFAULT_PROJECT",
            "GOOGLE_ENABLED",
            "GOOGLE_CLIENT_ID",
            "GOOGLE_SECRET",
            "POOLER_TENANT_ID",
            "POSTGRES_DB",
            "POSTGRES_HOST",
        }
        or key.endswith("_IMAGE")
        or key.endswith("_VERSION")
        or "IMAGE" in key
    }

    def config(directory: Path, files: str) -> dict:
        result = run(
            ["docker", "compose", "config", "--format", "json"],
            cwd=directory,
            env={
                **interpolation,
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": "/nonexistent",
                "COMPOSE_PROJECT_NAME": cp,
                "COMPOSE_FILE": files,
                "COMPOSE_PATH_SEPARATOR": ":",
            },
            timeout=20,
            check=False,
        )
        if not result.ok:
            raise ValueError("compose unavailable")
        return json.loads(result.stdout)

    vendor = upstream.cache_dir(root, meta["upstream"]["sha"]) / "docker"
    contract = compose.build_approved_standard_profile_contract(
        config(vendor, "docker-compose.yml"),
        vendor_docker_root=vendor,
        deployment=deployment,
        compose_project=cp,
        fleet_id=meta["fleet_id"],
        project_id=meta["id"],
    )
    ports = meta["ports"]
    compose.assert_effective_matches_contract(
        config(deployment, auth.COMPOSE_FILE_VALUE),
        contract,
        gateway_port=ports["gateway"],
        db_direct_port=ports["db_direct"],
        pooler_session_port=ports["pooler_session"],
        pooler_transaction_port=ports["pooler_transaction"],
        deployment=deployment,
    )
    inventory = auth.invent_owned_resources(
        compose_project=cp,
        fleet_id=meta["fleet_id"],
        project_id=meta["id"],
        deployment=deployment,
        contract=contract,
    )
    if inventory.residuals:
        raise ValueError("unknown ownership")
    databases = [
        c for c in inventory.containers if c.name == contract.services["db"].container_name
    ]
    if len(databases) != 1:
        raise ValueError("database unavailable")
    result = run(
        [
            "docker",
            "exec",
            "-i",
            "-e",
            "PGOPTIONS=-c default_transaction_read_only=on -c search_path=pg_catalog",
            databases[0].resource_id,
            "psql",
            "-X",
            "-U",
            "supabase_admin",
            "-d",
            "postgres",
            "-v",
            "ON_ERROR_STOP=1",
            "-qAt",
        ],
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"},
        input_data=READ_SQL,
        timeout=25,
        check=False,
    )
    if not result.ok or len(result.stdout or "") > 8_000_000:
        raise ValueError("catalog unavailable")
    redactor = project_diagnostic_redactor(deployment)
    # Even identifiers can contain a configured secret. Refuse rather than
    # redacting identities into collisions or returning secret-bearing facts.
    safe = sanitize_configured_diagnostic(result.stdout, redactor=redactor, max_len=8_000_001)
    if safe != result.stdout:
        raise ValueError("secret-bearing catalog")
    return json.loads(result.stdout)


def collect_schema(root: Path, slug: str) -> SchemaSnapshot:
    snapshot = SchemaSnapshot(project=slug)
    try:
        reg.validate_slug(slug)
        reg.assert_managed_entry(root, under=root, expect_dir=True)
        reg.assert_managed_entry(root / "projects", under=root, expect_dir=True)
        path = reg.project_dir(root, slug)
        if not path.exists() and not path.is_symlink():
            snapshot.error = "NOT_FOUND"
            return snapshot
        meta = reg.validate_project_identity(root, reg.read_project(root, slug))
        if meta["upstream"] != SUPPORTED_PIN:
            snapshot.error = "UNSUPPORTED_PIN"
            return snapshot
        snapshot.pin = dict(SUPPORTED_PIN)
        if reg.journal_is_unresolved(reg.read_operation_journal(root, slug)):
            snapshot.error = "PROJECT_BUSY"
            return snapshot
        raw = _read_catalog(root, slug, meta)
        if reg.read_project(root, slug) != meta:
            raise ValueError("changed during observation")
        return normalize(raw, slug, snapshot.pin)
    except Exception:
        snapshot.error = "SCHEMA_OBSERVATION_FAILED"
        return snapshot


def unsupported(obj: SchemaObject) -> bool:
    return (
        obj.kind in {"EXTENSION", "UNSUPPORTED"}
        or (obj.kind == "FUNCTION" and obj.facts.get("kind") not in {"f", "p"})
        or (obj.kind == "TABLE" and bool(obj.facts.get("partitioned") or obj.facts.get("inherits")))
    )


def compare(source: SchemaSnapshot, target: SchemaSnapshot) -> SchemaDiff:
    result = SchemaDiff(
        source=source.project,
        target=target.project,
        source_pin=source.pin,
        target_pin=target.pin,
        pin_mismatch=source.pin != target.pin,
    )
    if source.state != "KNOWN" or target.state != "KNOWN":
        result.error = source.error or target.error or "SCHEMA_OBSERVATION_FAILED"
        return result
    if result.pin_mismatch or source.pin != SUPPORTED_PIN:
        result.error = "UNSUPPORTED_PIN"
        return result
    result.state = "KNOWN"
    desired = {(o.kind, tuple(o.key)): o for o in source.objects}
    current = {(o.kind, tuple(o.key)): o for o in target.objects}
    unsupported_tables = {
        tuple(o.key)
        for o in source.objects + target.objects
        if o.kind == "TABLE" and unsupported(o)
    }
    for key in sorted(desired.keys() | current.keys()):
        new, old = desired.get(key), current.get(key)
        obj = new or old
        assert obj is not None
        is_unsupported = any(unsupported(o) for o in (new, old) if o is not None) or (
            obj.kind in {"COLUMN", "CONSTRAINT", "INDEX", "RLS", "POLICY", "TRIGGER"}
            and tuple(obj.key[:2]) in unsupported_tables
        )
        if is_unsupported:
            result.unsupported_objects.append(obj)
        if new is not None and old is not None and new.facts == old.facts:
            continue
        before, after = old.facts if old else None, new.facts if new else None
        result.differences.append(
            Difference(
                kind=obj.kind,
                key=obj.key,
                classification=obj.classification,
                change=(
                    "UNSUPPORTED"
                    if is_unsupported
                    else "ADDED"
                    if old is None
                    else "REMOVED"
                    if new is None
                    else "CHANGED"
                ),
                before=before,
                after=after,
                changed_fields=sorted(
                    k
                    for k in (before or {}).keys() | (after or {}).keys()
                    if (before or {}).get(k) != (after or {}).get(k)
                ),
            )
        )
    result.summary = {
        c: sum(d.change == c for d in result.differences)
        for c in ("ADDED", "REMOVED", "CHANGED", "UNSUPPORTED")
    }
    return result


def schema_diff(root: Path, source: str, target: str) -> SchemaDiff:
    first = collect_schema(root, source)
    second = first if source == target else collect_schema(root, target)
    return compare(first, second)


def classify(d: Difference) -> tuple[Risk, str]:
    if d.change == "UNSUPPORTED":
        return "UNSUPPORTED", "Object semantics are outside the supported planning contract."
    if d.change == "REMOVED":
        if d.kind in {"SCHEMA", "TABLE", "COLUMN", "ENUM", "SEQUENCE", "MATERIALIZED_VIEW"}:
            return "DESTRUCTIVE", "Removal can discard stored data or dependent objects."
        return "REVIEW_REQUIRED", "Removal changes behavior, enforcement or dependencies."
    if d.kind == "COLUMN" and d.change == "CHANGED":
        if {"data_type", "type_schema", "type_name"} & set(d.changed_fields):
            return "DESTRUCTIVE", "Type conversion may lose data; widening is not assumed safe."
        return "REVIEW_REQUIRED", "Column constraints, defaults or identity semantics change."
    if d.classification != "APPLICATION":
        return "REVIEW_REQUIRED", "Supabase-managed objects require platform-specific review."
    if d.change == "ADDED":
        if d.kind in {"SCHEMA", "TABLE"}:
            return "SAFE", "Additive object only; dependent plan items must be reviewed separately."
        if d.kind == "COLUMN" and d.after:
            if (
                d.after.get("ordinary_table") is True
                and d.after.get("nullable") is True
                and d.after.get("type_schema") == "pg_catalog"
                and d.after.get("type_name") in SAFE_COLUMN_TYPES
                and d.after.get("default_hash") is None
                and not d.after.get("identity")
                and not d.after.get("generated")
            ):
                return "SAFE", "Nullable built-in scalar column without default or generation."
        if d.kind == "RLS" and d.after == {"enabled": False, "forced": False}:
            return "SAFE", "Records the default disabled RLS state of a new table."
    return "REVIEW_REQUIRED", "Review data, dependencies, locking and security behavior before DDL."


def plan_from_diff(diff: SchemaDiff) -> MigrationPlan:
    plan = MigrationPlan(diff=diff)
    if diff.state == "KNOWN":
        for d in diff.differences:
            risk, reason = classify(d)
            plan.items.append(PlanItem(difference=d, classification=risk, reason=reason))
    plan.summary = {
        r: sum(i.classification == r for i in plan.items)
        for r in ("SAFE", "REVIEW_REQUIRED", "DESTRUCTIVE", "UNSUPPORTED")
    }
    return plan


def migration_plan(root: Path, source: str, target: str) -> MigrationPlan:
    return plan_from_diff(schema_diff(root, source, target))


def render(diff: SchemaDiff, plan: MigrationPlan | None = None) -> str:
    title = "Migration plan (preview only; no SQL execution)" if plan else "Schema diff"
    lines = [f"{title}: {diff.target} -> {diff.source} (SOURCE is desired)"]
    if diff.error:
        return "\n".join(lines + [f"UNKNOWN: {diff.error}"])
    if plan:
        for item in plan.items:
            d = item.difference
            lines.append(
                f"{item.classification}: {d.change} {d.kind} {json.dumps(d.key)} — {item.reason}"
            )
    else:
        for d in diff.differences:
            fields = f" ({', '.join(d.changed_fields)})" if d.changed_fields else ""
            lines.append(f"{d.change} {d.kind} {json.dumps(d.key)}{fields}")
    if not diff.differences:
        lines.append("No material differences in the supported model.")
    lines.append(f"Unsupported inventory: {len(diff.unsupported_objects)} object(s).")
    lines.extend(f"PARTIAL: {limit}" for limit in diff.limitations)
    return "\n".join(lines)


def schema_cmd(root: Path, source: str, target: str, *, plan: bool, as_json: bool) -> int:
    diff = schema_diff(root, source, target)
    result = plan_from_diff(diff) if plan else diff
    print(
        json.dumps(result.model_dump(), sort_keys=True, ensure_ascii=True)
        if as_json
        else render(diff, result if plan else None)
    )
    return 0 if diff.state == "KNOWN" else 5
