"""Disposable recovery verification environment .

Uses a minimal isolated DB-centric environment and returns
``RecoveryVerificationResult`` — never project lifecycle HEALTHY when mandatory
standard-stack services are intentionally absent.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sbfleet.archive_safe import iter_file_digests, sha256_file
from sbfleet.backup_manifest import (
    PROFILE_OWNERSHIP,
    REQUIRED_AUTH_RELATIONS,
    REQUIRED_RECOVERY_ASSERTIONS,
    REQUIRED_RECOVERY_DATABASES,
    REQUIRED_RECOVERY_ROLES,
    VERIFIER_CONTRACT_VERSION,
    ManifestError,
    require_db_recovery_facts,
    utc_now,
)
from sbfleet.process import run

HELPER_IMAGE = "alpine:3.20"
SOURCE_CRYPTO_NAME_PREFIX = "sbfleet.rv."


@dataclass
class RecoveryAssertion:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class RecoveryVerificationResult:
    """Finite recovery-verifier outcome — not project lifecycle HEALTHY."""

    ok: bool
    verifier_id: str
    operation_id: str
    assertions: list[RecoveryAssertion] = field(default_factory=list)
    fixture_identity: str = ""
    outcome_version: str = VERIFIER_CONTRACT_VERSION
    error: str | None = None
    resources: dict[str, Any] = field(default_factory=dict)
    source_pin: dict[str, Any] = field(default_factory=dict)
    source_crypto: dict[str, Any] | None = None
    manifest_sha256: str | None = None
    project_id: str | None = None
    backup_id: str | None = None
    verified_at: str | None = None

    def as_receipt_evidence(self) -> dict[str, Any]:
        # Never include challenge plaintext — only nonsecret verification metadata.
        crypto_meta = None
        if isinstance(self.source_crypto, dict):
            crypto_meta = {
                k: self.source_crypto[k]
                for k in ("name", "salt_hex", "digest_sha256", "encoding")
                if k in self.source_crypto
            }
        return {
            "outcome_version": self.outcome_version,
            "verifier_contract": self.outcome_version,
            "verifier_id": self.verifier_id,
            "operation_id": self.operation_id,
            "fixture_identity": self.fixture_identity,
            "ok": self.ok,
            "assertions": [
                {"name": a.name, "ok": a.ok, "detail": a.detail[:200]} for a in self.assertions
            ],
            "required_assertions": sorted(REQUIRED_RECOVERY_ASSERTIONS),
            "source_pin": self.source_pin or {},
            "source_crypto": crypto_meta,
            "manifest_sha256": self.manifest_sha256,
            "project_id": self.project_id,
            "backup_id": self.backup_id,
            "verified_at": self.verified_at or utc_now(),
            "error": self.error,
        }


class RecoveryVerifyError(Exception):
    def __init__(self, msg: str, *, result: RecoveryVerificationResult | None = None) -> None:
        super().__init__(msg)
        self.result = result


def _docker(argv: list[str], *, timeout: float = 300.0) -> Any:
    return run(
        argv,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        timeout=timeout,
        check=False,
    )


def _label_args(fleet_id: str, verifier_id: str, operation_id: str) -> list[str]:
    return [
        "--label",
        f"io.sbfleet.fleet={fleet_id}",
        "--label",
        f"io.sbfleet.project={verifier_id}",
        "--label",
        f"io.sbfleet.operation={operation_id}",
        "--label",
        "io.sbfleet.role=recovery-verifier",
    ]


def _owned_ids(resources: dict[str, Any]) -> list[tuple[str, str]]:
    """Return (kind, id) pairs recorded during verification."""
    out: list[tuple[str, str]] = []
    for kind in ("containers", "volumes", "networks"):
        for item in resources.get(kind) or []:
            if isinstance(item, dict) and item.get("id"):
                out.append((kind[:-1] if kind.endswith("s") else kind, str(item["id"])))
    return out


def _resource_still_exists(kind: str, rid: str) -> bool:
    if kind == "container":
        r = _docker(["docker", "inspect", rid])
    elif kind == "volume":
        r = _docker(["docker", "volume", "inspect", rid])
    elif kind == "network":
        r = _docker(["docker", "network", "inspect", rid])
    else:
        return False
    return bool(r.ok)


def cleanup_verifier_resources(
    resources: dict[str, Any],
    *,
    fleet_id: str,
    verifier_id: str,
    operation_id: str,
) -> list[str]:
    """Delete owned verifier resources: containers, then volumes, then networks.

    Every deletion result is checked. Residual owned IDs/names are returned when
    cleanup is incomplete. No global prune or prefix sweep.
    """
    errors: list[str] = []
    residuals: list[str] = []
    owned = _owned_ids(resources)
    # Explicit order — never reverse append-order (volumes must not precede containers).
    ordered: list[tuple[str, str]] = []
    for want in ("container", "volume", "network"):
        ordered.extend([(k, rid) for k, rid in owned if k == want])

    for kind, rid in ordered:
        if kind == "container":
            insp = _docker(
                [
                    "docker",
                    "inspect",
                    "--format",
                    '{{index .Config.Labels "io.sbfleet.fleet"}}|'
                    '{{index .Config.Labels "io.sbfleet.project"}}|'
                    '{{index .Config.Labels "io.sbfleet.operation"}}',
                    rid,
                ]
            )
            if not insp.ok:
                errors.append(f"skip missing container {rid[:12]}")
                continue
            parts = (insp.stdout or "").strip().split("|")
            if (
                len(parts) != 3
                or parts[0] != fleet_id
                or parts[1] != verifier_id
                or parts[2] != operation_id
            ):
                errors.append(f"refuse delete foreign container {rid[:12]}")
                continue
            rm = _docker(["docker", "rm", "-f", rid])
            if not rm.ok or _resource_still_exists("container", rid):
                msg = f"residual container id={rid}"
                errors.append(msg)
                residuals.append(msg)
        elif kind == "volume":
            name = rid
            insp = _docker(
                [
                    "docker",
                    "volume",
                    "inspect",
                    "--format",
                    '{{index .Labels "io.sbfleet.fleet"}}|'
                    '{{index .Labels "io.sbfleet.project"}}|'
                    '{{index .Labels "io.sbfleet.operation"}}',
                    name,
                ]
            )
            if not insp.ok:
                errors.append(f"skip missing volume {name}")
                continue
            parts = (insp.stdout or "").strip().split("|")
            if (
                len(parts) != 3
                or parts[0] != fleet_id
                or parts[1] != verifier_id
                or parts[2] != operation_id
            ):
                errors.append(f"refuse delete foreign volume {name}")
                continue
            rm = _docker(["docker", "volume", "rm", name])
            if not rm.ok or _resource_still_exists("volume", name):
                msg = f"residual volume name={name}"
                errors.append(msg)
                residuals.append(msg)
        elif kind == "network":
            insp = _docker(
                [
                    "docker",
                    "network",
                    "inspect",
                    "--format",
                    '{{index .Labels "io.sbfleet.fleet"}}|'
                    '{{index .Labels "io.sbfleet.project"}}|'
                    '{{index .Labels "io.sbfleet.operation"}}',
                    rid,
                ]
            )
            if not insp.ok:
                errors.append(f"skip missing network {rid[:12]}")
                continue
            parts = (insp.stdout or "").strip().split("|")
            if (
                len(parts) != 3
                or parts[0] != fleet_id
                or parts[1] != verifier_id
                or parts[2] != operation_id
            ):
                errors.append(f"refuse delete foreign network {rid[:12]}")
                continue
            rm = _docker(["docker", "network", "rm", rid])
            if not rm.ok or _resource_still_exists("network", rid):
                msg = f"residual network id={rid}"
                errors.append(msg)
                residuals.append(msg)
    if residuals:
        resources["cleanup_residuals"] = residuals
    return errors


def _create_labeled_volume(
    name: str, *, fleet_id: str, verifier_id: str, operation_id: str, resources: dict
) -> None:
    r = _docker(
        [
            "docker",
            "volume",
            "create",
            "--label",
            f"io.sbfleet.fleet={fleet_id}",
            "--label",
            f"io.sbfleet.project={verifier_id}",
            "--label",
            f"io.sbfleet.operation={operation_id}",
            "--label",
            "io.sbfleet.role=recovery-verifier",
            name,
        ]
    )
    if not r.ok:
        raise RecoveryVerifyError(f"volume create failed: {name}: {(r.stderr or '')[:160]}")
    resources.setdefault("volumes", []).append({"name": name, "id": name})


def _copy_tree_to_volume(
    src: Path,
    volume: str,
    *,
    uid: int,
    gid: int,
    mode_file: str | None = None,
    mode_path: str | None = None,
) -> None:
    if not src.exists():
        raise RecoveryVerifyError(f"missing source for volume copy: {src}")
    cmd = (
        "rm -rf /to/* /to/.[!.]* /to/..?* 2>/dev/null; "
        f"cp -a /from/. /to/ && chown -R {uid}:{gid} /to"
    )
    if mode_file and mode_path:
        cmd += f" && chmod {mode_file} /to/{mode_path}"
    r = _docker(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{src}:/from:ro",
            "-v",
            f"{volume}:/to",
            HELPER_IMAGE,
            "sh",
            "-c",
            cmd,
        ],
        timeout=600.0,
    )
    if not r.ok:
        raise RecoveryVerifyError(f"copy to volume {volume} failed: {(r.stderr or '')[:200]}")


def _psql(container: str, sql: str, *, user: str = "postgres", db: str = "postgres") -> Any:
    return _docker(
        [
            "docker",
            "exec",
            "-u",
            "postgres",
            container,
            "psql",
            "-U",
            user,
            "-d",
            db,
            "-v",
            "ON_ERROR_STOP=1",
            "-tAc",
            sql,
        ],
        timeout=120.0,
    )


def _compose_psql(
    deployment: Path,
    compose_project: str,
    sql: str,
    *,
    db: str = "postgres",
) -> Any:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(Path(deployment) / ".run-home"),
        "COMPOSE_PROJECT_NAME": compose_project,
        "COMPOSE_FILE": "docker-compose.yml:docker-compose.override.yml",
        "COMPOSE_PATH_SEPARATOR": ":",
    }
    return run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
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
        ],
        cwd=deployment,
        env=env,
        timeout=60.0,
        check=False,
    )


def _sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def capture_source_crypto_challenge(
    deployment: Path,
    compose_project: str,
    *,
    operation_id: str,
) -> dict[str, Any]:
    """Encrypt an operation-private challenge with SOURCE Vault/pgsodium material.

    Leaves a uniquely named vault secret in the source DB for cold backup inclusion.
    Returns only nonsecret verification metadata (never plaintext).
    """
    import hashlib
    import secrets

    challenge = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    digest = hashlib.sha256(salt + challenge).hexdigest()
    name = f"{SOURCE_CRYPTO_NAME_PREFIX}{operation_id}"
    challenge_hex = challenge.hex()
    desc = "sbfleet-recovery-challenge"
    ext = _compose_psql(
        deployment,
        compose_project,
        "CREATE EXTENSION IF NOT EXISTS supabase_vault CASCADE;",
    )
    if not ext.ok:
        raise RecoveryVerifyError(
            f"source vault extension unavailable: {(ext.stderr or ext.stdout or '')[:160]}"
        )
    _compose_psql(
        deployment,
        compose_project,
        f"DELETE FROM vault.secrets WHERE name = {_sql_literal(name)};",
    )
    created = _compose_psql(
        deployment,
        compose_project,
        f"SELECT vault.create_secret({_sql_literal(challenge_hex)}, "
        f"{_sql_literal(name)}, {_sql_literal(desc)});",
    )
    if not created.ok:
        raise RecoveryVerifyError(
            "source vault challenge encrypt failed: "
            f"{(created.stderr or created.stdout or '')[:160]}"
        )
    check = _compose_psql(
        deployment,
        compose_project,
        "SELECT decrypted_secret FROM vault.decrypted_secrets "
        f"WHERE name = {_sql_literal(name)} LIMIT 1;",
    )
    got = (check.stdout or "").strip() if check.ok else ""
    if got != challenge_hex:
        _compose_psql(
            deployment,
            compose_project,
            f"DELETE FROM vault.secrets WHERE name = {_sql_literal(name)};",
        )
        raise RecoveryVerifyError("source vault challenge roundtrip mismatch")
    del challenge
    return {
        "name": name,
        "salt_hex": salt.hex(),
        "digest_sha256": digest,
        "encoding": "hex",
    }


def capture_functions_snippets_inventory(deployment: Path) -> dict[str, str]:
    """Bounded source-side path→sha256 for volumes/functions and volumes/snippets.

    Paths are archive-relative (``deployment/functions/...``, ``deployment/snippets/...``).
    """
    out: dict[str, str] = {}
    for unit in ("functions", "snippets"):
        root = deployment / "volumes" / unit
        if not root.is_dir():
            continue
        walk_error: list[BaseException] = []

        def _onerror(err: OSError, _errs: list[BaseException] = walk_error) -> None:
            _errs.append(err)

        for dirpath, _dirnames, filenames in os.walk(root, followlinks=False, onerror=_onerror):
            if walk_error:
                raise RecoveryVerifyError(f"source {unit} inventory unreadable: {walk_error[0]}")
            for name in filenames:
                fp = Path(dirpath) / name
                try:
                    if fp.is_symlink() or not fp.is_file():
                        continue
                    rel = fp.relative_to(root).as_posix()
                    out[f"deployment/{unit}/{rel}"] = sha256_file(fp)
                except OSError as exc:
                    raise RecoveryVerifyError(f"source {unit} inventory failed: {exc}") from exc
        if walk_error:
            raise RecoveryVerifyError(f"source {unit} inventory unreadable: {walk_error[0]}")
    return out


def capture_source_recovery_facts(
    deployment: Path,
    compose_project: str,
) -> dict[str, Any]:
    """Capture nonsecret source recovery facts after writer quiesce (PG still up)."""
    from sbfleet.backup_manifest import REQUIRED_AUTH_RELATIONS, REQUIRED_RECOVERY_ROLES

    facts: dict[str, Any] = {"facts_version": 1}
    dbs = _compose_psql(
        deployment,
        compose_project,
        "SELECT string_agg(datname, ',' ORDER BY datname) "
        "FROM pg_database WHERE datistemplate = false",
    )
    if not dbs.ok or not (dbs.stdout or "").strip():
        raise RecoveryVerifyError("source database catalog capture failed")
    facts["databases"] = (dbs.stdout or "").strip()

    roles = _compose_psql(
        deployment,
        compose_project,
        "SELECT string_agg(rolname, ',' ORDER BY rolname) FROM pg_roles",
    )
    if not roles.ok or not (roles.stdout or "").strip():
        raise RecoveryVerifyError("source role catalog capture failed")
    facts["roles"] = (roles.stdout or "").strip()

    role_list = ", ".join(_sql_literal(r) for r in sorted(REQUIRED_RECOVERY_ROLES))
    logins = _compose_psql(
        deployment,
        compose_project,
        "SELECT string_agg(rolname || ':' || rolcanlogin::text, ',' ORDER BY rolname) "
        f"FROM pg_roles WHERE rolname IN ({role_list})",
    )
    if not logins.ok:
        raise RecoveryVerifyError("source role login capture failed")
    facts["role_logins"] = (logins.stdout or "").strip()

    memberships = _compose_psql(
        deployment,
        compose_project,
        "SELECT string_agg(r.rolname || '>' || m.rolname, ',' ORDER BY 1) "
        "FROM pg_auth_members am "
        "JOIN pg_roles r ON r.oid = am.member "
        "JOIN pg_roles m ON m.oid = am.roleid "
        "WHERE r.rolname IN ('authenticator','supabase_auth_admin',"
        "'supabase_storage_admin','supabase_admin')",
    )
    if not memberships.ok:
        raise RecoveryVerifyError("source role membership capture failed")
    facts["role_memberships"] = (memberships.stdout or "").strip()

    grants = _compose_psql(
        deployment,
        compose_project,
        "SELECT string_agg(rol || ':' || priv, ',' ORDER BY 1) FROM ("
        "SELECT 'authenticator' AS rol, "
        "has_database_privilege('authenticator','postgres','CONNECT')::text AS priv "
        ") s",
    )
    if not grants.ok:
        raise RecoveryVerifyError("source grant capture failed")
    facts["role_grants"] = (grants.stdout or "").strip()

    rel_list = ", ".join(_sql_literal(t) for t in sorted(REQUIRED_AUTH_RELATIONS))
    auth_rels = _compose_psql(
        deployment,
        compose_project,
        "SELECT string_agg(table_name, ',' ORDER BY table_name) "
        "FROM information_schema.tables "
        f"WHERE table_schema='auth' AND table_name IN ({rel_list})",
    )
    if not auth_rels.ok:
        raise RecoveryVerifyError("source auth relation capture failed")
    facts["auth_relations"] = (auth_rels.stdout or "").strip()

    auth_count = _compose_psql(
        deployment,
        compose_project,
        "SELECT count(*)::text FROM auth.users",
    )
    if not auth_count.ok:
        raise RecoveryVerifyError("source auth user-count capture failed")
    facts["auth_users_count"] = (auth_count.stdout or "").strip()

    facts["functions_snippets"] = capture_functions_snippets_inventory(deployment)
    return facts


def cleanup_source_crypto_challenge(
    deployment: Path,
    compose_project: str,
    *,
    name: str,
) -> None:
    """Best-effort remove operation-private challenge from live source after backup."""
    if not name.startswith(SOURCE_CRYPTO_NAME_PREFIX):
        return
    _compose_psql(
        deployment,
        compose_project,
        f"DELETE FROM vault.secrets WHERE name = {_sql_literal(name)};",
    )


def verify_storage_tree(
    storage_root: Path, expected_checksums: dict[str, str]
) -> RecoveryAssertion:
    """Compare Storage object tree hashes against inventory (file-backend)."""
    if not storage_root.is_dir():
        return RecoveryAssertion("storage_tree", False, "storage tree missing")
    found = {rel: digest for rel, _size, digest in iter_file_digests(storage_root)}
    # expected paths are archive-relative (storage/...)
    mismatches = []
    checked = 0
    for path, digest in expected_checksums.items():
        if not path.startswith("storage/"):
            continue
        rel = path[len("storage/") :]
        if not rel:
            continue
        checked += 1
        got = found.get(rel)
        if got != digest:
            mismatches.append(path)
            if len(mismatches) >= 5:
                break
    if checked == 0:
        if storage_root.is_dir():
            return RecoveryAssertion("storage_tree", True, "empty-storage-unit-present")
        return RecoveryAssertion("storage_tree", False, "no storage members in inventory")
    if mismatches:
        return RecoveryAssertion(
            "storage_tree", False, f"checksum mismatch count={len(mismatches)}"
        )
    return RecoveryAssertion("storage_tree", True, f"files={checked}")


def run_disposable_recovery_verification(
    *,
    extract_root: Path,
    manifest: dict[str, Any],
    fleet_id: str,
    operation_id: str,
    expected_sql: dict[str, Any] | None = None,
    expected_auth: dict[str, Any] | None = None,
    expected_vault: dict[str, Any] | None = None,
    expected_functions: dict[str, Any] | None = None,
    source_crypto: dict[str, Any] | None = None,
    source_facts: dict[str, Any] | None = None,
    identity_path: Path | None = None,  # unused; reserved
) -> RecoveryVerificationResult:
    """Decrypt staging already extracted; start isolated DB; assert recovery facts.

    Does not claim project HEALTHY. Returns RecoveryVerificationResult only.
    Acceptance ``expected_*`` may add probes but cannot raise the recovery level
    above the mandatory production assertion set.
    """
    verifier_id = f"rv-{uuid.uuid4().hex[:12]}"
    resources: dict[str, Any] = {"containers": [], "volumes": [], "networks": []}
    assertions: list[RecoveryAssertion] = []
    fixture_identity = str(
        (expected_sql or {}).get("fixture_id") or manifest.get("backup_id") or verifier_id
    )
    upstream = manifest.get("upstream") or {}
    # Prefer explicit caller metadata; else nonsecret fields from encrypted manifest.
    effective_crypto = source_crypto
    if not effective_crypto and isinstance(manifest.get("source_crypto"), dict):
        effective_crypto = dict(manifest["source_crypto"])
    result = RecoveryVerificationResult(
        ok=False,
        verifier_id=verifier_id,
        operation_id=operation_id,
        fixture_identity=fixture_identity,
        resources=resources,
        source_pin={
            "ref": upstream.get("ref"),
            "sha": upstream.get("sha"),
        },
        source_crypto=effective_crypto,
        project_id=str(manifest.get("project_id") or "") or None,
        backup_id=str(manifest.get("backup_id") or "") or None,
    )

    try:
        require_db_recovery_facts(manifest)
    except ManifestError as exc:
        result.error = str(exc)
        result.assertions.append(RecoveryAssertion("db_recovery_facts", False, str(exc)[:200]))
        return result

    images = manifest.get("images") or {}
    db_image = (images.get("db") or {}).get("image_id") or (images.get("db") or {}).get("image_ref")
    if not db_image or db_image == "UNKNOWN":
        result.error = "db image unavailable for verifier"
        return result

    pgdata = extract_root / "postgres"
    db_config = extract_root / "db-config"
    storage = extract_root / "storage"
    if not pgdata.is_dir() or not db_config.is_dir():
        result.error = "extracted postgres/ or db-config/ missing"
        result.assertions.append(RecoveryAssertion("units_present", False, result.error))
        return result

    checksums = {
        e["path"]: e["sha256"]
        for e in manifest.get("inventory") or []
        if e.get("type") == "file" and e.get("sha256")
    }
    assertions.append(verify_storage_tree(storage, checksums))

    # Resolve source facts: caller arg or archived manifest (restore path).
    effective_facts = source_facts
    if not effective_facts and isinstance(manifest.get("source_facts"), dict):
        effective_facts = dict(manifest["source_facts"])

    facts_ok = bool(
        isinstance(effective_facts, dict)
        and effective_facts.get("databases")
        and effective_facts.get("roles")
        and effective_facts.get("role_logins")
        and effective_facts.get("auth_relations") is not None
        and effective_facts.get("auth_users_count") is not None
        and isinstance(effective_facts.get("functions_snippets"), dict)
    )
    assertions.append(
        RecoveryAssertion(
            "source_facts",
            facts_ok,
            "present" if facts_ok else "missing-or-incomplete",
        )
    )

    # Functions/snippets: source inventory == manifest inventory == recovered tree.
    # Never derive expectations solely from the extracted tree (tautology).
    src_fn = dict((effective_facts or {}).get("functions_snippets") or {})
    if expected_functions and expected_functions.get("files"):
        # Acceptance may add files but cannot replace missing source inventory.
        for k, v in dict(expected_functions["files"]).items():
            src_fn.setdefault(k, v)
    man_fn = {
        p: d
        for p, d in checksums.items()
        if p.startswith("deployment/functions/") or p.startswith("deployment/snippets/")
    }
    rec_fn: dict[str, str] = {}
    for base in ("deployment/functions", "deployment/snippets"):
        root = extract_root / base
        if root.is_dir():
            for rel, _size, digest in iter_file_digests(root):
                rec_fn[f"{base}/{rel}"] = digest
    fn_ok = src_fn == man_fn == rec_fn
    assertions.append(
        RecoveryAssertion(
            "functions_snippets",
            fn_ok,
            "ok" if fn_ok else f"src={len(src_fn)} man={len(man_fn)} rec={len(rec_fn)}",
        )
    )

    vol_pg = f"sbfleet-rv-{verifier_id}-pgdata"
    vol_cfg = f"sbfleet-rv-{verifier_id}-dbconfig"
    cname = f"sbfleet-rv-{verifier_id}-db"

    try:
        _create_labeled_volume(
            vol_pg,
            fleet_id=fleet_id,
            verifier_id=verifier_id,
            operation_id=operation_id,
            resources=resources,
        )
        _create_labeled_volume(
            vol_cfg,
            fleet_id=fleet_id,
            verifier_id=verifier_id,
            operation_id=operation_id,
            resources=resources,
        )
        own = PROFILE_OWNERSHIP
        _copy_tree_to_volume(pgdata, vol_pg, uid=own["postgres"]["uid"], gid=own["postgres"]["gid"])
        _copy_tree_to_volume(
            db_config,
            vol_cfg,
            uid=own["db-config"]["uid"],
            gid=own["db-config"]["gid"],
            mode_file=oct(own["pgsodium_root.key_mode"])[2:],
            mode_path="pgsodium_root.key",
        )

        start = _docker(
            [
                "docker",
                "run",
                "-d",
                "--name",
                cname,
                "--network",
                "none",
                *_label_args(fleet_id, verifier_id, operation_id),
                "-v",
                f"{vol_pg}:/var/lib/postgresql/data",
                "-v",
                f"{vol_cfg}:/etc/postgresql-custom",
                "-e",
                "POSTGRES_HOST=/var/run/postgresql",
                db_image,
            ],
            timeout=120.0,
        )
        if not start.ok:
            raise RecoveryVerifyError(f"verifier db start failed: {(start.stderr or '')[:200]}")
        cid = (start.stdout or "").strip()
        resources["containers"].append({"name": cname, "id": cid or cname})

        ready = False
        for _ in range(60):
            r = _docker(
                ["docker", "exec", "-u", "postgres", cname, "pg_isready", "-U", "postgres"],
                timeout=15.0,
            )
            if r.ok:
                ready = True
                break
            import time

            time.sleep(2)
        assertions.append(
            RecoveryAssertion("postgres_ready", ready, "pg_isready" if ready else "timeout")
        )
        if not ready:
            result.assertions = assertions
            result.error = "verifier postgres not ready"
            return result

        q1 = _psql(cname, "SELECT 1")
        assertions.append(
            RecoveryAssertion("select_1", q1.ok and (q1.stdout or "").strip() == "1", "select 1")
        )

        dbs = _psql(
            cname,
            "SELECT string_agg(datname, ',' ORDER BY datname) "
            "FROM pg_database WHERE datistemplate = false",
        )
        db_list = (dbs.stdout or "").strip() if dbs.ok else ""
        db_set = {x for x in db_list.split(",") if x}
        src_dbs = {x for x in str((effective_facts or {}).get("databases") or "").split(",") if x}
        db_ok = facts_ok and db_set == src_dbs and REQUIRED_RECOVERY_DATABASES.issubset(db_set)
        assertions.append(RecoveryAssertion("databases", db_ok, db_list[:120]))

        roles = _psql(cname, "SELECT string_agg(rolname, ',' ORDER BY rolname) FROM pg_roles")
        role_list = (roles.stdout or "").strip() if roles.ok else ""
        role_set = {x for x in role_list.split(",") if x}
        src_roles = {x for x in str((effective_facts or {}).get("roles") or "").split(",") if x}
        role_list_sql = ", ".join(
            "'" + r.replace("'", "''") + "'" for r in sorted(REQUIRED_RECOVERY_ROLES)
        )
        logins = _psql(
            cname,
            "SELECT string_agg(rolname || ':' || rolcanlogin::text, ',' ORDER BY rolname) "
            f"FROM pg_roles WHERE rolname IN ({role_list_sql})",
        )
        got_logins = (logins.stdout or "").strip() if logins.ok else ""
        memberships = _psql(
            cname,
            "SELECT string_agg(r.rolname || '>' || m.rolname, ',' ORDER BY 1) "
            "FROM pg_auth_members am "
            "JOIN pg_roles r ON r.oid = am.member "
            "JOIN pg_roles m ON m.oid = am.roleid "
            "WHERE r.rolname IN ('authenticator','supabase_auth_admin',"
            "'supabase_storage_admin','supabase_admin')",
        )
        got_memberships = (memberships.stdout or "").strip() if memberships.ok else ""
        grants = _psql(
            cname,
            "SELECT string_agg(rol || ':' || priv, ',' ORDER BY 1) FROM ("
            "SELECT 'authenticator' AS rol, "
            "has_database_privilege('authenticator','postgres','CONNECT')::text AS priv "
            ") s",
        )
        got_grants = (grants.stdout or "").strip() if grants.ok else ""
        role_ok = (
            facts_ok
            and REQUIRED_RECOVERY_ROLES.issubset(role_set)
            and src_roles.issubset(role_set)
            and got_logins == str((effective_facts or {}).get("role_logins") or "")
            and got_memberships == str((effective_facts or {}).get("role_memberships") or "")
            and got_grants == str((effective_facts or {}).get("role_grants") or "")
        )
        assertions.append(RecoveryAssertion("roles", role_ok, role_list[:120]))

        if expected_sql and expected_sql.get("query") and expected_sql.get("expect") is not None:
            q = _psql(
                cname,
                str(expected_sql["query"]),
                db=str(expected_sql.get("database") or "postgres"),
            )
            got = (q.stdout or "").strip() if q.ok else ""
            expect = str(expected_sql["expect"])
            assertions.append(
                RecoveryAssertion(
                    "seeded_sql",
                    got == expect,
                    "match" if got == expect else "mismatch",
                )
            )

        rel_sql = ", ".join(
            "'" + t.replace("'", "''") + "'" for t in sorted(REQUIRED_AUTH_RELATIONS)
        )
        aq = _psql(
            cname,
            "SELECT string_agg(table_name, ',' ORDER BY table_name) "
            "FROM information_schema.tables "
            f"WHERE table_schema='auth' AND table_name IN ({rel_sql})",
        )
        got_rels = (aq.stdout or "").strip() if aq.ok else ""
        src_rels = str((effective_facts or {}).get("auth_relations") or "")
        auth_schema_ok = facts_ok and got_rels == src_rels and bool(got_rels)
        assertions.append(RecoveryAssertion("auth_schema", auth_schema_ok, got_rels[:80]))

        au = _psql(cname, "SELECT count(*)::text FROM auth.users")
        got_count = (au.stdout or "").strip() if au.ok else ""
        src_count = str((effective_facts or {}).get("auth_users_count") or "")
        auth_viable = facts_ok and au.ok and got_count == src_count and got_count.isdigit()
        assertions.append(
            RecoveryAssertion(
                "auth_viability",
                auth_viable,
                f"count={got_count}" if au.ok else "query-failed",
            )
        )
        if expected_auth and expected_auth.get("email"):
            email = str(expected_auth["email"]).replace("'", "''")
            aue = _psql(
                cname,
                f"SELECT count(*)::text FROM auth.users WHERE email = '{email}'",
                db=str(expected_auth.get("database") or "postgres"),
            )
            got = (aue.stdout or "").strip() if aue.ok else "0"
            assertions.append(RecoveryAssertion("auth_user", got == "1", f"count={got}"))

        crypto_ok = False
        crypto_detail = "missing-source-crypto"
        if (
            effective_crypto
            and effective_crypto.get("name")
            and effective_crypto.get("digest_sha256")
        ):
            import hashlib

            name = str(effective_crypto["name"])
            salt_hex = str(effective_crypto.get("salt_hex") or "")
            expect_digest = str(effective_crypto["digest_sha256"])
            vq = _psql(
                cname,
                "SELECT decrypted_secret FROM vault.decrypted_secrets "
                f"WHERE name = {_sql_literal(name)} LIMIT 1;",
            )
            plain = (vq.stdout or "").strip() if vq.ok else ""
            if plain and salt_hex:
                try:
                    salt = bytes.fromhex(salt_hex)
                    challenge = bytes.fromhex(plain)
                    got_digest = hashlib.sha256(salt + challenge).hexdigest()
                    crypto_ok = got_digest == expect_digest
                    crypto_detail = "match" if crypto_ok else "digest-mismatch"
                except ValueError:
                    crypto_ok = False
                    crypto_detail = "decode-error"
            else:
                crypto_detail = "decrypt-failed"
        elif expected_vault and expected_vault.get("expect") is not None:
            # Fixture probes alone never satisfy mandatory vault_crypto.
            crypto_detail = "fixture-only-insufficient"
        assertions.append(RecoveryAssertion("vault_crypto", crypto_ok, crypto_detail))

        # Acceptance fixtures may add vault_decrypt probes; independent of vault_crypto.
        if (
            expected_vault
            and expected_vault.get("sql_decrypt")
            and expected_vault.get("expect") is not None
        ):
            vq = _psql(
                cname,
                str(expected_vault["sql_decrypt"]),
                db=str(expected_vault.get("database") or "postgres"),
            )
            got = (vq.stdout or "").strip() if vq.ok else ""
            expect = str(expected_vault["expect"])
            assertions.append(
                RecoveryAssertion(
                    "vault_decrypt",
                    got == expect,
                    "match" if got == expect else "mismatch",
                )
            )

        required = set(REQUIRED_RECOVERY_ASSERTIONS)
        by_name = {a.name: a for a in assertions}
        hard_ok = facts_ok and all(by_name.get(n) and by_name[n].ok for n in required)
        if expected_sql and expected_sql.get("expect") is not None:
            hard_ok = hard_ok and bool(by_name.get("seeded_sql") and by_name["seeded_sql"].ok)
        if expected_auth and expected_auth.get("email"):
            hard_ok = hard_ok and bool(by_name.get("auth_user") and by_name["auth_user"].ok)
        if expected_vault and expected_vault.get("expect") is not None:
            hard_ok = hard_ok and bool(by_name.get("vault_decrypt") and by_name["vault_decrypt"].ok)

        result.assertions = assertions
        result.ok = hard_ok
        result.verified_at = utc_now()
        if not hard_ok:
            result.error = "one or more recovery assertions failed"
        return result
    except RecoveryVerifyError as exc:
        result.error = str(exc)
        result.assertions = assertions
        return result
    except Exception as exc:  # noqa: BLE001
        result.error = f"verifier exception: {exc}"[:300]
        result.assertions = assertions
        return result
    finally:
        cleanup_errs = cleanup_verifier_resources(
            resources, fleet_id=fleet_id, verifier_id=verifier_id, operation_id=operation_id
        )
        if cleanup_errs:
            result.resources["cleanup_errors"] = cleanup_errs
            residuals = resources.get("cleanup_residuals") or [
                e for e in cleanup_errs if e.startswith("residual ")
            ]
            if residuals:
                result.resources["cleanup_residuals"] = residuals
                if result.ok:
                    result.ok = False
                    result.error = (
                        "recovery verification cleanup incomplete: " + "; ".join(residuals)[:240]
                    )


def parse_pg_controldata(output: str) -> dict[str, str]:
    facts: dict[str, str] = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        facts[key.strip()] = val.strip()
    return facts


def prove_clean_shutdown(
    *,
    db_image: str,
    pgdata: Path,
    db_config: Path | None = None,
) -> dict[str, Any]:
    """Run pg_controldata from exact DB image against RO mounts; require shut down."""
    if not pgdata.is_dir():
        raise RecoveryVerifyError("PGDATA missing for clean-shutdown check")
    mounts = ["-v", f"{pgdata}:/pgdata:ro"]
    if db_config and db_config.is_dir():
        mounts.extend(["-v", f"{db_config}:/etc/postgresql-custom:ro"])
    # Bypass postgres entrypoint; run pg_controldata directly when present.
    r = _docker(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "pg_controldata",
            *mounts,
            db_image,
            "/pgdata",
        ],
        timeout=120.0,
    )
    if not r.ok:
        # Some images need full path or gosu; try via bash -c
        r = _docker(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--entrypoint",
                "",
                *mounts,
                db_image,
                "bash",
                "-lc",
                "pg_controldata /pgdata || /usr/lib/postgresql/*/bin/pg_controldata /pgdata",
            ],
            timeout=120.0,
        )
    if not r.ok:
        raise RecoveryVerifyError(f"pg_controldata failed: {(r.stderr or r.stdout or '')[:200]}")
    text = r.stdout or ""
    facts = parse_pg_controldata(text)
    state = facts.get("Database cluster state") or facts.get("Database cluster state".lower()) or ""
    # Keys may vary slightly; search case-insensitively.
    if not state:
        for k, v in facts.items():
            if "cluster state" in k.lower():
                state = v
                break
    if "shut down" not in state.lower() or "in production" in state.lower():
        raise RecoveryVerifyError(f"dirty or unknown PG shutdown state: {state!r}")
    # postmaster.pid must not remain for clean cold copy claim
    pid_check = _docker(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{pgdata}:/pgdata:ro",
            "alpine:3.20",
            "sh",
            "-c",
            "test ! -e /pgdata/postmaster.pid",
        ]
    )
    if not pid_check.ok:
        raise RecoveryVerifyError("postmaster.pid present after shutdown")
    return {
        "cluster_state": state,
        "pg_control_version": facts.get("pg_control version number")
        or facts.get("PG_CONTROL_VERSION")
        or "UNKNOWN",
        "catalog_version": facts.get("Catalog version number") or "UNKNOWN",
        "system_identifier": facts.get("Database system identifier") or "UNKNOWN",
        "tool": "pg_controldata",
        "raw_keys": sorted(facts.keys())[:30],
    }
