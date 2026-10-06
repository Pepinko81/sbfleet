"""Versioned backup internal manifest and public receipt helpers (Run 2B).

Internal encrypted manifest is authoritative recovery-identity evidence after
decrypt + inventory validation. A sidecar receipt is not authentication; when
both exist they must agree (receipt/archive binding verified).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sbfleet.archive_safe import MemberSpec, normalize_member_path, write_buffered_hash

MANIFEST_FORMAT_VERSION = 1
RECEIPT_FORMAT_VERSION = 1
# Destructive gates (remove/update/restore-swap) require this verifier contract.
VERIFIER_CONTRACT_VERSION = "recovery-verify/v3"
REQUIRED_RECOVERY_ASSERTIONS = frozenset(
    {
        "postgres_ready",
        "select_1",
        "databases",
        "roles",
        "auth_schema",
        "auth_viability",
        "storage_tree",
        "vault_crypto",
        "functions_snippets",
    }
)
# Supabase self-hosted recovery-critical roles/databases (not application semantics).
REQUIRED_RECOVERY_DATABASES = frozenset({"postgres"})
REQUIRED_RECOVERY_ROLES = frozenset(
    {
        "postgres",
        "authenticator",
        "supabase_admin",
        "supabase_auth_admin",
        "supabase_storage_admin",
    }
)
# Auth relations whose presence is part of the bounded recovery contract.
REQUIRED_AUTH_RELATIONS = frozenset(
    {
        "users",
        "identities",
        "sessions",
        "refresh_tokens",
    }
)

# Exact files that must be present (as regular files) before restore mutation.
REQUIRED_RECOVERY_FILES = frozenset(
    {
        "db-config/pgsodium_root.key",
        "deployment/.env",
        "project.json",
    }
)

VERIFICATION_NONE = "none"
VERIFICATION_DECRYPT_STRUCTURAL = "decrypt_structural"
VERIFICATION_RECOVERY = "recovery"

# Keys restored from source recovery material (must travel with PGDATA/crypto).
SOURCE_RECOVERY_ENV_KEYS = frozenset(
    {
        "JWT_SECRET",
        "ANON_KEY",
        "SERVICE_ROLE_KEY",
        "SUPABASE_PUBLISHABLE_KEY",
        "SUPABASE_SECRET_KEY",
        "JWT_KEYS",
        "JWT_JWKS",
        "POSTGRES_PASSWORD",
        "SECRET_KEY_BASE",
        "VAULT_ENC_KEY",
        "PG_META_CRYPTO_KEY",
        "DASHBOARD_PASSWORD",
        "POOLER_TENANT_ID",
        "POOLER_DEFAULT_POOL_SIZE",
        "POOLER_MAX_CLIENT_CONN",
        "PGRST_DB_SCHEMAS",
        "POSTGRES_HOST",
        "POSTGRES_DB",
        "POSTGRES_PORT",
        "POSTGRES_USER",
        "JWT_EXPIRY",
    }
)

# Destination-owned placement / authority selectors — never take from archive blindly.
DESTINATION_OWNED_ENV_KEYS = frozenset(
    {
        "COMPOSE_PROJECT_NAME",
        "COMPOSE_FILE",
        "COMPOSE_PATH_SEPARATOR",
        "KONG_HTTP_PORT",
        "KONG_HTTPS_PORT",
        "POSTGRES_PORT_HOST",
        "SUPABASE_PUBLIC_URL",
        "API_EXTERNAL_URL",
        "SITE_URL",
        "ADDITIONAL_REDIRECT_URLS",
        "STUDIO_DEFAULT_ORGANIZATION",
        "STUDIO_DEFAULT_PROJECT",
        "DASHBOARD_USERNAME",
    }
)

REQUIRED_ARCHIVE_TOP = frozenset(
    {
        "manifest.json",
        "postgres",
        "db-config",
        "storage",
        "deployment",
        "project.json",
    }
)

PROFILE_OWNERSHIP = {
    "postgres": {"uid": 100, "gid": 1000},
    "storage": {"uid": 1000, "gid": 1000},
    "db-config": {"uid": 100, "gid": 101},
    "pgsodium_root.key_mode": 0o640,
}


class ManifestError(Exception):
    """Manifest schema / identity / compatibility refusal."""


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_receipt_verification(receipt: dict) -> str:
    level = receipt.get("verification")
    if level in {
        VERIFICATION_NONE,
        VERIFICATION_DECRYPT_STRUCTURAL,
        VERIFICATION_RECOVERY,
    }:
        return str(level)
    if receipt.get("verified") is True:
        return VERIFICATION_DECRYPT_STRUCTURAL
    return VERIFICATION_NONE


def is_recovery_verified_receipt(receipt: dict) -> bool:
    return normalize_receipt_verification(receipt) == VERIFICATION_RECOVERY


def validate_recovery_receipt_evidence(
    receipt: dict,
    *,
    require_contract: str = VERIFIER_CONTRACT_VERSION,
) -> dict[str, Any]:
    """Fail closed unless receipt proves the current mandatory verifier contract."""
    if not isinstance(receipt, dict):
        raise ManifestError("recovery receipt must be an object")
    if receipt.get("format_version") != RECEIPT_FORMAT_VERSION:
        raise ManifestError(
            f"unsupported receipt format_version: {receipt.get('format_version')!r}"
        )
    if normalize_receipt_verification(receipt) != VERIFICATION_RECOVERY:
        raise ManifestError("receipt verification is not recovery")
    recovery = receipt.get("recovery")
    if not isinstance(recovery, dict):
        raise ManifestError("recovery receipt missing recovery evidence object")
    contract = recovery.get("outcome_version") or recovery.get("verifier_contract")
    if contract != require_contract:
        raise ManifestError(
            f"recovery evidence contract {contract!r} does not satisfy required "
            f"{require_contract!r}"
        )
    if recovery.get("ok") is not True:
        raise ManifestError("recovery evidence ok is not true")
    assertions = recovery.get("assertions")
    if not isinstance(assertions, list) or not assertions:
        raise ManifestError("recovery evidence missing assertion result set")
    by_name: dict[str, dict[str, Any]] = {}
    for item in assertions:
        if not isinstance(item, dict) or not item.get("name"):
            raise ManifestError("invalid recovery assertion entry")
        by_name[str(item["name"])] = item
    missing = sorted(REQUIRED_RECOVERY_ASSERTIONS - set(by_name))
    if missing:
        raise ManifestError("recovery evidence missing required assertions: " + ", ".join(missing))
    failed = sorted(
        name for name in REQUIRED_RECOVERY_ASSERTIONS if by_name[name].get("ok") is not True
    )
    if failed:
        raise ManifestError(
            "recovery evidence has failed required assertions: " + ", ".join(failed)
        )
    if not recovery.get("verifier_id") or not recovery.get("operation_id"):
        # operation_id may live on receipt root for older drafts — require one source.
        if not recovery.get("verifier_id"):
            raise ManifestError("recovery evidence missing verifier_id")
        if not (recovery.get("operation_id") or receipt.get("operation_id")):
            raise ManifestError("recovery evidence missing operation identity")
    if not receipt.get("project_id") or not receipt.get("backup_id"):
        raise ManifestError("recovery receipt missing project/backup identity")
    if not receipt.get("ciphertext_sha256") or not isinstance(receipt.get("ciphertext_bytes"), int):
        raise ManifestError("recovery receipt missing ciphertext binding facts")
    if not receipt.get("manifest_sha256"):
        raise ManifestError("recovery receipt missing manifest_sha256")
    upstream = receipt.get("upstream") or recovery.get("source_pin") or {}
    if not isinstance(upstream, dict) or not upstream.get("ref") or not upstream.get("sha"):
        raise ManifestError("recovery receipt missing source pin ref/sha")
    if not (recovery.get("verified_at") or receipt.get("verified_at")):
        raise ManifestError("recovery receipt missing verification timestamp")
    return recovery


def build_internal_manifest(
    *,
    backup_id: str,
    project_id: str,
    fleet_id: str,
    slug: str,
    upstream: dict[str, Any] | None,
    last_verified_upstream: dict[str, Any] | None,
    prior_state: str,
    images: dict[str, Any],
    postgres: dict[str, Any],
    members: dict[str, MemberSpec],
    includes: list[str],
    clean_shutdown_evidence: dict[str, Any],
    platform: str | None = None,
    source_crypto: dict[str, Any] | None = None,
    source_facts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    inventory = []
    for path in sorted(members):
        m = members[path]
        entry: dict[str, Any] = {
            "path": m.path,
            "type": m.type,
            "size": m.size,
        }
        if m.type == "file":
            if not m.sha256:
                raise ManifestError(f"missing checksum for {path}")
            entry["sha256"] = m.sha256
        inventory.append(entry)
    out: dict[str, Any] = {
        "format_version": MANIFEST_FORMAT_VERSION,
        "backup_id": backup_id,
        "project_id": project_id,
        "fleet_id": fleet_id,
        "slug": slug,
        "created_at": utc_now(),
        "profile": "standard",
        "method": "cold-physical",
        "storage_backend": "file",
        "prior_state": prior_state,
        "upstream": upstream or {},
        "last_verified_upstream": last_verified_upstream,
        "platform": platform or "UNKNOWN",
        "images": images,
        "postgres": postgres,
        "clean_shutdown": clean_shutdown_evidence,
        "includes": includes,
        "inventory": inventory,
    }
    # Nonsecret only: name + salt_hex + digest — never plaintext challenge.
    if isinstance(source_crypto, dict) and source_crypto.get("name"):
        out["source_crypto"] = {
            k: source_crypto[k]
            for k in ("name", "salt_hex", "digest_sha256", "encoding")
            if k in source_crypto
        }
    if isinstance(source_facts, dict) and source_facts:
        out["source_facts"] = dict(source_facts)
    return out


def manifest_bytes(manifest: dict[str, Any]) -> bytes:
    import json

    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")


def manifest_sha256(manifest: dict[str, Any]) -> str:
    return write_buffered_hash(manifest_bytes(manifest))


def inventory_to_member_specs(manifest: dict[str, Any]) -> dict[str, MemberSpec]:
    from sbfleet.archive_safe import ArchiveSafetyError

    inv = manifest.get("inventory")
    if not isinstance(inv, list):
        raise ManifestError("manifest inventory missing")
    out: dict[str, MemberSpec] = {}
    for entry in inv:
        if not isinstance(entry, dict):
            raise ManifestError("invalid inventory entry")
        raw_path = str(entry.get("path") or "")
        kind = str(entry.get("type") or "")
        size = int(entry.get("size") or 0)
        if not raw_path or kind not in {"file", "dir"}:
            raise ManifestError(f"invalid inventory entry: {entry!r}")
        try:
            path = normalize_member_path(raw_path)
        except ArchiveSafetyError as exc:
            raise ManifestError(str(exc)) from exc
        if path != raw_path:
            # Alias forms like ./x must not silently remap checksum keys.
            raise ManifestError(f"inventory path must be normalized (no aliases): {raw_path!r}")
        if path in out:
            raise ManifestError(f"duplicate inventory path: {path}")
        sha = entry.get("sha256") if kind == "file" else None
        if kind == "file" and (not isinstance(sha, str) or len(sha) != 64):
            raise ManifestError(f"invalid sha256 for {path}")
        out[path] = MemberSpec(
            path=path,
            type=kind,
            size=size,
            sha256=str(sha) if sha else None,
        )
    return out


def bootstrap_expected_from_manifest(
    manifest: dict[str, Any],
    *,
    manifest_tar_size: int,
) -> tuple[dict[str, MemberSpec], dict[str, str]]:
    """Build exact expected inventory including ``manifest.json`` (size/type only).

    Inventory file checksums are returned separately for ``safe_extract(verify_sha256=...)``.
    ``manifest.json`` itself is never self-checksummed in the inventory list.
    """
    if not isinstance(manifest_tar_size, int) or manifest_tar_size <= 0:
        raise ManifestError("manifest.tar size must be a positive int")
    specs = inventory_to_member_specs(manifest)
    if "manifest.json" in specs:
        raise ManifestError("manifest must not include itself in inventory checksum list")
    expected = dict(specs)
    expected["manifest.json"] = MemberSpec(
        path="manifest.json",
        type="file",
        size=manifest_tar_size,
        sha256=None,
    )
    checksums = {p: m.sha256 for p, m in specs.items() if m.type == "file" and m.sha256}
    return expected, checksums


def require_recovery_files(manifest: dict[str, Any]) -> None:
    """Refuse archives missing mandatory recovery files (exact paths, file type)."""
    specs = inventory_to_member_specs(manifest)
    for path in sorted(REQUIRED_RECOVERY_FILES):
        spec = specs.get(path)
        if spec is None or spec.type != "file":
            raise ManifestError(f"archive missing required recovery file: {path}")
        if spec.size <= 0:
            raise ManifestError(f"required recovery file empty: {path}")


def file_checksum_map(manifest: dict[str, Any]) -> dict[str, str]:
    specs = inventory_to_member_specs(manifest)
    return {p: m.sha256 for p, m in specs.items() if m.type == "file" and m.sha256}


def validate_internal_manifest(manifest: dict[str, Any]) -> None:
    if not isinstance(manifest, dict):
        raise ManifestError("manifest not an object")
    if manifest.get("format_version") != MANIFEST_FORMAT_VERSION:
        raise ManifestError(
            f"unsupported manifest format_version={manifest.get('format_version')!r}"
        )
    for key in ("backup_id", "project_id", "fleet_id", "created_at", "method"):
        if not manifest.get(key):
            raise ManifestError(f"manifest missing {key}")
    if manifest.get("method") != "cold-physical":
        raise ManifestError("unsupported backup method")
    if manifest.get("profile") not in {None, "standard"}:
        raise ManifestError("unsupported profile")
    inventory_to_member_specs(manifest)
    paths = {e["path"] for e in manifest["inventory"]}
    if "manifest.json" in paths:
        # Manifest is written into the archive but must not checksum itself in inventory.
        # Prefer inventory without self-entry; if present, refuse.
        raise ManifestError("manifest must not include itself in inventory checksum list")
    # Required unit prefixes / files.
    required_prefixes = ("postgres/", "db-config/", "storage/", "deployment/")
    for prefix in required_prefixes:
        if not any(p == prefix.rstrip("/") or p.startswith(prefix) for p in paths):
            raise ManifestError(f"archive missing required unit: {prefix}")
    # Explicit recovery-critical files (not merely unit prefixes).
    for required in (
        "project.json",
        "deployment/.env",
        "db-config/pgsodium_root.key",
    ):
        if required not in paths:
            raise ManifestError(f"archive missing required recovery file: {required}")


def require_db_recovery_facts(manifest: dict[str, Any]) -> None:
    """Refuse recovery receipt when facts required for deterministic DB recovery unknown."""
    images = manifest.get("images") or {}
    db = images.get("db") if isinstance(images, dict) else None
    if not isinstance(db, dict):
        raise ManifestError("manifest missing db image facts required for recovery")
    for key in ("image_ref", "image_id"):
        val = db.get(key)
        if not val or val == "UNKNOWN":
            raise ManifestError(f"db {key} UNKNOWN; cannot issue recovery receipt")
    pg = manifest.get("postgres") or {}
    if not isinstance(pg, dict):
        raise ManifestError("manifest missing postgres control facts")
    state = (pg.get("cluster_state") or "").lower()
    if "shut down" not in state:
        raise ManifestError("postgres cluster was not cleanly shut down")
    if not pg.get("pg_version") and not pg.get("major"):
        raise ManifestError("postgres version facts missing")


def project_identity_matches(manifest: dict[str, Any], destination_project_id: str) -> None:
    src = str(manifest.get("project_id") or "")
    if src != destination_project_id:
        raise ManifestError(
            f"project identity mismatch: archive project_id={src} "
            f"destination={destination_project_id}"
        )


def compatibility_matches(
    manifest: dict[str, Any],
    *,
    destination_images: dict[str, Any] | None = None,
    destination_upstream: dict[str, Any] | None = None,
    require_same_pin: bool = True,
) -> None:
    """Refuse incompatible runtime/image/PG facts; same-pin restore is the V1 contract."""
    images = manifest.get("images") or {}
    if not isinstance(images, dict):
        raise ManifestError("manifest images invalid")
    upstream = manifest.get("upstream") or {}
    if require_same_pin:
        aref = str(upstream.get("ref") or "")
        asha = str(upstream.get("sha") or "")
        if not aref or not asha or asha == "UNKNOWN":
            raise ManifestError("archive missing approved upstream pin facts")
        if not destination_upstream:
            raise ManifestError("destination authoritative upstream pin facts unavailable")
        dref = str(destination_upstream.get("ref") or "")
        dsha = str(destination_upstream.get("sha") or "")
        if not dref or not dsha or dsha == "UNKNOWN":
            raise ManifestError("destination upstream pin UNKNOWN; refuse restore")
        if aref != dref or asha != dsha:
            raise ManifestError(
                f"cross-pin restore refused: archive {aref}@{asha[:12]} "
                f"!= destination {dref}@{dsha[:12]} (same-pin only)"
            )
    if not destination_images:
        raise ManifestError("destination image facts unavailable; refuse restore")
    dest_db = destination_images.get("db") or {}
    src_db = images.get("db") or {}
    for key in ("image_id", "image_ref"):
        s = src_db.get(key)
        d = dest_db.get(key)
        if not s or s == "UNKNOWN" or not d or d == "UNKNOWN":
            raise ManifestError(f"db {key} UNKNOWN on archive or destination; refuse restore")
        if s != d:
            raise ManifestError(f"db {key} incompatible: archive={s} destination={d}")
    src_plat = src_db.get("platform") or manifest.get("platform")
    dest_plat = dest_db.get("platform")
    if not src_plat or src_plat == "UNKNOWN" or not dest_plat or dest_plat == "UNKNOWN":
        raise ManifestError("platform UNKNOWN on archive or destination; refuse restore")
    if src_plat != dest_plat:
        raise ManifestError(f"platform mismatch: archive={src_plat} destination={dest_plat}")
    pg = manifest.get("postgres") or {}
    major = pg.get("major")
    if major is not None and not isinstance(major, int):
        try:
            int(str(major).split(".")[0])
        except ValueError as exc:
            raise ManifestError("invalid postgres major") from exc


def require_same_pin(
    manifest: dict[str, Any],
    *,
    destination_ref: str,
    destination_sha: str,
) -> None:
    """Same-pin restore only — refuse UNKNOWN and cross-ref/cross-SHA restores."""
    upstream = manifest.get("upstream") or {}
    if not isinstance(upstream, dict):
        raise ManifestError("archive upstream pin missing")
    src_ref = str(upstream.get("ref") or "").strip()
    src_sha = str(upstream.get("sha") or "").strip()
    dest_ref = str(destination_ref or "").strip()
    dest_sha = str(destination_sha or "").strip()
    if (
        not src_ref
        or not src_sha
        or src_ref == "UNKNOWN"
        or src_sha == "UNKNOWN"
        or len(src_sha) != 40
    ):
        raise ManifestError("archive upstream pin UNKNOWN; refuse restore")
    if (
        not dest_ref
        or not dest_sha
        or dest_ref == "UNKNOWN"
        or dest_sha == "UNKNOWN"
        or len(dest_sha) != 40
    ):
        raise ManifestError("destination pin UNKNOWN; refuse restore")
    if src_ref != dest_ref or src_sha != dest_sha:
        raise ManifestError(
            "cross-pin restore refused (same-pin only): "
            f"archive={src_ref}@{src_sha[:12]} destination={dest_ref}@{dest_sha[:12]}"
        )


def receipt_archive_binding_ok(
    receipt: dict[str, Any],
    *,
    ciphertext_sha256: str,
    project_id: str,
    backup_id: str,
    manifest_sha256: str | None = None,
) -> None:
    """When a sidecar receipt exists, verify receipt/archive binding (not provenance)."""
    if receipt.get("ciphertext_sha256") and receipt["ciphertext_sha256"] != ciphertext_sha256:
        raise ManifestError("receipt/archive binding failed: ciphertext_sha256 mismatch")
    if receipt.get("project_id") and receipt["project_id"] != project_id:
        raise ManifestError("receipt/archive binding failed: project_id mismatch")
    if receipt.get("backup_id") and receipt["backup_id"] != backup_id:
        raise ManifestError("receipt/archive binding failed: backup_id mismatch")
    if (
        manifest_sha256
        and receipt.get("manifest_sha256")
        and receipt["manifest_sha256"] != manifest_sha256
    ):
        raise ManifestError("receipt/archive binding failed: manifest_sha256 mismatch")


def public_receipt(
    *,
    backup_id: str,
    project_id: str,
    slug: str,
    digest: str,
    size: int,
    upstream: dict | None,
    verification: str,
    manifest_sha256: str | None = None,
    prior_state: str | None = None,
    recovery: dict[str, Any] | None = None,
    note: str | None = None,
    operation_id: str | None = None,
) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "format_version": RECEIPT_FORMAT_VERSION,
        "backup_id": backup_id,
        "project_id": project_id,
        "slug": slug,
        "created_at": utc_now(),
        "ciphertext_sha256": digest,
        "ciphertext_bytes": size,
        "upstream": upstream or {},
        "includes": ["postgres", "storage", "db-config", "deployment", "project.json"],
        "verification": verification,
        "verified": verification == VERIFICATION_RECOVERY,
        "method": "cold-physical",
    }
    if operation_id:
        receipt["operation_id"] = operation_id
    if manifest_sha256:
        receipt["manifest_sha256"] = manifest_sha256
    if prior_state:
        receipt["prior_state"] = prior_state
    if recovery:
        receipt["recovery"] = recovery
    if note:
        receipt["note"] = note
    return receipt


# Back-compat alias used by older unit tests / imports via backup.manifest_for
def manifest_for(
    *,
    project_id: str,
    backup_id: str,
    digest: str,
    size: int,
    slug: str = "",
    upstream: dict | None = None,
) -> dict:
    return public_receipt(
        backup_id=backup_id,
        project_id=project_id,
        slug=slug,
        digest=digest,
        size=size,
        upstream=upstream,
        verification=VERIFICATION_NONE,
    )
