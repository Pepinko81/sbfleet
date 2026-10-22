"""Verified same-pin clone, separate from strict same-project restore."""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from sbfleet import authority as auth
from sbfleet import backup as bak
from sbfleet import registry as reg
from sbfleet import upstream as up
from sbfleet.archive_safe import sha256_file
from sbfleet.backup_manifest import compatibility_matches, file_checksum_map
from sbfleet.backup_recovery import (
    _copy_tree_to_volume,
    capture_source_recovery_facts,
    verify_storage_tree,
)
from sbfleet.health import collect_status, collect_status_for_mutation, lifecycle_op_succeeded
from sbfleet.pooler_rebind import (
    SUPPORTED_PIN,
    RebindError,
    rebind_pooler,
    sql,
    tenant_id,
    verify_pooler,
)
from sbfleet.process import run
from sbfleet.projects import create_project, start_project, stop_project
from sbfleet.ux import QuietProgress


class CloneError(Exception):
    """Only fixed, nonsecret failure classifications leave this module."""


def _compose(ctx, *args):
    result = run(
        ["docker", "compose", *args],
        cwd=ctx.deployment,
        env=ctx.compose_env,
        timeout=180,
        check=False,
    )
    if not result.ok:
        raise CloneError("destination_compose_failed")


def _prove_new_identity(root, source, target):
    reg.validate_project_identity(root, target)
    for record in reg.list_projects(root):
        if record.path.name == target["slug"]:
            continue
        if record.error:
            raise CloneError("fleet_identity_unknown")
        other = reg.validate_project_identity(root, record.data)
        if (
            other["id"] == target["id"]
            or other["compose_project"] == target["compose_project"]
            or set(other["ports"].values()) & set(target["ports"].values())
        ):
            raise CloneError("destination_identity_collision")
    if target["upstream"] != source["upstream"] or target["upstream"] != SUPPORTED_PIN:
        raise CloneError("unsupported_pin")


def _install(ctx, extract, archived_env):
    destination_env = up.parse_dotenv((ctx.deployment / ".env").read_text())
    reconciled = bak.reconcile_destination_env(
        archived_env=archived_env, destination_env=destination_env, destination_meta=ctx.meta
    )
    # Clone policy is distinct from ordinary same-project recovery.
    for key in ("DASHBOARD_PASSWORD", "DASHBOARD_USERNAME"):
        reconciled[key] = destination_env[key]
    # Only DB is started until the source-derived pooler rows have been rebound.
    reconciled["POOLER_TENANT_ID"] = tenant_id(ctx.project_id)
    env_path = ctx.deployment / ".env"
    env_path.write_text(up.dump_dotenv(reconciled))
    env_path.chmod(0o600)
    auth.revalidate_deployment_authority(ctx)
    for rel, dest, owner in (
        ("postgres", "db/data", "100:1000"),
        ("storage", "storage", "1000:1000"),
        ("deployment/functions", "functions", None),
        ("deployment/snippets", "snippets", None),
    ):
        bak._install_unit_from_extract(
            extract / rel, ctx.deployment / "volumes" / dest, chown=owner, label=rel
        )
    inventory = auth.invent_owned_resources(
        compose_project=ctx.compose_project,
        fleet_id=ctx.fleet_id,
        project_id=ctx.project_id,
        deployment=ctx.deployment,
        contract=ctx.contract,
    )
    volume = f"{ctx.compose_project}_db-config"
    if inventory.residuals or volume not in {v.name for v in inventory.volumes}:
        raise CloneError("destination_volume_authority_unknown")
    _copy_tree_to_volume(
        extract / "db-config",
        volume,
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
    raise CloneError("destination_database_unavailable")


def _verify_recovered(ctx, manifest, source_id):
    if not lifecycle_op_succeeded(collect_status_for_mutation(ctx), expect="HEALTHY"):
        raise CloneError("destination_health_failed")
    facts = capture_source_recovery_facts(ctx.deployment, ctx.compose_project)
    if facts != manifest.get("source_facts"):
        raise CloneError("destination_recovery_facts_mismatch")
    storage = verify_storage_tree(
        ctx.deployment / "volumes" / "storage", file_checksum_map(manifest)
    )
    if not storage.ok:
        raise CloneError("destination_storage_mismatch")
    crypto = manifest.get("source_crypto") or {}
    # A challenge name is an exact archive fact, not an SQL identifier/expression.
    name = str(crypto.get("name", "")).replace("'", "''")
    plain = sql(
        ctx,
        f"SELECT decrypted_secret FROM vault.decrypted_secrets WHERE name='{name}'",
        database="postgres",
    )
    try:
        digest = hashlib.sha256(
            bytes.fromhex(crypto["salt_hex"]) + bytes.fromhex(plain)
        ).hexdigest()
    except (ValueError, KeyError):
        raise CloneError("destination_vault_proof_failed") from None
    if digest != crypto.get("digest_sha256"):
        raise CloneError("destination_vault_proof_failed")
    verify_pooler(ctx, source_project_id=source_id)


def _cleanup_target(root, target, operation_id):
    """Only this operation's proven incomplete target. Never clear a journal to remove."""
    from sbfleet.projects_remove import _rm_by_id

    with auth.authorize_mutation(
        root, target["slug"], intent="stop", ignore_unresolved_journal=True
    ) as ctx:
        journal = reg.read_operation_journal(root, target["slug"]) or {}
        if ctx.project_id != target["id"] or journal.get("operation_id") != operation_id:
            raise CloneError("cleanup_authority_changed")
        stop_project(root, target["slug"], already_locked=True, manage_journal=False)
        inventory = auth.invent_owned_resources(
            compose_project=ctx.compose_project,
            fleet_id=ctx.fleet_id,
            project_id=ctx.project_id,
            deployment=ctx.deployment,
            contract=ctx.contract,
        )
        if inventory.residuals:
            raise CloneError("cleanup_foreign_resources")
        for resource in inventory.containers + inventory.networks + inventory.volumes:
            _rm_by_id(resource.kind, resource.resource_id)
        remaining = auth.invent_owned_resources(
            compose_project=ctx.compose_project,
            fleet_id=ctx.fleet_id,
            project_id=ctx.project_id,
            deployment=ctx.deployment,
            contract=ctx.contract,
        )
        if remaining.residuals or remaining.all_ids:
            raise CloneError("cleanup_resources_remain")
        reg.assert_managed_entry(
            ctx.project_dir, under=root / "projects", expect_dir=True, refuse_mountpoint=True
        )
        bak._wipe_staging(ctx.project_dir)


def clone_project(root: Path, source: str, target: str, *, identity: str | None = None) -> dict:
    """Return a versioned allowlisted outcome, including failures; never raw diagnostics."""
    operation_id = uuid.uuid4().hex
    result = {
        "schema_version": "sbfleet.clone.v1",
        "source": source,
        "target": target,
        "pin": None,
        "destination_identity": None,
        "operation_id": operation_id,
        "verification": "NOT_VERIFIED",
        "final_state": "UNKNOWN",
        "attention": [],
        "success": False,
    }
    target_meta = None
    destination_operation = None
    staging = None
    record = None
    phase = "preflight"
    try:
        reg.validate_slug(source)
        reg.validate_slug(target)
        if source == target:
            raise CloneError("target_exists")
        reg.assert_managed_entry(root, under=root, expect_dir=True)
        reg.fleet_id(root)
        target_path = reg.project_dir(root, target)
        if target_path.exists() or target_path.is_symlink():
            raise CloneError("target_exists")
        # Do not initialize a missing source/fleet just to report a clone refusal.
        source_meta = reg.validate_project_identity(root, reg.read_project(root, source))
        if source_meta.get("upstream") != SUPPORTED_PIN:
            raise CloneError("unsupported_pin")
        result["pin"] = dict(SUPPORTED_PIN)
        age = bak._require_age()
        key = bak._resolve_identity(identity)
        if key is None:
            raise CloneError("backup_identity_required")
        bak._fleet_recipients(root)
        records = root / "clone-operations"
        if records.is_symlink():
            raise CloneError("unsafe_evidence_path")
        records.mkdir(mode=0o700, exist_ok=True)
        reg.assert_managed_entry(records, under=root, expect_dir=True)
        record_candidate = records / f"{operation_id}.json"
        fd = os.open(record_candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(result, stream, sort_keys=True)
        record = record_candidate
        staging_candidate = root / "staging" / f"clone-{operation_id}"
        reg.assert_managed_entry(root / "staging", under=root, expect_dir=True)
        staging_candidate.mkdir(mode=0o700)
        staging = staging_candidate
        with auth.authorize_mutation(root, source, intent="backup") as ctx:
            if ctx.meta.get("upstream") != SUPPORTED_PIN:
                raise CloneError("unsupported_pin")
            if target_path.exists() or target_path.is_symlink():
                raise CloneError("target_exists")
            source_meta = dict(ctx.meta)
            source_env_hash = sha256_file(ctx.deployment / ".env")
            bak.disk_preflight(root, ctx.deployment, staging_path=staging)
            phase = "source_backup"
            auth.begin_operation(ctx, phase="clone_source_backup")
            try:
                fresh = bak._create_backup_locked(ctx, verify=True, identity=key)
                if (
                    fresh.verification != "recovery"
                    or not fresh.cleanup_ok
                    or fresh.restart_ok is False
                ):
                    raise CloneError("source_backup_not_verified_or_restored")
                if sha256_file(ctx.deployment / ".env") != source_env_hash:
                    raise CloneError("source_configuration_changed")
                auth.complete_operation(
                    ctx, phase="completed", evidence={"backup_id": fresh.backup_id}
                )
            except Exception:
                auth.fail_operation(ctx, error="clone source backup failed", phase="failed")
                raise
            phase = "archive_validation"
            decrypted = staging / "payload.tar"
            decrypted_result = run(
                [age, "-d", "-i", str(key), "-o", str(decrypted), str(fresh.archive_path)],
                env={"PATH": os.environ.get("PATH", "")},
                timeout=600,
                check=False,
            )
            if not decrypted_result.ok:
                raise CloneError("archive_decrypt_failed")
            manifest, archived_env, _ = bak.prevalidate_restore_archive(
                tar_path=decrypted,
                extract_dir=staging / "extract",
                destination_project_id=ctx.project_id,
                destination_meta=ctx.meta,
                deployment=ctx.deployment,
                root=root,
                ciphertext_sha256=sha256_file(fresh.archive_path),
                filename_backup_id=fresh.backup_id,
                receipt=fresh.receipt,
            )
            # Still validates ORIGINAL source UUID; no manifest/receipt rewriting.
            bak.disk_preflight(root, ctx.deployment, staging_path=staging)
        phase = "destination_creation"
        target_meta = create_project(
            root,
            target,
            start=False,
            progress=QuietProgress(),
            upstream_ref=SUPPORTED_PIN["ref"],
            upstream_sha=SUPPORTED_PIN["sha"],
        )
        _prove_new_identity(root, source_meta, target_meta)
        result["destination_identity"] = {
            k: target_meta[k] for k in ("id", "fleet_id", "compose_project", "ports")
        }
        with auth.authorize_mutation(root, target, intent="restore") as ctx:
            destination_operation = ctx.operation_id
            auth.begin_operation(ctx, phase="clone_initializing")
            try:
                # Bootstrap only the new destination, to establish owned volumes/images.
                start_project(
                    root,
                    target,
                    already_locked=True,
                    manage_journal=False,
                    progress=QuietProgress(),
                )
                stop_project(root, target, already_locked=True, manage_journal=False)
                ctx.meta = reg.read_project(root, target)
                pin = bak._authoritative_destination_pin(root, ctx.deployment, ctx.meta)
                images = bak._authoritative_destination_images(
                    ctx.deployment, ctx.compose_project, ctx.meta
                )
                compatibility_matches(manifest, destination_images=images, destination_upstream=pin)
                phase = "destination_install"
                auth.record_operation_phase(ctx, phase=phase)
                _install(ctx, staging / "extract", archived_env)
                phase = "pooler_rebind"
                auth.record_operation_phase(ctx, phase=phase)
                rebind_pooler(ctx, source_project_id=source_meta["id"], manifest=manifest)
                phase = "destination_verify"
                auth.record_operation_phase(ctx, phase=phase)
                start_project(
                    root,
                    target,
                    already_locked=True,
                    manage_journal=False,
                    progress=QuietProgress(),
                )
                _verify_recovered(ctx, manifest, source_meta["id"])
                stop_project(root, target, already_locked=True, manage_journal=False)
                if not lifecycle_op_succeeded(collect_status_for_mutation(ctx), expect="STOPPED"):
                    raise CloneError("destination_not_stopped")
                auth.complete_operation(
                    ctx,
                    phase="completed",
                    evidence={
                        "clone_operation_id": operation_id,
                        "source_project_id": source_meta["id"],
                        "source_backup_id": fresh.backup_id,
                        "destination_verified": True,
                        "pooler_rebound": True,
                        "final_state": "STOPPED",
                    },
                )
            except Exception:
                auth.fail_operation(ctx, error="clone destination failed", phase=phase)
                raise
        phase = "source_postcondition"
        current = reg.read_project(root, source)
        if any(
            current[k] != source_meta[k]
            for k in ("id", "fleet_id", "compose_project", "ports", "upstream")
        ):
            raise CloneError("source_identity_changed")
        if sha256_file(reg.project_dir(root, source) / "deployment" / ".env") != source_env_hash:
            raise CloneError("source_configuration_changed")
        if not lifecycle_op_succeeded(collect_status(root, source), expect=fresh.prior_state):
            raise CloneError("source_prior_state_not_preserved")
        phase = "plaintext_cleanup"
        bak._wipe_staging(staging)
        staging = None
        result.update(success=True, verification="VERIFIED", final_state="STOPPED")
    except Exception as exc:
        result["attention"] = [str(exc) if isinstance(exc, CloneError) else f"{phase}_failed"]
        if target_meta and destination_operation:
            try:
                _cleanup_target(root, target_meta, destination_operation)
                result["final_state"] = "REMOVED"
            except Exception:
                result["attention"].append("target_retained_for_review")
        elif target_meta:
            result["attention"].append("target_retained_for_review")
    finally:
        if staging is not None:
            try:
                bak._wipe_staging(staging)
            except Exception:
                result["success"] = False
                result["attention"].append("plaintext_cleanup_incomplete")
        if record is not None:
            try:
                reg.atomic_write_json(record, result)
            except Exception:
                result["success"] = False
                result["attention"].append("evidence_write_failed")
    return result


def clone_cmd(root: Path, source: str, target: str, *, identity=None, as_json=False) -> int:
    with open(os.devnull, "w") as quiet, redirect_stdout(quiet), redirect_stderr(quiet):
        result = clone_project(root, source, target, identity=identity)
    if as_json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"clone {source} -> {target}: {result['verification']} / {result['final_state']}")
        if result["attention"]:
            print("attention: " + ", ".join(result["attention"]))
    return 0 if result["success"] else 5
