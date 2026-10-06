"""Read-only doctor checks.

Every check has an explicit criticality class. Exit code, JSON ``ok``, and
human rows derive from the same classification — there is no generic
UNKNOWN→warning rule.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from sbfleet import registry as reg
from sbfleet.cli import EXIT_OK, EXIT_PREREQUISITE, EXIT_SAFETY, EXIT_UNHEALTHY
from sbfleet.process import (
    CREDENTIAL_SAFE_RENDERING_UNAVAILABLE,
    DiagnosticRedactorUnavailable,
    Redactor,
    run,
    sanitize_configured_diagnostic,
    sanitize_diagnostic,
)
from sbfleet.upstream import PINNED_REF, require_local_node

# Criticality classes (impact). Exit priority: safety > prerequisite > unhealthy.
CLASS_SAFETY = "safety"
CLASS_PREREQUISITE = "prerequisite"
CLASS_HEALTH = "health"
CLASS_INFORMATIONAL = "informational"

# Default criticality by check id. UNKNOWN/FAIL on non-informational classes
# produce nonzero exits per _exit_for_checks.
CHECK_CLASS: dict[str, str] = {
    # Host prerequisites
    "docker": CLASS_PREREQUISITE,
    "docker-daemon": CLASS_PREREQUISITE,
    "docker-compose": CLASS_PREREQUISITE,
    "node": CLASS_PREREQUISITE,
    "age": CLASS_INFORMATIONAL,
    "sandbox-cli": CLASS_INFORMATIONAL,
    "disk": CLASS_HEALTH,
    # Project identity / authority
    "project-meta": CLASS_SAFETY,
    "project-env": CLASS_SAFETY,
    "secret-file": CLASS_SAFETY,
    "vendor-integrity": CLASS_SAFETY,
    "compose-contract": CLASS_SAFETY,
    "live-ownership": CLASS_SAFETY,
    "journal": CLASS_SAFETY,
    "backup": CLASS_SAFETY,
    # Runtime
    "health": CLASS_HEALTH,
    "upstream-pin": CLASS_INFORMATIONAL,
    "runtime-images-recorded": CLASS_INFORMATIONAL,
    "runtime-images-current": CLASS_INFORMATIONAL,
    # Branding / public URL shape (informational unless fail on required URL)
    "public-url": CLASS_INFORMATIONAL,
    "public-host-match": CLASS_INFORMATIONAL,
    "public-https": CLASS_INFORMATIONAL,
    "api-external-url": CLASS_INFORMATIONAL,
    "site-url": CLASS_INFORMATIONAL,
    "site-url-distinct": CLASS_INFORMATIONAL,
    "google-enabled": CLASS_INFORMATIONAL,
    "google-client-id": CLASS_INFORMATIONAL,
    "google-secret": CLASS_INFORMATIONAL,
    # Sandbox
    "sandbox-path": CLASS_PREREQUISITE,
    "sandbox-cli-version": CLASS_PREREQUISITE,
    "sandbox-adoption": CLASS_SAFETY,
    "sandbox-config": CLASS_SAFETY,
    "sandbox-dotenv": CLASS_SAFETY,
    "sandbox-linked": CLASS_SAFETY,
    "sandbox-fingerprint": CLASS_SAFETY,
    "sandbox-network": CLASS_SAFETY,
    "sandbox-inventory": CLASS_INFORMATIONAL,
    "sandbox-endpoints": CLASS_INFORMATIONAL,
    "sandbox-canonical-root": CLASS_SAFETY,
}


def _class_for(cid: str) -> str:
    if cid in CHECK_CLASS:
        return CHECK_CLASS[cid]
    if cid.startswith("sandbox-"):
        return CLASS_SAFETY
    if cid.startswith("google-") or cid.startswith("public-") or cid.startswith("site-"):
        return CLASS_INFORMATIONAL
    return CLASS_HEALTH


def _exit_for_checks(checks: list[dict[str, str]]) -> int:
    """Derive exit from explicit check criticality (safety > prerequisite > unhealthy)."""
    has_safety = False
    has_prereq = False
    has_health = False
    for c in checks:
        status = c.get("status", "")
        cls = c.get("class") or _class_for(c["id"])
        if status not in {"fail", "unknown"}:
            continue
        if cls == CLASS_INFORMATIONAL:
            # Informational UNKNOWN/WARN never force nonzero; FAIL on informational
            # is still treated as unhealthy so broken optional config is visible.
            if status == "fail":
                has_health = True
            continue
        if status == "unknown" and cls == CLASS_INFORMATIONAL:
            continue
        # Authority-sensitive / prerequisite / health: UNKNOWN and FAIL are nonzero.
        if cls == CLASS_SAFETY:
            has_safety = True
        elif cls == CLASS_PREREQUISITE:
            has_prereq = True
        else:
            has_health = True
    if has_safety:
        return EXIT_SAFETY
    if has_prereq:
        return EXIT_PREREQUISITE
    if has_health:
        return EXIT_UNHEALTHY
    return EXIT_OK


def run_doctor(
    root: Path,
    *,
    project: str | None,
    sandbox: str | None,
    as_json: bool,
) -> int:
    if project and sandbox:
        print("error: --sandbox mutually exclusive with project", file=sys.stderr)
        return 2
    checks: list[dict[str, str]] = []
    diag_redactor: Redactor | None = None
    diag_redactor_ok = True

    def add(
        cid: str,
        status: str,
        reason: str,
        action: str,
        *,
        cls: str | None = None,
    ) -> None:
        krit = cls or _class_for(cid)
        if not diag_redactor_ok:
            safe_reason = CREDENTIAL_SAFE_RENDERING_UNAVAILABLE[:240]
        else:
            safe_reason = sanitize_configured_diagnostic(
                str(reason),
                redactor=diag_redactor,
                max_len=240,
            )
        checks.append(
            {
                "id": cid,
                "status": status,
                "reason": safe_reason,
                "action": action,
                "class": krit,
            }
        )

    # For project-scoped doctor, construct configured redactor BEFORE any
    # potentially secret-bearing host/Docker diagnostic is accumulated.
    if project:
        deployment = reg.project_dir(root, project) / "deployment"
        try:
            from sbfleet.process import project_diagnostic_redactor

            diag_redactor = project_diagnostic_redactor(deployment)
            diag_redactor_ok = True
        except DiagnosticRedactorUnavailable:
            diag_redactor = Redactor()
            diag_redactor_ok = False

    # Host checks
    if shutil.which("docker"):
        di = run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            timeout=30.0,
            check=False,
        )
        if di.ok:
            add("docker-daemon", "pass", f"daemon ok version={(di.stdout or '').strip()}", "none")
        else:
            add(
                "docker-daemon",
                "fail",
                di.stderr or "docker info failed",
                "start Docker daemon",
            )
        cv = run(
            ["docker", "compose", "version"],
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            timeout=30.0,
            check=False,
        )
        if cv.ok:
            add("docker-compose", "pass", (cv.stdout or "").strip()[:120], "none")
        else:
            add("docker-compose", "fail", "compose plugin missing/failed", "install Compose v2+")
        add("docker", "pass", "docker binary present", "none")
    else:
        add("docker", "fail", "docker missing", "install Docker Engine")
        add("docker-daemon", "unknown", "docker binary missing", "install Docker Engine")
        add("docker-compose", "unknown", "docker binary missing", "install Compose")

    from sbfleet.tools import PINNED_AGE, PINNED_SUPABASE_CLI, resolve_age, resolve_supabase

    age_path, age_detail = resolve_age()
    if age_path:
        add("age", "pass", f"age present ({age_detail})", "none")
    else:
        add(
            "age",
            "warn",
            "age missing",
            f"run scripts/install-user.sh for managed age {PINNED_AGE}",
        )

    supabase_path, supabase_detail = resolve_supabase()
    if supabase_path:
        add(
            "sandbox-cli",
            "pass",
            f"supabase {PINNED_SUPABASE_CLI} ({supabase_detail})",
            "none",
        )
    else:
        add(
            "sandbox-cli",
            "warn",
            supabase_detail,
            f"run scripts/install-user.sh for managed supabase {PINNED_SUPABASE_CLI}",
        )

    try:
        require_local_node()
        add("node", "pass", "node >=16", "none")
    except Exception as exc:  # noqa: BLE001
        add("node", "fail", str(exc), "install Node >=16")

    try:
        usage = shutil.disk_usage(root)
        free_gb = usage.free / (1024**3)
        if free_gb < 2:
            add("disk", "fail", f"free={free_gb:.1f}GiB", "free disk space")
        elif free_gb < 10:
            add("disk", "warn", f"free={free_gb:.1f}GiB", "monitor disk")
        else:
            add("disk", "pass", f"free={free_gb:.1f}GiB", "none")
    except OSError as exc:
        add("disk", "unknown", str(exc), "check filesystem")

    if project:
        _doctor_project(root, project, add)

    if sandbox:
        add(
            "sandbox-path",
            "pass" if Path(sandbox).is_dir() else "fail",
            sandbox,
            "check path",
        )
        if Path(sandbox).is_dir():
            try:
                from sbfleet.process import sandbox_diagnostic_redactor

                diag_redactor = sandbox_diagnostic_redactor(Path(sandbox).resolve())
                diag_redactor_ok = True
            except DiagnosticRedactorUnavailable:
                diag_redactor = Redactor()
                diag_redactor_ok = False
            from sbfleet.sandbox import doctor_sandbox_checks

            for c in doctor_sandbox_checks(sandbox, home=root):
                add(
                    c["id"],
                    c["status"],
                    c.get("detail") or c.get("reason") or "",
                    c.get("next") or c.get("action") or "none",
                )

    worst = _exit_for_checks(checks)

    if as_json:
        print(
            json.dumps(
                {
                    "format_version": 1,
                    "ok": worst == EXIT_OK,
                    "command": "doctor",
                    "data": {"checks": checks},
                    "warnings": [],
                    "errors": [],
                }
            )
        )
    else:
        for c in checks:
            print(f"{c['id']}\t{c['status']}\t{c['reason']}\t{c['action']}")
    return worst


def _doctor_project(root: Path, project: str, add) -> None:  # noqa: ANN001
    try:
        meta = reg.read_project(root, project)
        add("project-meta", "pass", f"slug={project} id={meta.get('id')}", "none")
    except reg.RegistryError as exc:
        add("project-meta", "fail", str(exc), "inspect registry")
        return

    if meta.get("upstream", {}).get("ref") != PINNED_REF:
        add("upstream-pin", "warn", "ref differs from current pin", "plan update")
    else:
        add("upstream-pin", "pass", PINNED_REF, "none")

    deployment = reg.project_dir(root, project) / "deployment"
    env: dict[str, str] | None = None
    env_path = deployment / ".env"

    if env_path.is_file():
        from sbfleet import upstream as up

        try:
            env = up.parse_dotenv(env_path.read_text(encoding="utf-8"))
            add("project-env", "pass", "dotenv parsed", "none")
        except up.UpstreamError as exc:
            add("project-env", "fail", str(exc), "inspect deployment/.env")
            env = None
        try:
            reg.assert_secret_file(env_path)
            add("secret-file", "pass", "mode/owner/nlink ok", "none")
        except reg.OwnershipError as exc:
            add("secret-file", "fail", str(exc), "fix .env permissions without chmod by sbfleet")
        try:
            sha = str((meta.get("upstream") or {}).get("sha") or "")
            if sha:
                up.verify_deployment_vendor(deployment, sha=sha, root=root)
                up.verify_stamp_matches_meta(deployment, meta)
                add("vendor-integrity", "pass", "matches upstream-anchored digests", "none")
            else:
                add("vendor-integrity", "unknown", "upstream sha missing in meta", "inspect meta")
        except Exception as exc:  # noqa: BLE001
            add("vendor-integrity", "fail", str(exc), "refuse start; rematerialize")
    else:
        add("project-env", "fail", ".env missing", "resume create or restore")
        add("secret-file", "fail", ".env missing", "resume create or restore")

    from sbfleet.branding import doctor_auth_checks

    for check in doctor_auth_checks(meta, env):
        add(
            check["id"],
            check["status"],
            check.get("reason") or check.get("detail") or "",
            check.get("action") or check.get("next") or "none",
        )

    # Effective Compose contract (read-only) — reuse production mutation prep path (V3-011).
    try:
        from sbfleet import authority as auth

        fleet_id = str(meta["fleet_id"])
        project_id = str(meta["id"])
        cp = reg.compose_project_name(fleet_id, project_id)
        contract = auth.build_project_contract(root, meta, deployment, cp)
        auth._validate_effective_compose(deployment, meta, cp, contract)
        add(
            "compose-contract",
            "pass",
            "effective compose validated against approved contract",
            "none",
        )
    except Exception as exc:  # noqa: BLE001
        add(
            "compose-contract",
            "fail",
            str(exc),
            "inspect compose/authority",
        )

    # Live ownership observation (read-only invent) with recorded image IDs when available.
    try:
        from sbfleet import authority as auth

        fleet_id = str(meta["fleet_id"])
        project_id = str(meta["id"])
        cp = reg.compose_project_name(fleet_id, project_id)
        contract = auth.build_project_contract(root, meta, deployment, cp)
        recorded: dict[str, str] = {}
        raw_digests = meta.get("image_digests")
        if isinstance(raw_digests, dict):
            for svc, entry in raw_digests.items():
                if svc.startswith("_"):
                    continue
                if isinstance(entry, dict):
                    iid = entry.get("image_id")
                    if iid and iid != "UNKNOWN":
                        recorded[str(svc)] = str(iid)
        inv = auth.invent_owned_resources(
            compose_project=cp,
            fleet_id=fleet_id,
            project_id=project_id,
            deployment=deployment,
            contract=contract,
            require_existing=False,
            recorded_image_ids=recorded or None,
        )
        residuals = list(getattr(inv, "residuals", None) or [])
        if residuals:
            add(
                "live-ownership",
                "fail",
                f"residuals={residuals[:5]}",
                "reconcile foreign/mislabeled resources",
            )
        else:
            n_c = len(getattr(inv, "containers", None) or [])
            add("live-ownership", "pass", f"owned containers={n_c}", "none")
    except Exception as exc:  # noqa: BLE001
        add(
            "live-ownership",
            "fail",
            str(exc),
            "inspect docker ownership",
        )

    # Health
    try:
        from sbfleet.health import HEALTHY, collect_status

        report = collect_status(root, project)
        if report.lifecycle == HEALTHY:
            add("health", "pass", f"lifecycle={report.lifecycle}", "none")
        elif report.lifecycle in {"STOPPED"}:
            add("health", "pass", f"lifecycle={report.lifecycle}", "none")
        else:
            add(
                "health",
                "fail",
                f"lifecycle={report.lifecycle}",
                "status/logs",
            )
    except Exception as exc:  # noqa: BLE001
        add("health", "unknown", str(exc), "inspect project")

    # Journal — shared unresolved policy
    journal = reg.read_operation_journal(root, project) or {}
    if reg.journal_is_unresolved(journal):
        add(
            "journal",
            "fail",
            f"intent={journal.get('intent')} phase={journal.get('phase')} "
            f"state={journal.get('state')}",
            "reconcile interrupted update: "
            "sbfleet update PROJECT --reconcile --operation-id "
            f"{journal.get('operation_id')}",
        )
    else:
        add(
            "journal",
            "pass",
            f"intent={journal.get('intent') or 'none'} phase={journal.get('phase') or 'none'}",
            "none",
        )

    # Backup: currently usable recovery archive, not receipt string alone
    from sbfleet.backup import BackupError, require_recovery_backup

    bid = meta.get("last_backup_id")
    if not bid:
        add("backup", "warn", "no backup receipt", "create backup before remove/update")
    else:
        try:
            require_recovery_backup(root, meta)
            add("backup", "pass", f"recovery archive usable id={bid}", "none")
        except BackupError as exc:
            # Missing/corrupt archive while claiming recovery is a safety fact.
            add("backup", "fail", str(exc), "create recovery-verified backup")

    # Recorded historical image facts (RECORDED metadata — not live Docker truth)
    digests = meta.get("image_digests") or {}
    if not digests:
        add(
            "runtime-images-recorded",
            "unknown",
            "RECORDED: image_digests empty (historical record absent)",
            "start project to record runtime identity",
        )
    else:
        unknown = [
            k for k, v in digests.items() if isinstance(v, dict) and v.get("status") == "UNKNOWN"
        ]
        if unknown:
            add(
                "runtime-images-recorded",
                "unknown",
                f"RECORDED incomplete for {', '.join(unknown[:5])}",
                "re-start or inspect docker images",
            )
        else:
            add(
                "runtime-images-recorded",
                "pass",
                f"RECORDED historical facts={len(digests)}",
                "none",
            )

    # CURRENT runtime identity via actual inspect (informational when absent/unknown)
    try:
        fleet_id = str(meta["fleet_id"])
        project_id = str(meta["id"])
        cp = reg.compose_project_name(fleet_id, project_id)
        current = _current_image_facts(
            deployment, cp, recorded=digests if isinstance(digests, dict) else {}
        )
        status = current.get("status")
        if status == "absent":
            add(
                "runtime-images-current",
                "unknown",
                "CURRENT: no runtime containers available to inspect",
                "start project for live image identity",
            )
        elif status == "ok":
            drift = current.get("drift") or []
            if drift:
                add(
                    "runtime-images-current",
                    "fail",
                    f"CURRENT image mismatch vs RECORDED: {', '.join(drift[:5])}",
                    "inspect runtime images / re-record after start",
                )
            else:
                add(
                    "runtime-images-current",
                    "pass",
                    f"CURRENT inspected services={current.get('inspected_services')} "
                    f"(refs/ids obtained)",
                    "none",
                )
        elif status == "count_only":
            add(
                "runtime-images-current",
                "unknown",
                f"container count={current.get('count')} (not an image inspection)",
                "inspect docker images",
            )
        else:
            add(
                "runtime-images-current",
                "unknown",
                str(current.get("detail") or "CURRENT image inspection failed"),
                "inspect docker images",
            )
    except Exception as exc:  # noqa: BLE001
        add(
            "runtime-images-current",
            "unknown",
            str(exc),
            "inspect docker images",
        )


def _current_image_facts(
    deployment: Path,
    compose_project: str,
    *,
    recorded: dict[str, Any],
) -> dict[str, Any]:
    """Inspect CURRENT runtime image refs/IDs; compare to RECORDED when available.

    Never treats ``docker ps -aq`` count alone as image inspection evidence.
    """
    from sbfleet.health import inspect_containers_result

    inspected = inspect_containers_result(deployment, compose_project)
    if not inspected.ok:
        return {
            "status": "error",
            "detail": inspected.error or "compose ps failed",
        }
    if not inspected.containers:
        return {"status": "absent"}

    services: dict[str, dict[str, str]] = {}
    drift: list[str] = []
    for svc, row in inspected.containers.items():
        entry: dict[str, str] = {
            "image_ref": str(row.get("Image") or row.get("ImageName") or "UNKNOWN"),
            "image_id": "UNKNOWN",
        }
        cid = row.get("ID") or row.get("Container") or row.get("Name")
        if not cid:
            return {
                "status": "error",
                "detail": f"malformed compose ps row for {svc}: missing container id",
            }
        insp = run(
            [
                "docker",
                "inspect",
                "--format",
                "{{.Image}}|{{index .Config.Image}}",
                str(cid),
            ],
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            timeout=30.0,
            check=False,
        )
        if not insp.ok:
            return {
                "status": "error",
                "detail": sanitize_diagnostic(
                    insp.stderr or insp.stdout or f"inspect failed for {svc}",
                    max_len=120,
                ),
            }
        parts = (insp.stdout or "").strip().split("|")
        if not parts or not parts[0]:
            return {
                "status": "error",
                "detail": f"malformed docker inspect for {svc}: empty Image",
            }
        entry["image_id"] = parts[0]
        if len(parts) > 1 and parts[1]:
            entry["image_ref"] = parts[1]
        services[svc] = entry
        rec = recorded.get(svc) if isinstance(recorded.get(svc), dict) else None
        if isinstance(rec, dict):
            rec_id = str(rec.get("image_id") or "")
            if rec_id and rec_id != "UNKNOWN" and rec_id != entry["image_id"]:
                drift.append(svc)

    return {
        "status": "ok",
        "inspected_services": len(services),
        "services": services,
        "drift": drift,
    }
