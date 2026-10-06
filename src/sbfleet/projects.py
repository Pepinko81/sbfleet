"""Official project create/resume and lifecycle wrappers."""

from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sbfleet import compose as c
from sbfleet import registry as reg
from sbfleet import upstream as up
from sbfleet.process import ProcessError, Redactor, StreamingRedactor, run, sanitize_diagnostic

STANDARD_PROFILE = "standard"


class ProjectError(Exception):
    """Project operation failure."""

    def __init__(self, message: str, *, code: int = 1) -> None:
        super().__init__(message)
        self.code = code


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def create_project(
    root: Path,
    slug: str,
    *,
    display_name: str | None = None,
    domain: str | None = None,
    resume: bool = False,
    start: bool = False,
    progress: Any | None = None,
    organization_name: str | None = None,
    studio_project_name: str | None = None,
    site_url: str | None = None,
    additional_redirect_urls: list[str] | None = None,
    google_oauth_enabled: bool = False,
    upstream_ref: str | None = None,
    upstream_sha: str | None = None,
) -> dict[str, Any]:
    """Transactional project creation. start=True starts after config materialization."""
    from sbfleet.branding import BrandingError, build_branding_meta
    from sbfleet.ux import Progress, get_progress

    prog: Progress = progress if progress is not None else get_progress()
    slug = reg.validate_slug(slug)
    name = reg.validate_display_name(display_name or slug)
    if domain is not None:
        _validate_domain(domain)

    public_url_preview = f"https://{domain}" if domain else None
    try:
        branding_extra = build_branding_meta(
            organization_name=organization_name,
            project_name=studio_project_name,
            site_url=site_url,
            additional_redirect_urls=additional_redirect_urls,
            google_oauth_enabled=google_oauth_enabled,
            public_url=public_url_preview,
        )
    except BrandingError as exc:
        raise ProjectError(str(exc), code=2) from exc

    root = reg.ensure_root(root)
    prog.heading(f"Creating {slug}")
    with reg.registry_lock(root):
        existing = reg.project_dir(root, slug)
        if existing.exists():
            if not resume:
                try:
                    meta = reg.read_project(root, slug)
                    if meta.get("creation_complete"):
                        raise ProjectError(f"project '{slug}' already exists", code=5)
                    raise ProjectError(
                        f"project '{slug}' exists incomplete; pass --resume",
                        code=5,
                    )
                except reg.RegistryError as exc:
                    raise ProjectError(
                        f"malformed existing directory for '{slug}' preserved: {exc}",
                        code=5,
                    ) from exc
            meta = reg.read_project(root, slug)
            if meta.get("creation_complete"):
                raise ProjectError(f"project '{slug}' already complete", code=5)
            if meta.get("fleet_id") != reg.fleet_id(root):
                raise ProjectError("fleet ownership mismatch", code=5)
            # Preserve original requested_start if resume omits an explicit start flag
            # by merging caller intent into create_intent before resume materialization.
            intent = dict(meta.get("create_intent") or {})
            if start:
                intent["requested_start"] = True
            if branding_extra:
                intent.setdefault("branding", branding_extra)
            meta["create_intent"] = intent
            reg.write_project(root, meta)
            meta = _resume_create(root, meta, progress=prog)
        elif resume:
            raise ProjectError(f"nothing to resume for '{slug}'", code=3)
        else:
            ports, held = reg.allocate_ports(root)
            try:
                meta = _fresh_create(
                    root,
                    slug,
                    name,
                    domain,
                    ports,
                    progress=prog,
                    branding_extra=branding_extra,
                    requested_start=start,
                    upstream_ref=upstream_ref,
                    upstream_sha=upstream_sha,
                )
            finally:
                reg.release_held_sockets(held)

    intent = dict(meta.get("create_intent") or {})
    want_start = bool(start or intent.get("requested_start"))
    if want_start:
        # Keep final create-completion metadata under registry-before-project lock
        # so concurrent create/remove/start cannot observe an intermediate state.
        with reg.locked_registry_then_project(root, str(meta["id"])):
            meta = reg.read_project(root, slug)
            intent = dict(meta.get("create_intent") or {})
            meta["creation_complete"] = False
            intent["requested_start"] = True
            meta["create_intent"] = intent
            reg.write_project(root, meta)
            try:
                start_project(root, slug, progress=prog, already_locked=True)
                from sbfleet.health import HEALTHY, collect_status, lifecycle_op_succeeded

                report = collect_status(root, slug)
                if not lifecycle_op_succeeded(report, expect=HEALTHY):
                    meta = reg.read_project(root, slug)
                    meta["creation_complete"] = False
                    intent = dict(meta.get("create_intent") or {})
                    intent["requested_start"] = True
                    meta["create_intent"] = intent
                    reg.write_project(root, meta)
                    raise ProjectError(f"start health failed: {report.lifecycle}", code=7)
                meta = reg.read_project(root, slug)
                meta["creation_complete"] = True
                intent = dict(meta.get("create_intent") or {})
                intent["requested_start"] = False
                intent["start_completed"] = True
                meta["create_intent"] = intent
                reg.write_project(root, meta)
            except ProjectError:
                meta = reg.read_project(root, slug)
                meta["creation_complete"] = False
                intent = dict(meta.get("create_intent") or {})
                intent["requested_start"] = True
                meta["create_intent"] = intent
                reg.write_project(root, meta)
                print_startup_failure_hint(root, slug)
                raise
    return reg.read_project(root, slug)


def _validate_domain(domain: str) -> str:
    import re

    if not domain or "/" in domain or ":" in domain or "*" in domain:
        raise ProjectError("invalid domain", code=2)
    if not re.fullmatch(
        r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        r"(?:\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*",
        domain,
    ):
        raise ProjectError("invalid domain hostname", code=2)
    if any(ch in domain for ch in "{};$\\"):
        raise ProjectError("domain contains nginx metacharacters", code=2)
    return domain


def _fresh_create(
    root: Path,
    slug: str,
    display_name: str,
    domain: str | None,
    ports: dict[str, int],
    *,
    upstream_ref: str | None = None,
    upstream_sha: str | None = None,
    progress: Any | None = None,
    branding_extra: dict[str, Any] | None = None,
    requested_start: bool = False,
) -> dict[str, Any]:
    from sbfleet.branding import (
        organization_name,
        project_name,
        resolve_additional_redirects,
        resolve_site_url,
    )
    from sbfleet.ux import Progress, QuietProgress

    prog: Progress = progress if progress is not None else QuietProgress()
    fid = reg.fleet_id(root)
    pid = str(uuid.uuid4())
    cp = reg.compose_project_name(fid, pid)
    public_url = f"https://{domain}" if domain else f"http://127.0.0.1:{ports['gateway']}"
    uref = upstream_ref or up.PINNED_REF
    usha = upstream_sha or (up.resolve_ref_sha(uref) if upstream_ref else up.PINNED_SHA)
    branding = dict(branding_extra or {})
    meta: dict[str, Any] = {
        "format_version": 1,
        "id": pid,
        "fleet_id": fid,
        "slug": slug,
        "display_name": display_name,
        "created_at": _utc_now(),
        "profile": STANDARD_PROFILE,
        "compose_project": cp,
        "ports": ports,
        "domain": domain,
        "public_url": public_url,
        "upstream": {"ref": uref, "sha": usha},
        "last_verified_upstream": None,
        "image_digests": {},
        "creation_complete": False,
        "create_intent": {
            "requested_start": bool(requested_start),
            "upstream_ref": uref,
            "upstream_sha": usha,
            "branding": branding,
            "domain": domain,
            "display_name": display_name,
        },
    }
    if branding:
        meta.update(branding)
    reg.write_project(root, meta)
    prog.step_ok("Registry initialized")
    prog.step_ok("Ports allocated")
    reg.write_operation_journal(
        root,
        slug,
        {"intent": "CREATING", "phase": "reserved", "at": _utc_now()},
    )

    staging = root / "staging" / str(uuid.uuid4())
    staging.mkdir(parents=True, mode=0o700)
    try:
        reg.write_operation_journal(
            root, slug, {"intent": "CREATING", "phase": "upstream", "at": _utc_now()}
        )
        cache = up.materialize_cache(root, ref=uref, sha=usha)
        deployment = reg.project_dir(root, slug) / "deployment"
        up.copy_vendor_docker(cache, deployment, sha=usha, ref=uref)
        prog.step_ok("Upstream materialized")

        reg.write_operation_journal(
            root, slug, {"intent": "CREATING", "phase": "secrets", "at": _utc_now()}
        )
        scratch = staging / "secrets"
        env = up.generate_secrets_in_scratch(
            cache / "docker",
            scratch,
            project_id=pid,
            public_url=public_url,
            gateway_port=ports["gateway"],
            organization_name=organization_name(meta, display_name=display_name),
            project_name=project_name(meta, display_name=display_name),
            site_url=resolve_site_url(meta, public_url=public_url),
            additional_redirect_urls=resolve_additional_redirects(meta),
            google_oauth_enabled=bool(meta.get("google_oauth_enabled")),
        )
        env["COMPOSE_PROJECT_NAME"] = cp
        (scratch / ".env").write_text(up.dump_dotenv(env), encoding="utf-8")
        os.chmod(scratch / ".env", 0o600)
        up.install_env_only(scratch / ".env", deployment)
        prog.step_ok("Secrets generated")

        reg.write_operation_journal(
            root, slug, {"intent": "CREATING", "phase": "compose", "at": _utc_now()}
        )
        override = c.render_override(
            compose_project=cp,
            fleet_id=fid,
            project_id=pid,
            gateway_port=ports["gateway"],
            db_direct_port=ports["db_direct"],
            pooler_session_port=ports["pooler_session"],
            pooler_transaction_port=ports["pooler_transaction"],
        )
        c.write_override(deployment, override)
        prog.step_ok("Compose configuration rendered")
        if not c.supports_override_tag():
            raise ProjectError("Compose !override unsupported", code=4)
        config = c.compose_config_json(deployment, compose_project=cp, env=env)
        c.validate_resolved_config(
            config,
            compose_project=cp,
            fleet_id=fid,
            project_id=pid,
            gateway_port=ports["gateway"],
            db_direct_port=ports["db_direct"],
            pooler_session_port=ports["pooler_session"],
            pooler_transaction_port=ports["pooler_transaction"],
            deployment=deployment,
            allowed_bind_roots=[deployment],
        )
        prog.step_ok("Configuration validated")

        # Config checkpoint only. Requested start must complete before creation_complete.
        meta["config_ready"] = True
        if requested_start:
            meta["creation_complete"] = False
            state = "CONFIGURED"
        else:
            meta["creation_complete"] = True
            state = "STOPPED"
        reg.write_project(root, meta)
        reg.write_operation_journal(
            root,
            slug,
            {"intent": "CREATED", "phase": "done", "at": _utc_now(), "state": state},
        )
        return meta
    except Exception as exc:
        reg.write_operation_journal(
            root,
            slug,
            {
                "intent": "CREATING",
                "phase": "failed",
                "at": _utc_now(),
                "error": type(exc).__name__,
            },
        )
        if isinstance(exc, ProjectError):
            raise
        raise ProjectError(str(exc), code=1) from exc
    finally:
        if staging.exists():
            try:
                reg.safe_rmtree(staging, under=root / "staging")
            except reg.OwnershipError:
                # Terminal — leave staging for diagnosis; never weaker-delete.
                pass


def _resume_create(
    root: Path, meta: dict[str, Any], *, progress: Any | None = None
) -> dict[str, Any]:
    """Resume incomplete create; never regenerate secrets or reset PGDATA."""
    from sbfleet.branding import (
        organization_name,
        project_name,
        resolve_additional_redirects,
        resolve_site_url,
    )
    from sbfleet.ux import Progress, QuietProgress

    prog: Progress = progress if progress is not None else QuietProgress()
    slug = str(meta["slug"])
    pid = str(meta["id"])
    fid = str(meta["fleet_id"])
    ports = meta["ports"]
    cp = str(meta["compose_project"])
    public_url = str(meta["public_url"])
    intent = dict(meta.get("create_intent") or {})
    uref = str(
        intent.get("upstream_ref") or (meta.get("upstream") or {}).get("ref") or up.PINNED_REF
    )
    usha = str(
        intent.get("upstream_sha") or (meta.get("upstream") or {}).get("sha") or up.PINNED_SHA
    )
    branding = dict(intent.get("branding") or {})
    for key, value in branding.items():
        meta.setdefault(key, value)
    deployment = reg.project_dir(root, slug) / "deployment"
    reg.write_operation_journal(
        root, slug, {"intent": "CREATING", "phase": "resume", "at": _utc_now()}
    )
    prog.step_ok("Registry initialized")

    if not deployment.exists() or not (deployment / "docker-compose.yml").exists():
        cache = up.materialize_cache(root, ref=uref, sha=usha)
        if deployment.exists():
            if (deployment / ".env").exists():
                pass
            else:
                raise ProjectError(
                    "partial deployment without recoverable .env; manual inspect required",
                    code=5,
                )
        else:
            up.copy_vendor_docker(cache, deployment, sha=usha, ref=uref)
        prog.step_ok("Upstream materialized")
    else:
        prog.step_ok("Upstream materialized")

    env_path = deployment / ".env"
    if not env_path.exists():
        scratch = root / "staging" / f"resume-{uuid.uuid4()}"
        scratch.mkdir(parents=True, mode=0o700)
        try:
            docker_src = up.cache_dir(root, usha) / "docker"
            if not docker_src.exists():
                docker_src = up.materialize_cache(root, ref=uref, sha=usha) / "docker"
            display_name = str(intent.get("display_name") or meta.get("display_name") or slug)
            env = up.generate_secrets_in_scratch(
                docker_src,
                scratch / "secrets",
                project_id=pid,
                public_url=public_url,
                gateway_port=int(ports["gateway"]),
                organization_name=organization_name(meta, display_name=display_name),
                project_name=project_name(meta, display_name=display_name),
                site_url=resolve_site_url(meta, public_url=public_url),
                additional_redirect_urls=resolve_additional_redirects(meta),
                google_oauth_enabled=bool(meta.get("google_oauth_enabled")),
            )
            env["COMPOSE_PROJECT_NAME"] = cp
            (scratch / "secrets" / ".env").write_text(up.dump_dotenv(env), encoding="utf-8")
            up.install_env_only(scratch / "secrets" / ".env", deployment)
        finally:
            if scratch.exists():
                try:
                    reg.safe_rmtree(scratch, under=root / "staging")
                except reg.OwnershipError:
                    pass
    else:
        env = up.parse_dotenv(env_path.read_text(encoding="utf-8"))

    override_path = deployment / "docker-compose.override.yml"
    if not override_path.exists():
        override = c.render_override(
            compose_project=cp,
            fleet_id=fid,
            project_id=pid,
            gateway_port=int(ports["gateway"]),
            db_direct_port=int(ports["db_direct"]),
            pooler_session_port=int(ports["pooler_session"]),
            pooler_transaction_port=int(ports["pooler_transaction"]),
        )
        c.write_override(deployment, override)

    if not c.supports_override_tag():
        raise ProjectError("Compose !override unsupported", code=4)
    config = c.compose_config_json(deployment, compose_project=cp, env=env)
    c.validate_resolved_config(
        config,
        compose_project=cp,
        fleet_id=fid,
        project_id=pid,
        gateway_port=int(ports["gateway"]),
        db_direct_port=int(ports["db_direct"]),
        pooler_session_port=int(ports["pooler_session"]),
        pooler_transaction_port=int(ports["pooler_transaction"]),
        deployment=deployment,
        allowed_bind_roots=[deployment],
    )
    prog.step_ok("Secrets generated")
    prog.step_ok("Compose configuration rendered")
    prog.step_ok("Configuration validated")
    meta = dict(meta)
    meta["config_ready"] = True
    meta["upstream"] = {"ref": uref, "sha": usha}
    # Completion only if start was not originally requested (or already satisfied).
    if intent.get("requested_start"):
        meta["creation_complete"] = False
        state = "CONFIGURED"
    else:
        meta["creation_complete"] = True
        state = "STOPPED"
    meta["create_intent"] = intent
    reg.write_project(root, meta)
    reg.write_operation_journal(
        root,
        slug,
        {"intent": "CREATED", "phase": "done", "at": _utc_now(), "state": state},
    )
    return meta


def _deployment_env(deployment: Path, *, compose_project: str | None = None) -> dict[str, str]:
    """Build child env. Compose selectors are forced when compose_project is provided."""
    from sbfleet.authority import forced_compose_env

    if compose_project is not None:
        return forced_compose_env(deployment, compose_project)
    # Legacy scaffolding path — still prefer not trusting .env for mutations.
    base = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(deployment / ".run-home"),
        "LC_ALL": "C",
    }
    (deployment / ".run-home").mkdir(mode=0o700, exist_ok=True)
    return base


def _redactor_for_project(deployment: Path) -> Redactor:
    from sbfleet.process import project_diagnostic_redactor

    return project_diagnostic_redactor(deployment)


def _preflight(root: Path, slug: str, *, allow_config_ready_start: bool = False) -> dict[str, Any]:
    """Lightweight pre-check for non-mutating callers (logs). Mutations use authority."""
    meta = reg.read_project(root, slug)
    if not meta.get("creation_complete"):
        if not (
            allow_config_ready_start
            and meta.get("config_ready")
            and (meta.get("create_intent") or {}).get("requested_start")
        ):
            raise ProjectError(f"project '{slug}' creation incomplete", code=5)
    deployment = reg.project_dir(root, slug) / "deployment"
    if not (deployment / "run.sh").is_file():
        raise ProjectError("deployment run.sh missing", code=5)
    return meta


def start_project(
    root: Path,
    slug: str,
    *,
    timeout: int = 300,
    progress: Any | None = None,
    already_locked: bool = False,
    manage_journal: bool = True,
) -> dict[str, Any]:
    """Start project stack.

    When nested under backup/restore (``already_locked=True``), pass
    ``manage_journal=False`` so the parent operation journal is not overwritten.
    """
    import threading
    import time

    from sbfleet import authority as auth
    from sbfleet.health import HEALTHY, collect_status, inspect_containers, lifecycle_op_succeeded
    from sbfleet.ux import (
        SERVICE_LABELS,
        START_WATCH_ORDER,
        Progress,
        elapsed_note,
        get_progress,
    )

    prog: Progress = progress if progress is not None else get_progress()

    def _do(ctx: auth.MutationContext) -> dict[str, Any]:
        if manage_journal:
            auth.begin_operation(ctx, phase="run")
        deployment = ctx.deployment
        meta = ctx.meta
        env = ctx.compose_env
        prog.heading(f"Starting {slug}...")
        started_at = time.monotonic()
        announced: set[str] = set()
        stop_poll = threading.Event()

        def _poll() -> None:
            while not stop_poll.wait(0.6):
                try:
                    containers = inspect_containers(deployment, ctx.compose_project)
                except Exception:  # noqa: BLE001
                    continue
                for svc in START_WATCH_ORDER:
                    if svc in announced:
                        continue
                    row = containers.get(svc)
                    if not row:
                        prog.step_wait(SERVICE_LABELS.get(svc, svc))
                        break
                    health_field = row.get("Health")
                    health = (health_field or row.get("State") or "").lower()
                    if "unhealthy" in health:
                        prog.step_fail(SERVICE_LABELS.get(svc, svc), health)
                        announced.add(svc)
                        continue
                    if "starting" in health:
                        prog.step_wait(SERVICE_LABELS.get(svc, svc))
                        break
                    if health_field is not None and "healthy" in health:
                        prog.step_ok(SERVICE_LABELS.get(svc, svc))
                        announced.add(svc)
                    elif health_field in (None, "") and health in {"running", ""}:
                        prog.step_ok(SERVICE_LABELS.get(svc, svc))
                        announced.add(svc)
                    else:
                        prog.step_wait(SERVICE_LABELS.get(svc, svc))
                        break

        poller = threading.Thread(target=_poll, name="sbfleet-start-poll", daemon=True)
        poller.start()
        try:
            result = run(
                ["sh", "run.sh", "start"],
                cwd=deployment,
                env=env,
                timeout=float(timeout),
                check=False,
            )
        finally:
            stop_poll.set()
            poller.join(timeout=2.0)
            prog.clear_wait()

        if not result.ok:
            if manage_journal:
                auth.fail_operation(ctx, error="start subprocess failed")
            raise ProjectError("start failed", code=1)

        try:
            containers = inspect_containers(deployment, ctx.compose_project)
            for svc in START_WATCH_ORDER:
                if svc in announced:
                    continue
                row = containers.get(svc)
                if not row:
                    continue
                health_field = row.get("Health")
                health = (health_field or row.get("State") or "").lower()
                if "unhealthy" in health:
                    prog.step_fail(SERVICE_LABELS.get(svc, svc), health)
                    announced.add(svc)
                elif health_field is not None and "healthy" in health:
                    prog.step_ok(SERVICE_LABELS.get(svc, svc))
                    announced.add(svc)
                elif health_field in (None, "") and health in {"running", ""}:
                    prog.step_ok(SERVICE_LABELS.get(svc, svc))
                    announced.add(svc)
        except Exception:  # noqa: BLE001
            pass

        prog.heading("Health checks...")
        if manage_journal:
            report = collect_status(root, slug)
        else:
            from sbfleet.health import collect_status_for_mutation

            report = collect_status_for_mutation(ctx)
        _emit_health_progress(prog, report)
        elapsed = time.monotonic() - started_at
        if report.lifecycle == HEALTHY:
            prog.note(elapsed_note(elapsed))
            try:
                _record_runtime_images(root, slug, meta, deployment)
            except Exception as exc:  # noqa: BLE001
                meta2 = reg.read_project(root, slug)
                digests = dict(meta2.get("image_digests") or {})
                digests["_error"] = {"status": "UNKNOWN", "reason": str(exc)[:200]}
                meta2["image_digests"] = digests
                reg.write_project(root, meta2)
        else:
            prog.note(f"Stack state: {report.lifecycle} ({elapsed:.1f}s)")
        if not lifecycle_op_succeeded(report, expect=HEALTHY):
            if manage_journal:
                auth.fail_operation(ctx, error=f"health={report.lifecycle}")
            raise ProjectError(f"start health failed: {report.lifecycle}", code=7)
        if manage_journal:
            auth.complete_operation(ctx)
        return reg.read_project(root, slug)

    try:
        with auth.authorize_mutation(
            root,
            slug,
            intent="start",
            allow_config_ready_start=True,
            already_locked=already_locked,
            ignore_unresolved_journal=already_locked and not manage_journal,
        ) as ctx:
            return _do(ctx)
    except auth.AuthorityError as exc:
        raise ProjectError(str(exc), code=exc.code) from exc


def _emit_health_progress(prog: Any, report: Any) -> None:
    from sbfleet.health import HEALTHY

    if "db" in {p.name for p in report.probes}:
        db = next(p for p in report.probes if p.name == "db")
        if db.status == HEALTHY:
            prog.step_ok("Database")
        else:
            prog.step_fail("Database", db.detail)
    auth_probe = next((p for p in report.probes if p.name == "auth-http"), None)
    if auth_probe is None:
        auth_probe = next((p for p in report.probes if p.name == "auth"), None)
    if auth_probe:
        if auth_probe.status == HEALTHY:
            prog.step_ok("Auth")
        else:
            prog.step_fail("Auth", auth_probe.detail)
    rest_probe = next((p for p in report.probes if p.name == "rest"), None)
    if rest_probe:
        if rest_probe.status == HEALTHY:
            prog.step_ok("API")
        else:
            prog.step_fail("API", rest_probe.detail)
    studio_probe = next((p for p in report.probes if p.name == "studio"), None)
    if studio_probe:
        if studio_probe.status == HEALTHY:
            prog.step_ok("Studio")
        else:
            prog.step_fail("Studio", studio_probe.detail)


def _record_runtime_images(root: Path, slug: str, meta: dict[str, Any], deployment: Path) -> None:
    """Record runtime image ID/digest/platform for supported running services.

    Missing facts are stored as UNKNOWN with reason — never silent empty success.
    """
    from sbfleet.health import inspect_containers_result

    inspected = inspect_containers_result(deployment, str(meta["compose_project"]))
    image_digests: dict[str, Any] = {}
    if not inspected.ok:
        image_digests["_enumeration"] = {
            "status": "UNKNOWN",
            "reason": inspected.error or "compose ps failed",
        }
        meta = reg.read_project(root, slug)
        meta["image_digests"] = image_digests
        reg.write_project(root, meta)
        return

    for svc, row in inspected.containers.items():
        entry: dict[str, Any] = {
            "image_ref": row.get("Image") or row.get("ImageName") or "UNKNOWN",
            "image_id": "UNKNOWN",
            "digest": "UNKNOWN",
            "platform": "UNKNOWN",
        }
        reasons: list[str] = []
        cid = row.get("ID") or row.get("Container") or row.get("Name")
        if not cid:
            reasons.append("container id missing from compose ps")
        else:
            insp = run(
                [
                    "docker",
                    "inspect",
                    "--format",
                    "{{.Image}}|{{.Os}}/{{.Architecture}}",
                    str(cid),
                ],
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                timeout=30.0,
                check=False,
            )
            if not insp.ok:
                reasons.append((insp.stderr or "docker inspect failed")[:120])
            else:
                parts = (insp.stdout or "").strip().split("|")
                if parts and parts[0]:
                    entry["image_id"] = parts[0]
                else:
                    reasons.append("image id empty")
                if len(parts) > 1 and parts[1] and parts[1] != "/":
                    entry["platform"] = parts[1]
                else:
                    reasons.append("platform unavailable from inspect")
                if entry["image_id"] != "UNKNOWN":
                    dig = run(
                        [
                            "docker",
                            "image",
                            "inspect",
                            "--format",
                            "{{json .RepoDigests}}|{{.Os}}/{{.Architecture}}",
                            entry["image_id"],
                        ],
                        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                        timeout=30.0,
                        check=False,
                    )
                    if dig.ok:
                        import json as _json

                        dparts = (dig.stdout or "").strip().split("|", 1)
                        try:
                            digests = _json.loads(dparts[0] or "[]")
                        except Exception:  # noqa: BLE001
                            digests = []
                        if digests:
                            chosen = str(digests[0])
                            entry["digest"] = chosen.split("@", 1)[1] if "@" in chosen else chosen
                        else:
                            reasons.append("RepoDigests empty")
                        if len(dparts) > 1 and dparts[1] and dparts[1] != "/":
                            entry["platform"] = dparts[1]
                    else:
                        reasons.append("image inspect failed for digest")
        if (
            entry["image_id"] == "UNKNOWN"
            or entry["digest"] == "UNKNOWN"
            or entry["platform"] == "UNKNOWN"
        ):
            entry["status"] = "UNKNOWN"
            entry["reason"] = "; ".join(reasons) or "incomplete runtime identity"
        else:
            entry["status"] = "RECORDED"
        image_digests[svc] = entry

    meta = reg.read_project(root, slug)
    meta["image_digests"] = image_digests
    reg.write_project(root, meta)


def stop_project(
    root: Path,
    slug: str,
    *,
    already_locked: bool = False,
    manage_journal: bool = True,
) -> dict[str, Any]:
    """Stop project stack.

    When nested under backup/restore (``already_locked=True``), pass
    ``manage_journal=False`` so the parent operation journal is not overwritten.
    """
    from sbfleet import authority as auth
    from sbfleet.health import (
        STOPPED,
        StatusReport,
        inspect_containers_result,
        lifecycle_op_succeeded,
    )

    def _do(ctx: auth.MutationContext) -> dict[str, Any]:
        journal = reg.read_operation_journal(root, slug)
        preserve_parent = auth.journal_is_maintenance_unresolved(journal)
        write_own_journal = manage_journal and not preserve_parent
        if write_own_journal:
            auth.begin_operation(ctx, phase="run")
        deployment = ctx.deployment
        meta = ctx.meta
        env = ctx.compose_env
        result = run(
            ["sh", "run.sh", "stop"],
            cwd=deployment,
            env=env,
            timeout=180.0,
            check=False,
        )
        if not result.ok:
            err = (result.stderr or result.stdout or "").lower()
            if "no such" not in err:
                if write_own_journal:
                    auth.fail_operation(ctx, error="stop subprocess failed")
                elif preserve_parent:
                    auth.record_subordinate_stop_evidence(ctx, detail="stop subprocess failed")
                raise ProjectError("stop failed", code=1)
        inspected = inspect_containers_result(deployment, ctx.compose_project)
        if not inspected.ok:
            if write_own_journal:
                auth.fail_operation(ctx, error="enum_failed")
            elif preserve_parent:
                auth.record_subordinate_stop_evidence(ctx, detail="stop enum_failed")
            raise ProjectError(f"stop enumeration failed: {inspected.error or 'unknown'}", code=7)
        report = StatusReport(
            slug=slug,
            lifecycle=STOPPED if not inspected.containers else "DEGRADED",
            probes=[],
            meta=meta,
            enum_ok=True,
        )
        if inspected.containers or not lifecycle_op_succeeded(report, expect=STOPPED):
            if write_own_journal:
                auth.fail_operation(
                    ctx,
                    error=f"remaining={sorted(inspected.containers)}",
                )
            elif preserve_parent:
                auth.record_subordinate_stop_evidence(
                    ctx, detail=f"stop incomplete remaining={sorted(inspected.containers)}"
                )
            raise ProjectError(f"stop incomplete; remaining={sorted(inspected.containers)}", code=7)
        if write_own_journal:
            auth.complete_operation(ctx)
        elif preserve_parent:
            auth.record_subordinate_stop_evidence(ctx, detail="stop completed under parent")
        return meta

    try:
        with auth.authorize_mutation(
            root,
            slug,
            intent="stop",
            already_locked=already_locked,
            # Stop may run during unresolved maintenance; journal writes are gated in _do.
            ignore_unresolved_journal=True,
        ) as ctx:
            return _do(ctx)
    except auth.AuthorityError as exc:
        raise ProjectError(str(exc), code=exc.code) from exc


def restart_project(
    root: Path,
    slug: str,
    *,
    timeout: int = 300,
    progress: Any | None = None,
    already_locked: bool = False,
) -> dict[str, Any]:
    import time

    from sbfleet import authority as auth
    from sbfleet.health import HEALTHY, collect_status, lifecycle_op_succeeded
    from sbfleet.ux import Progress, elapsed_note, get_progress

    prog: Progress = progress if progress is not None else get_progress()

    def _do(ctx: auth.MutationContext) -> dict[str, Any]:
        deployment = ctx.deployment
        meta = ctx.meta
        env = ctx.compose_env
        ps = run(
            ["docker", "compose", "ps", "-q"],
            cwd=deployment,
            env=env,
            timeout=60.0,
            check=False,
        )
        if not (ps.stdout or "").strip():
            raise ProjectError("restart refused: project is not running", code=1)
        auth.begin_operation(ctx, phase="run")
        prog.heading(f"Restarting {slug}...")
        started_at = time.monotonic()
        result = run(
            ["sh", "run.sh", "restart"],
            cwd=deployment,
            env=env,
            timeout=float(timeout),
            check=False,
        )
        if not result.ok:
            auth.fail_operation(ctx, error="restart subprocess failed")
            raise ProjectError("restart failed", code=1)
        prog.heading("Health checks...")
        deadline = time.monotonic() + float(timeout)
        report = collect_status(root, slug)
        while report.lifecycle != HEALTHY and time.monotonic() < deadline:
            time.sleep(2.0)
            report = collect_status(root, slug)
        _emit_health_progress(prog, report)
        elapsed = time.monotonic() - started_at
        if report.lifecycle == HEALTHY:
            prog.note(elapsed_note(elapsed))
        else:
            prog.note(f"Stack state: {report.lifecycle} ({elapsed:.1f}s)")
        if not lifecycle_op_succeeded(report, expect=HEALTHY):
            auth.fail_operation(ctx, error=f"health={report.lifecycle}")
            raise ProjectError(f"restart health failed: {report.lifecycle}", code=7)
        auth.complete_operation(ctx)
        return meta

    try:
        with auth.authorize_mutation(
            root,
            slug,
            intent="restart",
            already_locked=already_locked,
        ) as ctx:
            return _do(ctx)
    except auth.AuthorityError as exc:
        raise ProjectError(str(exc), code=exc.code) from exc


def fetch_logs_text(
    root: Path,
    slug: str,
    *,
    service: str | None = None,
    tail: int = 20,
) -> str:
    """Return redacted log text (no print)."""
    from sbfleet.compose import STANDARD_SERVICES

    meta = _preflight(root, slug)
    deployment = reg.project_dir(root, slug) / "deployment"
    if service and service not in STANDARD_SERVICES:
        raise ProjectError(f"unknown service '{service}'", code=2)
    cp = reg.compose_project_name(str(meta["fleet_id"]), str(meta["id"]))
    env = _deployment_env(deployment, compose_project=cp)
    redactor = _redactor_for_project(deployment)
    argv = ["docker", "compose", "logs", "--no-color", f"--tail={tail}"]
    if service:
        argv.append(service)
    result = run(argv, cwd=deployment, env=env, check=False)
    if not result.ok:
        raise ProjectError("logs failed", code=1)
    return redactor.redact_text(result.stdout or result.stderr or "")


def print_startup_failure_hint(root: Path, slug: str, *, service: str | None = None) -> None:
    """Print a small redacted log tail and suggested commands after start/create failure."""
    from sbfleet.health import collect_status

    suspect = service
    deployment = reg.project_dir(root, slug) / "deployment"
    redactor = _redactor_for_project(deployment)
    try:
        report = collect_status(root, slug)
        if suspect is None:
            for p in report.probes:
                if p.status in {"UNHEALTHY", "DEGRADED"} and p.name in {
                    "auth",
                    "auth-http",
                    "db",
                    "rest",
                    "api-gw",
                    "studio",
                }:
                    suspect = "auth" if p.name == "auth-http" else p.name
                    label = "Auth" if suspect == "auth" else suspect
                    safe_detail = sanitize_diagnostic(str(p.detail), redactor=redactor, max_len=160)
                    print(f"\n{label} failed health check ({safe_detail}).", flush=True)
                    break
    except Exception:  # noqa: BLE001
        pass
    suspect = suspect or "auth"
    try:
        text = fetch_logs_text(root, slug, service=suspect, tail=20)
    except Exception:  # noqa: BLE001
        text = ""
    if text.strip():
        print(f"\nLast 20 {suspect} log lines:", flush=True)
        print(text.rstrip(), flush=True)
    print("\nSuggested:", flush=True)
    print(f"  /logs {suspect}", flush=True)
    print("  /doctor", flush=True)
    print("  /status", flush=True)


def project_logs(
    root: Path,
    slug: str,
    *,
    service: str | None = None,
    follow: bool = False,
    tail: int = 100,
) -> ProcessError | None:
    """Fetch logs. follow inherits stdio. Returns None on finite success."""
    from sbfleet.compose import STANDARD_SERVICES

    meta = _preflight(root, slug)
    deployment = reg.project_dir(root, slug) / "deployment"
    if service and service not in STANDARD_SERVICES:
        raise ProjectError(f"unknown service '{service}'", code=2)
    cp = reg.compose_project_name(str(meta["fleet_id"]), str(meta["id"]))
    env = _deployment_env(deployment, compose_project=cp)
    redactor = _redactor_for_project(deployment)
    argv = ["docker", "compose", "logs", "--no-color", f"--tail={tail}"]
    if follow:
        argv.append("--follow")
    if service:
        argv.append(service)
    if follow:
        # Stream through redactor — never inherit raw stdio for fleet logs.
        import subprocess

        child_env = dict(env)
        proc = subprocess.Popen(
            argv,
            cwd=str(deployment),
            env=child_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        assert proc.stdout is not None
        streamer = StreamingRedactor(redactor)
        try:
            while True:
                chunk = proc.stdout.read(4096)
                if not chunk:
                    break
                sys.stdout.write(streamer.feed(chunk))
                sys.stdout.flush()
            sys.stdout.write(streamer.flush())
            sys.stdout.flush()
            rc = proc.wait()
        except KeyboardInterrupt:
            proc.terminate()
            raise ProjectError("interrupted", code=130) from None
        if rc == 130:
            raise ProjectError("interrupted", code=130)
        if rc not in (0, None):
            raise ProjectError("logs failed", code=1)
        return None
    result = run(argv, cwd=deployment, env=env, check=False)
    if not result.ok:
        raise ProjectError("logs failed", code=1)
    text = redactor.redact_text(result.stdout)
    print(text, end="" if text.endswith("\n") else "\n")
    return None
