"""Post-create presentation settings (fleet display_name + Studio labels).

Identity-neutral only: never renames slug / UUID / Compose / Docker resources.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sbfleet import registry as reg
from sbfleet import upstream as up
from sbfleet.authority import journal_is_maintenance_unresolved
from sbfleet.branding import (
    DEFAULT_ORGANIZATION,
    DEFAULT_PROJECT,
    BrandingError,
    organization_name,
    project_name,
    validate_display_label,
)
from sbfleet.process import run

STUDIO_ORG_KEY = "STUDIO_DEFAULT_ORGANIZATION"
STUDIO_PROJECT_KEY = "STUDIO_DEFAULT_PROJECT"
_STUDIO_ENV_KEYS = frozenset({STUDIO_ORG_KEY, STUDIO_PROJECT_KEY})
# Upstream Studio container receives interpolated names (not STUDIO_DEFAULT_*).
_STUDIO_CONTAINER_ORG = "DEFAULT_ORGANIZATION_NAME"
_STUDIO_CONTAINER_PROJECT = "DEFAULT_PROJECT_NAME"
_STUDIO_CONTAINER_KEYS = frozenset({_STUDIO_CONTAINER_ORG, _STUDIO_CONTAINER_PROJECT})

# Hooks for unit tests (ordering / dual-write failure injection).
_after_meta_write: Callable[[], None] | None = None
_env_write: Callable[[Path, dict[str, str]], None] | None = None
_probe_studio_env: Callable[[Path, str], dict[str, str] | None] | None = None
_lock_released_hook: Callable[[], None] | None = None


class ConfigureError(Exception):
    """Presentation configure failure."""

    def __init__(self, message: str, *, code: int = 1) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class PresentationSnapshot:
    slug: str
    display_name: str
    studio_organization: str
    studio_project: str
    meta_organization: str
    meta_project: str
    drift: list[str] = field(default_factory=list)


@dataclass
class AppliedState:
    """Best-effort runtime observation (not durable state)."""

    status: str  # yes | no | unknown | pending_start | n/a
    detail: str
    studio_organization: str | None = None
    studio_project: str | None = None


@dataclass
class ConfigureResult:
    snapshot: PresentationSnapshot
    applied: AppliedState
    mutated: bool
    changed: list[str] = field(default_factory=list)
    guidance: list[str] = field(default_factory=list)


def _deployment(root: Path, slug: str, meta: dict[str, Any]) -> Path:
    del meta
    return reg.project_dir(root, slug) / "deployment"


def _configured_studio_from_files(
    meta: dict[str, Any], env: dict[str, str]
) -> tuple[str, str, list[str]]:
    """Return (org, project, drift notes). Prefer .env; fall back to meta/defaults."""
    meta_org = organization_name(meta)
    meta_proj = project_name(meta)
    env_org = (env.get(STUDIO_ORG_KEY) or "").strip()
    env_proj = (env.get(STUDIO_PROJECT_KEY) or "").strip()
    drift: list[str] = []
    if env_org and env_org != meta_org:
        drift.append(
            f"meta branding.organization_name={meta_org!r} != {STUDIO_ORG_KEY}={env_org!r}"
        )
    if env_proj and env_proj != meta_proj:
        drift.append(
            f"meta branding.project_name={meta_proj!r} != {STUDIO_PROJECT_KEY}={env_proj!r}"
        )
    org = env_org or meta_org or DEFAULT_ORGANIZATION
    proj = env_proj or meta_proj or DEFAULT_PROJECT
    return org, proj, drift


def _load_snapshot(
    root: Path, slug: str
) -> tuple[dict[str, Any], dict[str, str], PresentationSnapshot]:
    try:
        meta = reg.read_project(root, slug)
    except reg.NotFoundError as exc:
        raise ConfigureError(str(exc), code=3) from exc
    except reg.RegistryError as exc:
        raise ConfigureError(str(exc), code=5) from exc
    meta = reg.validate_project_identity(root, meta)
    if not meta.get("creation_complete"):
        raise ConfigureError(f"project '{slug}' creation incomplete", code=5)

    deployment = _deployment(root, slug, meta)
    env_path = deployment / ".env"
    try:
        reg.assert_secret_file(env_path)
    except reg.OwnershipError as exc:
        raise ConfigureError(str(exc), code=5) from exc
    try:
        env = up.parse_dotenv(env_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise ConfigureError(f"unsafe/unreadable .env: {exc}", code=5) from exc

    org, proj, drift = _configured_studio_from_files(meta, env)
    snap = PresentationSnapshot(
        slug=str(meta["slug"]),
        display_name=str(meta.get("display_name") or meta["slug"]),
        studio_organization=org,
        studio_project=proj,
        meta_organization=organization_name(meta),
        meta_project=project_name(meta),
        drift=drift,
    )
    return meta, env, snap


def _probe_studio_container_env(deployment: Path, compose_project: str) -> dict[str, str] | None:
    """Read applied Studio labels from running studio container Env.

    Returns a dict keyed by STUDIO_DEFAULT_* (mapped from container
    DEFAULT_ORGANIZATION_NAME / DEFAULT_PROJECT_NAME). Empty dict means
    no containers (stopped). None means probe unavailable.
    """
    if _probe_studio_env is not None:
        return _probe_studio_env(deployment, compose_project)
    from sbfleet.health import inspect_containers_result

    inspected = inspect_containers_result(deployment, compose_project)
    if not inspected.ok:
        return None
    if not inspected.containers:
        return {}
    row = inspected.containers.get("studio")
    if not row:
        return None
    cid = row.get("ID") or row.get("Container") or row.get("Name")
    if not cid:
        return None
    insp = run(
        ["docker", "inspect", "--format", "{{json .Config.Env}}", str(cid)],
        env={"PATH": __import__("os").environ.get("PATH", "/usr/bin:/bin")},
        timeout=30.0,
        check=False,
    )
    if not insp.ok:
        return None
    try:
        import json

        items = json.loads((insp.stdout or "").strip() or "null")
    except Exception:
        return None
    if not isinstance(items, list):
        return None
    raw: dict[str, str] = {}
    for item in items:
        if not isinstance(item, str) or "=" not in item:
            continue
        key, value = item.split("=", 1)
        if key in _STUDIO_CONTAINER_KEYS or key in _STUDIO_ENV_KEYS:
            raw[key] = value
    out: dict[str, str] = {}
    if _STUDIO_CONTAINER_ORG in raw:
        out[STUDIO_ORG_KEY] = raw[_STUDIO_CONTAINER_ORG]
    elif STUDIO_ORG_KEY in raw:
        out[STUDIO_ORG_KEY] = raw[STUDIO_ORG_KEY]
    if _STUDIO_CONTAINER_PROJECT in raw:
        out[STUDIO_PROJECT_KEY] = raw[_STUDIO_CONTAINER_PROJECT]
    elif STUDIO_PROJECT_KEY in raw:
        out[STUDIO_PROJECT_KEY] = raw[STUDIO_PROJECT_KEY]
    return out


def observe_applied(
    root: Path,
    slug: str,
    *,
    configured_org: str,
    configured_project: str,
    meta: dict[str, Any] | None = None,
) -> AppliedState:
    """Best-effort APPLIED probe — must run without holding mutation locks."""
    if meta is None:
        try:
            meta = reg.read_project(root, slug)
        except reg.RegistryError:
            return AppliedState(status="unknown", detail="metadata unavailable for applied probe")
    deployment = _deployment(root, slug, meta)
    compose_project = str(meta.get("compose_project") or "")
    if not compose_project:
        return AppliedState(status="unknown", detail="compose_project missing")

    env_map = _probe_studio_container_env(deployment, compose_project)
    if env_map is None:
        return AppliedState(
            status="unknown",
            detail="pending stop/start to apply (runtime Env unavailable)",
        )
    if env_map == {}:
        return AppliedState(
            status="pending_start",
            detail="will apply on next start",
        )
    live_org = env_map.get(STUDIO_ORG_KEY)
    live_proj = env_map.get(STUDIO_PROJECT_KEY)
    if live_org is None and live_proj is None:
        return AppliedState(
            status="unknown",
            detail="pending stop/start to apply (studio Env keys absent)",
            studio_organization=live_org,
            studio_project=live_proj,
        )
    org_ok = live_org is None or live_org == configured_org
    proj_ok = live_proj is None or live_proj == configured_project
    if org_ok and proj_ok and (live_org is not None or live_proj is not None):
        # Require both present and matching when running.
        if live_org == configured_org and live_proj == configured_project:
            return AppliedState(
                status="yes",
                detail="running studio Env matches configured values",
                studio_organization=live_org,
                studio_project=live_proj,
            )
    return AppliedState(
        status="no",
        detail="pending stop/start to apply",
        studio_organization=live_org,
        studio_project=live_proj,
    )


def format_configure_human(result: ConfigureResult) -> str:
    snap = result.snapshot
    applied = result.applied
    lines = [
        f"Project: {snap.slug}",
        "",
        "SBfleet",
        f"  Display name   {snap.display_name}     (configured)",
        f"  Slug           {snap.slug}              (immutable in V1)",
        "",
        "Studio",
        f"  Organization   {snap.studio_organization}               configured",
        f"  Project        {snap.studio_project}             configured",
    ]
    if applied.status == "yes":
        lines.append("  Applied        yes                 running studio Env matches")
    elif applied.status == "pending_start":
        lines.append("  Applied        pending             will apply on next start")
    elif applied.status == "no":
        lines.append("  Applied        no                  pending stop/start to apply")
    else:
        lines.append(f"  Applied        unknown             {applied.detail}")

    if snap.drift:
        lines.append("")
        lines.append("Warning: presentation configuration drift (meta vs .env):")
        for note in snap.drift:
            lines.append(f"  - {note}")

    if result.mutated:
        lines.append("")
        if result.changed:
            lines.append("Changes saved:")
            for item in result.changed:
                lines.append(f"  - {item}")
        else:
            lines.append("No changes (values already configured).")

    for line in result.guidance:
        lines.append(line)
    return "\n".join(lines) + "\n"


def _apply_guidance(slug: str, applied: AppliedState, *, studio_changed: bool) -> list[str]:
    lines = [
        "",
        "Plain restart does not refresh container environment.",
    ]
    if not studio_changed:
        return lines
    if applied.status == "pending_start":
        lines.append(f"Studio names will apply on next: sbfleet start {slug}")
    elif applied.status in {"no", "unknown"}:
        lines.append("To apply Studio names:")
        lines.append(f"  sbfleet stop {slug}")
        lines.append(f"  sbfleet start {slug}")
    elif applied.status == "yes":
        lines.append("Running studio Env already matches configured Studio names.")
    return lines


def configure_project(
    root: Path,
    slug: str,
    *,
    display_name: str | None = None,
    organization_name_value: str | None = None,
    studio_project_value: str | None = None,
) -> ConfigureResult:
    """Read or mutate presentation settings. Locks released before applied probe."""
    slug = reg.validate_slug(slug)
    mutate = any(
        v is not None for v in (display_name, organization_name_value, studio_project_value)
    )

    # Validate inputs before lock (cheap).
    new_display: str | None = None
    new_org: str | None = None
    new_studio: str | None = None
    try:
        if display_name is not None:
            new_display = reg.validate_display_name(display_name)
        if organization_name_value is not None:
            new_org = validate_display_label(organization_name_value, field="organization_name")
        if studio_project_value is not None:
            new_studio = validate_display_label(studio_project_value, field="project_name")
    except (reg.ValidationError, BrandingError) as exc:
        raise ConfigureError(str(exc), code=2) from exc

    studio_touch = new_org is not None or new_studio is not None
    changed: list[str] = []
    final_meta: dict[str, Any]
    final_snap: PresentationSnapshot

    # Resolve project id for locking.
    try:
        preliminary = reg.read_project(root, slug)
    except reg.NotFoundError as exc:
        raise ConfigureError(str(exc), code=3) from exc
    except reg.RegistryError as exc:
        raise ConfigureError(str(exc), code=5) from exc
    project_id = str(preliminary["id"])

    with reg.locked_registry_then_project(root, project_id):
        meta, env, snap = _load_snapshot(root, slug)
        journal = reg.read_operation_journal(root, slug)
        if journal_is_maintenance_unresolved(journal):
            detail = (
                f"intent={journal.get('intent')!r} phase={journal.get('phase')!r} "
                f"state={journal.get('state')!r}"
                if journal
                else "unknown"
            )
            raise ConfigureError(
                "unresolved maintenance journal blocks configure; "
                f"{detail}. Reconcile explicitly before continuing.",
                code=5,
            )

        if not mutate:
            final_meta = meta
            final_snap = snap
        else:
            original_meta = copy.deepcopy(meta)
            original_env = dict(env)
            work_meta = copy.deepcopy(meta)
            work_env = dict(env)

            if new_display is not None and new_display != str(work_meta.get("display_name")):
                changed.append(
                    f"display_name: {work_meta.get('display_name')!r} -> {new_display!r}"
                )
                work_meta["display_name"] = new_display

            branding = dict(work_meta.get("branding") or {})
            if not isinstance(branding, dict):
                branding = {}
            if new_org is not None:
                prev = organization_name(work_meta)
                if new_org != prev or work_env.get(STUDIO_ORG_KEY) != new_org:
                    changed.append(f"studio organization: {prev!r} -> {new_org!r}")
                branding["organization_name"] = new_org
                work_env[STUDIO_ORG_KEY] = new_org
            if new_studio is not None:
                prev = project_name(work_meta)
                if new_studio != prev or work_env.get(STUDIO_PROJECT_KEY) != new_studio:
                    changed.append(f"studio project: {prev!r} -> {new_studio!r}")
                branding["project_name"] = new_studio
                work_env[STUDIO_PROJECT_KEY] = new_studio
            if branding:
                work_meta["branding"] = branding

            # Identity invariants (refuse accidental mutation).
            for key in ("slug", "id", "fleet_id", "compose_project", "ports", "public_url"):
                if work_meta.get(key) != original_meta.get(key):
                    raise ConfigureError(f"configure refused identity mutation of {key}", code=5)
            for key, value in original_env.items():
                if key in _STUDIO_ENV_KEYS:
                    continue
                if work_env.get(key) != value:
                    raise ConfigureError(
                        f"configure refused non-allowlisted .env change: {key}", code=5
                    )

            env_path = _deployment(root, slug, work_meta) / ".env"
            try:
                reg.assert_secret_file(env_path)
            except reg.OwnershipError as exc:
                raise ConfigureError(str(exc), code=5) from exc

            if not studio_touch:
                # Metadata-only (--name).
                try:
                    reg.write_project(root, work_meta)
                except Exception as exc:  # noqa: BLE001
                    raise ConfigureError(f"failed to write project.json: {exc}", code=5) from exc
            else:
                # Dual-file: meta first, then .env; rollback meta on env failure.
                try:
                    reg.write_project(root, work_meta)
                except Exception as exc:  # noqa: BLE001
                    raise ConfigureError(f"failed to write project.json: {exc}", code=5) from exc
                if _after_meta_write is not None:
                    _after_meta_write()
                writer = _env_write or up.atomic_write_dotenv
                try:
                    writer(env_path, work_env)
                except Exception as env_exc:  # noqa: BLE001
                    try:
                        reg.write_project(root, original_meta)
                    except Exception as rb_exc:  # noqa: BLE001
                        raise ConfigureError(
                            "presentation configuration drift/inconsistency: "
                            f".env write failed ({env_exc}); "
                            f"project.json rollback also failed ({rb_exc}). "
                            "Inspect project.json branding vs deployment/.env "
                            f"{STUDIO_ORG_KEY}/{STUDIO_PROJECT_KEY} before retrying.",
                            code=5,
                        ) from rb_exc
                    raise ConfigureError(
                        f"failed to write deployment/.env ({env_exc}); "
                        "project.json rolled back to previous presentation values.",
                        code=5,
                    ) from env_exc

            meta, env, final_snap = _load_snapshot(root, slug)
            final_meta = meta

    if _lock_released_hook is not None:
        _lock_released_hook()

    applied = observe_applied(
        root,
        slug,
        configured_org=final_snap.studio_organization,
        configured_project=final_snap.studio_project,
        meta=final_meta,
    )
    # Studio apply guidance only when Studio keys were targeted or drift/applied pending.
    studio_changed = studio_touch or (mutate and any("studio " in c for c in changed))
    if not mutate:
        studio_changed = True  # always show apply semantics on read
    guidance = _apply_guidance(slug, applied, studio_changed=studio_changed or not mutate)

    return ConfigureResult(
        snapshot=final_snap,
        applied=applied,
        mutated=mutate,
        changed=changed,
        guidance=guidance,
    )


def run_configure(
    root: Path,
    slug: str,
    *,
    display_name: str | None = None,
    organization_name: str | None = None,
    studio_project: str | None = None,
) -> int:
    """CLI entry: print human output; return exit code."""
    import sys

    try:
        result = configure_project(
            root,
            slug,
            display_name=display_name,
            organization_name_value=organization_name,
            studio_project_value=studio_project,
        )
    except ConfigureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.code
    print(format_configure_human(result), end="")
    return 0
