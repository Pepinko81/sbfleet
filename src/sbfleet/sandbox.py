"""Local Supabase CLI sandbox lifecycle with proven adoption authority (Run 2D)."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from types import SimpleNamespace

from sbfleet.cli import EXIT_FAILURE, EXIT_OK, EXIT_PREREQUISITE, EXIT_SAFETY, EXIT_USAGE
from sbfleet.process import Redactor, run, sanitize_diagnostic
from sbfleet.sandbox_adoption import (
    SandboxAdoptionError,
    SandboxLocks,
    canonicalize_app_root,
    clear_owned_resources,
    commit_adoption_pair,
    new_adoption,
    path_hash_short,
    reconcile_adoption_index,
    state_dir_for,
    update_record_fields,
)
from sbfleet.sandbox_authority import (
    SandboxAuthorityError,
    assert_effective_bindings,
    attempt_delta_owned,
    audit_linked_remote_state,
    child_env,
    cleanup_attempt_delta_owned,
    ensure_owned_network,
    invent_owned_resources,
    observe_sandbox_live,
    prove_network_owned,
    reenumerate_cli_namespace_residuals,
    refuse_foreign_cli_resources,
    require_action_live_authority,
    snapshot_positively_owned,
    status_endpoints_local,
)
from sbfleet.sandbox_authority import (
    audit_dotenv as _audit_dotenv_impl,
)
from sbfleet.sandbox_config import (
    SandboxConfigError,
    assert_local_url,
    classify_fingerprint_drift,
    parse_sandbox_config,
    static_binding_preflight,
    validate_external_paths,
    validate_migration_mode,
)

PINNED_CLI = "2.118.0"
FORBIDDEN_TOKENS = frozenset(
    {
        "--linked",
        "--db-url",
        "--project-ref",
        "--all",
        "login",
        "link",
    }
)


class SandboxError(Exception):
    def __init__(self, msg: str, *, code: int = EXIT_SAFETY) -> None:
        super().__init__(msg)
        self.code = code


def audit_dotenv(app_path: Path) -> None:
    """Raise SandboxError when dotenv/target selectors are unsafe."""
    try:
        _audit_dotenv_impl(app_path)
    except SandboxAuthorityError as exc:
        raise SandboxError(str(exc), code=exc.code) from exc


def _cli_version() -> str | None:
    from sbfleet.tools import resolve_supabase

    path, _detail = resolve_supabase()
    if not path:
        return None
    result = run(
        [path, "--version"],
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        check=False,
    )
    text = (result.stdout or result.stderr or "").strip()
    m = re.search(r"(\d+\.\d+\.\d+)", text)
    return m.group(1) if m else text


def require_pinned_cli() -> str:
    from sbfleet.tools import ToolError, require_supabase

    try:
        path = require_supabase()
    except ToolError as exc:
        raise SandboxError(str(exc), code=EXIT_PREREQUISITE) from exc
    ver = _cli_version()
    if not ver:
        raise SandboxError("supabase CLI missing", code=EXIT_PREREQUISITE)
    if ver != PINNED_CLI:
        raise SandboxError(
            f"supabase CLI {ver} incompatible; require {PINNED_CLI}",
            code=EXIT_PREREQUISITE,
        )
    return path


def path_hash(app_path: Path) -> str:
    """Backward-compatible short hash (name helper only)."""
    return path_hash_short(app_path.resolve())


def _map_exc(exc: Exception) -> SandboxError:
    if isinstance(exc, SandboxError):
        return exc
    code = getattr(exc, "code", EXIT_SAFETY)
    return SandboxError(str(exc), code=code)


def _parse_remainder_flags(args) -> list[str]:  # noqa: ANN001
    cmd = list(getattr(args, "cmd", []) or [])
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if args.action != "env":
        filtered: list[str] = []
        for tok in cmd:
            if tok == "--yes":
                args.yes = True
                continue
            if tok == "--json":
                args.json = True
                continue
            if tok == "--revalidate":
                args.revalidate = True
                continue
            if tok.startswith("--migration-mode="):
                args.migration_mode = tok.split("=", 1)[1]
                continue
            if tok == "--migration-mode" and filtered:
                # unlikely; handled by argparse usually
                continue
            filtered.append(tok)
        # Also peel --migration-mode VALUE from remainder
        out: list[str] = []
        i = 0
        while i < len(filtered):
            if filtered[i] == "--migration-mode" and i + 1 < len(filtered):
                args.migration_mode = filtered[i + 1]
                i += 2
                continue
            out.append(filtered[i])
            i += 1
        cmd = out
    args.cmd = cmd
    return cmd


def doctor_sandbox_checks(
    app_path: str | Path, *, home: Path | None = None
) -> list[dict[str, str]]:
    """Read-only doctor checks for --sandbox PATH. No mutation/adopt."""
    from sbfleet.registry import resolve_home

    checks: list[dict[str, str]] = []

    def add(cid: str, status: str, detail: str, next_action: str) -> None:
        checks.append({"id": cid, "status": status, "detail": detail, "next": next_action})

    try:
        cli_ver = _cli_version()
        if cli_ver == PINNED_CLI:
            add("sandbox-cli-version", "pass", cli_ver or "", "none")
        elif cli_ver:
            add("sandbox-cli-version", "fail", f"{cli_ver} != {PINNED_CLI}", "install pinned CLI")
        else:
            add("sandbox-cli-version", "fail", "missing", "install pinned CLI")
    except Exception as exc:  # noqa: BLE001
        add("sandbox-cli-version", "unknown", str(exc), "inspect CLI")

    fleet_home = resolve_home(home)
    try:
        canonical = canonicalize_app_root(Path(app_path), fleet_home=fleet_home)
        add("sandbox-canonical-root", "pass", str(canonical), "none")
    except Exception as exc:  # noqa: BLE001
        add("sandbox-canonical-root", "fail", str(exc), "fix path")
        return checks

    try:
        cfg = parse_sandbox_config(canonical)
        add("sandbox-cli-project-id", "pass", cfg.project_id, "none")
        add("sandbox-config-fingerprint", "pass", cfg.fingerprint[:16] + "…", "none")
    except Exception as exc:  # noqa: BLE001
        add("sandbox-cli-project-id", "fail", str(exc), "fix config.toml")
        add("sandbox-config-fingerprint", "fail", str(exc), "fix config.toml")
        cfg = None  # type: ignore[assignment]

    try:
        audit_dotenv(canonical)
        add("sandbox-dotenv", "pass", "clean", "none")
    except Exception as exc:  # noqa: BLE001
        add("sandbox-dotenv", "fail", str(exc), "remove dangerous dotenv")

    state = state_dir_for(fleet_home, canonical)
    cli_home = state / "supabase-home"
    try:
        has_remotes = bool(cfg.has_remotes) if cfg else False
        audit_linked_remote_state(canonical, has_remotes, cli_home if cli_home.exists() else state)
        add("sandbox-link-remote", "pass", "clean", "none")
    except Exception as exc:  # noqa: BLE001
        add("sandbox-link-remote", "fail", str(exc), "unlink remote state")

    try:
        with SandboxLocks(fleet_home, canonical, timeout=5.0):
            adoption = reconcile_adoption_index(
                fleet_home,
                canonical,
                cli_project_id=cfg.project_id if cfg else None,
            )
        if adoption is None:
            add("sandbox-adoption", "fail", "not adopted", "sandbox start")
            add("sandbox-fingerprint-state", "unknown", "no adoption", "sandbox start")
            add("sandbox-migration-mode", "unknown", "no adoption", "sandbox start")
            add("sandbox-network", "unknown", "no adoption", "sandbox start")
            add("sandbox-inventory", "unknown", "no adoption", "sandbox start")
            add("sandbox-endpoints", "unknown", "no adoption", "sandbox start")
            return checks
        add("sandbox-adoption", "pass", adoption.sandbox_uuid, "none")
        add("sandbox-migration-mode", "pass", adoption.migration_mode, "none")
        if cfg and adoption.config_fingerprint != cfg.fingerprint:
            drift = classify_fingerprint_drift(adoption.fingerprint_fields, cfg.fingerprint_fields)
            add(
                "sandbox-fingerprint-state",
                "fail",
                "drift: " + "; ".join(drift[:5]),
                "sandbox start --revalidate",
            )
        else:
            add("sandbox-fingerprint-state", "pass", "matches", "none")
        if adoption.network_id:
            try:
                prove_network_owned(
                    adoption.network_id,
                    path_hash=adoption.path_hash,
                    sandbox_uuid=adoption.sandbox_uuid,
                )
                add("sandbox-network", "pass", adoption.network_id[:12], "none")
            except Exception as exc:  # noqa: BLE001
                add("sandbox-network", "fail", str(exc), "recreate via start")
        else:
            add("sandbox-network", "unknown", "no network_id", "sandbox start")
        resources = adoption.owned_resources or {}
        if resources.get("containers"):
            add(
                "sandbox-inventory",
                "pass",
                f"containers={len(resources.get('containers') or [])}",
                "none",
            )
        else:
            add("sandbox-inventory", "unknown", "empty inventory", "sandbox start")
        add("sandbox-endpoints", "unknown", "run status for live endpoints", "sandbox status")
    except Exception as exc:  # noqa: BLE001
        add("sandbox-adoption", "fail", str(exc), "resolve authority pair")

    return checks


def _sandbox_redactor(canonical: Path) -> Redactor:
    """Build a redactor from known configured secrets under the sandbox root."""
    from sbfleet.process import sandbox_diagnostic_redactor

    return sandbox_diagnostic_redactor(canonical)


def _emit_error(
    message: str,
    *,
    redactor: Redactor | None = None,
    redactor_ok: bool = True,
    sandbox_root: Path | None = None,
    max_len: int = 240,
) -> None:
    """Ordinary sandbox error path: configured redact then truncate (V4-002)."""
    from sbfleet.process import (
        CREDENTIAL_SAFE_RENDERING_UNAVAILABLE,
        sanitize_configured_diagnostic,
    )

    if not redactor_ok:
        detail = CREDENTIAL_SAFE_RENDERING_UNAVAILABLE[:max_len]
    else:
        detail = sanitize_configured_diagnostic(
            str(message),
            redactor=redactor,
            sandbox_root=sandbox_root,
            max_len=max_len,
        )
    print(f"error: {detail}", file=sys.stderr)


def _emit_child_summary(
    *,
    action: str,
    result,
    redactor: Redactor,
    ok_message: str | None = None,
    redactor_ok: bool = True,
) -> None:
    """Emit allowlisted sanitized summary — never raw CLI stdout/stderr."""
    from sbfleet.process import (
        CREDENTIAL_SAFE_RENDERING_UNAVAILABLE,
        sanitize_configured_diagnostic,
    )

    if result.ok:
        print(ok_message or f"sandbox {action} ok")
        return
    if not redactor_ok:
        detail = CREDENTIAL_SAFE_RENDERING_UNAVAILABLE[:240]
    else:
        detail = sanitize_configured_diagnostic(
            (result.stderr or result.stdout or "").strip(),
            redactor=redactor,
            max_len=240,
        )
    print(
        f"error: sandbox {action} failed rc={result.returncode}"
        + (f": {detail}" if detail else ""),
        file=sys.stderr,
    )


def sandbox_cmd(args) -> int:  # noqa: ANN001
    try:
        cli = require_pinned_cli()
    except SandboxError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.code

    cmd = _parse_remainder_flags(args)
    revalidate = bool(getattr(args, "revalidate", False))
    migration_mode_arg = getattr(args, "migration_mode", None)
    migration_mode = migration_mode_arg or "supabase"

    raw = [args.action, args.path, *cmd]
    for tok in raw:
        if tok in FORBIDDEN_TOKENS:
            print(f"error: forbidden sandbox argument: {tok}", file=sys.stderr)
            return EXIT_SAFETY

    if revalidate and args.action != "start":
        print("error: --revalidate is only valid with sandbox start", file=sys.stderr)
        return EXIT_USAGE

    from sbfleet.registry import resolve_home

    home = resolve_home(getattr(args, "home", None))
    action = args.action

    # Pre-lock: locate canonical root / lock key only. Do not authorize.
    try:
        canonical = canonicalize_app_root(Path(args.path), fleet_home=home)
    except (SandboxError, SandboxAdoptionError) as exc:
        err = _map_exc(exc)
        print(f"error: {err}", file=sys.stderr)
        return err.code

    state = state_dir_for(home, canonical)
    state.mkdir(parents=True, exist_ok=True)
    os.chmod(state, 0o700)
    cli_home = state / "supabase-home"
    cli_home.mkdir(exist_ok=True)
    os.chmod(cli_home, 0o700)

    try:
        with SandboxLocks(home, canonical) as _locks:
            # Under lock: re-read all authority-relevant facts.
            audit_dotenv(canonical)
            cfg = parse_sandbox_config(canonical)
            validate_external_paths(canonical, cfg.raw)
            static_binding_preflight(cfg)
            if action == "start":
                mode_for_validate = migration_mode_arg or "supabase"
                validate_migration_mode(cfg, mode_for_validate)
            audit_linked_remote_state(canonical, cfg.has_remotes, cli_home)

            env = child_env(cli_home)
            project_id = cfg.project_id
            from sbfleet.process import (
                CREDENTIAL_SAFE_RENDERING_UNAVAILABLE,
                DiagnosticRedactorUnavailable,
            )

            redactor_ok = True
            try:
                redactor = _sandbox_redactor(canonical)
            except DiagnosticRedactorUnavailable:
                redactor = Redactor()
                redactor_ok = False
            adoption = reconcile_adoption_index(home, canonical, cli_project_id=project_id)

            if adoption is not None:
                if Path(adoption.canonical_app_root).resolve() != canonical.resolve():
                    raise SandboxError("adoption root mismatch")
                # contract: project ID immutable — reconcile_adoption_index already refuses drift.
                if adoption.cli_project_id != project_id:
                    raise SandboxError(
                        f"adopted project_id {adoption.cli_project_id!r} != config "
                        f"{project_id!r}; project ID is immutable after adoption — "
                        "destroy and re-adopt (new identity), not --revalidate"
                    )
                fp_mismatch = adoption.config_fingerprint != cfg.fingerprint
                if fp_mismatch and not revalidate:
                    drift = classify_fingerprint_drift(
                        adoption.fingerprint_fields, cfg.fingerprint_fields
                    )
                    print("error: authority-relevant config fingerprint drift:", file=sys.stderr)
                    for line in drift:
                        print(f"  {line}", file=sys.stderr)
                    print(
                        "error: refuse mutation; run: sbfleet sandbox start PATH --revalidate",
                        file=sys.stderr,
                    )
                    return EXIT_SAFETY
                if revalidate:
                    drift = classify_fingerprint_drift(
                        adoption.fingerprint_fields, cfg.fingerprint_fields
                    )
                    print("revalidate: authority drift classification:", file=sys.stderr)
                    if drift:
                        for line in drift:
                            print(f"  {line}", file=sys.stderr)
                    else:
                        print("  (fingerprint hash changed without field diff?)", file=sys.stderr)
                    mode = migration_mode
                    validate_migration_mode(cfg, mode)
                    if adoption.network_id:
                        prove_network_owned(
                            adoption.network_id,
                            path_hash=adoption.path_hash,
                            sandbox_uuid=adoption.sandbox_uuid,
                        )
                    # Same root + UUID + exact project ID; fingerprint/mode only.
                    adoption = update_record_fields(
                        adoption,
                        config_fingerprint=cfg.fingerprint,
                        fingerprint_fields=cfg.fingerprint_fields,
                        migration_mode=mode,
                        cli_version=PINNED_CLI,
                    )
                    commit_adoption_pair(home, adoption)
                    print("revalidate: adoption fingerprint updated", file=sys.stderr)

                if (
                    args.action == "start"
                    and migration_mode_arg
                    and adoption.migration_mode != migration_mode_arg
                ):
                    validate_migration_mode(cfg, migration_mode_arg)
                    adoption = update_record_fields(adoption, migration_mode=migration_mode_arg)
                    commit_adoption_pair(home, adoption)

            else:
                if action != "start":
                    raise SandboxError(
                        "sandbox not adopted; run sandbox start first",
                        code=EXIT_PREREQUISITE,
                    )
                if revalidate:
                    raise SandboxError("nothing to revalidate; sandbox not yet adopted")
                validate_migration_mode(cfg, migration_mode)
                refuse_foreign_cli_resources(project_id, canonical)
                adoption = new_adoption(
                    canonical=canonical,
                    cli_project_id=project_id,
                    config_fingerprint=cfg.fingerprint,
                    fingerprint_fields=cfg.fingerprint_fields,
                    cli_version=PINNED_CLI,
                    migration_mode=migration_mode,
                )
                commit_adoption_pair(home, adoption)

            if action == "reset" and not args.yes:
                print("error: reset requires --yes", file=sys.stderr)
                return EXIT_SAFETY
            if action == "destroy" and not args.yes:
                print("error: destroy requires --yes", file=sys.stderr)
                return EXIT_SAFETY

            if action == "start":
                # Live ownership preflight before any start dispatch (V3-005 / V4-003).
                live = observe_sandbox_live(adoption, canonical=canonical)
                require_action_live_authority("start", live)
                if (
                    live.containers.status == "PRESENT_AND_OWNED"
                    and live.containers.runtime == "RUNNING"
                ):
                    # All required owned containers actually RUNNING — idempotent.
                    if live.inventory is not None:
                        try:
                            assert_effective_bindings(live.inventory)
                        except (SandboxAuthorityError, SandboxConfigError) as exc:
                            _emit_error(str(exc), redactor=redactor, redactor_ok=redactor_ok)
                            return EXIT_SAFETY
                        adoption = update_record_fields(
                            adoption,
                            owned_resources=live.inventory,
                            network_id=adoption.network_id,
                        )
                        commit_adoption_pair(home, adoption)
                    print("sandbox start ok (already running)")
                    return EXIT_OK

                pre_owned = snapshot_positively_owned(live)
                net_id = ensure_owned_network(adoption)
                if adoption.network_id != net_id:
                    adoption = update_record_fields(adoption, network_id=net_id)
                    commit_adoption_pair(home, adoption)
                prove_network_owned(
                    net_id, path_hash=adoption.path_hash, sandbox_uuid=adoption.sandbox_uuid
                )
                argv = [cli, "--workdir", str(canonical), "--network-id", net_id, "start"]
                result = run(argv, cwd=canonical, env=env, check=False, timeout=600.0)
                if not result.ok:
                    _emit_child_summary(
                        action="start", result=result, redactor=redactor, redactor_ok=redactor_ok
                    )
                    return EXIT_FAILURE
                try:
                    inventory = invent_owned_resources(
                        project_id=project_id,
                        canonical_root=canonical,
                        network_id=net_id,
                        network_name=adoption.network_name,
                    )
                    assert_effective_bindings(inventory)
                except (SandboxAuthorityError, SandboxConfigError) as exc:
                    # Attempt-delta cleanup only: post_owned − pre_owned. Never stop --project-id.
                    post_live = observe_sandbox_live(adoption, canonical=canonical)
                    delta = attempt_delta_owned(pre_owned, post_live)
                    residuals = cleanup_attempt_delta_owned(delta)
                    unknown_parts: list[str] = []
                    for name, obs in (
                        ("containers", post_live.containers),
                        ("network", post_live.network),
                        ("volumes", post_live.volumes),
                    ):
                        if obs.status in {"PRESENT_BUT_FOREIGN", "UNKNOWN"}:
                            unknown_parts.append(f"{name}={obs.status}:{obs.detail}")
                    _emit_error(str(exc), redactor=redactor, redactor_ok=redactor_ok)
                    if unknown_parts:
                        _emit_error(
                            "post-start ownership foreign/unknown; left untouched: "
                            + "; ".join(unknown_parts),
                            redactor=redactor,
                            redactor_ok=redactor_ok,
                        )
                    if residuals:
                        _emit_error(
                            "attempt-delta cleanup residuals: " + ", ".join(residuals),
                            redactor=redactor,
                            redactor_ok=redactor_ok,
                        )
                    print(
                        "note: post-start binding inspection is not proof that no temporary "
                        "exposure was possible; preflight + fail-closed inspect gate success. "
                        "Cleanup limited to attempt-delta positively owned resources only.",
                        file=sys.stderr,
                    )
                    return EXIT_SAFETY
                adoption = update_record_fields(
                    adoption, owned_resources=inventory, network_id=net_id
                )
                commit_adoption_pair(home, adoption)
                _emit_child_summary(
                    action="start", result=result, redactor=redactor, redactor_ok=redactor_ok
                )
                return EXIT_OK

            if action == "stop":
                live = observe_sandbox_live(adoption, canonical=canonical)
                require_action_live_authority("stop", live)
                if live.containers.status == "CONFIRMED_ABSENT":
                    return EXIT_OK
                argv = [cli, "--workdir", str(canonical), "stop", "--project-id", project_id]
                result = run(argv, cwd=canonical, env=env, check=False, timeout=600.0)
                _emit_child_summary(
                    action="stop", result=result, redactor=redactor, redactor_ok=redactor_ok
                )
                return EXIT_OK if result.ok else EXIT_FAILURE

            if action == "reset":
                live = observe_sandbox_live(adoption, canonical=canonical)
                require_action_live_authority("reset", live)
                if not adoption.network_id:
                    raise SandboxError("adoption network_id unknown; refuse reset")
                argv = [
                    cli,
                    "--workdir",
                    str(canonical),
                    "--network-id",
                    adoption.network_id,
                    "db",
                    "reset",
                    "--local",
                ]
                result = run(argv, cwd=canonical, env=env, check=False, timeout=600.0)
                if not result.ok:
                    _emit_child_summary(
                        action="reset", result=result, redactor=redactor, redactor_ok=redactor_ok
                    )
                    return EXIT_FAILURE
                try:
                    inventory = invent_owned_resources(
                        project_id=project_id,
                        canonical_root=canonical,
                        network_id=adoption.network_id,
                        network_name=adoption.network_name,
                    )
                    assert_effective_bindings(inventory)
                except (SandboxAuthorityError, SandboxConfigError) as exc:
                    _emit_error(
                        f"post-reset inspection failed: {exc}",
                        redactor=redactor,
                        redactor_ok=redactor_ok,
                    )
                    return EXIT_SAFETY
                adoption = update_record_fields(adoption, owned_resources=inventory)
                commit_adoption_pair(home, adoption)
                _emit_child_summary(
                    action="reset", result=result, redactor=redactor, redactor_ok=redactor_ok
                )
                return EXIT_OK

            if action == "destroy":
                live = observe_sandbox_live(adoption, canonical=canonical)
                require_action_live_authority("destroy", live)
                # Delete only proven-owned resources — never recorded-name fallback.
                live_volumes = (
                    list(live.volumes.names) if live.volumes.status == "PRESENT_AND_OWNED" else []
                )
                if live.containers.status == "PRESENT_AND_OWNED":
                    argv = [
                        cli,
                        "--workdir",
                        str(canonical),
                        "stop",
                        "--project-id",
                        project_id,
                        "--no-backup",
                    ]
                    result = run(argv, cwd=canonical, env=env, check=False, timeout=600.0)
                else:
                    # Containers already confirmed absent — no stop dispatch needed.
                    result = SimpleNamespace(ok=True, stdout="", stderr="", returncode=0)
                for vname in live_volumes:
                    rm = run(
                        ["docker", "volume", "rm", vname],
                        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                        check=False,
                    )
                    if not rm.ok:
                        # Residual re-enumeration will catch leftovers.
                        pass
                if live.network.status == "PRESENT_AND_OWNED" and adoption.network_id:
                    run(
                        ["docker", "network", "rm", adoption.network_id],
                        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                        check=False,
                    )
                residuals = reenumerate_cli_namespace_residuals(
                    project_id=project_id,
                    canonical=canonical,
                    network_id=adoption.network_id,
                    path_hash=adoption.path_hash,
                    sandbox_uuid=adoption.sandbox_uuid,
                )
                if residuals:
                    print(
                        "error: residual resources after destroy (not broadened cleanup): "
                        + ", ".join(residuals),
                        file=sys.stderr,
                    )
                    # Retain adoption evidence of residuals — do not clear ownership blindly.
                    adoption = update_record_fields(
                        adoption,
                        owned_resources={
                            "residuals": residuals,
                            "containers": [],
                            "volumes": [],
                        },
                    )
                    commit_adoption_pair(home, adoption)
                    return EXIT_SAFETY
                adoption = clear_owned_resources(adoption)
                commit_adoption_pair(home, adoption)
                if not result.ok:
                    _emit_child_summary(
                        action="destroy", result=result, redactor=redactor, redactor_ok=redactor_ok
                    )
                    return EXIT_FAILURE
                _emit_child_summary(
                    action="destroy", result=result, redactor=redactor, redactor_ok=redactor_ok
                )
                return EXIT_OK

            if action == "status":
                argv = [cli, "--workdir", str(canonical), "status", "-o", "json"]
                result = run(argv, cwd=canonical, env=env, check=False, timeout=120.0)
                return _emit_status(
                    args, project_id, result, redactor=redactor, redactor_ok=redactor_ok
                )

            if action == "studio":
                st = run(
                    [cli, "--workdir", str(canonical), "status", "-o", "json"],
                    cwd=canonical,
                    env=env,
                    check=False,
                )
                if not st.ok:
                    from sbfleet.process import CREDENTIAL_SAFE_RENDERING_UNAVAILABLE

                    if not redactor_ok:
                        detail = CREDENTIAL_SAFE_RENDERING_UNAVAILABLE[:240]
                    else:
                        detail = sanitize_diagnostic(
                            (st.stderr or st.stdout or "status failed").strip(),
                            redactor=redactor,
                            max_len=240,
                        )
                    print(f"error: sandbox studio status failed: {detail}", file=sys.stderr)
                    return EXIT_FAILURE
                try:
                    data = json.loads(st.stdout or "{}")
                except json.JSONDecodeError:
                    print("error: malformed status JSON", file=sys.stderr)
                    return EXIT_FAILURE
                url = data.get("STUDIO_URL") or data.get("studio_url") or ""
                try:
                    assert_local_url(str(url), context="STUDIO_URL", kind="http")
                except SandboxConfigError as exc:
                    _emit_error(str(exc), redactor=redactor, redactor_ok=redactor_ok)
                    return EXIT_SAFETY
                if any(s in url.lower() for s in ("apikey=", "token=", "password=", "secret=")):
                    print("error: refusing secret-bearing studio URL", file=sys.stderr)
                    return EXIT_SAFETY
                # Belt-and-suspenders: never print userinfo even if assert_local_url drifts.
                safe_url = sanitize_diagnostic(str(url), redactor=redactor)
                if safe_url != str(url) or "@" in (str(url).split("://", 1)[-1].split("/", 1)[0]):
                    print("error: refusing credential-bearing studio URL", file=sys.stderr)
                    return EXIT_SAFETY
                print(url)
                return EXIT_OK

            if action == "env":
                if not cmd:
                    return EXIT_USAGE
                live = observe_sandbox_live(adoption, canonical=canonical)
                require_action_live_authority("env", live)
                st = run(
                    [cli, "--workdir", str(canonical), "status", "-o", "json"],
                    cwd=canonical,
                    env=env,
                    check=False,
                )
                if not st.ok:
                    print(
                        "error: sandbox status failed; refusing to spawn env child",
                        file=sys.stderr,
                    )
                    return EXIT_SAFETY
                try:
                    data = json.loads(st.stdout or "{}")
                except json.JSONDecodeError:
                    print("error: malformed status JSON; refusing env spawn", file=sys.stderr)
                    return EXIT_SAFETY
                try:
                    injected = status_endpoints_local(data)
                except SandboxAuthorityError as exc:
                    _emit_error(str(exc), redactor=redactor, redactor_ok=redactor_ok)
                    return EXIT_SAFETY
                child = dict(env)
                child.update(injected)
                result = run(
                    cmd, cwd=canonical, env=child, inherit_stdio=True, capture_output=False
                )
                # Documented 128+signal contract for child signals.
                if result.returncode is not None and result.returncode < 0:
                    return 128 + (-result.returncode)
                return result.returncode

            return EXIT_USAGE

    except (SandboxError, SandboxAdoptionError, SandboxAuthorityError, SandboxConfigError) as exc:
        err = _map_exc(exc)
        # Prefer configured redaction when we already resolved a sandbox root.
        try:
            _emit_error(str(err), sandbox_root=canonical, max_len=240)
        except Exception:  # noqa: BLE001
            print(f"error: {err}", file=sys.stderr)
        return err.code


def _emit_status(  # noqa: ANN001
    args,
    project_id: str,
    result,
    *,
    redactor: Redactor | None = None,
    redactor_ok: bool = True,
) -> int:
    from sbfleet.process import CREDENTIAL_SAFE_RENDERING_UNAVAILABLE

    redactor = redactor or Redactor()
    allow_keys = {
        "name",
        "status",
        "ports",
        "db_url_host",
        "api_url",
        "studio_url",
        "project_id",
        "version",
        "services",
    }

    def _scrub(obj):
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                kl = str(k).lower()
                if any(
                    s in kl
                    for s in (
                        "key",
                        "secret",
                        "password",
                        "token",
                        "jwt",
                        "db_url",
                        "database_url",
                        "url",
                    )
                ):
                    if "url" in kl or "db" in kl:
                        out[k] = (
                            redactor.redact_text(str(v)) if isinstance(v, str) else "[REDACTED]"
                        )
                    else:
                        out[k] = "[REDACTED]"
                else:
                    out[k] = _scrub(v)
            return out
        if isinstance(obj, list):
            return [_scrub(x) for x in obj]
        if isinstance(obj, str):
            return redactor.redact_text(obj)
        return obj

    if not result.ok:
        if not redactor_ok:
            detail = CREDENTIAL_SAFE_RENDERING_UNAVAILABLE[:240]
        else:
            detail = sanitize_diagnostic(
                (result.stderr or result.stdout or "").strip(),
                redactor=redactor,
                max_len=240,
            )
        print(
            f"error: sandbox status failed rc={result.returncode}"
            + (f": {detail}" if detail else ""),
            file=sys.stderr,
        )
        return EXIT_FAILURE
    try:
        data = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        print(
            "error: sandbox status returned malformed JSON; refusing raw dump",
            file=sys.stderr,
        )
        return EXIT_FAILURE
    data = _scrub(data)
    if args.json:
        print(
            json.dumps(
                {
                    "format_version": 1,
                    "ok": result.ok,
                    "command": "sandbox",
                    "data": {"project_id": project_id, "status": data},
                    "warnings": [],
                    "errors": [],
                }
            )
        )
    else:
        print(f"project_id={project_id}")
        if isinstance(data, dict):
            for k in sorted(data):
                if k.lower() in allow_keys or k in allow_keys:
                    print(f"{k}={data[k]}")
                else:
                    print(f"{k}=[redacted-field]")
    return EXIT_OK if result.ok else EXIT_FAILURE
