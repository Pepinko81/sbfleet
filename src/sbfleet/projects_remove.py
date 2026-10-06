"""Ownership-proven project removal ."""

from __future__ import annotations

import sys
from pathlib import Path

from sbfleet import authority as auth
from sbfleet import registry as reg
from sbfleet.cli import EXIT_OK, EXIT_SAFETY
from sbfleet.process import run
from sbfleet.projects import ProjectError, stop_project


def _rm_by_id(kind: str, resource_id: str) -> None:
    if kind == "container":
        argv = ["docker", "rm", "-f", resource_id]
    elif kind == "network":
        argv = ["docker", "network", "rm", resource_id]
    elif kind == "volume":
        argv = ["docker", "volume", "rm", resource_id]
    else:
        raise ProjectError(f"unknown resource kind {kind}", code=EXIT_SAFETY)
    result = run(
        argv,
        env={"PATH": __import__("os").environ.get("PATH", "/usr/bin:/bin")},
        timeout=120.0,
        check=False,
    )
    if not result.ok:
        detail = (result.stderr or result.stdout or "")[:200]
        raise ProjectError(f"failed to remove {kind} {resource_id}: {detail}", code=EXIT_SAFETY)


def remove_project(root: Path, slug: str, *, yes: bool, no_backup: bool) -> int:
    if not yes:
        print("error: remove requires --yes", file=sys.stderr)
        return EXIT_SAFETY

    def _err(exc: BaseException) -> None:
        from sbfleet.process import sanitize_configured_diagnostic

        deployment = reg.project_dir(root, slug) / "deployment"
        print(
            "error: "
            + sanitize_configured_diagnostic(str(exc), deployment=deployment, max_len=500),
            file=sys.stderr,
        )

    try:
        with auth.authorize_mutation(
            root,
            slug,
            intent="remove",
            require_creation_complete=False,
            validate_compose=True,
            invent_live=True,
        ) as ctx:
            if not no_backup:
                from sbfleet.backup import BackupError, require_recovery_backup

                try:
                    require_recovery_backup(root, ctx.meta)
                except BackupError as exc:
                    print(f"error: {exc}; pass --no-backup to skip", file=sys.stderr)
                    return EXIT_SAFETY

            auth.begin_operation(ctx, phase="stop")
            # Already holding locks — nested stop must not replace REMOVING journal.
            try:
                stop_project(root, slug, already_locked=True, manage_journal=False)
            except ProjectError as exc:
                # Allow remove of never-started / already-stopped stacks.
                if "creation incomplete" in str(exc).lower():
                    raise
                # Re-inventory after best-effort stop.
                pass

            auth.record_operation_phase(ctx, phase="inventory")
            contract = ctx.contract or auth.build_project_contract(
                root, ctx.meta, ctx.deployment, ctx.compose_project
            )
            inventory = auth.invent_owned_resources(
                compose_project=ctx.compose_project,
                fleet_id=ctx.fleet_id,
                project_id=ctx.project_id,
                deployment=ctx.deployment,
                contract=contract,
            )
            if inventory.residuals:
                auth.fail_operation(
                    ctx,
                    error="residuals: " + ", ".join(inventory.residuals),
                )
                print(
                    "error: refusing remove; unproven/foreign resources: "
                    + ", ".join(inventory.residuals),
                    file=sys.stderr,
                )
                return EXIT_SAFETY

            auth.record_operation_phase(ctx, phase="delete-resources")
            # Delete proven containers, then network, then volumes — by ID only.
            for resource in inventory.containers:
                _rm_by_id("container", resource.resource_id)
            for resource in inventory.networks:
                _rm_by_id("network", resource.resource_id)
            for resource in inventory.volumes:
                _rm_by_id("volume", resource.resource_id)

            # Wipe container-owned bind trees only after proving containment
            # and that no unexpected mountpoint exists at/beneath the tree.
            volumes = ctx.deployment / "volumes"
            if volumes.exists() or volumes.is_symlink():
                try:
                    reg.assert_managed_entry(
                        volumes,
                        under=ctx.deployment,
                        expect_dir=True,
                        refuse_mountpoint=True,
                    )
                    reg.assert_destructive_tree_safe(volumes, under=ctx.deployment)
                except reg.OwnershipError as exc:
                    auth.fail_operation(ctx, error=str(exc))
                    print(f"error: volumes path unsafe: {exc}", file=sys.stderr)
                    return EXIT_SAFETY
                wipe = run(
                    [
                        "docker",
                        "run",
                        "--rm",
                        "--network",
                        "none",
                        "-v",
                        f"{volumes}:/wipe",
                        "alpine:3.20",
                        "sh",
                        "-c",
                        "rm -rf /wipe/* /wipe/.[!.]* /wipe/..?*",
                    ],
                    env={"PATH": __import__("os").environ.get("PATH", "/usr/bin:/bin")},
                    timeout=300.0,
                    check=False,
                )
                if not wipe.ok:
                    auth.fail_operation(ctx, error="volumes wipe failed")
                    print("error: volumes wipe failed", file=sys.stderr)
                    return EXIT_SAFETY

            # Re-check no owned-looking resources remain that we failed to delete.
            leftover = auth.invent_owned_resources(
                compose_project=ctx.compose_project,
                fleet_id=ctx.fleet_id,
                project_id=ctx.project_id,
                deployment=ctx.deployment,
                contract=contract,
            )
            if leftover.containers or leftover.networks or leftover.volumes:
                names = [r.name for r in leftover.containers + leftover.networks + leftover.volumes]
                auth.fail_operation(ctx, error="leftover: " + ",".join(names))
                print(
                    "error: remove incomplete; residual owned resources remain: "
                    + ", ".join(names),
                    file=sys.stderr,
                )
                return EXIT_SAFETY

            auth.record_operation_phase(ctx, phase="delete-metadata")
            try:
                reg.safe_rmtree(ctx.project_dir, under=root / "projects")
            except reg.OwnershipError as exc:
                auth.fail_operation(ctx, error=str(exc))
                print(f"error: project tree unsafe for deletion: {exc}", file=sys.stderr)
                return EXIT_SAFETY
            # Project gone — journal cannot be written; print success.
            print(f"removed {slug} (backups retained)")
            return EXIT_OK
    except auth.AuthorityError as exc:
        _err(exc)
        return EXIT_SAFETY
    except ProjectError as exc:
        _err(exc)
        return int(exc.code) if exc.code else EXIT_SAFETY
    except OSError as exc:
        _err(exc)
        return EXIT_SAFETY
