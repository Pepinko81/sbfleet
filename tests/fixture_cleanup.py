"""Exact owned Docker resource cleanup for disposable fixtures (V3-013).

Enumerates only label-proven containers/networks/volumes for a fleet/project,
then deletes by exact ID/name. Never prune. Never delete by name resemblance.
"""

from __future__ import annotations

import os
from pathlib import Path

from sbfleet.process import run


def _docker(argv: list[str], *, timeout: float = 60.0):
    return run(
        argv,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        timeout=timeout,
        check=False,
    )


def _enumerate_owned(labels: dict[str, str]) -> tuple[dict[str, list[str]], list[str]]:
    filters = [arg for key, value in labels.items() for arg in ("--filter", f"label={key}={value}")]
    resources = {}
    errors = []
    for kind, command in (
        ("container", ["ps", "-aq", "--no-trunc"]),
        ("network", ["network", "ls", "-q", "--no-trunc"]),
        ("volume", ["volume", "ls", "-q"]),
    ):
        result = _docker(["docker", *command, *filters])
        resources[kind] = result.stdout.split() if result.ok else []
        if not result.ok:
            errors.append(f"enumeration-failed:{kind}")
    return resources, errors


def _cleanup_owned(labels: dict[str, str]) -> list[str]:
    resources, errors = _enumerate_owned(labels)
    for kind, identifiers in resources.items():
        for identifier in identifiers:
            label_path = ".Config.Labels" if kind == "container" else ".Labels"
            fmt = "|".join("{{index " + label_path + ' "' + key + '"}}' for key in labels)
            inspected = _docker(["docker", kind, "inspect", "--format", fmt, identifier])
            if not inspected.ok or inspected.stdout.strip().split("|") != list(labels.values()):
                errors.append(f"skip-unproven-{kind}:{identifier}")
                continue
            command = ["docker", kind, "rm"]
            if kind == "container":
                command.append("-f")
            removed = _docker([*command, identifier])
            if not removed.ok:
                errors.append(f"remove-failed:{kind}:{identifier}")
    remaining, final_errors = _enumerate_owned(labels)
    errors.extend(final_errors)
    errors.extend(
        f"residual:{kind}:{identifier}" for kind, ids in remaining.items() for identifier in ids
    )
    return errors


def cleanup_compose_resources(project: str) -> None:
    """Require successful cleanup and final enumeration for one exact Compose fixture."""
    errors = _cleanup_owned({"com.docker.compose.project": project})
    assert not errors, f"Compose fixture cleanup failed for {project}: {errors}"


def cleanup_labeled_fleet_resources(*, fleet_id: str, project_id: str | None = None) -> list[str]:
    """Return every cleanup failure and exact residual; callers must assert success."""
    labels = {"io.sbfleet.fleet": fleet_id}
    if project_id:
        labels["io.sbfleet.project"] = project_id
    return _cleanup_owned(labels)


def assert_labeled_absent(*, fleet_id: str, project_id: str | None = None) -> None:
    labels = {"io.sbfleet.fleet": fleet_id}
    if project_id:
        labels["io.sbfleet.project"] = project_id
    resources, errors = _enumerate_owned(labels)
    assert not errors, f"Cannot establish fixture absence: {errors}"
    assert not any(resources.values()), f"Residual fixture resources: {resources}"


def wipe_fixture_filesystem(root: Path) -> None:
    """Best-effort remove disposable fixture home."""
    if not root.exists():
        return
    try:
        from sbfleet import registry as reg

        reg.safe_rmtree(root, under=root.parent)
    except Exception:  # noqa: BLE001
        pass
