"""Exact owned Docker resource cleanup for disposable fixtures (V3-013).

Enumerates only label-proven containers/networks/volumes for a fleet/project,
then deletes by exact ID/name. Never prune. Never delete by name resemblance.
"""

from __future__ import annotations

import os
from pathlib import Path

from sbfleet.process import run

_FMT_CTR = (
    '{{index .Config.Labels "io.sbfleet.fleet"}}|'
    '{{index .Config.Labels "io.sbfleet.project"}}|{{.Id}}'
)
# fmt: off
_FMT_NET = '{{index .Labels "io.sbfleet.fleet"}}|{{index .Labels "io.sbfleet.project"}}|{{.Id}}'  # noqa: E501
_FMT_VOL = '{{index .Labels "io.sbfleet.fleet"}}|{{index .Labels "io.sbfleet.project"}}|{{.Name}}'  # noqa: E501
# fmt: on


def _docker(argv: list[str], *, timeout: float = 60.0):
    return run(
        argv,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        timeout=timeout,
        check=False,
    )


def cleanup_labeled_fleet_resources(
    *,
    fleet_id: str,
    project_id: str | None = None,
) -> list[str]:
    """Best-effort exact cleanup of io.sbfleet.* labeled resources for a fixture.

    Returns residual descriptors still present after cleanup attempts.
    """
    residuals: list[str] = []
    filters = [f"label=io.sbfleet.fleet={fleet_id}"]
    if project_id:
        filters.append(f"label=io.sbfleet.project={project_id}")

    cf: list[str] = []
    for f in filters:
        cf.extend(["--filter", f])

    listed = _docker(["docker", "ps", "-aq", *cf])
    ids = [x for x in (listed.stdout or "").split() if x]
    for cid in ids:
        insp = _docker(["docker", "inspect", "--format", _FMT_CTR, cid])
        parts = (insp.stdout or "").strip().split("|")
        if len(parts) < 3 or parts[0] != fleet_id:
            residuals.append(f"skip-unproven-container:{cid[:12]}")
            continue
        if project_id and parts[1] != project_id:
            residuals.append(f"skip-other-project-container:{cid[:12]}")
            continue
        _docker(["docker", "rm", "-f", cid])

    listed = _docker(["docker", "network", "ls", "-q", *cf])
    nids = [x for x in (listed.stdout or "").split() if x]
    for nid in nids:
        insp = _docker(["docker", "network", "inspect", "--format", _FMT_NET, nid])
        parts = (insp.stdout or "").strip().split("|")
        if len(parts) < 3 or parts[0] != fleet_id:
            residuals.append(f"skip-unproven-network:{nid[:12]}")
            continue
        if project_id and parts[1] != project_id:
            residuals.append(f"skip-other-project-network:{nid[:12]}")
            continue
        _docker(["docker", "network", "rm", nid])

    listed = _docker(["docker", "volume", "ls", "-q", *cf])
    vnames = [x for x in (listed.stdout or "").split() if x]
    for vname in vnames:
        insp = _docker(["docker", "volume", "inspect", "--format", _FMT_VOL, vname])
        parts = (insp.stdout or "").strip().split("|")
        if len(parts) < 3 or parts[0] != fleet_id:
            residuals.append(f"skip-unproven-volume:{vname}")
            continue
        if project_id and parts[1] != project_id:
            if not str(parts[1] or "").startswith("rv-"):
                residuals.append(f"skip-other-project-volume:{vname}")
                continue
        rm = _docker(["docker", "volume", "rm", vname])
        if not rm.ok:
            residuals.append(f"volume-rm-failed:{vname}")

    return residuals


def assert_labeled_absent(*, fleet_id: str, project_id: str | None = None) -> None:
    """Assert no fleet/project labeled containers/networks/volumes remain."""
    filters = [f"label=io.sbfleet.fleet={fleet_id}"]
    if project_id:
        filters.append(f"label=io.sbfleet.project={project_id}")
    cf: list[str] = []
    for f in filters:
        cf.extend(["--filter", f])
    for kind, argv in (
        ("container", ["docker", "ps", "-aq", *cf]),
        ("network", ["docker", "network", "ls", "-q", *cf]),
        ("volume", ["docker", "volume", "ls", "-q", *cf]),
    ):
        listed = _docker(argv)
        left = [x for x in (listed.stdout or "").split() if x]
        if project_id is None:
            assert not left, f"residual {kind}s for fleet {fleet_id}: {left}"
            continue
        if kind == "volume":
            exact = []
            for vname in left:
                insp = _docker(
                    [
                        "docker",
                        "volume",
                        "inspect",
                        "--format",
                        '{{index .Labels "io.sbfleet.project"}}',
                        vname,
                    ]
                )
                pl = (insp.stdout or "").strip()
                if pl == project_id:
                    exact.append(vname)
            assert not exact, f"residual volumes for project {project_id}: {exact}"
        else:
            assert not left, f"residual {kind}s for project {project_id}: {left}"


def wipe_fixture_filesystem(root: Path) -> None:
    """Best-effort remove disposable fixture home."""
    if not root.exists():
        return
    try:
        from sbfleet import registry as reg

        reg.safe_rmtree(root, under=root.parent)
    except Exception:  # noqa: BLE001
        pass
