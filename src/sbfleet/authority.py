"""Single mutation authority boundary .

Protects against accidental/stale/copied/tampered project state and cross-project
mistakes. This is NOT a hostile same-user security sandbox against unrestricted
Docker/filesystem access.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from sbfleet import compose as c
from sbfleet import registry as reg
from sbfleet import upstream as up
from sbfleet.process import run

# Docker network/container IDs: full=64 hex; short>=12 hex. Never coerce non-strings.
_DOCKER_ID_RE = re.compile(r"^[0-9a-fA-F]{12,64}$")

MutationIntent = Literal[
    "start",
    "stop",
    "restart",
    "remove",
    "backup",
    "restore",
    "update",
]

COMPOSE_FILE_VALUE = "docker-compose.yml:docker-compose.override.yml"
COMPOSE_PATH_SEPARATOR = ":"

INTENT_JOURNAL = {
    "start": "STARTING",
    "stop": "STOPPING",
    "restart": "RESTARTING",
    "remove": "REMOVING",
    "backup": "BACKUP",
    "restore": "RESTORING",
    "update": "UPDATING",
}


class AuthorityError(Exception):
    """Mutation authority refusal (fail closed)."""

    def __init__(self, message: str, *, code: int = 5) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class OwnedResource:
    kind: str  # container | network | volume
    name: str
    resource_id: str
    labels: dict[str, str] = field(default_factory=dict)


@dataclass
class OwnedInventory:
    containers: list[OwnedResource] = field(default_factory=list)
    networks: list[OwnedResource] = field(default_factory=list)
    volumes: list[OwnedResource] = field(default_factory=list)
    residuals: list[str] = field(default_factory=list)

    @property
    def all_ids(self) -> list[str]:
        return [r.resource_id for r in self.containers + self.networks + self.volumes]


@dataclass
class MutationContext:
    root: Path
    slug: str
    meta: dict[str, Any]
    deployment: Path
    project_dir: Path
    compose_project: str
    fleet_id: str
    project_id: str
    compose_env: dict[str, str]
    operation_id: str
    intent: MutationIntent
    inventory: OwnedInventory | None = None
    contract: c.ApprovedProfileContract | None = None


def forced_compose_env(deployment: Path, compose_project: str) -> dict[str, str]:
    """Compose selectors forced from recomputed identity — never trust mutable .env."""
    (deployment / ".run-home").mkdir(mode=0o700, exist_ok=True)
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(deployment / ".run-home"),
        "LC_ALL": "C",
        "COMPOSE_PROJECT_NAME": compose_project,
        "COMPOSE_FILE": COMPOSE_FILE_VALUE,
        "COMPOSE_PATH_SEPARATOR": COMPOSE_PATH_SEPARATOR,
    }


def _verify_env_selectors(deployment: Path, compose_project: str) -> None:
    env_path = deployment / ".env"
    if not env_path.exists():
        return
    try:
        reg.assert_secret_file(env_path)
    except reg.OwnershipError as exc:
        raise AuthorityError(str(exc)) from exc
    try:
        parsed = up.parse_dotenv(env_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise AuthorityError(f"unsafe/unreadable .env: {exc}") from exc
    for key, expected in (
        ("COMPOSE_PROJECT_NAME", compose_project),
        ("COMPOSE_FILE", COMPOSE_FILE_VALUE),
        ("COMPOSE_PATH_SEPARATOR", COMPOSE_PATH_SEPARATOR),
    ):
        present = parsed.get(key)
        if present is not None and present != expected:
            raise AuthorityError(
                f".env {key}={present!r} disagrees with metadata identity "
                f"expected={expected!r}; refusing mutation (fail closed)"
            )


def _validate_project_paths(root: Path, slug: str, meta: dict[str, Any]) -> Path:
    pdir = reg.project_dir(root, slug)
    reg.assert_managed_entry(pdir, under=root / "projects", expect_dir=True)
    meta_path = pdir / "project.json"
    if meta_path.exists() or meta_path.is_symlink():
        try:
            reg.assert_secret_file(meta_path)
        except reg.OwnershipError as exc:
            raise AuthorityError(str(exc)) from exc
    deployment = pdir / "deployment"
    reg.assert_managed_entry(
        deployment,
        under=pdir,
        expect_dir=True,
        refuse_mountpoint=True,
    )
    for rel, is_dir in (
        ("run.sh", False),
        ("docker-compose.yml", False),
        ("docker-compose.override.yml", False),
        (".env", False),
    ):
        path = deployment / rel
        if path.exists() or path.is_symlink():
            if rel == ".env":
                try:
                    reg.assert_secret_file(path)
                except reg.OwnershipError as exc:
                    raise AuthorityError(str(exc)) from exc
            else:
                reg.assert_managed_entry(
                    path,
                    under=deployment if is_dir else pdir,
                    expect_dir=is_dir,
                    expect_file=not is_dir,
                    refuse_mountpoint=True,
                )
    volumes = deployment / "volumes"
    if volumes.exists() or volumes.is_symlink():
        reg.assert_managed_entry(
            volumes,
            under=deployment,
            expect_dir=True,
            refuse_mountpoint=True,
        )
    return deployment


def build_project_contract(
    root: Path,
    meta: dict[str, Any],
    deployment: Path,
    compose_project: str,
) -> c.ApprovedProfileContract:
    """Build pin-derived approved contract (vendor cache + sbfleet identity facts)."""
    env_path = deployment / ".env"
    env: dict[str, str] = {}
    if env_path.is_file() and not env_path.is_symlink():
        try:
            reg.assert_secret_file(env_path)
        except reg.OwnershipError as exc:
            raise AuthorityError(str(exc)) from exc
        env = up.parse_dotenv(env_path.read_text(encoding="utf-8"))
    sha = str((meta.get("upstream") or {}).get("sha") or "")
    if not sha or len(sha) != 40:
        raise AuthorityError("project upstream sha missing; cannot build approved contract")
    cache = up.cache_dir(root, sha)
    vendor_docker = cache / "docker"
    if not vendor_docker.is_dir():
        raise AuthorityError(
            f"pinned vendor cache missing for sha={sha[:12]}; cannot build approved contract"
        )
    try:
        vendor_config = c.compose_config_json(
            vendor_docker,
            compose_project=compose_project,
            env=env or None,
            compose_file="docker-compose.yml",
        )
        return c.build_approved_standard_profile_contract(
            vendor_config,
            vendor_docker_root=vendor_docker,
            deployment=deployment,
            compose_project=compose_project,
            fleet_id=str(meta["fleet_id"]),
            project_id=str(meta["id"]),
        )
    except c.ComposeError as exc:
        raise AuthorityError(f"approved contract build failed: {exc}", code=5) from exc


def _validate_effective_compose(
    deployment: Path,
    meta: dict[str, Any],
    compose_project: str,
    contract: c.ApprovedProfileContract,
) -> None:
    env_path = deployment / ".env"
    env: dict[str, str] = {}
    if env_path.is_file() and not env_path.is_symlink():
        try:
            reg.assert_secret_file(env_path)
        except reg.OwnershipError as exc:
            raise AuthorityError(str(exc)) from exc
        env = up.parse_dotenv(env_path.read_text(encoding="utf-8"))
    config = c.compose_config_json(deployment, compose_project=compose_project, env=env)
    ports = meta["ports"]
    # Effective Compose is evidence — compare against pin-derived contract.
    try:
        c.assert_effective_matches_contract(
            config,
            contract,
            gateway_port=int(ports["gateway"]),
            db_direct_port=int(ports["db_direct"]),
            pooler_session_port=int(ports["pooler_session"]),
            pooler_transaction_port=int(ports["pooler_transaction"]),
            deployment=deployment,
        )
    except c.ComposeError as exc:
        raise AuthorityError(f"compose contract violated: {exc}", code=5) from exc


ObservationState = Literal["ABSENT", "PRESENT", "UNKNOWN", "FAILED"]


@dataclass
class DockerObservation:
    """Explicit Docker resource observation — never collapse UNKNOWN into ABSENT."""

    state: ObservationState
    data: dict[str, Any] | None = None
    detail: str = ""


# Exact Docker Engine missing-resource phrases (narrow ABSENT contract).
_MISSING_OBJECT_MARKERS = (
    "no such object",
    "no such container",
    "no such network",
    "no such volume",
    "error: no such object:",
    "network ",  # paired with " not found" below
    "volume ",
)


def _is_exact_missing_resource(result: Any) -> bool:
    """True only for the supported Docker missing-resource contract."""
    if result.ok:
        return False
    text = f"{result.stderr or ''}\n{result.stdout or ''}".lower()
    if not text.strip():
        return False
    # Refuse ambiguous failures (daemon down, permission, context, timeout text).
    ambiguous = (
        "cannot connect",
        "permission denied",
        "timeout",
        "context deadline",
        "error response from daemon: client version",
        "is the docker daemon running",
        "got permission denied",
        "connect: no such file",
    )
    if any(a in text for a in ambiguous):
        return False
    if any(
        m in text
        for m in (
            "no such object",
            "no such container",
            "no such network",
            "no such volume",
            "error: no such object:",
        )
    ):
        return True
    # Docker network/volume inspect: "Error response from daemon: network X not found"
    if " not found" in text and ("network " in text or "volume " in text or "container " in text):
        # Ensure this is an Error response style missing resource, not a generic failure.
        if "error response from daemon:" in text or "error:" in text:
            return True
    return False


def _docker_inspect_observation(args: list[str]) -> DockerObservation:
    """Inspect one Docker object; distinguish ABSENT from UNKNOWN/FAILED."""
    try:
        result = run(
            ["docker", *args],
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            timeout=60.0,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001
        return DockerObservation(state="FAILED", detail=f"docker inspect raised: {exc}")
    if not result.ok:
        if _is_exact_missing_resource(result):
            return DockerObservation(state="ABSENT", detail="confirmed missing")
        detail = (result.stderr or result.stdout or "docker inspect failed")[:300]
        return DockerObservation(state="UNKNOWN", detail=detail)
    text = (result.stdout or "").strip()
    if not text:
        return DockerObservation(state="FAILED", detail="empty inspect stdout")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return DockerObservation(state="FAILED", detail=f"malformed inspect JSON: {exc}")
    if isinstance(data, list):
        if not data:
            return DockerObservation(state="FAILED", detail="empty inspect list")
        data = data[0]
    if not isinstance(data, dict):
        return DockerObservation(state="FAILED", detail="inspect root is not an object")
    return DockerObservation(state="PRESENT", data=data)


def _docker_ps_filter_ids(filter_expr: str) -> DockerObservation:
    """List IDs for a docker filter; empty success is ABSENT-of-matches (caller decides)."""
    try:
        result = run(
            ["docker", "ps", "-aq", "--filter", filter_expr],
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            timeout=60.0,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001
        return DockerObservation(state="FAILED", detail=f"docker ps raised: {exc}")
    if not result.ok:
        detail = (result.stderr or result.stdout or "docker ps failed")[:300]
        return DockerObservation(state="UNKNOWN", detail=detail)
    ids = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
    return DockerObservation(state="PRESENT", data={"ids": ids})


def _docker_network_ls_ids(filter_expr: str) -> DockerObservation:
    try:
        result = run(
            ["docker", "network", "ls", "-q", "--filter", filter_expr],
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            timeout=60.0,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001
        return DockerObservation(state="FAILED", detail=f"docker network ls raised: {exc}")
    if not result.ok:
        detail = (result.stderr or result.stdout or "docker network ls failed")[:300]
        return DockerObservation(state="UNKNOWN", detail=detail)
    ids = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
    return DockerObservation(state="PRESENT", data={"ids": ids})


def _docker_volume_ls_names(filter_expr: str) -> DockerObservation:
    try:
        result = run(
            ["docker", "volume", "ls", "-q", "--filter", filter_expr],
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            timeout=60.0,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001
        return DockerObservation(state="FAILED", detail=f"docker volume ls raised: {exc}")
    if not result.ok:
        detail = (result.stderr or result.stdout or "docker volume ls failed")[:300]
        return DockerObservation(state="UNKNOWN", detail=detail)
    names = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
    return DockerObservation(state="PRESENT", data={"names": names})


def _label_map(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    return {str(k): str(v) for k, v in raw.items()}


def _prove_labels(
    labels: dict[str, str],
    *,
    fleet_id: str,
    project_id: str,
    resource: str,
) -> None:
    if labels.get("io.sbfleet.fleet") != fleet_id:
        raise AuthorityError(f"{resource}: missing/mismatched fleet label")
    if labels.get("io.sbfleet.project") != project_id:
        raise AuthorityError(f"{resource}: missing/mismatched project label")


def _refuse_observation(kind: str, obs: DockerObservation) -> None:
    if obs.state in {"UNKNOWN", "FAILED"}:
        raise AuthorityError(
            f"{kind} Docker observation {obs.state}: {obs.detail or 'unproven'}; refusing mutation"
        )


def _mount_mode_readonly(mount: dict, *, resource_name: str) -> bool:
    """Return read-only from explicit inspect facts; refuse missing/contradictory mode."""
    facts: list[bool] = []
    if "RW" in mount:
        rw = mount.get("RW")
        if not isinstance(rw, bool):
            raise AuthorityError(
                f"container {resource_name}: mount RW must be boolean, got {type(rw).__name__}"
            )
        facts.append(not rw)
    if "Mode" in mount:
        mode = mount.get("Mode")
        if mode is None:
            raise AuthorityError(f"container {resource_name}: mount Mode is null")
        if not isinstance(mode, str):
            raise AuthorityError(
                f"container {resource_name}: mount Mode must be string, got {type(mode).__name__}"
            )
        parts = [p.strip() for p in mode.split(",") if p.strip()]
        has_ro = "ro" in parts
        has_rw = "rw" in parts
        if has_ro and has_rw:
            raise AuthorityError(
                f"container {resource_name}: mount Mode {mode!r} has both ro and rw"
            )
        if has_ro:
            facts.append(True)
        elif has_rw:
            facts.append(False)
        else:
            raise AuthorityError(f"container {resource_name}: mount Mode {mode!r} missing ro/rw")
    if "ReadOnly" in mount:
        read_only = mount.get("ReadOnly")
        if not isinstance(read_only, bool):
            raise AuthorityError(
                f"container {resource_name}: mount ReadOnly must be boolean, "
                f"got {type(read_only).__name__}"
            )
        facts.append(read_only)
    if not facts:
        raise AuthorityError(f"container {resource_name}: mount missing RW/Mode/ReadOnly mode fact")
    if len(set(facts)) > 1:
        raise AuthorityError(
            f"container {resource_name}: contradictory mount mode facts (UNKNOWN/malformed)"
        )
    return facts[0]


def _require_typed_docker_network_id(value: Any, *, resource_name: str, net_name: str) -> str:
    """Require nonempty str Docker ID evidence; never stringify arbitrary JSON."""
    if value is None:
        raise AuthorityError(
            f"container {resource_name}: network attachment {net_name!r} missing NetworkID"
        )
    if not isinstance(value, str):
        raise AuthorityError(
            f"container {resource_name}: network attachment {net_name!r} "
            f"NetworkID must be string, got {type(value).__name__}"
        )
    net_id = value.strip()
    if not net_id:
        raise AuthorityError(
            f"container {resource_name}: network attachment {net_name!r} missing NetworkID"
        )
    if not _DOCKER_ID_RE.fullmatch(net_id):
        raise AuthorityError(
            f"container {resource_name}: network attachment {net_name!r} "
            f"malformed NetworkID {net_id[:24]!r}"
        )
    return net_id


def _prove_present_container(
    data: dict[str, Any],
    *,
    contract: c.ApprovedProfileContract,
    service: str | None,
    resource_name: str,
    recorded_image_ids: dict[str, str] | None = None,
    expected_network_canonical_id: str | None = None,
) -> OwnedResource:
    """Full PRESENT-container proof against the pin-derived contract."""
    rid = str(data.get("Id") or "")
    if not rid:
        raise AuthorityError(f"container {resource_name}: missing Id in inspect schema")
    labels = _label_map(data.get("Config", {}).get("Labels") or data.get("Labels"))
    _prove_labels(
        labels,
        fleet_id=contract.fleet_id,
        project_id=contract.project_id,
        resource=resource_name,
    )
    # Service identity is only the inspected compose label — never name-derived fill-in.
    compose_svc = labels.get("com.docker.compose.service") or ""
    compose_proj = labels.get("com.docker.compose.project") or ""
    if compose_proj != contract.compose_project:
        raise AuthorityError(
            f"container {resource_name}: compose project mismatch "
            f"{compose_proj!r} != {contract.compose_project!r}"
        )
    if not compose_svc or compose_svc not in contract.services:
        raise AuthorityError(
            f"container {resource_name}: unexpected or missing compose service {compose_svc!r}"
        )
    if service is not None and service != compose_svc:
        raise AuthorityError(
            f"container {resource_name}: compose service label {compose_svc!r} "
            f"does not match discovery hint {service!r}"
        )
    svc_contract = contract.services[compose_svc]

    # Mounts: required present + structurally valid — never coerce missing/null to [].
    if "Mounts" not in data:
        raise AuthorityError(f"container {resource_name}: missing Mounts in inspect schema")
    mounts_raw = data.get("Mounts")
    if mounts_raw is None:
        raise AuthorityError(f"container {resource_name}: null Mounts in inspect schema")
    if not isinstance(mounts_raw, list):
        raise AuthorityError(f"container {resource_name}: Mounts must be a list")

    got_mounts: set[tuple[str, str, str, bool]] = set()
    for mount in mounts_raw:
        if not isinstance(mount, dict):
            raise AuthorityError(f"container {resource_name}: malformed Mounts entry")
        mtype = str(mount.get("Type") or "")
        dest = str(mount.get("Destination") or mount.get("Target") or "")
        if not mtype:
            raise AuthorityError(f"container {resource_name}: mount missing Type")
        ro = _mount_mode_readonly(mount, resource_name=resource_name)
        if mtype == "bind":
            src = str(mount.get("Source") or "")
            if not src:
                raise AuthorityError(f"container {resource_name}: bind mount missing Source")
            if not dest:
                raise AuthorityError(f"container {resource_name}: bind mount missing Destination")
            got_mounts.add(("bind", str(Path(src).resolve(strict=False)), dest, ro))
        elif mtype == "volume":
            vol_name = str(mount.get("Name") or "")
            if not vol_name:
                raise AuthorityError(f"container {resource_name}: named volume missing Name")
            if not dest:
                raise AuthorityError(f"container {resource_name}: volume mount missing Destination")
            got_mounts.add(("volume", vol_name, dest, ro))
        elif mtype == "tmpfs":
            raise AuthorityError(
                f"container {resource_name}: unapproved tmpfs mount at {dest or '<unknown>'!r}"
            )
        else:
            raise AuthorityError(f"container {resource_name}: unsupported mount type {mtype!r}")
    exp_mounts = {(m.mount_type, m.source, m.destination, m.read_only) for m in svc_contract.mounts}
    if got_mounts != exp_mounts:
        raise AuthorityError(
            f"container {resource_name}: mount contract mismatch "
            f"extra={got_mounts - exp_mounts} missing={exp_mounts - got_mounts}"
        )

    # Networks: required present + structurally valid; exact attachment set + record schema.
    net_settings = data.get("NetworkSettings")
    if not isinstance(net_settings, dict):
        raise AuthorityError(f"container {resource_name}: missing/malformed NetworkSettings")
    if "Networks" not in net_settings:
        raise AuthorityError(f"container {resource_name}: missing NetworkSettings.Networks")
    networks = net_settings.get("Networks")
    if networks is None:
        raise AuthorityError(f"container {resource_name}: null NetworkSettings.Networks")
    if not isinstance(networks, dict):
        raise AuthorityError(
            f"container {resource_name}: NetworkSettings.Networks must be an object"
        )
    for net_name, ndata in networks.items():
        if ndata is None or not isinstance(ndata, dict):
            raise AuthorityError(
                f"container {resource_name}: null/malformed network attachment {net_name!r}"
            )
        net_id = _require_typed_docker_network_id(
            ndata.get("NetworkID"),
            resource_name=resource_name,
            net_name=str(net_name),
        )
        # When the expected owned network was positively inspected, require exact Id match.
        if (
            expected_network_canonical_id is not None
            and str(net_name) == contract.expected_network
            and net_id != expected_network_canonical_id
        ):
            raise AuthorityError(
                f"container {resource_name}: network attachment {net_name!r} "
                f"NetworkID mismatch got={net_id[:12]} "
                f"expected={expected_network_canonical_id[:12]}"
            )
    attached = frozenset(networks.keys())
    if attached != svc_contract.networks:
        raise AuthorityError(
            f"container {resource_name}: network attachment set mismatch "
            f"got={sorted(attached)} expected={sorted(svc_contract.networks)}"
        )

    # Image reference (Config.Image) vs approved vendor reference — distinct from Image ID.
    cfg = data.get("Config") if isinstance(data.get("Config"), dict) else {}
    config_image = str((cfg or {}).get("Image") or "")
    if config_image != svc_contract.image_ref:
        raise AuthorityError(
            f"container {resource_name}: Config.Image reference mismatch "
            f"got={config_image!r} expected={svc_contract.image_ref!r}"
        )
    # Runtime image identity (Image / ImageID) is a separate fact.
    runtime_image_id = str(data.get("Image") or cfg.get("ImageID") or data.get("ImageID") or "")
    if not runtime_image_id:
        raise AuthorityError(
            f"container {resource_name}: missing runtime image identity (Image/ImageID)"
        )
    if recorded_image_ids and compose_svc in recorded_image_ids:
        expected_id = recorded_image_ids[compose_svc]
        if expected_id and expected_id != "UNKNOWN" and runtime_image_id != expected_id:
            raise AuthorityError(
                f"container {resource_name}: runtime image identity mismatch "
                f"got={runtime_image_id[:24]} expected recorded={expected_id[:24]}"
            )

    return OwnedResource(
        kind="container",
        name=str(data.get("Name") or "").lstrip("/") or resource_name,
        resource_id=rid,
        labels=labels,
    )


def invent_owned_resources(
    *,
    compose_project: str,
    fleet_id: str,
    project_id: str,
    deployment: Path,
    contract: c.ApprovedProfileContract,
    recorded_image_ids: dict[str, str] | None = None,
    require_existing: bool = False,
) -> OwnedInventory:
    """
    Inventory the complete live Compose/project namespace independently for
    containers, networks, and named volumes.

    Expected names may discover conflicts; they do not independently authorize
    mutation. PRESENT resources require full contract proof (ID, labels, mounts,
    networks, image reference, runtime image identity).
    """
    if (
        contract.compose_project != compose_project
        or contract.fleet_id != fleet_id
        or contract.project_id != project_id
    ):
        raise AuthorityError("invent contract identity mismatch with invent parameters")

    inventory = OwnedInventory()
    expected_net = contract.expected_network
    expected_vols = set(contract.expected_volumes)
    expected_container_names = {svc.container_name for svc in contract.services.values()}

    # Resolve expected owned network identity first when positively inspectable so
    # container attachment NetworkIDs can be compared to that canonical Id.
    expected_network_canonical_id: str | None = None
    seen_nets: set[str] = set()
    n_ls = _docker_network_ls_ids(f"label=com.docker.compose.project={compose_project}")
    _refuse_observation("network-list", n_ls)
    net_ids = list((n_ls.data or {}).get("ids") or [])
    for nid in net_ids:
        obs = _docker_inspect_observation(["network", "inspect", nid])
        _refuse_observation(f"network:{nid[:12]}", obs)
        if obs.state == "ABSENT":
            continue
        data = obs.data or {}
        rid = data.get("Id")
        if not isinstance(rid, str) or not rid:
            raise AuthorityError(f"network {nid}: missing Id in inspect schema")
        if not _DOCKER_ID_RE.fullmatch(rid):
            raise AuthorityError(f"network {nid}: malformed Id {rid[:24]!r}")
        name = str(data.get("Name") or "")
        labels = _label_map(data.get("Labels"))
        try:
            _prove_labels(labels, fleet_id=fleet_id, project_id=project_id, resource=name or rid)
        except AuthorityError:
            inventory.residuals.append(f"foreign-or-mislabeled-network:{name or rid[:12]}")
            continue
        if name and name != expected_net:
            inventory.residuals.append(f"unexpected-project-network:{name}")
            continue
        seen_nets.add(rid)
        inventory.networks.append(
            OwnedResource(kind="network", name=name or rid[:12], resource_id=rid, labels=labels)
        )
        if name == expected_net:
            expected_network_canonical_id = rid
    if expected_network_canonical_id is None:
        obs = _docker_inspect_observation(["network", "inspect", expected_net])
        if obs.state != "ABSENT":
            _refuse_observation(f"network:{expected_net}", obs)
            data = obs.data or {}
            rid = data.get("Id")
            if not isinstance(rid, str) or not rid:
                raise AuthorityError(f"network {expected_net}: missing Id")
            if not _DOCKER_ID_RE.fullmatch(rid):
                raise AuthorityError(f"network {expected_net}: malformed Id {rid[:24]!r}")
            labels = _label_map(data.get("Labels"))
            try:
                _prove_labels(
                    labels, fleet_id=fleet_id, project_id=project_id, resource=expected_net
                )
                if rid not in seen_nets:
                    inventory.networks.append(
                        OwnedResource(
                            kind="network",
                            name=expected_net,
                            resource_id=rid,
                            labels=labels,
                        )
                    )
                    seen_nets.add(rid)
                expected_network_canonical_id = rid
            except AuthorityError:
                inventory.residuals.append(f"expected-name-conflict-network:{expected_net}")

    c_ls = _docker_ps_filter_ids(f"label=com.docker.compose.project={compose_project}")
    _refuse_observation("container-list", c_ls)
    container_ids = list((c_ls.data or {}).get("ids") or [])
    seen_ids: set[str] = set()
    for cid in container_ids:
        obs = _docker_inspect_observation(["inspect", "--format", "{{json .}}", cid])
        _refuse_observation(f"container:{cid[:12]}", obs)
        if obs.state == "ABSENT":
            continue
        data = obs.data or {}
        name = str(data.get("Name") or "").lstrip("/") or cid[:12]
        try:
            owned = _prove_present_container(
                data,
                contract=contract,
                service=None,
                resource_name=name,
                recorded_image_ids=recorded_image_ids,
                expected_network_canonical_id=expected_network_canonical_id,
            )
        except AuthorityError as exc:
            inventory.residuals.append(str(exc))
            continue
        seen_ids.add(owned.resource_id)
        inventory.containers.append(owned)

    # Expected-name probes: conflict discovery with the SAME full proof — never
    # authorize from labels/name alone.
    for cname in sorted(expected_container_names):
        if any(r.name == cname for r in inventory.containers):
            continue
        obs = _docker_inspect_observation(["inspect", "--format", "{{json .}}", cname])
        if obs.state == "ABSENT":
            continue
        _refuse_observation(f"container:{cname}", obs)
        data = obs.data or {}
        rid = str(data.get("Id") or "")
        if rid in seen_ids:
            continue
        # Expected name may discover conflicts; it must never synthesize service identity.
        try:
            owned = _prove_present_container(
                data,
                contract=contract,
                service=None,
                resource_name=cname,
                recorded_image_ids=recorded_image_ids,
                expected_network_canonical_id=expected_network_canonical_id,
            )
        except AuthorityError as exc:
            inventory.residuals.append(f"expected-name-conflict:{cname}:{exc}")
            continue
        seen_ids.add(owned.resource_id)
        inventory.containers.append(owned)

    # --- Volumes ---
    v_ls = _docker_volume_ls_names(f"label=com.docker.compose.project={compose_project}")
    _refuse_observation("volume-list", v_ls)
    vol_names = list((v_ls.data or {}).get("names") or [])
    seen_vols: set[str] = set()
    for vol_name in vol_names:
        obs = _docker_inspect_observation(["volume", "inspect", vol_name])
        _refuse_observation(f"volume:{vol_name}", obs)
        if obs.state == "ABSENT":
            continue
        data = obs.data or {}
        rid = str(data.get("Name") or vol_name)
        if not rid:
            raise AuthorityError(f"volume {vol_name}: missing Name")
        labels = _label_map(data.get("Labels"))
        try:
            _prove_labels(labels, fleet_id=fleet_id, project_id=project_id, resource=vol_name)
        except AuthorityError:
            inventory.residuals.append(f"foreign-or-mislabeled-volume:{vol_name}")
            continue
        if vol_name not in expected_vols:
            inventory.residuals.append(f"unexpected-project-volume:{vol_name}")
            continue
        seen_vols.add(rid)
        inventory.volumes.append(
            OwnedResource(kind="volume", name=vol_name, resource_id=rid, labels=labels)
        )
    for vol_name in sorted(expected_vols):
        if any(r.name == vol_name for r in inventory.volumes):
            continue
        obs = _docker_inspect_observation(["volume", "inspect", vol_name])
        if obs.state == "ABSENT":
            continue
        _refuse_observation(f"volume:{vol_name}", obs)
        data = obs.data or {}
        rid = str(data.get("Name") or vol_name)
        if not rid:
            raise AuthorityError(f"volume {vol_name}: missing Name")
        labels = _label_map(data.get("Labels"))
        try:
            _prove_labels(labels, fleet_id=fleet_id, project_id=project_id, resource=vol_name)
            if rid not in seen_vols:
                inventory.volumes.append(
                    OwnedResource(kind="volume", name=vol_name, resource_id=rid, labels=labels)
                )
        except AuthorityError:
            inventory.residuals.append(f"expected-name-conflict-volume:{vol_name}")

    if require_existing and not inventory.containers and not inventory.networks:
        pass
    if inventory.residuals:
        raise AuthorityError(
            "live Docker ownership cannot be proven for: "
            + ", ".join(inventory.residuals)
            + "; refusing mutation"
        )
    return inventory


# Back-compat alias used by older tests/helpers — prefer invent_owned_resources.
def _docker_inspect_json(args: list[str]) -> Any | None:
    """Deprecated collapse helper — prefer _docker_inspect_observation."""
    obs = _docker_inspect_observation(args)
    if obs.state == "PRESENT":
        return obs.data
    return None


def _check_unresolved_for_intent(
    journal: dict[str, Any] | None,
    intent: MutationIntent,
) -> None:
    """Explicit journal transition policy — refuse illegal overwrites."""
    if not reg.journal_is_unresolved(journal):
        return
    assert journal is not None
    j_intent = str(journal.get("intent") or "")
    j_phase = str(journal.get("phase") or "")
    j_state = str(journal.get("state") or "")
    detail = f"intent={j_intent!r} phase={j_phase!r} state={j_state!r}"
    if intent in {"start", "restart"}:
        raise AuthorityError(
            "unresolved operation journal blocks ordinary start/restart; "
            f"{detail}. Reconcile explicitly before continuing.",
            code=5,
        )
    if intent in {"backup", "restore", "update", "remove"}:
        raise AuthorityError(
            "unresolved maintenance/destructive journal blocks a new "
            f"{intent} operation; {detail}. Reconcile explicitly before continuing "
            "(no silent overwrite; no --force).",
            code=5,
        )
    # Ordinary stop may proceed to halt containers, but must not replace the
    # unresolved parent journal (enforced in stop_project / begin_operation).


def journal_is_maintenance_unresolved(journal: dict[str, Any] | None) -> bool:
    """True when an unresolved maintenance/destructive intent must be preserved."""
    if not reg.journal_is_unresolved(journal):
        return False
    intent = str((journal or {}).get("intent") or "")
    return intent in {"RESTORING", "UPDATING", "REMOVING", "BACKUP"}


@contextmanager
def authorize_mutation(
    root: Path,
    slug: str,
    *,
    intent: MutationIntent,
    timeout: float = reg.DEFAULT_LOCK_TIMEOUT_S,
    require_creation_complete: bool = True,
    allow_config_ready_start: bool = False,
    validate_compose: bool = True,
    invent_live: bool = True,
    already_locked: bool = False,
    ignore_unresolved_journal: bool = False,
    skip_pin_vendor_check: bool = False,
) -> Iterator[MutationContext]:
    """
    Resolve → lock → re-read → identity → paths → compose → live → journal → authorize.

    When already_locked=True, caller must already hold registry+project locks;
    this path does not reacquire (prevents nested deadlock).

    When ignore_unresolved_journal=True (nested lifecycle under backup/restore),
    skip the ordinary-start unresolved check so prior-state restart can proceed
    while the parent operation journal remains in progress.

    When skip_pin_vendor_check=True (interrupted-update reconcile), do not refuse
    because mixed live bytes fail current metadata pin proof — frozen promote-record
    is the recovery truth.
    """
    slug = reg.validate_slug(slug)
    # Pre-lock resolve only to discover project_id for locking — do not trust for mutation.
    try:
        preliminary = reg.read_project(root, slug)
    except reg.NotFoundError as exc:
        raise AuthorityError(f"cannot resolve project '{slug}': {exc}", code=3) from exc
    except reg.RegistryError as exc:
        # Corrupt/incomplete/ownership — fail closed, not "absent".
        raise AuthorityError(f"cannot resolve project '{slug}': {exc}", code=5) from exc
    project_id = str(preliminary["id"])

    def _authorize_under_lock() -> MutationContext:
        # Re-read under lock — never trust pre-lock state.
        try:
            meta = reg.read_project(root, slug)
            meta = reg.validate_project_identity(root, meta)
        except reg.NotFoundError as exc:
            raise AuthorityError(f"re-read under lock failed: {exc}", code=3) from exc
        except reg.RegistryError as exc:
            raise AuthorityError(f"re-read under lock failed: {exc}", code=5) from exc
        if str(meta["id"]) != project_id:
            raise AuthorityError("project id changed under lock; refusing")

        if require_creation_complete and not meta.get("creation_complete"):
            if not (
                allow_config_ready_start
                and meta.get("config_ready")
                and (meta.get("create_intent") or {}).get("requested_start")
            ):
                raise AuthorityError(f"project '{slug}' creation incomplete", code=5)

        fleet = str(meta["fleet_id"])
        pid = str(meta["id"])
        compose_project = reg.compose_project_name(fleet, pid)
        if meta.get("compose_project") != compose_project:
            raise AuthorityError(
                f"compose_project mismatch under lock: {meta.get('compose_project')!r} "
                f"!= {compose_project!r}"
            )

        journal = reg.read_operation_journal(root, slug)
        if not ignore_unresolved_journal:
            _check_unresolved_for_intent(journal, intent)

        deployment = _validate_project_paths(root, slug, meta)
        if not (deployment / "run.sh").is_file():
            raise AuthorityError("deployment run.sh missing", code=5)

        _verify_env_selectors(deployment, compose_project)

        # Pin/stamp: fail closed when upstream SHA is recorded (refuse missing cache).
        # Interrupted-update reconcile skips live pin proof (mixed tree; frozen plan wins).
        sha = str((meta.get("upstream") or {}).get("sha") or "")
        if sha and len(sha) == 40 and not skip_pin_vendor_check:
            cache = up.cache_dir(root, sha)
            if not cache.is_dir():
                raise AuthorityError(
                    f"pin/vendor integrity: upstream cache missing for sha={sha[:12]}",
                    code=5,
                )
            try:
                up.verify_deployment_vendor(deployment, sha=sha, root=root)
                up.verify_stamp_matches_meta(deployment, meta)
            except up.UpstreamError as exc:
                raise AuthorityError(f"pin/vendor integrity: {exc}", code=5) from exc

        if validate_compose or invent_live:
            contract = build_project_contract(root, meta, deployment, compose_project)
        else:
            contract = None

        if validate_compose:
            assert contract is not None
            _validate_effective_compose(deployment, meta, compose_project, contract)

        inventory: OwnedInventory | None = None
        if invent_live:
            assert contract is not None
            recorded: dict[str, str] = {}
            raw_digests = meta.get("image_digests")
            digests = raw_digests if isinstance(raw_digests, dict) else {}
            for svc, entry in digests.items():
                if isinstance(entry, dict):
                    iid = str(entry.get("image_id") or "")
                    if iid:
                        recorded[str(svc)] = iid
            inventory = invent_owned_resources(
                compose_project=compose_project,
                fleet_id=fleet,
                project_id=pid,
                deployment=deployment,
                contract=contract,
                recorded_image_ids=recorded or None,
            )

        # Fresh operation identity for each legal top-level authorization.
        # Nested already-managed callers must not call begin_operation over a parent.
        operation_id = __import__("uuid").uuid4().hex
        # Proven parent-operation context: under held locks with nested ignore, bind
        # to the durable maintenance journal identity so status exemption cannot be
        # forged with a raw operation-id string alone.
        if ignore_unresolved_journal and journal_is_maintenance_unresolved(journal):
            parent_op = str((journal or {}).get("operation_id") or "")
            if parent_op:
                operation_id = parent_op

        compose_env = forced_compose_env(deployment, compose_project)
        return MutationContext(
            root=root,
            slug=slug,
            meta=meta,
            deployment=deployment,
            project_dir=reg.project_dir(root, slug),
            compose_project=compose_project,
            fleet_id=fleet,
            project_id=pid,
            compose_env=compose_env,
            operation_id=operation_id,
            intent=intent,
            inventory=inventory,
            contract=contract,
        )

    if already_locked:
        ctx = _authorize_under_lock()
        yield ctx
        return

    with reg.locked_registry_then_project(root, project_id, timeout=timeout):
        ctx = _authorize_under_lock()
        yield ctx


def begin_operation(ctx: MutationContext, *, phase: str = "run") -> dict[str, Any]:
    current = reg.read_operation_journal(ctx.root, ctx.slug)
    if journal_is_maintenance_unresolved(current):
        cur = str((current or {}).get("intent") or "")
        new = INTENT_JOURNAL[ctx.intent]
        if cur != new:
            raise AuthorityError(
                f"refusing to overwrite unresolved {cur} journal with {new}; "
                "reconcile explicitly before continuing",
                code=5,
            )
        # Same maintenance intent: advance phase without replacing operation identity.
        parent_op = str((current or {}).get("operation_id") or "")
        if parent_op:
            ctx.operation_id = parent_op
        return record_operation_phase(ctx, phase=phase)
    journal = reg.new_operation_journal(
        intent=INTENT_JOURNAL[ctx.intent],
        phase=phase,
        state=reg.OP_STATE_IN_PROGRESS,
        operation_id=ctx.operation_id,
    )
    reg.write_operation_journal(ctx.root, ctx.slug, journal)
    return journal


def record_subordinate_stop_evidence(ctx: MutationContext, *, detail: str) -> dict[str, Any]:
    """Record a nested/ordinary stop under an unresolved parent without replacing it."""
    from datetime import datetime, timezone

    current = reg.read_operation_journal(ctx.root, ctx.slug) or {}
    if not journal_is_maintenance_unresolved(current):
        return current
    evidence = dict(current.get("evidence") or {})
    stops = list(evidence.get("subordinate_stops") or [])
    stops.append(
        {
            "detail": detail[:200],
            "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )
    evidence["subordinate_stops"] = stops[-20:]
    merged = dict(current)
    merged["evidence"] = evidence
    merged["at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    # Never change intent/state/operation_id — stop is subordinate evidence only.
    reg.write_operation_journal(ctx.root, ctx.slug, merged)
    return merged


def record_operation_phase(
    ctx: MutationContext,
    *,
    phase: str,
    evidence: dict[str, Any] | None = None,
    merge_evidence: bool = True,
) -> dict[str, Any]:
    """Advance phase on the authoritative journal without changing intent/operation_id.

    Used for multi-phase backup/restore machines. Nested pre-restore evidence is
    merged under keys such as ``pre_restore`` — it must never replace RESTORING
    with a BACKUP intent.
    """
    from datetime import datetime, timezone

    current = reg.read_operation_journal(ctx.root, ctx.slug) or {}
    intent = INTENT_JOURNAL[ctx.intent]
    # Preserve original started_at when continuing the same operation.
    started = current.get("started_at") if current.get("operation_id") == ctx.operation_id else None
    journal = reg.new_operation_journal(
        intent=intent,
        phase=phase,
        state=reg.OP_STATE_IN_PROGRESS,
        operation_id=ctx.operation_id,
    )
    if started:
        journal["started_at"] = started
    journal["at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if merge_evidence and isinstance(current.get("evidence"), dict):
        merged = dict(current["evidence"])
    else:
        merged = {}
    if evidence:
        for key, value in evidence.items():
            if (
                merge_evidence
                and key in merged
                and isinstance(merged[key], dict)
                and isinstance(value, dict)
            ):
                nested = dict(merged[key])
                nested.update(value)
                merged[key] = nested
            else:
                merged[key] = value
    if merged:
        journal["evidence"] = merged
    # Carry forward known nonsecret diagnostic fields.
    for key in ("quarantine_path", "pre_restore", "archive_path", "backup_id"):
        if key in current and key not in journal:
            journal[key] = current[key]
    reg.write_operation_journal(ctx.root, ctx.slug, journal)
    return journal


def complete_operation(
    ctx: MutationContext,
    *,
    phase: str = "done",
    intent: str | None = None,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    current = reg.read_operation_journal(ctx.root, ctx.slug) or {}
    journal = reg.new_operation_journal(
        intent=intent or INTENT_JOURNAL[ctx.intent],
        phase=phase,
        state=reg.OP_STATE_COMPLETED,
        operation_id=ctx.operation_id,
        extra={"evidence": evidence} if evidence else None,
    )
    if isinstance(current.get("evidence"), dict) and not evidence:
        journal["evidence"] = current["evidence"]
    elif isinstance(current.get("evidence"), dict) and evidence:
        merged = dict(current["evidence"])
        merged.update(evidence)
        journal["evidence"] = merged
    # Stable completed intent names for lifecycle.
    if ctx.intent == "start" and phase == "done":
        journal["intent"] = "STARTED"
    elif ctx.intent == "stop" and phase == "done":
        journal["intent"] = "STOPPED"
    elif ctx.intent == "restart" and phase == "done":
        journal["intent"] = "RESTARTED"
    elif ctx.intent == "backup" and phase in {"done", "completed"}:
        journal["intent"] = "BACKUP"
        journal["phase"] = "completed"
    elif ctx.intent == "restore" and phase in {"done", "completed"}:
        journal["intent"] = "RESTORING"
        journal["phase"] = "completed"
    reg.write_operation_journal(ctx.root, ctx.slug, journal)
    return journal


def revalidate_deployment_authority(ctx: MutationContext) -> None:
    """Re-run env selector + Compose contract checks under an existing lock.

    Used after restore field-level .env reconciliation before starting services.
    """
    _verify_env_selectors(ctx.deployment, ctx.compose_project)
    contract = ctx.contract or build_project_contract(
        ctx.root, ctx.meta, ctx.deployment, ctx.compose_project
    )
    _validate_effective_compose(ctx.deployment, ctx.meta, ctx.compose_project, contract)


def fail_operation(
    ctx: MutationContext,
    *,
    error: str,
    phase: str = "failed",
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from sbfleet.process import (
        CREDENTIAL_SAFE_RENDERING_UNAVAILABLE,
        DiagnosticRedactorUnavailable,
        sanitize_configured_diagnostic,
    )

    try:
        safe_error = sanitize_configured_diagnostic(
            error,
            deployment=ctx.deployment,
            max_len=500,
        )
    except DiagnosticRedactorUnavailable:
        safe_error = CREDENTIAL_SAFE_RENDERING_UNAVAILABLE[:500]
    current = reg.read_operation_journal(ctx.root, ctx.slug) or {}
    journal = reg.new_operation_journal(
        intent=INTENT_JOURNAL[ctx.intent],
        phase=phase,
        state=reg.OP_STATE_FAILED,
        operation_id=ctx.operation_id,
        error=safe_error,
    )
    if isinstance(current.get("evidence"), dict):
        merged = dict(current["evidence"])
        if evidence:
            merged.update(evidence)
        journal["evidence"] = merged
    elif evidence:
        journal["evidence"] = evidence
    for key in ("quarantine_path", "pre_restore", "archive_path", "backup_id"):
        if key in current:
            journal[key] = current[key]
    reg.write_operation_journal(ctx.root, ctx.slug, journal)
    return journal
