"""Sandbox network ownership, inventory, linked/dotenv audits (Run 2D)."""

from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from sbfleet.cli import EXIT_SAFETY
from sbfleet.process import run
from sbfleet.sandbox_adoption import AdoptionRecord
from sbfleet.sandbox_config import SandboxConfigError, assert_local_url, assert_loopback_host_ip

# Verified CLI 2.118.0 identity labels (see docs/verification/CLI-2.118.0-docker-identity-facts.md)
CLI_PROJECT_LABEL = "com.supabase.cli.project"
CLI_WORKDIR_LABEL = "com.supabase.cli.workdir"
SBFLEET_SANDBOX_LABEL = "io.sbfleet.sandbox"
SBFLEET_UUID_LABEL = "io.sbfleet.sandbox_uuid"
SBFLEET_OP_LABEL = "io.sbfleet.operation"
HOST_BINDING_OPT = "com.docker.network.bridge.host_binding_ipv4"

DOCKER_ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}

# Docker IDs: full=64 hex; stored short>=12 hex. Attachment compares to canonical full Id only.
_DOCKER_ID_RE = re.compile(r"^[0-9a-fA-F]{12,64}$")
_DOCKER_FULL_ID_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class SandboxAuthorityError(Exception):
    def __init__(self, msg: str, *, code: int = EXIT_SAFETY) -> None:
        super().__init__(msg)
        self.code = code


def _docker_json(argv: list[str]) -> Any:
    result = run(argv, env=DOCKER_ENV, check=False)
    if not result.ok:
        raise SandboxAuthorityError(
            f"docker inspect failed: {(result.stderr or result.stdout or '')}"
        )
    try:
        return json.loads(result.stdout or "null")
    except json.JSONDecodeError as exc:
        raise SandboxAuthorityError(f"malformed docker JSON: {exc}") from exc


def _require_typed_docker_id(value: Any, *, what: str) -> str:
    """Require nonempty str Docker ID; never stringify arbitrary JSON."""
    if value is None:
        raise SandboxAuthorityError(f"{what} missing")
    if not isinstance(value, str):
        raise SandboxAuthorityError(f"{what} must be string, got {type(value).__name__}")
    text = value.strip()
    if not text:
        raise SandboxAuthorityError(f"{what} missing")
    if not _DOCKER_ID_RE.fullmatch(text):
        raise SandboxAuthorityError(f"{what} malformed Docker ID {text[:24]!r}")
    return text


def _canonical_network_id_from_inspect(net: dict[str, Any], *, stored_ref: str) -> str:
    """Return positively inspected full network Id; resolve supported stored short refs."""
    full_raw = net.get("Id")
    if not isinstance(full_raw, str) or not full_raw.strip():
        raise SandboxAuthorityError("network inspect missing Id")
    full = full_raw.strip()
    if not _DOCKER_FULL_ID_RE.fullmatch(full):
        raise SandboxAuthorityError(f"network inspect Id not canonical full form {full[:24]!r}")
    stored = _require_typed_docker_id(stored_ref, what="stored network id")
    stored_l = stored.lower()
    full_l = full.lower()
    if stored_l == full_l:
        return full
    # Legacy short stored ID: >=12 hex and exact prefix of the inspected full Id.
    if len(stored) < 64 and full_l.startswith(stored_l):
        return full
    raise SandboxAuthorityError(
        f"stored network id {stored[:12]} does not resolve to inspected Id {full[:12]}"
    )


def _prove_exact_owned_network_attachments(
    nets: Any,
    *,
    canonical_network_id: str,
    network_name: str,
    resource: str,
) -> None:
    """Require exact approved attachment name/key plus exact canonical NetworkID.

    Attachment NetworkID must equal the positively inspected full network Id.
    Valid-length prefix sharing is not authority.
    """
    if not isinstance(nets, dict):
        raise SandboxAuthorityError(f"{resource} Networks missing/malformed")
    if not canonical_network_id or not network_name:
        raise SandboxAuthorityError(
            f"{resource} owned network identity incomplete (name/id required)"
        )
    canonical = _require_typed_docker_id(
        canonical_network_id, what=f"{resource} canonical network id"
    )
    if not _DOCKER_FULL_ID_RE.fullmatch(canonical):
        raise SandboxAuthorityError(
            f"{resource} canonical network id must be full 64-hex, got {canonical[:24]!r}"
        )
    expected_keys = {network_name}
    got_keys = set(nets.keys())
    if got_keys != expected_keys:
        raise SandboxAuthorityError(
            f"{resource} network attachment set mismatch "
            f"got={sorted(got_keys)} expected={sorted(expected_keys)}"
        )
    for net_key, ndata in nets.items():
        if ndata is None or not isinstance(ndata, dict):
            raise SandboxAuthorityError(f"{resource} null/malformed network attachment {net_key!r}")
        if net_key != network_name:
            raise SandboxAuthorityError(
                f"{resource} unexpected network attachment name {net_key!r}"
            )
        att_id = _require_typed_docker_id(
            ndata.get("NetworkID"),
            what=f"{resource} network attachment {net_key!r} NetworkID",
        )
        if att_id != canonical:
            raise SandboxAuthorityError(
                f"{resource} network attachment {net_key!r} NetworkID mismatch "
                f"got={att_id[:12]} expected={canonical[:12]}"
            )


def _container_runtime_state(obj: dict[str, Any], *, resource: str) -> str:
    """Classify Running/STOPPED/UNKNOWN from inspect State — never infer from presence."""
    state = obj.get("State")
    if not isinstance(state, dict):
        raise SandboxAuthorityError(f"{resource} State missing/malformed")
    if "Running" not in state:
        raise SandboxAuthorityError(f"{resource} State.Running missing")
    running = state.get("Running")
    if not isinstance(running, bool):
        raise SandboxAuthorityError(
            f"{resource} State.Running must be boolean, got {type(running).__name__}"
        )
    if running:
        return "RUNNING"
    status = str(state.get("Status") or "").lower()
    if status in {"exited", "dead", "created", "paused", "restarting"} or status == "":
        return "STOPPED"
    return "UNKNOWN"


# --- Linked / remote / dotenv -------------------------------------------------

DANGEROUS_ENV_KEYS = frozenset(
    {
        "SUPABASE_ACCESS_TOKEN",
        "SUPABASE_AUTH_TOKEN",
        "SUPABASE_SERVICE_ROLE_KEY",
        "SUPABASE_DB_PASSWORD",
        "POSTGRES_PASSWORD",
        "DATABASE_URL",
        "SUPABASE_URL",
        "SUPABASE_PROJECT_ID",
        "SUPABASE_PROJECT_REF",
        "SUPABASE_WORKDIR",
        "SUPABASE_INTERNAL_IMAGE_REGISTRY",
        "SUPABASE_INTERNAL_IMAGE_VERSION",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CERT_PATH",
        "COMPOSE_FILE",
        "COMPOSE_PROJECT_NAME",
        "PGHOST",
        "PGHOSTADDR",
        "PGPORT",
        "PGDATABASE",
        "PGUSER",
        "PGPASSWORD",
        "PGPASSFILE",
        "PGSERVICE",
        "PGSERVICEFILE",
        "PGSSLMODE",
        "PGOPTIONS",
    }
)

# Keys that must not appear targeting remote/cloud in dotenv (prefix match).
DANGEROUS_PREFIXES = (
    "SUPABASE_ACCESS",
    "SUPABASE_AUTH",
    "SUPABASE_SERVICE",
    "SUPABASE_PROJECT",
    "SUPABASE_INTERNAL",
    "POSTGRES_",
    "PG",
    "DATABASE_URL",
    "AWS_",
    "AZURE_",
    "DOCKER_",
    "COMPOSE_",
)

_DOTENV_LINE = re.compile(r"""^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$""")


def parse_dotenv_keys(text: str) -> dict[str, str]:
    """
    Parse supported sandbox-authority dotenv grammar.

    Supported non-empty lines:
      KEY=value
      export KEY=value
      optional single/double quotes around value
      blank lines and # comments

    Malformed / ambiguous non-empty lines refuse (fail closed).
    """
    out: dict[str, str] = {}
    for lineno, line in enumerate(text.splitlines(), start=1):
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        m = _DOTENV_LINE.match(line)
        if not m:
            raise SandboxAuthorityError(
                f"unsupported/malformed dotenv line {lineno}: refuse ambiguous grammar"
            )
        key, val = m.group(1), m.group(2).strip()
        if (val.startswith('"') and val.endswith('"') and len(val) >= 2) or (
            val.startswith("'") and val.endswith("'") and len(val) >= 2
        ):
            val = val[1:-1]
        elif val.startswith(("'", '"')) or val.endswith(("'", '"')):
            raise SandboxAuthorityError(f"unsupported/malformed dotenv quoting on line {lineno}")
        out[key] = val
    return out


def audit_dotenv(app: Path) -> None:
    locations = [
        app / ".env",
        app / ".env.local",
        app / "supabase" / ".env",
        app / "supabase" / ".env.local",
    ]
    # Ancestor dotenv that pinned CLI may load (app parent only — one level).
    if app.parent != app:
        locations.extend([app.parent / ".env", app.parent / ".env.local"])
    for p in locations:
        if not p.is_file():
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        parsed = parse_dotenv_keys(text)
        for key in parsed:
            up = key.upper()
            if up in DANGEROUS_ENV_KEYS or any(up.startswith(pref) for pref in DANGEROUS_PREFIXES):
                # Allow empty values? Still refuse presence of dangerous selectors.
                raise SandboxAuthorityError(
                    f"credential/target-bearing dotenv refused: {p.name} ({key})"
                )


def audit_linked_remote_state(app: Path, cfg_has_remotes: bool, cli_home: Path) -> None:
    if cfg_has_remotes:
        raise SandboxAuthorityError("config.toml [remotes] present; refuse local sandbox authority")

    temp = app / "supabase" / ".temp"
    if temp.is_dir():
        # Known linked marker from CLI; also refuse any non-empty project-ref-like files.
        linked_names = ("project-ref", "project-ref.txt", "linked-project.json", "gotrue")
        for name in linked_names:
            p = temp / name
            if p.is_file() and p.read_text(encoding="utf-8", errors="replace").strip():
                raise SandboxAuthorityError(
                    f"linked remote marker present: {p.relative_to(app)}; unlink before sandbox use"
                )
        # Ambiguous remote cache: profile / access under .temp
        for p in temp.rglob("*"):
            if not p.is_file():
                continue
            low = p.name.lower()
            if "access-token" in low or "access_token" in low or low == "profile.json":
                if p.read_text(encoding="utf-8", errors="replace").strip():
                    raise SandboxAuthorityError(f"remote credential cache present: {p}")

    # Private CLI home must not contain Cloud credentials.
    for name in ("access-token", "access_token", ".supabase/access-token"):
        p = cli_home / name if "/" not in name else cli_home.joinpath(*name.split("/"))
        if p.is_file() and p.read_text(encoding="utf-8", errors="replace").strip():
            raise SandboxAuthorityError(f"CLI home contains credentials: {p.name}")
    # Nested ~/.supabase style under isolated home
    for p in cli_home.rglob("*"):
        if not p.is_file():
            continue
        low = p.name.lower()
        if "access-token" in low or low == "credentials.json":
            if p.stat().st_size > 0:
                raise SandboxAuthorityError(f"CLI home contains credentials: {p}")


def child_env(cli_home: Path) -> dict[str, str]:
    """Allowlisted child environment; does not inherit os.environ."""
    path = os.environ.get("PATH", "/usr/bin:/bin")
    tmp = os.environ.get("TMPDIR") or os.environ.get("TMP") or "/tmp"
    env = {
        "PATH": path,
        "HOME": str(cli_home),
        "SUPABASE_HOME": str(cli_home),
        "SUPABASE_NO_KEYRING": "1",
        "SUPABASE_TELEMETRY_DISABLED": "1",
        "DO_NOT_TRACK": "1",
        "SUPABASE_EXPERIMENTAL_STACK": "0",
        "SUPABASE_ACCESS_TOKEN": "invalid-token-sentinel",
        "SUPABASE_AUTH_TOKEN": "invalid-token-sentinel",
        "SUPABASE_API_URL": "http://127.0.0.1:9",
        "LC_ALL": "C",
        "TMPDIR": tmp,
        "TMP": tmp,
        "TEMP": tmp,
    }
    return env


# --- Network ------------------------------------------------------------------


def prove_network_owned(
    network_ref: str,
    *,
    path_hash: str,
    sandbox_uuid: str,
) -> dict[str, Any]:
    data = _docker_json(["docker", "network", "inspect", network_ref])
    if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
        raise SandboxAuthorityError("docker network inspect returned unexpected shape")
    net = data[0]
    labels = net.get("Labels") or {}
    if not isinstance(labels, dict):
        raise SandboxAuthorityError("network labels missing/malformed")
    if labels.get(SBFLEET_SANDBOX_LABEL) != path_hash:
        raise SandboxAuthorityError(
            f"network missing/mismatched {SBFLEET_SANDBOX_LABEL} "
            f"(have {labels.get(SBFLEET_SANDBOX_LABEL)!r})"
        )
    if labels.get(SBFLEET_UUID_LABEL) != sandbox_uuid:
        raise SandboxAuthorityError(
            f"network missing/mismatched {SBFLEET_UUID_LABEL} "
            f"(have {labels.get(SBFLEET_UUID_LABEL)!r})"
        )
    if net.get("Driver") != "bridge":
        raise SandboxAuthorityError(f"network driver must be bridge, got {net.get('Driver')!r}")
    if net.get("Scope") != "local":
        raise SandboxAuthorityError(f"network scope must be local, got {net.get('Scope')!r}")
    options = net.get("Options") or {}
    if not isinstance(options, dict):
        raise SandboxAuthorityError("network options missing/malformed")
    if options.get(HOST_BINDING_OPT) != "127.0.0.1":
        raise SandboxAuthorityError(
            f"network {HOST_BINDING_OPT} must be 127.0.0.1, got {options.get(HOST_BINDING_OPT)!r}"
        )
    return net


def create_owned_network(
    *,
    name: str,
    path_hash: str,
    sandbox_uuid: str,
) -> str:
    op = str(uuid.uuid4())
    create = run(
        [
            "docker",
            "network",
            "create",
            "--label",
            f"{SBFLEET_SANDBOX_LABEL}={path_hash}",
            "--label",
            f"{SBFLEET_UUID_LABEL}={sandbox_uuid}",
            "--label",
            f"{SBFLEET_OP_LABEL}={op}",
            "-o",
            f"{HOST_BINDING_OPT}=127.0.0.1",
            name,
        ],
        env=DOCKER_ENV,
        check=False,
    )
    if not create.ok:
        # Do not silently adopt foreign same-name network.
        insp = run(["docker", "network", "inspect", name], env=DOCKER_ENV, check=False)
        if insp.ok:
            raise SandboxAuthorityError(
                f"network name {name!r} already exists and is not proven owned; refuse takeover"
            )
        raise SandboxAuthorityError(f"network create failed: {(create.stderr or '')}")
    net_id = (create.stdout or "").strip()
    if not net_id:
        raise SandboxAuthorityError("network create returned empty id")
    prove_network_owned(net_id, path_hash=path_hash, sandbox_uuid=sandbox_uuid)
    return net_id


def ensure_owned_network(record: AdoptionRecord) -> str:
    name = record.network_name
    if record.network_id:
        try:
            net = prove_network_owned(
                record.network_id,
                path_hash=record.path_hash,
                sandbox_uuid=record.sandbox_uuid,
            )
            return _canonical_network_id_from_inspect(net, stored_ref=record.network_id)
        except SandboxAuthorityError:
            # Stored id invalid — do not reuse by name alone.
            raise
    # No network yet: create.
    return create_owned_network(
        name=name, path_hash=record.path_hash, sandbox_uuid=record.sandbox_uuid
    )


# --- Inventory / bindings -----------------------------------------------------


def list_cli_containers(project_id: str) -> list[str]:
    result = run(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label={CLI_PROJECT_LABEL}={project_id}",
            "--format",
            "{{.ID}}",
        ],
        env=DOCKER_ENV,
        check=False,
    )
    if not result.ok:
        raise SandboxAuthorityError(f"docker ps failed: {(result.stderr or result.stdout or '')}")
    return [x.strip() for x in (result.stdout or "").splitlines() if x.strip()]


def list_cli_volumes(project_id: str) -> list[str]:
    # Verified: volumes carry com.supabase.cli.project label; inventory by Name.
    result = run(
        ["docker", "volume", "ls", "--format", "{{.Name}}"],
        env=DOCKER_ENV,
        check=False,
    )
    if not result.ok:
        raise SandboxAuthorityError(f"docker volume ls failed: {(result.stderr or '')}")
    names = [x.strip() for x in (result.stdout or "").splitlines() if x.strip()]
    owned: list[str] = []
    for name in names:
        insp = run(
            ["docker", "volume", "inspect", name, "--format", "{{json .Labels}}"],
            env=DOCKER_ENV,
            check=False,
        )
        if not insp.ok:
            raise SandboxAuthorityError(f"docker volume inspect failed for {name}")
        try:
            labels = json.loads(insp.stdout or "null") or {}
        except json.JSONDecodeError as exc:
            raise SandboxAuthorityError(f"malformed volume labels for {name}: {exc}") from exc
        if isinstance(labels, dict) and labels.get(CLI_PROJECT_LABEL) == project_id:
            owned.append(name)
    return owned


def invent_owned_resources(
    *,
    project_id: str,
    canonical_root: Path,
    network_id: str,
    network_name: str,
    require_containers: bool = True,
) -> dict[str, Any]:
    """Build inventory from verified CLI 2.118.0 labels + exact owned network attachment."""
    containers = list_cli_containers(project_id)
    if not containers:
        if require_containers:
            raise SandboxAuthorityError("no CLI containers found after start; refuse success")
        volumes = list_cli_volumes(project_id)
        return {
            "containers": [],
            "volumes": [{"name": n} for n in volumes],
            "network_id": network_id,
            "network_name": network_name,
            "labels_expected": {
                CLI_PROJECT_LABEL: project_id,
                CLI_WORKDIR_LABEL: str(canonical_root),
            },
            "published_bindings": [],
        }

    bindings: list[dict[str, Any]] = []
    container_meta: list[dict[str, Any]] = []
    for cid in containers:
        data = _docker_json(["docker", "inspect", cid])
        if not isinstance(data, list) or not data:
            raise SandboxAuthorityError(f"docker inspect empty for {cid}")
        obj = data[0]
        labels = (obj.get("Config") or {}).get("Labels")
        if not isinstance(labels, dict):
            raise SandboxAuthorityError(f"container {cid[:12]} Labels missing/malformed")
        if labels.get(CLI_PROJECT_LABEL) != project_id:
            raise SandboxAuthorityError(f"container {cid[:12]} project label mismatch")
        workdir = labels.get(CLI_WORKDIR_LABEL)
        if not workdir:
            raise SandboxAuthorityError(f"container {cid[:12]} workdir label missing")
        if Path(str(workdir)).resolve() != canonical_root.resolve():
            raise SandboxAuthorityError(
                f"container {cid[:12]} workdir {workdir!r} != canonical {canonical_root}"
            )
        # Exact owned attachment: expected name/key AND exact canonical NetworkID.
        net_settings = obj.get("NetworkSettings")
        if not isinstance(net_settings, dict):
            raise SandboxAuthorityError(f"container {cid[:12]} NetworkSettings missing")
        nets = net_settings.get("Networks")
        _prove_exact_owned_network_attachments(
            nets,
            canonical_network_id=network_id,
            network_name=network_name,
            resource=f"container {cid[:12]}",
        )

        # Ports must be present as a mapping; missing/null is UNKNOWN — not {}.
        if "Ports" not in net_settings:
            raise SandboxAuthorityError(f"container {cid[:12]} Ports field missing")
        ports = net_settings.get("Ports")
        if ports is None:
            raise SandboxAuthorityError(f"container {cid[:12]} Ports is null")
        if not isinstance(ports, dict):
            raise SandboxAuthorityError(f"container {cid[:12]} Ports malformed")
        for port, hosts in ports.items():
            if not hosts:
                continue
            for h in hosts:
                hip = (h or {}).get("HostIp")
                hport = (h or {}).get("HostPort")
                try:
                    assert_loopback_host_ip(hip or "", context=f"{cid[:12]} {port}")
                except SandboxConfigError as exc:
                    raise SandboxAuthorityError(str(exc)) from exc
                bindings.append(
                    {
                        "container_id": cid,
                        "port": port,
                        "host_ip": hip,
                        "host_port": hport,
                    }
                )

        container_meta.append(
            {
                "id": cid,
                "name": (obj.get("Name") or "").lstrip("/"),
                "labels": {
                    CLI_PROJECT_LABEL: labels.get(CLI_PROJECT_LABEL),
                    CLI_WORKDIR_LABEL: labels.get(CLI_WORKDIR_LABEL),
                },
            }
        )

    volumes = list_cli_volumes(project_id)
    return {
        "containers": container_meta,
        "volumes": [{"name": n} for n in volumes],
        "network_id": network_id,
        "network_name": network_name,
        "labels_expected": {
            CLI_PROJECT_LABEL: project_id,
            CLI_WORKDIR_LABEL: str(canonical_root),
        },
        "published_bindings": bindings,
    }


def assert_effective_bindings(inventory: dict[str, Any]) -> None:
    bindings = inventory.get("published_bindings") or []
    if not bindings:
        # Some containers may not publish; require at least API/DB typically — fail if none at all.
        raise SandboxAuthorityError("no published bindings inventoried; refuse success")
    for b in bindings:
        try:
            assert_loopback_host_ip(b.get("host_ip") or "", context="published binding")
        except SandboxConfigError as exc:
            raise SandboxAuthorityError(str(exc)) from exc


def status_endpoints_local(status_data: dict[str, Any]) -> dict[str, str]:
    """Validate and return local endpoints from status JSON."""
    out: dict[str, str] = {}
    mapping = {
        "DB_URL": ("DATABASE_URL", "postgres"),
        "API_URL": ("SUPABASE_URL", "http"),
        "STUDIO_URL": ("STUDIO_URL", "http"),
        "ANON_KEY": ("SUPABASE_ANON_KEY", None),
        "SERVICE_ROLE_KEY": ("SUPABASE_SERVICE_ROLE_KEY", None),
    }
    for src, (dst, kind) in mapping.items():
        val = status_data.get(src)
        if val is None:
            continue
        if kind is not None:
            try:
                assert_local_url(str(val), context=src, kind=kind)  # type: ignore[arg-type]
            except SandboxConfigError as exc:
                raise SandboxAuthorityError(str(exc)) from exc
        out[dst] = str(val)
    if "DATABASE_URL" not in out or "SUPABASE_URL" not in out:
        raise SandboxAuthorityError("status missing required local DB/API endpoints")
    return out


def refuse_foreign_cli_resources(project_id: str, canonical: Path) -> None:
    """Before first adoption/start: refuse existing CLI resources for this project_id."""
    containers = list_cli_containers(project_id)
    if not containers:
        vols = list_cli_volumes(project_id)
        if vols:
            raise SandboxAuthorityError(
                f"existing CLI volumes for {project_id!r} without adoption; refuse takeover"
            )
        return
    for cid in containers:
        data = _docker_json(["docker", "inspect", cid])
        labels = (data[0].get("Config") or {}).get("Labels") or {}
        wd = labels.get(CLI_WORKDIR_LABEL)
        if wd and Path(wd).resolve() != canonical.resolve():
            raise SandboxAuthorityError(
                f"CLI resources for {project_id!r} belong to other workdir {wd!r}; refuse"
            )
        raise SandboxAuthorityError(
            f"existing CLI containers for {project_id!r} without proven adoption; refuse takeover"
        )


# --- Per-class live ownership ---------------------------------------

ResourceClassStatus = Literal[
    "PRESENT_AND_OWNED",
    "CONFIRMED_ABSENT",
    "PRESENT_BUT_FOREIGN",
    "UNKNOWN",
]

ContainerRuntimeStatus = Literal[
    "RUNNING",
    "STOPPED",
    "MIXED",
    "UNKNOWN",
    "ABSENT",
]


@dataclass
class ClassObservation:
    status: ResourceClassStatus
    detail: str = ""
    names: list[str] = field(default_factory=list)
    ids: list[str] = field(default_factory=list)
    # Ownership and runtime are separate facts (V4-003).
    runtime: ContainerRuntimeStatus | None = None


@dataclass
class SandboxLiveAuthority:
    """Independent observations for containers / network / volumes."""

    containers: ClassObservation
    network: ClassObservation
    volumes: ClassObservation
    inventory: dict[str, Any] | None = None

    def any_foreign_or_unknown(self) -> bool:
        return any(
            obs.status in {"PRESENT_BUT_FOREIGN", "UNKNOWN"}
            for obs in (self.containers, self.network, self.volumes)
        )


def _observe_containers(
    *,
    project_id: str,
    canonical_root: Path,
    network_id: str | None,
    network_name: str | None,
) -> ClassObservation:
    try:
        cids = list_cli_containers(project_id)
    except SandboxAuthorityError as exc:
        return ClassObservation(status="UNKNOWN", detail=str(exc), runtime="UNKNOWN")
    if not cids:
        return ClassObservation(
            status="CONFIRMED_ABSENT", detail="no CLI containers", runtime="ABSENT"
        )
    owned_ids: list[str] = []
    owned_names: list[str] = []
    runtimes: list[str] = []
    for cid in cids:
        try:
            data = _docker_json(["docker", "inspect", cid])
            if not isinstance(data, list) or not data:
                return ClassObservation(
                    status="UNKNOWN", detail=f"inspect empty for {cid[:12]}", runtime="UNKNOWN"
                )
            obj = data[0]
            labels = (obj.get("Config") or {}).get("Labels")
            if not isinstance(labels, dict):
                return ClassObservation(
                    status="UNKNOWN", detail=f"labels missing {cid[:12]}", runtime="UNKNOWN"
                )
            if labels.get(CLI_PROJECT_LABEL) != project_id:
                return ClassObservation(
                    status="PRESENT_BUT_FOREIGN",
                    detail=f"project label mismatch {cid[:12]}",
                    ids=[cid],
                    runtime="UNKNOWN",
                )
            workdir = labels.get(CLI_WORKDIR_LABEL)
            if not workdir:
                return ClassObservation(
                    status="UNKNOWN",
                    detail=f"workdir missing {cid[:12]}",
                    ids=[cid],
                    runtime="UNKNOWN",
                )
            if Path(str(workdir)).resolve() != canonical_root.resolve():
                return ClassObservation(
                    status="PRESENT_BUT_FOREIGN",
                    detail=f"workdir {workdir!r} != canonical",
                    ids=[cid],
                    runtime="UNKNOWN",
                )
            if not network_id or not network_name:
                return ClassObservation(
                    status="UNKNOWN",
                    detail=f"owned network name/id incomplete for {cid[:12]}",
                    ids=[cid],
                    runtime="UNKNOWN",
                )
            nets = (obj.get("NetworkSettings") or {}).get("Networks")
            try:
                _prove_exact_owned_network_attachments(
                    nets,
                    canonical_network_id=network_id,
                    network_name=network_name,
                    resource=f"container {cid[:12]}",
                )
            except SandboxAuthorityError as exc:
                msg = str(exc).lower()
                if "mismatch" in msg or "unexpected" in msg or "null/malformed" in msg:
                    return ClassObservation(
                        status="PRESENT_BUT_FOREIGN",
                        detail=str(exc),
                        ids=[cid],
                        runtime="UNKNOWN",
                    )
                return ClassObservation(
                    status="UNKNOWN", detail=str(exc), ids=[cid], runtime="UNKNOWN"
                )
            try:
                rt = _container_runtime_state(obj, resource=f"container {cid[:12]}")
            except SandboxAuthorityError as exc:
                return ClassObservation(
                    status="UNKNOWN", detail=str(exc), ids=[cid], runtime="UNKNOWN"
                )
            runtimes.append(rt)
            owned_ids.append(cid)
            owned_names.append((obj.get("Name") or "").lstrip("/"))
        except SandboxAuthorityError as exc:
            return ClassObservation(status="UNKNOWN", detail=str(exc), ids=[cid], runtime="UNKNOWN")
    if not runtimes:
        runtime: ContainerRuntimeStatus = "UNKNOWN"
    elif all(r == "RUNNING" for r in runtimes):
        runtime = "RUNNING"
    elif all(r == "STOPPED" for r in runtimes):
        runtime = "STOPPED"
    elif any(r == "UNKNOWN" for r in runtimes):
        runtime = "UNKNOWN"
    else:
        runtime = "MIXED"
    return ClassObservation(
        status="PRESENT_AND_OWNED",
        detail=f"containers={len(owned_ids)} runtime={runtime}",
        ids=owned_ids,
        names=owned_names,
        runtime=runtime,
    )


def _observe_network(record: AdoptionRecord) -> ClassObservation:
    if not record.network_id:
        name = record.network_name
        insp = run(["docker", "network", "inspect", name], env=DOCKER_ENV, check=False)
        if insp.ok:
            return ClassObservation(
                status="PRESENT_BUT_FOREIGN",
                detail=f"network {name!r} exists without adoption network_id",
                names=[name],
            )
        text = f"{insp.stderr or ''}\n{insp.stdout or ''}".lower()
        if "no such" in text or "not found" in text:
            return ClassObservation(status="CONFIRMED_ABSENT", detail="no network_id / name absent")
        return ClassObservation(status="UNKNOWN", detail="network inspect failed without absence")
    try:
        net = prove_network_owned(
            record.network_id,
            path_hash=record.path_hash,
            sandbox_uuid=record.sandbox_uuid,
        )
        canonical = _canonical_network_id_from_inspect(net, stored_ref=record.network_id)
        return ClassObservation(
            status="PRESENT_AND_OWNED",
            detail="network owned",
            ids=[canonical],
            names=[record.network_name],
        )
    except SandboxAuthorityError as exc:
        msg = str(exc).lower()
        insp = run(
            ["docker", "network", "inspect", record.network_id],
            env=DOCKER_ENV,
            check=False,
        )
        if not insp.ok:
            text = f"{insp.stderr or ''}\n{insp.stdout or ''}".lower()
            if "no such" in text or "not found" in text:
                return ClassObservation(
                    status="CONFIRMED_ABSENT", detail="network inspect: not found"
                )
            return ClassObservation(status="UNKNOWN", detail=str(exc))
        if "mismatch" in msg or "must be" in msg or "missing" in msg or "malformed" in msg:
            return ClassObservation(
                status="PRESENT_BUT_FOREIGN",
                detail=str(exc),
                ids=[record.network_id],
            )
        return ClassObservation(status="UNKNOWN", detail=str(exc), ids=[record.network_id])


def _observe_volumes(*, project_id: str) -> ClassObservation:
    try:
        vols = list_cli_volumes(project_id)
    except SandboxAuthorityError as exc:
        return ClassObservation(status="UNKNOWN", detail=str(exc))
    if not vols:
        return ClassObservation(status="CONFIRMED_ABSENT", detail="no CLI volumes")
    return ClassObservation(
        status="PRESENT_AND_OWNED",
        detail=f"volumes={len(vols)}",
        names=list(vols),
    )


def observe_sandbox_live(
    record: AdoptionRecord,
    *,
    canonical: Path,
) -> SandboxLiveAuthority:
    """Fresh per-class Docker observations. Never collapses UNKNOWN into ABSENT."""
    # Resolve owned network to positively inspected canonical full Id before
    # container attachment proof — never authorize via stored-prefix alone.
    network = _observe_network(record)
    canonical_network_id: str | None = None
    if network.status == "PRESENT_AND_OWNED" and network.ids:
        canonical_network_id = network.ids[0]
    containers = _observe_containers(
        project_id=record.cli_project_id,
        canonical_root=canonical,
        network_id=canonical_network_id,
        network_name=record.network_name,
    )
    volumes = _observe_volumes(project_id=record.cli_project_id)
    inventory = None
    if (
        containers.status == "PRESENT_AND_OWNED"
        and network.status == "PRESENT_AND_OWNED"
        and canonical_network_id
        and record.network_name
        and containers.runtime == "RUNNING"
    ):
        try:
            inventory = invent_owned_resources(
                project_id=record.cli_project_id,
                canonical_root=canonical,
                network_id=canonical_network_id,
                network_name=record.network_name,
                require_containers=True,
            )
        except SandboxAuthorityError as exc:
            containers = ClassObservation(
                status="UNKNOWN", detail=str(exc), ids=containers.ids, runtime="UNKNOWN"
            )
    return SandboxLiveAuthority(
        containers=containers,
        network=network,
        volumes=volumes,
        inventory=inventory,
    )


def require_action_live_authority(action: str, live: SandboxLiveAuthority) -> None:
    """Action-specific predicates. Raise on refuse."""
    if live.any_foreign_or_unknown():
        parts = []
        for name, obs in (
            ("containers", live.containers),
            ("network", live.network),
            ("volumes", live.volumes),
        ):
            if obs.status in {"PRESENT_BUT_FOREIGN", "UNKNOWN"}:
                parts.append(f"{name}={obs.status}:{obs.detail}")
        raise SandboxAuthorityError(
            f"live ownership UNKNOWN/foreign before {action}: " + "; ".join(parts)
        )

    if action == "stop":
        if live.containers.status not in {"CONFIRMED_ABSENT", "PRESENT_AND_OWNED"}:
            raise SandboxAuthorityError(
                f"stop refuses containers status {live.containers.status}: {live.containers.detail}"
            )
        return

    if action == "destroy":
        for name, obs in (
            ("containers", live.containers),
            ("network", live.network),
            ("volumes", live.volumes),
        ):
            if obs.status not in {"PRESENT_AND_OWNED", "CONFIRMED_ABSENT"}:
                raise SandboxAuthorityError(
                    f"destroy refuses {name} status {obs.status}: {obs.detail}"
                )
        return

    if action == "reset":
        if live.containers.status != "PRESENT_AND_OWNED":
            raise SandboxAuthorityError(
                f"reset requires PRESENT_AND_OWNED containers; got {live.containers.status}: "
                f"{live.containers.detail}"
            )
        if live.containers.runtime != "RUNNING":
            raise SandboxAuthorityError(
                f"reset requires RUNNING owned containers; got runtime={live.containers.runtime}: "
                f"{live.containers.detail}"
            )
        if live.network.status != "PRESENT_AND_OWNED":
            raise SandboxAuthorityError(
                f"reset requires PRESENT_AND_OWNED network; got {live.network.status}: "
                f"{live.network.detail}"
            )
        return

    if action == "env":
        if live.containers.status != "PRESENT_AND_OWNED":
            raise SandboxAuthorityError(
                f"env requires PRESENT_AND_OWNED running resources; got "
                f"{live.containers.status}: {live.containers.detail}"
            )
        if live.containers.runtime != "RUNNING":
            raise SandboxAuthorityError(
                f"env requires RUNNING owned containers; got runtime={live.containers.runtime}: "
                f"{live.containers.detail}"
            )
        if live.network.status != "PRESENT_AND_OWNED":
            raise SandboxAuthorityError(
                f"env requires PRESENT_AND_OWNED network; got {live.network.status}: "
                f"{live.network.detail}"
            )
        return

    if action == "start":
        # Cold start: containers absent; network/volumes absent or already owned.
        # Already-running: PRESENT_AND_OWNED + all required containers actually RUNNING.
        if live.containers.status == "PRESENT_AND_OWNED":
            if live.containers.runtime != "RUNNING":
                raise SandboxAuthorityError(
                    f"start refuses non-running owned containers "
                    f"(runtime={live.containers.runtime}); not already-running; "
                    f"use supported cleanup/start path: {live.containers.detail}"
                )
            if live.network.status != "PRESENT_AND_OWNED":
                raise SandboxAuthorityError(
                    f"start (already-running) requires PRESENT_AND_OWNED network; got "
                    f"{live.network.status}: {live.network.detail}"
                )
            if live.volumes.status not in {"PRESENT_AND_OWNED", "CONFIRMED_ABSENT"}:
                raise SandboxAuthorityError(
                    f"start (already-running) refuses volumes status {live.volumes.status}: "
                    f"{live.volumes.detail}"
                )
            return
        if live.containers.status != "CONFIRMED_ABSENT":
            raise SandboxAuthorityError(
                f"start refuses containers status {live.containers.status}: "
                f"{live.containers.detail}"
            )
        if live.network.status not in {"CONFIRMED_ABSENT", "PRESENT_AND_OWNED"}:
            raise SandboxAuthorityError(
                f"start refuses network status {live.network.status}: {live.network.detail}"
            )
        if live.volumes.status not in {"CONFIRMED_ABSENT", "PRESENT_AND_OWNED"}:
            raise SandboxAuthorityError(
                f"start refuses volumes status {live.volumes.status}: {live.volumes.detail}"
            )
        return

    raise SandboxAuthorityError(f"unsupported live-authority action: {action!r}")


def snapshot_positively_owned(live: SandboxLiveAuthority) -> dict[str, set[str]]:
    """Exact IDs/names whose ownership is positively proven in this observation."""
    containers: set[str] = set()
    volumes: set[str] = set()
    networks: set[str] = set()
    if live.containers.status == "PRESENT_AND_OWNED":
        containers = {str(x) for x in live.containers.ids if x}
    if live.volumes.status == "PRESENT_AND_OWNED":
        volumes = {str(x) for x in live.volumes.names if x}
    if live.network.status == "PRESENT_AND_OWNED":
        networks = {str(x) for x in live.network.ids if x}
    return {"containers": containers, "volumes": volumes, "networks": networks}


def attempt_delta_owned(
    pre: dict[str, set[str]],
    post: SandboxLiveAuthority,
) -> dict[str, set[str]]:
    """Owned resources newly observed after start: post_owned − pre_owned."""
    post_snap = snapshot_positively_owned(post)
    return {
        "containers": post_snap["containers"] - pre.get("containers", set()),
        "volumes": post_snap["volumes"] - pre.get("volumes", set()),
        "networks": post_snap["networks"] - pre.get("networks", set()),
    }


def cleanup_attempt_delta_owned(delta: dict[str, set[str]]) -> list[str]:
    """Remove only attempt-delta positively owned resources by exact ID/name.

    Never grants broad CLI ``stop --project-id`` authority. Returns residual
    evidence strings for resources that could not be removed.
    """
    residuals: list[str] = []
    path_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    for cid in sorted(delta.get("containers") or ()):
        stop = run(["docker", "stop", "--", cid], env=path_env, check=False, timeout=120.0)
        rm = run(["docker", "rm", "-f", "--", cid], env=path_env, check=False, timeout=120.0)
        if not stop.ok and not rm.ok:
            residuals.append(f"container:{cid[:12]}")
    for vname in sorted(delta.get("volumes") or ()):
        rm = run(["docker", "volume", "rm", "--", vname], env=path_env, check=False, timeout=60.0)
        if not rm.ok:
            residuals.append(f"volume:{vname}")
    for nid in sorted(delta.get("networks") or ()):
        rm = run(["docker", "network", "rm", "--", nid], env=path_env, check=False, timeout=60.0)
        if not rm.ok:
            residuals.append(f"network:{nid[:12]}")
    return residuals


def reenumerate_cli_namespace_residuals(
    *,
    project_id: str,
    canonical: Path,
    network_id: str | None,
    path_hash: str,
    sandbox_uuid: str,
) -> list[str]:
    """
    Full-namespace post-destroy check (not only previously recorded IDs).
    Returns residual evidence strings; empty means clean success for owned resources.
    """
    residuals: list[str] = []
    try:
        left_c = list_cli_containers(project_id)
    except SandboxAuthorityError as exc:
        residuals.append(f"containers-UNKNOWN:{exc}")
        left_c = []
    for cid in left_c:
        try:
            data = _docker_json(["docker", "inspect", cid])
            labels = (data[0].get("Config") or {}).get("Labels") or {}
            wd = labels.get(CLI_WORKDIR_LABEL)
            if wd and Path(str(wd)).resolve() == canonical.resolve():
                residuals.append(f"container:{cid[:12]}")
            elif not wd:
                residuals.append(f"container-UNKNOWN:{cid[:12]}")
            else:
                residuals.append(f"container-FOREIGN:{cid[:12]}")
        except SandboxAuthorityError as exc:
            residuals.append(f"container-UNKNOWN:{cid[:12]}:{exc}")
    try:
        left_v = list_cli_volumes(project_id)
    except SandboxAuthorityError as exc:
        residuals.append(f"volumes-UNKNOWN:{exc}")
        left_v = []
    for v in left_v:
        residuals.append(f"volume:{v}")
    if network_id:
        insp = run(["docker", "network", "inspect", network_id], env=DOCKER_ENV, check=False)
        if insp.ok:
            try:
                prove_network_owned(network_id, path_hash=path_hash, sandbox_uuid=sandbox_uuid)
                residuals.append(f"network:{network_id[:12]}")
            except SandboxAuthorityError:
                residuals.append(f"network-FOREIGN:{network_id[:12]}")
        else:
            text = f"{insp.stderr or ''}\n{insp.stdout or ''}".lower()
            if "no such" not in text and "not found" not in text:
                residuals.append(f"network-UNKNOWN:{network_id[:12]}")
    return residuals
