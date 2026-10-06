"""Additive Compose isolation override renderer and validator."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sbfleet.process import run

STANDARD_SERVICES = (
    "studio",
    "api-gw",
    "auth",
    "rest",
    "realtime",
    "storage",
    "imgproxy",
    "meta",
    "functions",
    "db",
    "supavisor",
)

REALTIME_ALIAS = "realtime-dev.supabase-realtime"

ASYMMETRIC_ENV = {
    "realtime": {"API_JWT_JWKS": "${JWT_JWKS}"},
    "auth": {
        "GOTRUE_JWT_KEYS": "${JWT_KEYS}",
        # Official compose leaves Google OAuth commented out; enable via .env only.
        "GOTRUE_EXTERNAL_GOOGLE_ENABLED": "${GOOGLE_ENABLED}",
        "GOTRUE_EXTERNAL_GOOGLE_CLIENT_ID": "${GOOGLE_CLIENT_ID}",
        "GOTRUE_EXTERNAL_GOOGLE_SECRET": "${GOOGLE_SECRET}",
        "GOTRUE_EXTERNAL_GOOGLE_REDIRECT_URI": "${API_EXTERNAL_URL}/callback",
    },
    "storage": {"JWT_JWKS": "${JWT_JWKS}"},
    "functions": {"SUPABASE_JWKS": "${JWT_JWKS}"},
}


class ComposeError(Exception):
    """Compose render/validation failure."""


def _yaml_quote(value: str) -> str:
    return json.dumps(value)


def render_override(
    *,
    compose_project: str,
    fleet_id: str,
    project_id: str,
    gateway_port: int,
    db_direct_port: int,
    pooler_session_port: int,
    pooler_transaction_port: int,
) -> str:
    """Render deterministic docker-compose.override.yml (no YAML library)."""
    if not re.fullmatch(r"sbfleet-[0-9a-f]{12}-[0-9a-f]{12}", compose_project):
        raise ComposeError(f"invalid compose_project name: {compose_project}")
    labels = {
        "io.sbfleet.fleet": fleet_id,
        "io.sbfleet.project": project_id,
    }
    lines: list[str] = [
        f"name: {compose_project}",
        "services:",
    ]
    for service in STANDARD_SERVICES:
        cname = f"{compose_project}-{service}"
        lines.append(f"  {service}:")
        lines.append(f"    container_name: {cname}")
        lines.append("    labels:")
        for lk, lv in labels.items():
            lines.append(f"      {lk}: {_yaml_quote(lv)}")
        if service == "api-gw":
            lines.append("    ports: !override")
            lines.append(f'      - "127.0.0.1:{gateway_port}:8000/tcp"')
        elif service == "db":
            lines.append("    ports: !override")
            lines.append(f'      - "127.0.0.1:{db_direct_port}:5432/tcp"')
        elif service == "supavisor":
            lines.append("    ports: !override")
            lines.append(f'      - "127.0.0.1:{pooler_session_port}:5432/tcp"')
            lines.append(f'      - "127.0.0.1:{pooler_transaction_port}:6543/tcp"')
        elif service in {
            "studio",
            "auth",
            "rest",
            "realtime",
            "storage",
            "imgproxy",
            "meta",
            "functions",
        }:
            # Explicit empty override not required; ensure no host ports added.
            pass
        if service == "realtime":
            lines.append("    networks:")
            lines.append("      default:")
            lines.append("        aliases:")
            lines.append(f"          - {REALTIME_ALIAS}")
        if service in ASYMMETRIC_ENV:
            lines.append("    environment:")
            for ek, ev in ASYMMETRIC_ENV[service].items():
                lines.append(f"      {ek}: {_yaml_quote(ev)}")

    lines.append("networks:")
    lines.append("  default:")
    lines.append("    labels:")
    for lk, lv in labels.items():
        lines.append(f"      {lk}: {_yaml_quote(lv)}")
    lines.append("volumes:")
    for vol in ("db-config", "deno-cache"):
        lines.append(f"  {vol}:")
        lines.append("    labels:")
        for lk, lv in labels.items():
            lines.append(f"      {lk}: {_yaml_quote(lv)}")
    lines.append("")
    return "\n".join(lines)


def write_override(deployment: Path, content: str) -> Path:
    path = Path(deployment) / "docker-compose.override.yml"
    path.write_text(content, encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def compose_config_json(
    deployment: Path,
    *,
    compose_project: str,
    env: dict[str, str] | None = None,
    compose_file: str = "docker-compose.yml:docker-compose.override.yml",
) -> dict[str, Any]:
    """Resolve Compose config to JSON in memory (secret-bearing — do not persist)."""
    deployment = Path(deployment)
    child_env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(deployment / ".compose-home"),
        "COMPOSE_PROJECT_NAME": compose_project,
        "COMPOSE_FILE": compose_file,
        "COMPOSE_PATH_SEPARATOR": ":",
    }
    (deployment / ".compose-home").mkdir(mode=0o700, exist_ok=True)
    if env:
        # Structural + image interpolation vars; secrets stay in-memory for compose only.
        for key, val in env.items():
            if not isinstance(key, str) or not isinstance(val, str):
                continue
            if (
                key
                in {
                    "POSTGRES_PORT",
                    "POOLER_PROXY_PORT_TRANSACTION",
                    "API_GW_HTTP_PORT",
                    "KONG_HTTP_PORT",
                    "JWT_SECRET",
                    "ANON_KEY",
                    "SERVICE_ROLE_KEY",
                    "JWT_KEYS",
                    "JWT_JWKS",
                    "POSTGRES_PASSWORD",
                    "DASHBOARD_USERNAME",
                    "DASHBOARD_PASSWORD",
                    "SECRET_KEY_BASE",
                    "VAULT_ENC_KEY",
                    "SUPABASE_PUBLIC_URL",
                    "API_EXTERNAL_URL",
                    "SITE_URL",
                    "ADDITIONAL_REDIRECT_URLS",
                    "STUDIO_DEFAULT_ORGANIZATION",
                    "STUDIO_DEFAULT_PROJECT",
                    "GOOGLE_ENABLED",
                    "GOOGLE_CLIENT_ID",
                    "GOOGLE_SECRET",
                    "POOLER_TENANT_ID",
                    "POSTGRES_DB",
                    "POSTGRES_HOST",
                }
                or key.endswith("_IMAGE")
                or key.endswith("_VERSION")
                or "IMAGE" in key
            ):
                child_env[key] = val
    result = run(
        ["docker", "compose", "config", "--format", "json"],
        cwd=deployment,
        env=child_env,
        timeout=60.0,
        check=False,
    )
    if not result.ok:
        from sbfleet.process import sanitize_configured_diagnostic

        # Prefer deployment dotenv inventory; also redact any secrets present in env dict.
        detail = sanitize_configured_diagnostic(
            result.stderr or result.stdout or "",
            deployment=deployment,
            max_len=500,
        )
        if env:
            from sbfleet import upstream as up
            from sbfleet.process import Redactor, sanitize_diagnostic

            extra = Redactor()
            extra.add_many(
                up.secret_values_for_redaction({k: v for k, v in env.items() if isinstance(v, str)})
            )
            detail = sanitize_diagnostic(detail, redactor=extra, max_len=500)
        raise ComposeError(f"compose config failed: {detail}")
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ComposeError("compose config produced invalid JSON") from exc
    if not isinstance(data, dict):
        raise ComposeError("compose config root must be object")
    return data


def vendor_expected_images(
    deployment: Path,
    *,
    compose_project: str,
    env: dict[str, str] | None = None,
) -> dict[str, str]:
    """
    Approved service image refs from the pinned vendor compose snapshot only
    (docker-compose.yml), not from override or mutable runtime digests.
    """
    config = compose_config_json(
        deployment,
        compose_project=compose_project,
        env=env,
        compose_file="docker-compose.yml",
    )
    services = config.get("services") or {}
    out: dict[str, str] = {}
    for name in STANDARD_SERVICES:
        svc = services.get(name)
        if not isinstance(svc, dict):
            raise ComposeError(f"vendor snapshot missing service {name}")
        image = svc.get("image")
        if not image or not isinstance(image, str):
            raise ComposeError(f"vendor snapshot missing image for {name}")
        out[name] = image
    return out


def validate_resolved_config(
    config: dict[str, Any],
    *,
    compose_project: str,
    fleet_id: str,
    project_id: str,
    gateway_port: int,
    db_direct_port: int,
    pooler_session_port: int,
    pooler_transaction_port: int,
    deployment: Path | None = None,
    allowed_bind_roots: list[Path] | None = None,
    expected_images: dict[str, str] | None = None,
) -> None:
    services = config.get("services") or {}
    if set(services) != set(STANDARD_SERVICES):
        extra = set(services) - set(STANDARD_SERVICES)
        missing = set(STANDARD_SERVICES) - set(services)
        raise ComposeError(f"service inventory mismatch extra={extra} missing={missing}")

    bind_roots = [p.resolve(strict=False) for p in (allowed_bind_roots or [])]
    if deployment is not None:
        dep = Path(deployment).resolve(strict=False)
        if dep not in bind_roots:
            bind_roots.append(dep)

    for name, svc in services.items():
        expected = f"{compose_project}-{name}"
        if svc.get("container_name") != expected:
            raise ComposeError(f"container_name for {name} not {expected}")
        labels = svc.get("labels") or {}
        if labels.get("io.sbfleet.fleet") != fleet_id:
            raise ComposeError(f"missing fleet label on {name}")
        if labels.get("io.sbfleet.project") != project_id:
            raise ComposeError(f"missing project label on {name}")
        image = svc.get("image")
        if not image or not isinstance(image, str):
            raise ComposeError(f"service {name} missing image")
        if expected_images is not None:
            if name not in expected_images:
                raise ComposeError(f"service {name} missing from approved vendor image map")
            if image != expected_images[name]:
                raise ComposeError(
                    f"service {name} image mismatch: got {image!r} "
                    f"expected vendor {expected_images[name]!r}"
                )
        for mount in svc.get("volumes") or []:
            src = ""
            mount_type = ""
            if isinstance(mount, str):
                src = mount.split(":")[0]
                mount_type = "bind" if src.startswith(".") or src.startswith("/") else "volume"
            elif isinstance(mount, dict):
                src = str(mount.get("source") or "")
                mount_type = str(mount.get("type") or "")
            if "docker.sock" in src:
                raise ComposeError("Docker socket mount refused")
            if mount_type == "bind" or (isinstance(mount, dict) and mount.get("type") == "bind"):
                _validate_bind_source(src, bind_roots=bind_roots, deployment=deployment)
            if mount_type == "volume" or (
                isinstance(mount, dict) and mount.get("type") == "volume"
            ):
                vol_name = src
                if isinstance(mount, dict):
                    vol_name = str(mount.get("source") or mount.get("Source") or src)
                # Named volumes must map to project-scoped expected keys when absolute name set.
                if vol_name and vol_name.startswith(f"{compose_project}_"):
                    suffix = vol_name[len(compose_project) + 1 :]
                    if suffix not in {"db-config", "deno-cache"}:
                        raise ComposeError(
                            f"unexpected named volume mapping {vol_name!r} on {name}"
                        )
        network_mode = svc.get("network_mode")
        if network_mode not in (None, "", "bridge"):
            raise ComposeError(
                f"unsupported network_mode {network_mode!r} on {name}; "
                "only unset/bridge is supported"
            )
        if svc.get("privileged"):
            raise ComposeError("privileged service refused")

        ports = svc.get("ports") or []
        published = []
        for p in ports:
            if isinstance(p, dict):
                published.append(p)
            elif isinstance(p, str):
                published.append({"raw": p})
        if name == "api-gw":
            _expect_loopback_port(published, gateway_port, 8000)
        elif name == "db":
            _expect_loopback_port(published, db_direct_port, 5432)
        elif name == "supavisor":
            if len(published) != 2:
                raise ComposeError(
                    f"supavisor must publish exactly two ports, got {len(published)}"
                )
            targets = {
                (int(p.get("published")), int(p.get("target")))
                for p in published
                if "published" in p
            }
            if (pooler_session_port, 5432) not in targets or (
                pooler_transaction_port,
                6543,
            ) not in targets:
                raise ComposeError("supavisor ports incorrect")
            for p in published:
                hip = p.get("host_ip")
                if hip != "127.0.0.1":
                    raise ComposeError(f"supavisor port must bind 127.0.0.1, got {hip!r}")
        elif published:
            raise ComposeError(f"unexpected published ports on {name}")

    # Realtime alias
    rt = services["realtime"]
    nets = rt.get("networks") or {}
    aliases: list[str] = []
    if isinstance(nets, dict):
        for net in nets.values():
            if isinstance(net, dict):
                aliases.extend(net.get("aliases") or [])
    elif isinstance(nets, list):
        pass
    if REALTIME_ALIAS not in aliases:
        blob = json.dumps(rt)
        if REALTIME_ALIAS not in blob:
            raise ComposeError("Realtime DNS alias missing")

    networks = config.get("networks") or {}
    if not networks:
        raise ComposeError("expected project default network")
    expected_net = f"{compose_project}_default"
    for net_key, net in networks.items():
        if not isinstance(net, dict):
            raise ComposeError(f"invalid network entry: {net_key}")
        if net.get("external"):
            raise ComposeError("external network refused")
        # Effective name must match project default — including networks.default.name.
        eff_name = str(net.get("name") or "")
        if eff_name and eff_name != expected_net:
            raise ComposeError(f"unexpected network name {eff_name!r}; expected {expected_net!r}")
        labels = net.get("labels") or {}
        if labels.get("io.sbfleet.fleet") != fleet_id:
            raise ComposeError("missing fleet label on network")
        if labels.get("io.sbfleet.project") != project_id:
            raise ComposeError("missing project label on network")

    volumes = config.get("volumes") or {}
    expected_vols = {"db-config", "deno-cache"}
    if set(volumes) != expected_vols:
        raise ComposeError(f"volume inventory mismatch got={set(volumes)} expected={expected_vols}")
    for vol_key, vol in volumes.items():
        if not isinstance(vol, dict):
            raise ComposeError(f"invalid volume entry: {vol_key}")
        if vol.get("external"):
            raise ComposeError("external volume refused")
        eff_name = str(vol.get("name") or "")
        expected_name = f"{compose_project}_{vol_key}"
        if eff_name and eff_name != expected_name:
            raise ComposeError(f"unexpected volume name {eff_name!r}; expected {expected_name!r}")
        labels = vol.get("labels") or {}
        if labels.get("io.sbfleet.fleet") != fleet_id:
            raise ComposeError(f"missing fleet label on volume {vol_key}")
        if labels.get("io.sbfleet.project") != project_id:
            raise ComposeError(f"missing project label on volume {vol_key}")


def _validate_bind_source(
    src: str,
    *,
    bind_roots: list[Path],
    deployment: Path | None,
) -> None:
    if not src:
        raise ComposeError("empty bind source refused")
    if src.startswith("/"):
        candidate = Path(src)
    elif deployment is not None:
        candidate = Path(deployment) / src
    else:
        # Relative binds require a deployment root for containment.
        if not bind_roots:
            raise ComposeError(f"relative bind without deployment root: {src}")
        candidate = bind_roots[0] / src
    if candidate.is_symlink() or any(p.is_symlink() for p in candidate.parents if p != candidate):
        # Check the path itself and refuse symlink components near the leaf.
        if candidate.exists() or candidate.is_symlink():
            import stat as statmod

            try:
                st = candidate.lstat()
                if statmod.S_ISLNK(st.st_mode):
                    raise ComposeError(f"symlink bind source refused: {src}")
            except FileNotFoundError:
                pass
    try:
        resolved = candidate.resolve(strict=False)
    except OSError as exc:
        raise ComposeError(f"unbindable bind source: {src}") from exc
    if not bind_roots:
        raise ComposeError(f"bind source refused without allowed roots: {src}")
    if not any(_path_is_under(resolved, root) for root in bind_roots):
        raise ComposeError(f"bind source escapes project roots: {src} -> {resolved}")


def _path_is_under(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _expect_loopback_port(published: list[dict[str, Any]], host_port: int, target: int) -> None:
    if len(published) != 1:
        raise ComposeError(f"expected one published port to {target}, got {len(published)}")
    p = published[0]
    if int(p.get("published")) != host_port or int(p.get("target")) != target:
        raise ComposeError(f"port mapping mismatch for target {target}")
    hip = p.get("host_ip")
    if hip != "127.0.0.1":
        raise ComposeError(f"published port must bind 127.0.0.1, got {hip!r}")


@dataclass(frozen=True)
class MountExpectation:
    """Exact approved mount for a service (pin + deployment remapping)."""

    mount_type: str  # bind | volume
    source: str  # absolute bind source under deployment, or named volume Docker name
    destination: str
    read_only: bool


@dataclass(frozen=True)
class ServiceContract:
    service: str
    container_name: str
    image_ref: str
    mounts: tuple[MountExpectation, ...]
    networks: frozenset[str]
    required_labels: frozenset[tuple[str, str]]


@dataclass(frozen=True)
class ApprovedProfileContract:
    """
    Approved standard-profile mutation contract.

    Built from the pinned vendor snapshot + sbfleet-owned override/metadata facts.
    Current effective Compose is evidence to compare — never the trust root.
    """

    compose_project: str
    fleet_id: str
    project_id: str
    services: dict[str, ServiceContract]
    expected_network: str
    expected_volumes: frozenset[str]


def _parse_vendor_mount(
    entry: Any,
    *,
    vendor_docker_root: Path,
    deployment: Path,
    compose_project: str,
) -> MountExpectation:
    if isinstance(entry, str):
        parts = entry.split(":")
        src = parts[0]
        dest = parts[1] if len(parts) > 1 else ""
        mode = parts[2] if len(parts) > 2 else ""
        read_only = "ro" in mode.split(",")
        if src.startswith(".") or src.startswith("/"):
            mount_type = "bind"
        else:
            mount_type = "volume"
        source = src
        destination = dest
    elif isinstance(entry, dict):
        mount_type = str(entry.get("type") or "")
        source = str(entry.get("source") or entry.get("Source") or "")
        destination = str(
            entry.get("target") or entry.get("Target") or entry.get("destination") or ""
        )
        read_only = bool(entry.get("read_only") or entry.get("ReadOnly"))
    else:
        raise ComposeError(f"unsupported volume entry type: {type(entry)!r}")
    if not destination:
        raise ComposeError(f"mount missing destination: {entry!r}")
    if mount_type == "bind":
        if not source:
            raise ComposeError("bind mount missing source")
        src_path = Path(source)
        vendor_root = vendor_docker_root.resolve(strict=False)
        try:
            rel = src_path.resolve(strict=False).relative_to(vendor_root)
        except ValueError as exc:
            # Relative sources already under vendor when compose cwd is vendor docker.
            if source.startswith("./") or (not source.startswith("/")):
                rel = Path(source)
            else:
                raise ComposeError(
                    f"vendor bind source escapes vendor docker root: {source}"
                ) from exc
        remapped = (Path(deployment) / rel).resolve(strict=False)
        return MountExpectation(
            mount_type="bind",
            source=str(remapped),
            destination=destination,
            read_only=read_only,
        )
    if mount_type == "volume":
        key = source
        if key.startswith(f"{compose_project}_"):
            key = key[len(compose_project) + 1 :]
        if key not in {"db-config", "deno-cache"}:
            raise ComposeError(f"unexpected named volume in vendor contract: {source!r}")
        return MountExpectation(
            mount_type="volume",
            source=f"{compose_project}_{key}",
            destination=destination,
            read_only=read_only,
        )
    raise ComposeError(f"unsupported mount type in vendor contract: {mount_type!r}")


def build_approved_standard_profile_contract(
    vendor_config: dict[str, Any],
    *,
    vendor_docker_root: Path,
    deployment: Path,
    compose_project: str,
    fleet_id: str,
    project_id: str,
) -> ApprovedProfileContract:
    """Derive the approved contract from pinned vendor compose + sbfleet identity facts."""
    services_cfg = vendor_config.get("services") or {}
    if set(services_cfg) != set(STANDARD_SERVICES):
        raise ComposeError(
            f"vendor service inventory mismatch extra="
            f"{set(services_cfg) - set(STANDARD_SERVICES)} missing="
            f"{set(STANDARD_SERVICES) - set(services_cfg)}"
        )
    expected_net = f"{compose_project}_default"
    expected_vols = frozenset({f"{compose_project}_db-config", f"{compose_project}_deno-cache"})
    required_labels = frozenset(
        {
            ("io.sbfleet.fleet", fleet_id),
            ("io.sbfleet.project", project_id),
            ("com.docker.compose.project", compose_project),
        }
    )
    services: dict[str, ServiceContract] = {}
    for name in STANDARD_SERVICES:
        svc = services_cfg[name]
        if not isinstance(svc, dict):
            raise ComposeError(f"vendor service {name} malformed")
        image = svc.get("image")
        if not image or not isinstance(image, str):
            raise ComposeError(f"vendor service {name} missing image reference")
        mounts: list[MountExpectation] = []
        for entry in svc.get("volumes") or []:
            mounts.append(
                _parse_vendor_mount(
                    entry,
                    vendor_docker_root=vendor_docker_root,
                    deployment=deployment,
                    compose_project=compose_project,
                )
            )
        services[name] = ServiceContract(
            service=name,
            container_name=f"{compose_project}-{name}",
            image_ref=image,
            mounts=tuple(mounts),
            networks=frozenset({expected_net}),
            required_labels=required_labels | frozenset({("com.docker.compose.service", name)}),
        )
    return ApprovedProfileContract(
        compose_project=compose_project,
        fleet_id=fleet_id,
        project_id=project_id,
        services=services,
        expected_network=expected_net,
        expected_volumes=expected_vols,
    )


def assert_effective_matches_contract(
    effective: dict[str, Any],
    contract: ApprovedProfileContract,
    *,
    gateway_port: int,
    db_direct_port: int,
    pooler_session_port: int,
    pooler_transaction_port: int,
    deployment: Path,
) -> None:
    """Compare current effective Compose evidence against the pin-derived contract."""
    services = effective.get("services") or {}
    if set(services) != set(contract.services):
        raise ComposeError(
            f"effective service inventory mismatch vs approved contract "
            f"extra={set(services) - set(contract.services)} "
            f"missing={set(contract.services) - set(services)}"
        )
    for name, expected in contract.services.items():
        svc = services[name]
        if not isinstance(svc, dict):
            raise ComposeError(f"effective service {name} malformed")
        if svc.get("container_name") != expected.container_name:
            raise ComposeError(f"container_name for {name} not {expected.container_name}")
        labels = svc.get("labels") or {}
        for lk, lv in expected.required_labels:
            if lk.startswith("com.docker.compose."):
                continue  # compose injects these; fleet labels must match
            if labels.get(lk) != lv:
                raise ComposeError(f"missing/mismatched label {lk} on {name}")
        if labels.get("io.sbfleet.fleet") != contract.fleet_id:
            raise ComposeError(f"missing fleet label on {name}")
        if labels.get("io.sbfleet.project") != contract.project_id:
            raise ComposeError(f"missing project label on {name}")
        image = svc.get("image")
        if image != expected.image_ref:
            raise ComposeError(
                f"service {name} image reference mismatch: got {image!r} "
                f"expected approved {expected.image_ref!r}"
            )
        # Mounts: remap effective sources and compare exact destination/ro/type set.
        got_mounts: list[MountExpectation] = []
        for entry in svc.get("volumes") or []:
            if isinstance(entry, dict):
                mtype = str(entry.get("type") or "")
                src = str(entry.get("source") or "")
                dest = str(entry.get("target") or entry.get("destination") or "")
                ro = bool(entry.get("read_only"))
                if mtype == "bind":
                    got_mounts.append(
                        MountExpectation(
                            mount_type="bind",
                            source=str(Path(src).resolve(strict=False)),
                            destination=dest,
                            read_only=ro,
                        )
                    )
                elif mtype == "volume":
                    vol = src
                    if not vol.startswith(f"{contract.compose_project}_"):
                        vol = f"{contract.compose_project}_{src}"
                    got_mounts.append(
                        MountExpectation(
                            mount_type="volume",
                            source=vol,
                            destination=dest,
                            read_only=ro,
                        )
                    )
                else:
                    raise ComposeError(f"unsupported effective mount type on {name}: {mtype}")
            elif isinstance(entry, str):
                # Should not appear in compose config --format json typically.
                raise ComposeError(f"unexpected string mount on {name}")
        exp_set = {(m.mount_type, m.source, m.destination, m.read_only) for m in expected.mounts}
        got_set = {(m.mount_type, m.source, m.destination, m.read_only) for m in got_mounts}
        if got_set != exp_set:
            raise ComposeError(
                f"service {name} mount contract mismatch: "
                f"extra={got_set - exp_set} missing={exp_set - got_set}"
            )
        network_mode = svc.get("network_mode")
        if network_mode not in (None, "", "bridge"):
            raise ComposeError(
                f"unsupported network_mode {network_mode!r} on {name}; "
                "only unset/bridge is supported"
            )
        if svc.get("privileged"):
            raise ComposeError("privileged service refused")
        ports = svc.get("ports") or []
        published = [p for p in ports if isinstance(p, dict)]
        if name == "api-gw":
            _expect_loopback_port(published, gateway_port, 8000)
        elif name == "db":
            _expect_loopback_port(published, db_direct_port, 5432)
        elif name == "supavisor":
            if len(published) != 2:
                raise ComposeError(
                    f"supavisor must publish exactly two ports, got {len(published)}"
                )
            targets = {
                (int(p.get("published")), int(p.get("target")))
                for p in published
                if "published" in p
            }
            if (pooler_session_port, 5432) not in targets or (
                pooler_transaction_port,
                6543,
            ) not in targets:
                raise ComposeError("supavisor ports incorrect")
            for p in published:
                if p.get("host_ip") != "127.0.0.1":
                    raise ComposeError(
                        f"supavisor port must bind 127.0.0.1, got {p.get('host_ip')!r}"
                    )
        elif published:
            raise ComposeError(f"unexpected published ports on {name}")

    # Realtime alias (override fact)
    rt = services["realtime"]
    nets = rt.get("networks") or {}
    aliases: list[str] = []
    if isinstance(nets, dict):
        for net in nets.values():
            if isinstance(net, dict):
                aliases.extend(net.get("aliases") or [])
    if REALTIME_ALIAS not in aliases:
        blob = json.dumps(rt)
        if REALTIME_ALIAS not in blob:
            raise ComposeError("Realtime DNS alias missing")

    networks = effective.get("networks") or {}
    if not networks:
        raise ComposeError("expected project default network")
    for net_key, net in networks.items():
        if not isinstance(net, dict):
            raise ComposeError(f"invalid network entry: {net_key}")
        if net.get("external"):
            raise ComposeError("external network refused")
        eff_name = str(net.get("name") or "")
        if eff_name and eff_name != contract.expected_network:
            raise ComposeError(
                f"unexpected network name {eff_name!r}; expected {contract.expected_network!r}"
            )
        labels = net.get("labels") or {}
        if labels.get("io.sbfleet.fleet") != contract.fleet_id:
            raise ComposeError("missing fleet label on network")
        if labels.get("io.sbfleet.project") != contract.project_id:
            raise ComposeError("missing project label on network")

    volumes = effective.get("volumes") or {}
    expected_keys = {"db-config", "deno-cache"}
    if set(volumes) != expected_keys:
        raise ComposeError(f"volume inventory mismatch got={set(volumes)} expected={expected_keys}")
    for vol_key, vol in volumes.items():
        if not isinstance(vol, dict):
            raise ComposeError(f"invalid volume entry: {vol_key}")
        if vol.get("external"):
            raise ComposeError("external volume refused")
        eff_name = str(vol.get("name") or "")
        expected_name = f"{contract.compose_project}_{vol_key}"
        if eff_name and eff_name != expected_name:
            raise ComposeError(f"unexpected volume name {eff_name!r}; expected {expected_name!r}")
        labels = vol.get("labels") or {}
        if labels.get("io.sbfleet.fleet") != contract.fleet_id:
            raise ComposeError(f"missing fleet label on volume {vol_key}")
        if labels.get("io.sbfleet.project") != contract.project_id:
            raise ComposeError(f"missing project label on volume {vol_key}")


def supports_override_tag() -> bool:
    """Probe whether Compose accepts !override (fail closed if not)."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "docker-compose.yml").write_text(
            "services:\n  web:\n    image: alpine:3.20\n    ports:\n      - '8080:80'\n",
            encoding="utf-8",
        )
        (root / "docker-compose.override.yml").write_text(
            "services:\n  web:\n    ports: !override\n      - '127.0.0.1:18080:80'\n",
            encoding="utf-8",
        )
        result = run(
            ["docker", "compose", "config", "--format", "json"],
            cwd=root,
            env={
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": str(root),
                "COMPOSE_FILE": "docker-compose.yml:docker-compose.override.yml",
                "COMPOSE_PATH_SEPARATOR": ":",
            },
            timeout=30.0,
            check=False,
        )
        if not result.ok:
            return False
        try:
            data = json.loads(result.stdout)
            ports = data["services"]["web"]["ports"]
            if len(ports) != 1:
                return False
            return int(ports[0]["published"]) == 18080
        except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError):
            return False
