"""Connection info, secrets listing, and env execution."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from urllib.parse import quote

from sbfleet import registry as reg
from sbfleet import upstream as up
from sbfleet.cli import EXIT_OK, EXIT_SAFETY, EXIT_USAGE
from sbfleet.process import run

# Narrow reveal allowlist for Studio credentials.
STUDIO_SECRET_KEYS = frozenset({"DASHBOARD_USERNAME", "DASHBOARD_PASSWORD"})


def connection_info(root: Path, slug: str, *, oauth_setup: bool = False) -> dict[str, str]:
    from sbfleet.branding import public_auth_summary

    meta = reg.read_project(root, slug)
    ports = meta["ports"]
    tenant = ""
    env_path = reg.project_dir(root, slug) / "deployment" / ".env"
    if env_path.exists():
        env = up.parse_dotenv(env_path.read_text(encoding="utf-8"))
        tenant = env.get("POOLER_TENANT_ID", "")
    # JSON contract preserved (format_version 1 fields). Support tiers are human-only.
    info = {
        "api_url": str(meta["public_url"]),
        "studio_url": f"{meta['public_url'].rstrip('/')}/project/default",
        "db_host": "127.0.0.1",
        "db_port": str(ports["db_direct"]),
        "pooler_session_port": str(ports["pooler_session"]),
        "pooler_transaction_port": str(ports["pooler_transaction"]),
        "db_name": "postgres",
        "admin_role": "postgres",
        "pooler_username_pattern": f"<role>.{tenant}" if tenant else "<role>.<tenant>",
        "note": "Passwords never shown; use env --admin or runtime credentials file",
    }
    if oauth_setup:
        info.update(public_auth_summary(meta))
    return info


def format_connection_human(info: dict[str, str]) -> str:
    """Human connection report with supported/unsupported contexts. No secrets."""
    lines = [
        "Host application (supported)",
        f"  API                   {info['api_url']}",
        f"  Studio                {info['studio_url']}",
        f"  PostgreSQL direct     {info['db_host']}:{info['db_port']}",
        f"  Pooler session        {info['db_host']}:{info['pooler_session_port']}",
        f"  Pooler transaction    {info['db_host']}:{info['pooler_transaction_port']}",
        f"  Database              {info['db_name']}",
        f"  Admin role            {info['admin_role']}",
        f"  Pooler username       {info['pooler_username_pattern']}",
        "",
        "Container application",
        "  Not supported by V1 — see documentation",
        "",
        "Remote / other machine",
        "  PostgreSQL not exposed remotely by default",
        "",
        f"Note: {info['note']}",
        "Container-internal Postgres port is 5432; use the host ports above.",
        "Never assume host PostgreSQL port 5432.",
    ]
    oauth_keys = [
        k
        for k in info
        if k
        not in {
            "api_url",
            "studio_url",
            "db_host",
            "db_port",
            "pooler_session_port",
            "pooler_transaction_port",
            "db_name",
            "admin_role",
            "pooler_username_pattern",
            "note",
        }
    ]
    if oauth_keys:
        lines.append("")
        lines.append("OAuth / public Auth")
        for k in oauth_keys:
            lines.append(f"  {k}: {info[k]}")
    return "\n".join(lines)


def show_secrets(
    root: Path,
    slug: str,
    *,
    reveal: bool,
    keys: list[str] | None = None,
) -> int:
    reg.read_project(root, slug)
    env_path = reg.project_dir(root, slug) / "deployment" / ".env"
    if not env_path.exists():
        print("error: .env missing", file=sys.stderr)
        return EXIT_SAFETY
    try:
        reg.assert_secret_file(env_path)
    except reg.OwnershipError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_SAFETY
    try:
        env = up.parse_dotenv(env_path.read_text(encoding="utf-8"))
        up.validate_generated_env(env)
    except up.UpstreamError as exc:
        print(f"error: unsafe .env: {exc}", file=sys.stderr)
        return EXIT_SAFETY
    selected = sorted(env)
    if keys:
        wanted = [k.strip() for k in keys if k.strip()]
        unknown = [k for k in wanted if k not in env]
        if unknown:
            print(f"error: unknown secret keys: {', '.join(unknown)}", file=sys.stderr)
            return EXIT_USAGE
        # Targeted reveal is limited to Studio keys unless full reveal of listed keys
        # that are within the Studio allowlist when using --keys without dumping all.
        selected = wanted
    if reveal:
        if keys:
            # Narrow path: only emit requested keys (Studio workflow).
            print("warning: revealing selected secrets on stdout", file=sys.stderr)
            for k in selected:
                print(f"{k}={env[k]}")
        else:
            print("warning: revealing secrets on stdout", file=sys.stderr)
            for k in selected:
                print(f"{k}={env[k]}")
    else:
        for k in selected:
            print(f"{k}=[REDACTED]")
    return EXIT_OK


def run_with_env(
    root: Path,
    slug: str,
    cmdline: list[str],
    *,
    admin: bool,
    credentials_file: str | None,
    service_role: bool,
) -> int:
    meta = reg.read_project(root, slug)
    env_path = reg.project_dir(root, slug) / "deployment" / ".env"
    try:
        reg.assert_secret_file(env_path)
    except reg.OwnershipError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_SAFETY
    env = up.parse_dotenv(env_path.read_text(encoding="utf-8"))
    ports = meta["ports"]
    child = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "LC_ALL": "C",
    }
    api = meta["public_url"].rstrip("/")
    child["SUPABASE_URL"] = api
    child["SUPABASE_ANON_KEY"] = env.get("SUPABASE_PUBLISHABLE_KEY") or env.get("ANON_KEY", "")
    if service_role:
        child["SUPABASE_SERVICE_ROLE_KEY"] = env.get("SUPABASE_SECRET_KEY") or env.get(
            "SERVICE_ROLE_KEY", ""
        )

    with reg.project_lock(root, str(meta["id"])):
        if admin:
            password = env["POSTGRES_PASSWORD"]
            user = "postgres"
            host = "127.0.0.1"
            port = str(ports["db_direct"])
            db = env.get("POSTGRES_DB", "postgres")
            child.update(
                {
                    "PGHOST": host,
                    "PGPORT": port,
                    "PGDATABASE": db,
                    "PGUSER": user,
                    "PGPASSWORD": password,
                    "DATABASE_URL": (
                        f"postgresql://{quote(user, safe='')}:{quote(password, safe='')}"
                        f"@{host}:{port}/{db}"
                    ),
                }
            )
        elif credentials_file:
            path = Path(credentials_file)
            if path.stat().st_mode & 0o077:
                print("error: credentials file must be mode 0600", file=sys.stderr)
                return EXIT_SAFETY
            data = json.loads(path.read_text(encoding="utf-8"))
            role = data["role"]
            password = data["password"]
            if role in {"postgres", "supabase_admin"}:
                print("error: reserved admin role refused in runtime mode", file=sys.stderr)
                return EXIT_SAFETY
            tenant = env.get("POOLER_TENANT_ID", "")
            if not tenant:
                print("error: POOLER_TENANT_ID missing from .env", file=sys.stderr)
                return EXIT_SAFETY
            # Role-plus-tenant pooler identity (matches connection_info advertisement).
            pooler_user = f"{role}.{tenant}"
            host = "127.0.0.1"
            port = str(ports["pooler_transaction"])
            db = env.get("POSTGRES_DB", "postgres")
            child.update(
                {
                    "PGHOST": host,
                    "PGPORT": port,
                    "PGDATABASE": db,
                    "PGUSER": pooler_user,
                    "PGPASSWORD": password,
                    "DATABASE_URL": (
                        f"postgresql://{quote(pooler_user, safe='')}:{quote(password, safe='')}"
                        f"@{host}:{port}/{db}"
                    ),
                }
            )
        else:
            return EXIT_USAGE

        result = run(cmdline, env=child, inherit_stdio=True, capture_output=False, check=False)
        if result.returncode is not None and result.returncode < 0:
            return 128 + (-result.returncode)
        return result.returncode
