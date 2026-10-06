"""Studio URL helpers and readiness gates."""

from __future__ import annotations

import webbrowser
from pathlib import Path

from sbfleet import registry as reg
from sbfleet.health import (
    DEGRADED,
    HEALTHY,
    STOPPED,
    UNHEALTHY,
    StatusReport,
    collect_status,
    format_status_human,
)
from sbfleet.ux import confirm, is_interactive

EXIT_OK = 0
EXIT_UNHEALTHY = 7


def studio_url(root: Path, slug: str, *, local: bool = False) -> str:
    meta = reg.read_project(root, slug)
    if local or not meta.get("domain"):
        port = int(meta["ports"]["gateway"])
        return f"http://127.0.0.1:{port}/project/default"
    return f"https://{meta['domain']}/project/default"


def maybe_open(url: str) -> None:
    try:
        opened = webbrowser.open(url)
        if opened is False:
            print(
                "warning: browser opener returned false; URL printed above for manual open",
                flush=True,
            )
    except Exception as exc:  # noqa: BLE001
        print(f"warning: could not open browser: {exc}", flush=True)


def _studio_probe_ok(report: StatusReport) -> tuple[bool, str]:
    """Return (ready, detail) for Studio HTTP readiness."""
    studio = next((p for p in report.probes if p.name == "studio"), None)
    if studio is None:
        gw = next((p for p in report.probes if p.name == "api-gw"), None)
        if gw and gw.status == HEALTHY and report.lifecycle == HEALTHY:
            return True, "gateway healthy"
        return False, "studio probe missing"
    if studio.status == HEALTHY:
        return True, studio.detail or "ok"
    return False, studio.detail or studio.status


def open_studio(
    root: Path,
    slug: str,
    *,
    local: bool = False,
    url_only: bool = False,
    offer_start: bool | None = None,
) -> int:
    """Gate Studio open on real project state. Returns process exit code."""
    from sbfleet.projects import ProjectError, print_startup_failure_hint, start_project

    if offer_start is None:
        offer_start = is_interactive()

    report = collect_status(root, slug)
    url = studio_url(root, slug, local=local)

    if report.lifecycle == STOPPED:
        print(f"Project `{slug}` is stopped.", flush=True)
        if url_only:
            # Honest local URL for operators; no browser open.
            print(url, flush=True)
            print("Start it with `/start` before using Studio.", flush=True)
            return EXIT_UNHEALTHY
        print("Start it with `/start`.", flush=True)
        if offer_start and confirm("Start it now?", default_yes=True):
            try:
                start_project(root, slug)
            except ProjectError as exc:
                print(f"error: {exc}", flush=True)
                print_startup_failure_hint(root, slug)
                return exc.code
            report = collect_status(root, slug)
            if report.lifecycle == STOPPED:
                return EXIT_UNHEALTHY
        else:
            return EXIT_UNHEALTHY

    if report.lifecycle in {DEGRADED, UNHEALTHY}:
        print(f"Project `{slug}` is {report.lifecycle}.", flush=True)
        print(format_status_human(report), flush=True)
        ready, detail = _studio_probe_ok(report)
        if not ready:
            print(f"\nStudio is not ready ({detail}).", flush=True)
        print("\nSuggested:", flush=True)
        print("  /status", flush=True)
        print("  /doctor", flush=True)
        print("  /logs", flush=True)
        return EXIT_UNHEALTHY

    ready, detail = _studio_probe_ok(report)
    if not ready:
        print(f"Project `{slug}` looks up, but Studio is unreachable ({detail}).", flush=True)
        print("\nSuggested:", flush=True)
        print("  /status", flush=True)
        print("  /logs studio", flush=True)
        print("  /doctor", flush=True)
        return EXIT_UNHEALTHY

    print(url, flush=True)
    # Studio Basic Auth guidance (never print password).
    env_path = reg.project_dir(root, slug) / "deployment" / ".env"
    print("Studio authentication: HTTP Basic Auth", flush=True)
    print(f"Credentials file: {env_path}", flush=True)
    if env_path.is_file():
        try:
            from sbfleet import upstream as up

            dash = up.parse_dotenv(env_path.read_text(encoding="utf-8")).get("DASHBOARD_USERNAME")
            if dash:
                print(f"Dashboard username: {dash}", flush=True)
            print(
                "Reveal password: sbfleet secrets PROJECT --reveal "
                "--keys DASHBOARD_USERNAME,DASHBOARD_PASSWORD",
                flush=True,
            )
        except Exception:  # noqa: BLE001
            pass
    if not url_only:
        maybe_open(url)
    return EXIT_OK
