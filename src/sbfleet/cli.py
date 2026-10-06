"""Command-line entry point for sbfleet."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from sbfleet import __version__

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2
EXIT_NOT_FOUND = 3
EXIT_PREREQUISITE = 4
EXIT_SAFETY = 5
EXIT_LOCK = 6
EXIT_UNHEALTHY = 7
EXIT_BACKUP = 8
EXIT_INTERRUPTED = 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sbfleet",
        description="Manage multiple official self-hosted Supabase projects on one host.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--home", metavar="PATH", help="Absolute fleet data root")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("projects", help="List projects")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("create", help="Create project")
    p.add_argument("slug")
    p.add_argument("--name")
    p.add_argument(
        "--profile",
        default="standard",
        choices=["standard"],
        help="Project profile (sole V1 profile: standard)",
    )
    p.add_argument("--domain")
    p.add_argument(
        "--organization-name",
        help="Studio organization display name (STUDIO_DEFAULT_ORGANIZATION)",
    )
    p.add_argument(
        "--studio-project",
        dest="studio_project",
        help="Studio project display name (STUDIO_DEFAULT_PROJECT)",
    )
    p.add_argument(
        "--site-url",
        help="Application Auth SITE_URL (not the Supabase public host)",
    )
    p.add_argument(
        "--redirect-url",
        action="append",
        default=[],
        dest="redirect_urls",
        help="ADDITIONAL_REDIRECT_URLS entry (repeatable)",
    )
    p.add_argument(
        "--google-oauth",
        action="store_true",
        help="Set GOOGLE_ENABLED=true (secrets still set privately in .env)",
    )
    p.add_argument("--start", action="store_true")
    p.add_argument("--no-start", action="store_true")
    p.add_argument("--resume", action="store_true")
    p.add_argument("--yes", action="store_true")

    for name in ("start", "stop", "restart"):
        p = sub.add_parser(name, help=f"{name} project")
        p.add_argument("project")
        if name in {"start", "restart"}:
            p.add_argument("--timeout", type=int, default=300)

    p = sub.add_parser("status", help="Project status")
    p.add_argument("project")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("studio", help="Studio URL / open")
    p.add_argument("project")
    p.add_argument("--local", action="store_true")
    p.add_argument("--url-only", action="store_true")

    p = sub.add_parser("logs", help="Project logs")
    p.add_argument("project")
    p.add_argument("service", nargs="?")
    p.add_argument("--follow", action="store_true")
    p.add_argument("--tail", type=int, default=100)

    p = sub.add_parser("doctor", help="Host/project/sandbox doctor")
    p.add_argument("project", nargs="?")
    p.add_argument("--sandbox")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("configure", help="Show or change presentation settings")
    p.add_argument("project")
    p.add_argument(
        "--name",
        help="SBfleet display name (metadata only; does not rename slug)",
    )
    p.add_argument(
        "--organization-name",
        help="Studio organization display name (STUDIO_DEFAULT_ORGANIZATION)",
    )
    p.add_argument(
        "--studio-project",
        dest="studio_project",
        help="Studio project display name (STUDIO_DEFAULT_PROJECT)",
    )

    p = sub.add_parser("connection", help="Nonsecret connection info")
    p.add_argument("project")
    p.add_argument("--json", action="store_true")
    p.add_argument(
        "--oauth-setup",
        action="store_true",
        help="Show Studio branding + Google callback URI (no secrets)",
    )

    p = sub.add_parser("env", help="Run command with project env")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--admin", action="store_true")
    g.add_argument("--credentials-file")
    p.add_argument("--service-role", action="store_true")
    p.add_argument("project")
    p.add_argument("cmd", nargs=argparse.REMAINDER)

    p = sub.add_parser("secrets", help="List or reveal secrets")
    p.add_argument("project")
    p.add_argument("--reveal", action="store_true")
    p.add_argument(
        "--keys",
        help="Comma-separated keys to list/reveal (Studio: DASHBOARD_USERNAME,DASHBOARD_PASSWORD)",
    )

    p = sub.add_parser("backup", help="Encrypted backup")
    p.add_argument("project")
    p.add_argument("--verify", action="store_true", default=True)
    p.add_argument("--no-verify", action="store_true")
    p.add_argument("--identity", help="age identity file for verification")

    p = sub.add_parser("restore", help="Restore backup")
    p.add_argument("project")
    p.add_argument("archive")
    p.add_argument("--yes", action="store_true")
    p.add_argument("--identity", help="age identity file for decrypt")

    p = sub.add_parser("remove", help="Remove project")
    p.add_argument("project")
    p.add_argument("--yes", action="store_true")
    p.add_argument("--no-backup", action="store_true")

    p = sub.add_parser("update", help="Staged official update")
    p.add_argument("project")
    p.add_argument("--to", default=None, help="Reviewed self-hosted/vX.Y.Z target ref")
    p.add_argument(
        "--reconcile",
        action="store_true",
        help="Continue one unresolved UPDATING op from its promote-record",
    )
    p.add_argument(
        "--operation-id",
        default=None,
        help="Exact unresolved UPDATING operation_id (required with --reconcile)",
    )
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--yes", action="store_true")
    p.add_argument("--identity", help="age identity file for pre-update recovery backup")

    p = sub.add_parser("sandbox", help="Local CLI sandbox")
    p.add_argument("--yes", action="store_true")
    p.add_argument("--json", action="store_true")
    p.add_argument(
        "--revalidate",
        action="store_true",
        help="Explicitly revalidate authority fingerprint (start only)",
    )
    p.add_argument(
        "--migration-mode",
        choices=["supabase", "external"],
        default=None,
        help="Migration authority mode (start; default supabase on first adopt)",
    )
    p.add_argument(
        "action",
        choices=["start", "stop", "status", "reset", "destroy", "env", "studio"],
    )
    p.add_argument("path")
    p.add_argument(
        "cmd",
        nargs=argparse.REMAINDER,
        help="For env: -- COMMAND ...",
    )

    p = sub.add_parser("nginx", help="Generate/validate nginx config")
    p.add_argument("action", choices=["generate", "validate", "install"])
    p.add_argument("project", nargs="?")
    p.add_argument("--json", action="store_true")

    return parser


def _root(args: argparse.Namespace) -> Path:
    from sbfleet.registry import ensure_root, resolve_home

    return ensure_root(resolve_home(args.home))


def dispatch_namespace(args: argparse.Namespace) -> int:
    if not args.command:
        return EXIT_USAGE
    try:
        return _dispatch(args)
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED


def _dispatch(args: argparse.Namespace) -> int:
    from sbfleet import projects as proj
    from sbfleet import registry as reg
    from sbfleet.process import ProcessError
    from sbfleet.projects import ProjectError
    from sbfleet.registry import RegistryError

    cmd = args.command
    try:
        if cmd == "projects":
            root = _root(args)
            rows = reg.list_projects(root)
            if args.json:
                payload = {
                    "format_version": 1,
                    "ok": all(r.ok for r in rows) or not rows,
                    "command": "projects",
                    "data": [
                        {
                            "slug": r.slug,
                            "ok": r.ok,
                            "error": r.error,
                            "display_name": r.data.get("display_name"),
                            "creation_complete": r.data.get("creation_complete"),
                            "public_url": r.data.get("public_url"),
                        }
                        for r in rows
                    ],
                    "warnings": [],
                    "errors": [],
                }
                print(json.dumps(payload))
            else:
                if not rows:
                    print("(no projects)")
                for r in rows:
                    flag = "OK" if r.ok else "FAILED"
                    print(f"{r.slug}\t{flag}\t{r.data.get('display_name', '')}\t{r.error or ''}")
            return EXIT_OK if all(r.ok for r in rows) or not rows else EXIT_FAILURE

        if cmd == "create":
            from sbfleet.health import HEALTHY, collect_status
            from sbfleet.ux import confirm, is_interactive

            root = _root(args)
            # Direct CLI: only --start starts. Interactive (no flag): ask after create.
            explicit_start = bool(args.start)
            explicit_no_start = bool(args.no_start)
            if explicit_start and explicit_no_start:
                print("error: --start and --no-start are mutually exclusive", file=sys.stderr)
                return EXIT_USAGE
            ask_start = is_interactive() and not explicit_start and not explicit_no_start
            do_start = explicit_start and not explicit_no_start
            meta = proj.create_project(
                root,
                args.slug,
                display_name=args.name,
                domain=args.domain,
                resume=args.resume,
                start=do_start,
                organization_name=args.organization_name,
                studio_project_name=args.studio_project,
                site_url=args.site_url,
                additional_redirect_urls=list(args.redirect_urls or []),
                google_oauth_enabled=bool(args.google_oauth),
            )
            started = do_start
            if ask_start:
                if confirm("Start project now?", default_yes=True):
                    try:
                        proj.start_project(root, args.slug)
                        started = True
                    except ProjectError as exc:
                        print(f"error: {exc}", file=sys.stderr)
                        proj.print_startup_failure_hint(root, args.slug)
                        print(
                            f"created {meta['slug']} {meta['public_url']} "
                            f"complete={meta['creation_complete']} STOPPED"
                        )
                        return exc.code
            state = "STOPPED"
            if started:
                report = collect_status(root, args.slug)
                state = report.lifecycle
                if report.lifecycle != HEALTHY:
                    proj.print_startup_failure_hint(root, args.slug)
                    print(
                        f"created {meta['slug']} {meta['public_url']} "
                        f"complete={meta['creation_complete']} {state}"
                    )
                    return EXIT_UNHEALTHY
            print(
                f"created {meta['slug']} {meta['public_url']} "
                f"complete={meta['creation_complete']} {state}"
            )
            from sbfleet import upstream as up
            from sbfleet.health import _project_locations

            loc = _project_locations(root, meta["slug"], meta)
            print(f"project_root: {loc['project_root']}")
            print(f"deployment: {loc['deployment']}")
            print(f"env: {loc['env_path']}")
            print(f"metadata: {loc['metadata_path']}")
            print(f"journal: {loc['journal_path']}")
            print(f"backups: {loc['backup_dir']}")
            print("studio_auth: HTTP Basic Auth (password in .env, not shown)")
            env_path = Path(loc["env_path"])
            if env_path.is_file():
                try:
                    dash = up.parse_dotenv(env_path.read_text(encoding="utf-8")).get(
                        "DASHBOARD_USERNAME"
                    )
                    if dash:
                        print(f"dashboard_username: {dash}")
                except Exception:
                    pass
            if meta.get("domain") or meta.get("google_oauth_enabled") or meta.get("branding"):
                from sbfleet.branding import google_callback_uri, public_auth_summary

                summary = public_auth_summary(meta)
                print(f"studio_organization: {summary['organization_name']}")
                print(f"studio_project: {summary['project_name']}")
                print(f"site_url: {summary['site_url']}")
                print(f"api_external_url: {summary['api_external_url']}")
                print(f"google_callback_uri: {google_callback_uri(str(meta['public_url']))}")
            return EXIT_OK

        if cmd in {"start", "stop", "restart"}:
            root = _root(args)
            if cmd == "start":
                try:
                    proj.start_project(root, args.project, timeout=args.timeout)
                except ProjectError as exc:
                    print(f"error: {exc}", file=sys.stderr)
                    proj.print_startup_failure_hint(root, args.project)
                    return exc.code
                from sbfleet.health import HEALTHY, collect_status

                report = collect_status(root, args.project)
                if report.lifecycle != HEALTHY:
                    proj.print_startup_failure_hint(root, args.project)
                    print(f"start {args.project}: {report.lifecycle}")
                    return EXIT_UNHEALTHY
            elif cmd == "stop":
                proj.stop_project(root, args.project)
            else:
                try:
                    proj.restart_project(root, args.project, timeout=args.timeout)
                except ProjectError as exc:
                    print(f"error: {exc}", file=sys.stderr)
                    proj.print_startup_failure_hint(root, args.project)
                    return exc.code
                from sbfleet.health import HEALTHY, collect_status

                report = collect_status(root, args.project)
                if report.lifecycle != HEALTHY:
                    proj.print_startup_failure_hint(root, args.project)
                    print(f"restart {args.project}: {report.lifecycle}")
                    return EXIT_UNHEALTHY
            print(f"{cmd} {args.project}: ok")
            return EXIT_OK

        if cmd == "status":
            from sbfleet.health import (
                collect_status,
                format_status_human,
                status_exit_code,
                status_json,
            )

            root = _root(args)
            report = collect_status(root, args.project)
            if args.json:
                print(json.dumps(status_json(report, root=root)))
            else:
                print(format_status_human(report, root=root))
            return status_exit_code(report)

        if cmd == "studio":
            from sbfleet.studio import open_studio
            from sbfleet.ux import is_interactive

            root = _root(args)
            return open_studio(
                root,
                args.project,
                local=args.local,
                url_only=args.url_only,
                offer_start=is_interactive(),
            )
        if cmd == "logs":
            root = _root(args)
            proj.project_logs(
                root,
                args.project,
                service=args.service,
                follow=args.follow,
                tail=args.tail,
            )
            return EXIT_OK

        if cmd == "doctor":
            from sbfleet.doctor import run_doctor

            root = _root(args)
            return run_doctor(
                root,
                project=args.project,
                sandbox=args.sandbox,
                as_json=args.json,
            )

        if cmd == "configure":
            from sbfleet.configure import run_configure

            root = _root(args)
            return run_configure(
                root,
                args.project,
                display_name=args.name,
                organization_name=args.organization_name,
                studio_project=args.studio_project,
            )

        if cmd == "connection":
            from sbfleet.connection import connection_info, format_connection_human

            root = _root(args)
            info = connection_info(root, args.project, oauth_setup=args.oauth_setup)
            if args.json:
                print(
                    json.dumps(
                        {
                            "format_version": 1,
                            "ok": True,
                            "command": "connection",
                            "data": info,
                            "warnings": [],
                            "errors": [],
                        }
                    )
                )
            else:
                print(format_connection_human(info))
            return EXIT_OK

        if cmd == "env":
            from sbfleet.connection import run_with_env

            root = _root(args)
            cmdline = list(args.cmd)
            if cmdline and cmdline[0] == "--":
                cmdline = cmdline[1:]
            if not cmdline:
                print("error: env requires -- COMMAND", file=sys.stderr)
                return EXIT_USAGE
            return run_with_env(
                root,
                args.project,
                cmdline,
                admin=args.admin,
                credentials_file=args.credentials_file,
                service_role=args.service_role,
            )

        if cmd == "secrets":
            from sbfleet.connection import show_secrets

            root = _root(args)
            keys = None
            if getattr(args, "keys", None):
                keys = [k.strip() for k in str(args.keys).split(",") if k.strip()]
            return show_secrets(root, args.project, reveal=args.reveal, keys=keys)

        if cmd == "backup":
            from sbfleet.backup import create_backup

            root = _root(args)
            verify = not args.no_verify
            return create_backup(root, args.project, verify=verify, identity=args.identity)

        if cmd == "restore":
            from sbfleet.backup import restore_backup

            root = _root(args)
            return restore_backup(
                root,
                args.project,
                args.archive,
                yes=args.yes,
                identity=args.identity,
            )

        if cmd == "remove":
            from sbfleet.projects_remove import remove_project

            root = _root(args)
            return remove_project(root, args.project, yes=args.yes, no_backup=args.no_backup)

        if cmd == "update":
            from sbfleet.update import update_project

            root = _root(args)
            return update_project(
                root,
                args.project,
                to_ref=args.to,
                dry_run=args.dry_run,
                yes=args.yes,
                identity=getattr(args, "identity", None),
                reconcile=bool(getattr(args, "reconcile", False)),
                operation_id=getattr(args, "operation_id", None),
            )

        if cmd == "sandbox":
            from sbfleet.sandbox import sandbox_cmd

            return sandbox_cmd(args)

        if cmd == "nginx":
            from sbfleet.nginx import nginx_cmd

            root = _root(args)
            return nginx_cmd(root, args)

        print(f"error: command '{cmd}' is not implemented yet", file=sys.stderr)
        return EXIT_FAILURE
    except ProjectError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.code
    except RegistryError as exc:
        from sbfleet.registry import NotFoundError

        print(f"error: {exc}", file=sys.stderr)
        if isinstance(exc, NotFoundError):
            return EXIT_NOT_FOUND
        msg = str(exc).lower()
        # Legacy string match only for true absence phrasing; never treat
        # incomplete/corrupt project.json as exit 3.
        if "incomplete/corrupt" in msg or "project.json missing" in msg:
            return EXIT_FAILURE
        if "not found" in msg or "unknown project" in msg or "absent" in msg:
            return EXIT_NOT_FOUND
        return EXIT_FAILURE
    except FileNotFoundError as exc:
        print(f"error: missing file or tool: {exc}", file=sys.stderr)
        return EXIT_PREREQUISITE
    except OSError as exc:
        # Expected operator/environment conditions (missing path, permission), not bugs.
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    except ProcessError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILURE


def main(argv: Sequence[str] | None = None) -> int:
    argv_list = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    if not argv_list:
        if sys.stdin.isatty() and sys.stdout.isatty():
            from sbfleet.shell import run_interactive_shell

            return run_interactive_shell(home=None)
        parser.print_help(sys.stderr)
        return EXIT_USAGE
    try:
        args = parser.parse_args(argv_list)
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return EXIT_OK
        if isinstance(code, int):
            return code
        return EXIT_FAILURE
    # `--home PATH` alone (no subcommand) opens the documented interactive shell.
    if not args.command:
        if getattr(args, "home", None) and sys.stdin.isatty() and sys.stdout.isatty():
            from sbfleet.shell import run_interactive_shell

            return run_interactive_shell(home=args.home)
        return EXIT_USAGE
    return dispatch_namespace(args)


if __name__ == "__main__":
    raise SystemExit(main())
