#!/usr/bin/env python3
"""Dev-only: walk production argparse + slash shell into a JSON inventory.

Usage (from repo root):
  .venv/bin/python scripts/cli_surface_inventory.py \
    --out docs/verification/V1-CLI-SURFACE-2026-10-02.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def _git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        return "unknown"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("docs/verification/V1-CLI-SURFACE-2026-10-02.json"),
    )
    ns = ap.parse_args(argv)

    from sbfleet.cli import (
        EXIT_BACKUP,
        EXIT_FAILURE,
        EXIT_INTERRUPTED,
        EXIT_LOCK,
        EXIT_NOT_FOUND,
        EXIT_OK,
        EXIT_PREREQUISITE,
        EXIT_SAFETY,
        EXIT_UNHEALTHY,
        EXIT_USAGE,
        build_parser,
    )
    from sbfleet.shell import _NO_INJECT, _PROJECT_SCOPED, SLASH_COMMANDS

    public_commands = {
        "projects",
        "create",
        "start",
        "stop",
        "restart",
        "status",
        "studio",
        "logs",
        "doctor",
        "configure",
        "connection",
        "env",
        "secrets",
        "backup",
        "restore",
        "remove",
        "update",
        "sandbox",
        "nginx",
    }
    slash_names = {c.name for c in SLASH_COMMANDS}

    def walk(parser: argparse.ArgumentParser, prefix: list[str] | None = None) -> list[dict]:
        prefix = prefix or []
        rows: list[dict] = []
        if not prefix:
            for a in parser._actions:
                if isinstance(a, argparse._SubParsersAction):
                    continue
                if a.option_strings:
                    for o in a.option_strings:
                        rows.append(
                            {
                                "surface": "global",
                                "command": None,
                                "subcommand": None,
                                "option": o,
                                "direct_syntax": f"sbfleet {o}",
                                "shell_syntax": None,
                                "destructive": False,
                                "confirmation": False,
                                "json_support": False,
                                "active_project": False,
                                "api_class": "PUBLIC",
                                "positional": False,
                                "choices": list(a.choices) if a.choices else None,
                                "default": None if a.default is argparse.SUPPRESS else a.default,
                                "help": a.help,
                            }
                        )
            rows.append(
                {
                    "surface": "global",
                    "command": "(interactive)",
                    "subcommand": None,
                    "option": None,
                    "direct_syntax": "sbfleet  # TTY shell",
                    "shell_syntax": None,
                    "destructive": False,
                    "confirmation": False,
                    "json_support": False,
                    "active_project": False,
                    "api_class": "PUBLIC",
                    "positional": False,
                    "choices": None,
                    "default": None,
                    "help": "TTY opens interactive slash shell",
                }
            )
        for a in parser._actions:
            if not isinstance(a, argparse._SubParsersAction):
                continue
            for name, sub in a.choices.items():
                cmd_path = prefix + [name]
                rows.append(
                    {
                        "surface": "direct",
                        "command": cmd_path[0],
                        "subcommand": "/".join(cmd_path[1:]) if len(cmd_path) > 1 else None,
                        "option": None,
                        "direct_syntax": "sbfleet " + " ".join(cmd_path),
                        "shell_syntax": (
                            ("/" + " ".join(cmd_path)) if cmd_path[0] in slash_names else None
                        ),
                        "destructive": cmd_path[0] in {"remove", "restore"},
                        "confirmation": False,
                        "json_support": False,
                        "active_project": cmd_path[0] in _PROJECT_SCOPED,
                        "api_class": (
                            "PUBLIC" if cmd_path[0] in public_commands else "ACCIDENTALLY_EXPOSED"
                        ),
                        "positional": False,
                        "choices": None,
                        "default": None,
                        "help": getattr(sub, "description", None),
                    }
                )
                for sa in sub._actions:
                    if isinstance(sa, argparse._SubParsersAction):
                        rows.extend(walk(sub, cmd_path))
                        continue
                    if sa.option_strings:
                        for o in sa.option_strings:
                            conf = o == "--yes"
                            js = o == "--json" or (cmd_path[0] == "update" and o == "--dry-run")
                            dest = (
                                cmd_path[0] in {"remove", "restore"}
                                and o in {"--yes", "--no-backup"}
                            ) or (cmd_path[0] == "sandbox" and o == "--yes")
                            rows.append(
                                {
                                    "surface": "direct",
                                    "command": cmd_path[0],
                                    "subcommand": (
                                        "/".join(cmd_path[1:]) if len(cmd_path) > 1 else None
                                    ),
                                    "option": o,
                                    "direct_syntax": "sbfleet " + " ".join(cmd_path) + f" {o}",
                                    "shell_syntax": (
                                        ("/" + " ".join(cmd_path) + f" {o}")
                                        if cmd_path[0] in slash_names
                                        else None
                                    ),
                                    "destructive": dest,
                                    "confirmation": conf or o == "--no-backup",
                                    "json_support": js,
                                    "active_project": cmd_path[0] in _PROJECT_SCOPED,
                                    "api_class": "PUBLIC",
                                    "positional": False,
                                    "choices": list(sa.choices) if sa.choices else None,
                                    "default": None
                                    if sa.default is argparse.SUPPRESS
                                    else sa.default,
                                    "help": sa.help,
                                    "dest": sa.dest,
                                }
                            )
                    elif sa.dest and sa.dest not in {"help"} and not sa.option_strings:
                        rows.append(
                            {
                                "surface": "direct",
                                "command": cmd_path[0],
                                "subcommand": (
                                    "/".join(cmd_path[1:]) if len(cmd_path) > 1 else None
                                ),
                                "option": f"<{sa.dest}>",
                                "direct_syntax": "sbfleet " + " ".join(cmd_path) + f" <{sa.dest}>",
                                "shell_syntax": (
                                    ("/" + " ".join(cmd_path) + f" <{sa.dest}>")
                                    if cmd_path[0] in slash_names
                                    else None
                                ),
                                "destructive": False,
                                "confirmation": False,
                                "json_support": False,
                                "active_project": (
                                    cmd_path[0] in _PROJECT_SCOPED and sa.dest == "project"
                                ),
                                "api_class": "PUBLIC",
                                "positional": True,
                                "choices": list(sa.choices) if sa.choices else None,
                                "default": None if sa.default is argparse.SUPPRESS else sa.default,
                                "help": sa.help,
                                "nargs": str(sa.nargs) if sa.nargs is not None else None,
                            }
                        )
        return rows

    rows = walk(build_parser())
    for sc in SLASH_COMMANDS:
        if sc.name in {"use", "help", "commands", "exit"}:
            rows.append(
                {
                    "surface": "shell",
                    "command": sc.name,
                    "subcommand": None,
                    "option": None,
                    "direct_syntax": None,
                    "shell_syntax": f"/{sc.name}",
                    "destructive": False,
                    "confirmation": False,
                    "json_support": False,
                    "active_project": sc.takes_project,
                    "api_class": "PUBLIC",
                    "positional": False,
                    "choices": None,
                    "default": None,
                    "help": sc.description,
                }
            )
    rows.append(
        {
            "surface": "shell",
            "command": "(discovery)",
            "subcommand": None,
            "option": None,
            "direct_syntax": None,
            "shell_syntax": "/",
            "destructive": False,
            "confirmation": False,
            "json_support": False,
            "active_project": False,
            "api_class": "PUBLIC",
            "positional": False,
            "choices": None,
            "default": None,
            "help": "Slash command palette",
        }
    )
    rows.append(
        {
            "surface": "shell",
            "command": "use",
            "subcommand": None,
            "option": "--clear",
            "direct_syntax": None,
            "shell_syntax": "/use --clear",
            "destructive": False,
            "confirmation": False,
            "json_support": False,
            "active_project": False,
            "api_class": "PUBLIC",
            "positional": False,
            "choices": None,
            "default": None,
            "help": "Clear active project",
        }
    )

    seen: set[tuple] = set()
    uniq: list[dict] = []
    for r in rows:
        key = (
            r.get("surface"),
            r.get("command"),
            r.get("subcommand"),
            r.get("option"),
            r.get("direct_syntax"),
            r.get("shell_syntax"),
        )
        if key in seen:
            continue
        seen.add(key)
        uniq.append(r)

    out = {
        "format_version": 1,
        "head": _git_head(),
        "exit_codes": {
            "0": EXIT_OK,
            "1": EXIT_FAILURE,
            "2": EXIT_USAGE,
            "3": EXIT_NOT_FOUND,
            "4": EXIT_PREREQUISITE,
            "5": EXIT_SAFETY,
            "6": EXIT_LOCK,
            "7": EXIT_UNHEALTHY,
            "8": EXIT_BACKUP,
            "130": EXIT_INTERRUPTED,
        },
        "slash_commands": [c.name for c in SLASH_COMMANDS],
        "project_scoped": sorted(_PROJECT_SCOPED),
        "no_inject": sorted(_NO_INJECT),
        "rows": uniq,
        "counts": {
            "rows": len(uniq),
            "top_level_commands": len(
                [
                    r
                    for r in uniq
                    if r["surface"] == "direct" and r["option"] is None and not r.get("subcommand")
                ]
            ),
            "options": sum(
                1
                for r in uniq
                if r.get("option")
                and str(r["option"]).startswith("-")
                and r["option"] not in {"-h", "--help"}
            ),
            "positionals": sum(1 for r in uniq if r.get("positional")),
            "shell_only": sum(1 for r in uniq if r.get("surface") == "shell"),
            "public": sum(1 for r in uniq if r.get("api_class") == "PUBLIC"),
            "accidentally_exposed": sum(
                1 for r in uniq if r.get("api_class") == "ACCIDENTALLY_EXPOSED"
            ),
            "internal_test_only": sum(
                1 for r in uniq if r.get("api_class") == "INTERNAL_TEST_ONLY"
            ),
            "public_deprecated": sum(1 for r in uniq if r.get("api_class") == "PUBLIC_DEPRECATED"),
        },
    }
    ns.out.parent.mkdir(parents=True, exist_ok=True)
    ns.out.write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps(out["counts"], indent=2))
    print(f"wrote {ns.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
