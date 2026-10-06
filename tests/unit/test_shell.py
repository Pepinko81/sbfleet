"""Shell unit tests — completion, active project, help aliases."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from sbfleet.shell import (
    FleetShell,
    SlashCompleter,
    filter_commands,
    filter_names,
    format_command_palette,
    slash_command_names,
    topic_help,
)


class _Doc:
    def __init__(self, text: str) -> None:
        self.text_before_cursor = text


def _completions(shell: FleetShell, text: str) -> list[str]:
    comp = SlashCompleter(shell)
    return [c.text for c in comp.get_completions(_Doc(text), None)]


def test_bare_input_not_executed(capsys: pytest.CaptureFixture[str]) -> None:
    sh = FleetShell()
    sh.default("rm -rf /")
    out = capsys.readouterr().out
    assert "no bare shell" in out.lower() or "unknown input" in out.lower()
    sh.default("docker ps")
    out = capsys.readouterr().out
    assert "unknown input" in out.lower()
    sh.default("sbfleet status")
    out = capsys.readouterr().out
    assert "unknown input" in out.lower()


def test_project_slash_suggests_use(capsys: pytest.CaptureFixture[str]) -> None:
    sh = FleetShell()
    sh.default("/project qa-alpha")
    out = capsys.readouterr().out
    assert "/project" in out.lower() or "unknown command" in out.lower()
    assert "/use qa-alpha" in out
    sh.default("/project")
    out = capsys.readouterr().out
    assert "/use" in out


def test_use_and_clear(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    sh = FleetShell(home=str(tmp_path))
    # Empty fleet: allow selecting by name for session UX when no registry rows.
    sh._use("demo")
    assert sh.active == "demo"
    assert sh.prompt == "sbfleet / demo ● ❯ "
    sh._use("")
    out = capsys.readouterr().out
    assert "Active project: demo" in out
    assert "/use --clear" in out
    sh._use("--clear")
    assert sh.active is None
    assert sh.prompt == "sbfleet ❯ "
    assert "cleared" in capsys.readouterr().out.lower()


def test_help_use_mentions_clear() -> None:
    from sbfleet.shell import format_command_palette, topic_help

    help_txt = topic_help("use")
    assert "/use --clear" in help_txt
    palette = format_command_palette(active="demo")
    assert "/use --clear" in palette
    assert "return to fleet root" in palette


def test_use_validates_against_registry(tmp_path: Path) -> None:
    from sbfleet import registry as reg

    root = reg.ensure_root(tmp_path)
    meta = {
        "format_version": 1,
        "id": "11111111-1111-1111-1111-111111111111",
        "fleet_id": reg.fleet_id(root),
        "slug": "myapp",
        "display_name": "Leadforge",
        "created_at": "2026-01-01T00:00:00Z",
        "profile": "standard",
        "compose_project": "sbfleet-111111111111-111111111111",
        "ports": {
            "gateway": 20000,
            "db_direct": 20001,
            "pooler_session": 20002,
            "pooler_transaction": 20003,
        },
        "domain": None,
        "public_url": "http://127.0.0.1:20000",
        "upstream": {"ref": "self-hosted/v0.8.2", "sha": "0" * 40},
        "creation_complete": True,
    }
    (root / "projects" / "myapp").mkdir(parents=True)
    reg.write_project(root, meta)
    sh = FleetShell(home=str(root))
    sh._use("missing")
    assert sh.active is None
    sh._use("myapp")
    assert sh.active == "myapp"


def test_slash_help_and_commands_alias(capsys: pytest.CaptureFixture[str]) -> None:
    sh = FleetShell()
    sh._run_slash("help")
    out = capsys.readouterr().out
    assert "/projects" in out
    assert "palette" in out.lower() or "Slash command" in out
    sh._run_slash("commands")
    out2 = capsys.readouterr().out
    assert "/status" in out2
    assert "/backup" in out2


def test_slash_alone_shows_palette(capsys: pytest.CaptureFixture[str]) -> None:
    sh = FleetShell()
    sh._run_slash("")
    assert "/studio" in capsys.readouterr().out


def test_help_topic(capsys: pytest.CaptureFixture[str]) -> None:
    sh = FleetShell()
    sh._run_slash("help status")
    out = capsys.readouterr().out
    assert "/status" in out
    assert "health" in out.lower()


def test_topic_help_unknown() -> None:
    assert "Unknown" in topic_help("nope")


def test_prefix_filter_commands() -> None:
    names = [c.name for c in filter_commands("/st")]
    assert "start" in names
    assert "status" in names
    assert "stop" in names
    assert "studio" in names
    assert "backup" not in names


def test_filter_names() -> None:
    assert filter_names(["myapp", "project-b", "demo"], "my") == [
        "myapp",
    ]


def test_slash_command_completion() -> None:
    sh = FleetShell()
    texts = _completions(sh, "/st")
    assert "/start" in texts
    assert "/status" in texts
    assert "/stop" in texts
    assert "/studio" in texts


def test_slash_command_completion_descriptions() -> None:
    sh = FleetShell()
    comp = SlashCompleter(sh)
    metas = {c.text: c.display_meta for c in comp.get_completions(_Doc("/stu"), None)}
    assert "/studio" in metas
    assert metas["/studio"] and "Studio" in str(metas["/studio"])


def test_project_completion(tmp_path: Path) -> None:
    from sbfleet import registry as reg

    root = reg.ensure_root(tmp_path)
    fid = reg.fleet_id(root)
    for slug, pid in (
        ("myapp", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        ("project-b", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
    ):
        meta: dict[str, Any] = {
            "format_version": 1,
            "id": pid,
            "fleet_id": fid,
            "slug": slug,
            "display_name": slug,
            "created_at": "2026-01-01T00:00:00Z",
            "profile": "standard",
            "compose_project": f"sbfleet-{fid.replace('-', '')[:12]}-{pid.replace('-', '')[:12]}",
            "ports": {
                "gateway": 20000,
                "db_direct": 20001,
                "pooler_session": 20002,
                "pooler_transaction": 20003,
            },
            "domain": None,
            "public_url": "http://127.0.0.1:20000",
            "upstream": {"ref": "self-hosted/v0.8.2", "sha": "0" * 40},
            "creation_complete": True,
        }
        (root / "projects" / slug).mkdir(parents=True)
        reg.write_project(root, meta)

    sh = FleetShell(home=str(root))
    assert "myapp" in _completions(sh, "/use my")
    assert "project-b" in _completions(sh, "/start pro")


def test_service_completion_with_active() -> None:
    sh = FleetShell()
    sh.active = "myapp"
    texts = _completions(sh, "/logs au")
    assert "auth" in texts


def test_active_project_argv_injection() -> None:
    sh = FleetShell()
    sh.active = "myapp"
    assert sh._build_argv("status", []) == ["status", "myapp"]
    assert sh._build_argv("start", []) == ["start", "myapp"]
    assert sh._build_argv("logs", ["auth"]) == ["logs", "myapp", "auth"]
    assert sh._build_argv("configure", []) == ["configure", "myapp"]
    assert sh._build_argv("configure", ["--organization-name", "Acme"]) == [
        "configure",
        "myapp",
        "--organization-name",
        "Acme",
    ]


def test_configure_in_palette_and_completion() -> None:
    from sbfleet.shell import _PROJECT_SCOPED, SLASH_COMMANDS, topic_help

    assert "configure" in _PROJECT_SCOPED
    assert any(c.name == "configure" for c in SLASH_COMMANDS)
    palette = format_command_palette(active="myapp")
    assert "/configure" in palette
    assert "presentation" in palette.lower()
    help_txt = topic_help("configure")
    assert "--organization-name" in help_txt or "organization" in help_txt.lower()
    sh = FleetShell()
    texts = _completions(sh, "/conf")
    assert "/configure" in texts


def test_explicit_project_overrides_active() -> None:
    sh = FleetShell()
    sh.active = "myapp"
    # Without registry, unknown slug still treated as explicit first token
    # when it matches a known project — seed empty → token is injected as active.
    # With empty project list, first token is treated as remaining arg + inject.
    # Simulate known project via monkeypatch.
    sh._project_slugs = lambda: ["myapp", "project-b"]  # type: ignore[method-assign]
    assert sh._build_argv("status", ["project-b"]) == ["status", "project-b"]
    assert sh._build_argv("logs", ["project-b", "auth"]) == [
        "logs",
        "project-b",
        "auth",
    ]


def test_no_active_project_friendly_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    sh = FleetShell()
    assert sh._build_argv("status", []) is None
    out = capsys.readouterr().out
    assert "No active project" in out
    assert "/use" in out
    assert "/projects" in out


def test_palette_includes_descriptions() -> None:
    text = format_command_palette(active="myapp")
    assert "Show project health" in text
    assert "myapp" in text
    assert set(slash_command_names()) <= {c.name for c in filter_commands("")}


def test_direct_cli_status_unchanged() -> None:
    """Direct CLI still requires an explicit project (no active-project concept)."""
    from sbfleet.cli import build_parser

    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["status"])
    args = parser.parse_args(["status", "myapp"])
    assert args.command == "status"
    assert args.project == "myapp"


def test_direct_slash_configure_parity() -> None:
    from sbfleet.cli import build_parser
    from sbfleet.shell import FleetShell

    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["configure"])
    args = parser.parse_args(
        [
            "configure",
            "myapp",
            "--name",
            "App",
            "--organization-name",
            "Acme",
            "--studio-project",
            "Orders",
        ]
    )
    assert args.command == "configure"
    assert args.project == "myapp"
    assert args.name == "App"
    assert args.organization_name == "Acme"
    assert args.studio_project == "Orders"
    sh = FleetShell()
    sh.active = "myapp"
    assert sh._build_argv("configure", ["--name", "App"]) == [
        "configure",
        "myapp",
        "--name",
        "App",
    ]


def test_direct_cli_logs_unchanged() -> None:
    from sbfleet.cli import build_parser

    args = parser = build_parser()
    args = parser.parse_args(["logs", "myapp", "auth"])
    assert args.project == "myapp"
    assert args.service == "auth"
