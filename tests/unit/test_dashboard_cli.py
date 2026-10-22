"""Public dashboard surfaces share the existing read-only observer handler."""

import builtins
from unittest.mock import Mock

import pytest
from prompt_toolkit.document import Document

from sbfleet import dashboard, registry
from sbfleet.cli import EXIT_PREREQUISITE, build_parser, main
from sbfleet.shell import FleetShell, SlashCompleter, slash_command_names


def test_dashboard_parser_and_help(capsys):
    args = build_parser().parse_args(["dashboard", "--refresh", "5", "--once"])
    assert (args.command, args.refresh, args.once) == ("dashboard", 5, True)
    assert main(["--help"]) == 0
    assert "dashboard" in capsys.readouterr().out


def test_shell_registry_help_and_completion(capsys):
    shell = FleetShell()
    assert "dashboard" in slash_command_names()
    shell.default("/help")
    assert "/dashboard" in capsys.readouterr().out
    completions = list(SlashCompleter(shell).get_completions(Document("/dash"), None))
    assert [c.text for c in completions] == ["/dashboard"]
    shell.default("/help dashboard")
    assert "--refresh" in capsys.readouterr().out


def test_both_surfaces_share_handler_without_project_injection(tmp_path, monkeypatch):
    handler = Mock(return_value=0)
    monkeypatch.setattr(dashboard, "run_dashboard", handler)
    shell = FleetShell(home=str(tmp_path))
    shell.active = "selected-project"
    assert main(["--home", str(tmp_path), "dashboard", "--refresh", "5"]) == 0
    shell.default("/dashboard --refresh 5")
    assert handler.call_count == 2
    assert handler.call_args_list[0] == handler.call_args_list[1]
    handler.assert_called_with(tmp_path, refresh=5, once=False)
    assert shell.active == "selected-project"


def test_shell_dashboard_never_initializes_or_dispatches_mutations(tmp_path, monkeypatch):
    from sbfleet import projects

    def forbidden(*args, **kwargs):
        pytest.fail("dashboard attempted mutation")

    for name in ("ensure_root", "atomic_write_json", "project_lock", "registry_lock"):
        monkeypatch.setattr(registry, name, forbidden)
    for name in ("create_project", "start_project", "stop_project", "restart_project"):
        monkeypatch.setattr(projects, name, forbidden)
    shell = FleetShell(home=str(tmp_path / "missing"))
    shell.active = "selected-project"
    monkeypatch.setattr(shell, "_remember_lifecycle", forbidden)
    shell.default("/dashboard --once")
    assert not (tmp_path / "missing").exists()


@pytest.mark.parametrize("refresh", ["-1", "1", "3601"])
def test_invalid_refresh_is_nonzero(refresh, capsys):
    assert main(["dashboard", "--refresh", refresh]) == 2
    assert "--refresh" in capsys.readouterr().err


def test_unavailable_dashboard_has_nonzero_diagnostic(monkeypatch, capsys):
    original = builtins.__import__

    def unavailable(name, *args, **kwargs):
        if name == "sbfleet.dashboard":
            raise ImportError("private dependency details")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", unavailable)
    assert main(["dashboard"]) == EXIT_PREREQUISITE
    assert capsys.readouterr().err == "error: dashboard dependencies unavailable\n"


def test_existing_project_and_fleet_status_grammar():
    parser = build_parser()
    assert parser.parse_args(["status", "project", "--json"]).project == "project"
    args = parser.parse_args(["status", "--all", "--json"])
    assert args.all and args.json and args.project is None
    assert parser.parse_args(["start", "project"]).project == "project"
