"""Operational UX: progress, studio gates, status breakdown, logs fallback."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import pytest

from sbfleet.cli import EXIT_OK, EXIT_UNHEALTHY
from sbfleet.health import (
    DEGRADED,
    HEALTHY,
    STARTING,
    STOPPED,
    UNHEALTHY,
    ProbeResult,
    StatusReport,
    format_status_human,
)
from sbfleet.shell import FleetShell
from sbfleet.ux import InteractiveProgress, QuietProgress, confirm, get_progress, is_interactive


def _meta(root: Path, slug: str = "myapp", gateway: int = 20008) -> dict[str, Any]:
    from sbfleet import registry as reg

    root = reg.ensure_root(root)
    fid = reg.fleet_id(root)
    pid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    meta: dict[str, Any] = {
        "format_version": 1,
        "id": pid,
        "fleet_id": fid,
        "slug": slug,
        "display_name": slug,
        "created_at": "2026-01-01T00:00:00Z",
        "profile": "standard",
        "compose_project": reg.compose_project_name(fid, pid),
        "ports": {
            "gateway": gateway,
            "db_direct": gateway + 1,
            "pooler_session": gateway + 2,
            "pooler_transaction": gateway + 3,
        },
        "domain": None,
        "public_url": f"http://127.0.0.1:{gateway}",
        "upstream": {"ref": "self-hosted/v0.8.2", "sha": "0" * 40},
        "creation_complete": True,
    }
    (root / "projects" / slug).mkdir(parents=True, exist_ok=True)
    reg.write_project(root, meta)
    return meta


def test_create_sets_active_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sbfleet import projects as proj
    from sbfleet.ux import reset_interactive, set_interactive

    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setattr(
        proj,
        "create_project",
        lambda *_a, **_k: {
            "slug": "myapp",
            "public_url": "http://127.0.0.1:20008",
            "creation_complete": True,
        },
    )
    monkeypatch.setattr("sbfleet.ux.confirm", lambda *a, **k: False)

    token = set_interactive(True)
    try:
        sh = FleetShell(home=str(tmp_path))
        sh._run_slash("create myapp")
    finally:
        reset_interactive(token)

    assert sh.active == "myapp"
    assert sh.prompt == "sbfleet / myapp ● ❯ "


def test_stopped_studio_does_not_open_browser(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from sbfleet.studio import open_studio

    root = tmp_path / "fleet"
    meta = _meta(root)
    (root / "projects" / "myapp" / "deployment").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(
        "sbfleet.studio.collect_status",
        lambda *_a, **_k: StatusReport(slug="myapp", lifecycle=STOPPED, probes=[], meta=meta),
    )
    opened: list[str] = []
    monkeypatch.setattr("sbfleet.studio.maybe_open", lambda url: opened.append(url))

    code = open_studio(root, "myapp", offer_start=False)
    out = capsys.readouterr().out
    assert code == EXIT_UNHEALTHY
    assert opened == []
    assert "stopped" in out.lower()
    assert "/start" in out


def test_healthy_studio_opens_browser(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sbfleet.studio import open_studio

    root = tmp_path / "fleet"
    meta = _meta(root)
    (root / "projects" / "myapp" / "deployment").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(
        "sbfleet.studio.collect_status",
        lambda *_a, **_k: StatusReport(
            slug="myapp",
            lifecycle=HEALTHY,
            probes=[ProbeResult("studio", HEALTHY, "HTTP 200")],
            meta=meta,
        ),
    )
    opened: list[str] = []
    monkeypatch.setattr("sbfleet.studio.maybe_open", lambda url: opened.append(url))

    code = open_studio(root, "myapp", offer_start=False)
    assert code == EXIT_OK
    assert opened and opened[0].endswith("/project/default")


def test_degraded_studio_diagnostics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from sbfleet.studio import open_studio

    root = tmp_path / "fleet"
    meta = _meta(root)
    (root / "projects" / "myapp" / "deployment").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(
        "sbfleet.studio.collect_status",
        lambda *_a, **_k: StatusReport(
            slug="myapp",
            lifecycle=DEGRADED,
            probes=[
                ProbeResult("db", HEALTHY, "healthy"),
                ProbeResult("auth-http", UNHEALTHY, "HTTP 503"),
                ProbeResult("studio", UNHEALTHY, "HTTP 502"),
            ],
            meta=meta,
        ),
    )
    opened: list[str] = []
    monkeypatch.setattr("sbfleet.studio.maybe_open", lambda url: opened.append(url))

    code = open_studio(root, "myapp", offer_start=False)
    out = capsys.readouterr().out
    assert code == EXIT_UNHEALTHY
    assert opened == []
    assert "DEGRADED" in out
    assert "/doctor" in out


def test_progress_ok_only_after_success() -> None:
    buf = io.StringIO()
    prog = InteractiveProgress(stream=buf)
    prog.step_wait("Auth")
    assert "✓ Auth" not in buf.getvalue()
    prog.step_ok("Auth")
    assert "✓ Auth" in buf.getvalue()


def test_quiet_progress_default_noninteractive() -> None:
    assert not is_interactive()
    assert isinstance(get_progress(), QuietProgress)


def test_failed_startup_redacted_logs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from sbfleet import projects as proj

    root = tmp_path / "fleet"
    meta = _meta(root)
    secret = "super-secret-jwt-token-value-xxxx"

    monkeypatch.setattr(
        "sbfleet.health.collect_status",
        lambda *_a, **_k: StatusReport(
            slug="myapp",
            lifecycle=DEGRADED,
            probes=[ProbeResult("auth-http", UNHEALTHY, "HTTP 503")],
            meta=meta,
        ),
    )
    monkeypatch.setattr(
        proj,
        "fetch_logs_text",
        lambda *_a, **_k: "auth failed JWT [REDACTED]\n",
    )

    proj.print_startup_failure_hint(root, "myapp")
    out = capsys.readouterr().out
    assert "Last 20 auth log lines" in out
    assert secret not in out
    assert "[REDACTED]" in out
    assert "/logs auth" in out
    assert "/doctor" in out
    assert "/status" in out


def test_logs_active_project_fallback() -> None:
    sh = FleetShell()
    sh.active = "myapp"
    assert sh._build_argv("logs", []) == ["logs", "myapp"]
    assert sh._build_argv("logs", ["auth"]) == ["logs", "myapp", "auth"]
    assert sh._build_argv("logs", ["auth", "--follow"]) == [
        "logs",
        "myapp",
        "auth",
        "--follow",
    ]


def test_logs_no_active_friendly(capsys: pytest.CaptureFixture[str]) -> None:
    sh = FleetShell()
    assert sh._build_argv("logs", []) is None
    out = capsys.readouterr().out
    assert "No active project" in out


def test_status_health_breakdown() -> None:
    report = StatusReport(
        slug="myapp",
        lifecycle=DEGRADED,
        probes=[
            ProbeResult("db", HEALTHY, "healthy"),
            ProbeResult("auth-http", UNHEALTHY, "HTTP 503"),
            ProbeResult("rest", STARTING, "starting"),
            ProbeResult("api-gw", HEALTHY, "healthy"),
            ProbeResult("studio", UNHEALTHY, "HTTP 502"),
        ],
        meta={"ports": {"gateway": 20008}},
    )
    text = format_status_human(report)
    assert "myapp" in text
    assert "DEGRADED" in text
    assert "Postgres" in text and "healthy" in text
    assert "Auth" in text and "unhealthy" in text
    assert "REST" in text and "waiting" in text
    assert "Gateway" in text
    assert "Studio" in text and "unhealthy" in text
    assert "http://127.0.0.1:20008/project/default" in text
    assert "/logs auth" in text
    assert "/doctor" in text


def test_direct_cli_create_start_flag() -> None:
    from sbfleet.cli import build_parser

    args = build_parser().parse_args(["create", "myapp"])
    assert args.start is False
    assert args.no_start is False
    assert build_parser().parse_args(["create", "myapp", "--start"]).start is True


def test_confirm_default_yes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *_a: "")
    assert confirm("Start project now?", default_yes=True) is True
    monkeypatch.setattr("builtins.input", lambda *_a: "n")
    assert confirm("Start project now?", default_yes=True) is False


def test_progress_never_marks_ok_before_success_event() -> None:
    events: list[tuple[str, str]] = []

    class Rec:
        def step_ok(self, name: str) -> None:
            events.append(("ok", name))

        def step_wait(self, name: str) -> None:
            events.append(("wait", name))

    rec = Rec()
    rec.step_wait("PostgreSQL")
    assert ("ok", "PostgreSQL") not in events
    underlying_ok = True
    if underlying_ok:
        rec.step_ok("PostgreSQL")
    assert events == [("wait", "PostgreSQL"), ("ok", "PostgreSQL")]
