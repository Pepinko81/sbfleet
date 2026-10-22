"""Interactive controls and bounded, truthful dashboard presentation."""

import asyncio
from unittest.mock import Mock

import pytest
from prompt_toolkit.input.defaults import create_pipe_input
from prompt_toolkit.output import DummyOutput
from prompt_toolkit.utils import get_cwidth

from sbfleet import dashboard
from sbfleet.fleet import BackupObservation, Check, FleetSnapshot, ProjectObservation, Totals


@pytest.fixture
def snapshot():
    return FleetSnapshot(
        observed_at="2026-10-22T12:13:47Z",
        totals=Totals(projects=2, healthy=1, stopped=1, needing_attention=1),
        projects=[
            ProjectObservation(
                slug="alpha",
                display_name="Alpha development",
                state="HEALTHY",
                runtime_state="RUNNING",
                health_state="HEALTHY",
                ports={
                    "gateway": 20004,
                    "db_direct": 20009,
                    "pooler_session": 20010,
                    "pooler_transaction": 20011,
                },
                studio_url="http://127.0.0.1:20004/project/default",
                services=[Check(name="api-gw", state="HEALTHY"), Check(name="db")],
                backup=BackupObservation(status="NONE"),
                operation_unresolved=False,
                attention=["backup"],
            ),
            ProjectObservation(slug="beta", state="STOPPED"),
        ],
    )


@pytest.mark.parametrize("width,height", [(140, 45), (80, 24), (48, 18), (20, 6)])
def test_layout_bounds_and_core_status(snapshot, width, height):
    text = dashboard.render(snapshot, width=width, height=height)
    assert all(get_cwidth(line) <= width for line in text.splitlines())
    assert "READ-ONLY" in text
    assert "alpha" in text
    if height < 10:
        assert "HEALTHY" in text.splitlines()[1]
    if width >= 36:
        assert "API" in text and "DB" in text
        assert "Pooler session" in text and "Pooler transaction" in text
        assert "db UNKNOWN" in text
        assert "NO VERIFIED BACKUP" in text
        assert "20004/20009" not in text


def test_attention_unknown_is_not_unresolved(snapshot):
    project = snapshot.projects[1]
    project.attention = ["backup", "operation", "runtime"]
    assert dashboard.attention_reasons(project) == [
        "HEALTH UNKNOWN",
        "BACKUP UNKNOWN",
        "OPERATION UNKNOWN",
    ]
    project.operation_unresolved = True
    assert "UNRESOLVED OPERATION" in dashboard.attention_reasons(project)


def test_unicode_and_control_characters(snapshot):
    snapshot.projects[0].display_name = "界" * 120 + "\x1b[31m\nINJECTED"
    text = dashboard.render(snapshot, width=48)
    assert "\x1b" not in text
    assert all(get_cwidth(line) <= 48 for line in text.splitlines())


@pytest.mark.parametrize("exit_key", ["q", "Q", "\x03", "\x1b"])
def test_keys_views_refresh_and_exit(snapshot, tmp_path, monkeypatch, exit_key):
    collect = Mock(return_value=snapshot)
    monkeypatch.setattr(dashboard, "collect_snapshot", collect)

    async def exercise():
        with create_pipe_input() as pipe:
            app = dashboard.make_application(tmp_path, input=pipe, output=DummyOutput())
            app.ttimeoutlen = 0.01
            app.timeoutlen = 0.01
            task = asyncio.create_task(app.run_async())

            def screen():
                control = app.layout.container.children[0].content
                return "".join(fragment[1] for fragment in control.text())

            async def key(value):
                pipe.send_text(value)
                await asyncio.sleep(0.06)

            try:
                await asyncio.sleep(0.1)
                assert "Selected: Alpha development" in screen()
                await key("\x1b[B")
                assert "Selected: beta" in screen()
                await key("\x1b[A\r")
                assert "PROJECT DETAILS" in screen()
                assert "Verified UNKNOWN" in screen()
                await key("\x1b")
                assert not task.done()
                assert "SELECTED PROJECT" in screen()
                await key("?")
                assert "HELP · READ-ONLY" in screen()
                assert "no lifecycle actions" in screen()
                await key("\x1b")
                assert not task.done()
                await key("R")
                assert collect.call_count == 2
                await key(exit_key)
                await asyncio.wait_for(task, 2)
            finally:
                if not task.done():
                    app.exit()
                    await task

    asyncio.run(exercise())
