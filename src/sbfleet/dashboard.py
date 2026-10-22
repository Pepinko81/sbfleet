"""Read-only terminal view of the canonical fleet snapshot."""

from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path

from prompt_toolkit.application import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, Layout, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.styles import Style
from prompt_toolkit.utils import get_cwidth

from sbfleet.fleet import FleetSnapshot, ProjectObservation, collect_snapshot

FOOTER = "↑↓ Select   Enter Details   R Refresh   ? Help   Q Quit"
PORT_LABELS = {
    "gateway": "API",
    "db_direct": "DB",
    "pooler_session": "Pooler session",
    "pooler_transaction": "Pooler transaction",
}


def attention_reasons(project: ProjectObservation) -> list[str]:
    reasons = []
    if "runtime" in project.attention:
        reasons.append(f"HEALTH {project.health_state}")
    if "backup" in project.attention:
        reasons.append(
            "NO VERIFIED BACKUP" if project.backup.status == "NONE" else "BACKUP UNKNOWN"
        )
    if "operation" in project.attention:
        reasons.append(
            "UNRESOLVED OPERATION" if project.operation_unresolved else "OPERATION UNKNOWN"
        )
    return reasons


def _clip(text: str, width: int) -> str:
    """Bound terminal cells, including wide Unicode; discard control characters."""
    result = ""
    for char in text:
        if char.isprintable():
            if get_cwidth(result + char) > width:
                break
            result += char
    return result


def _panel(title: str, rows: list[str], width: int) -> list[str]:
    inner = max(0, width - 4)
    wrapped = []
    for row in rows:
        remaining = "".join(char for char in row if char.isprintable())
        while get_cwidth(remaining) > inner and inner:
            part = _clip(remaining, inner)
            wrapped.append(part)
            remaining = remaining[len(part) :]
        wrapped.append(remaining)
    rows = wrapped
    top = _clip(f"┌─ {title} " + "─" * width, max(0, width - 1)) + "┐"
    return (
        [top]
        + [
            "│ " + _clip(row, inner) + " " * max(0, inner - get_cwidth(_clip(row, inner))) + " │"
            for row in rows
        ]
        + ["└" + "─" * max(0, width - 2) + "┘"]
    )


def _connections(project: ProjectObservation) -> list[str]:
    rows = [
        f"{label:19} :{project.ports[key]}"
        for key, label in PORT_LABELS.items()
        if key in project.ports
    ]
    if project.studio_url:
        rows.append(f"Studio  {project.studio_url}")
    return rows or ["UNKNOWN — no connection observations"]


def _services(project: ProjectObservation, width: int) -> list[str]:
    cells = [f"{'●' if s.state == 'HEALTHY' else '○'} {s.name} {s.state}" for s in project.services]
    cell_width = max((get_cwidth(c) for c in cells), default=25) + 3
    columns = max(1, (width - 4) // cell_width)
    return [
        "".join(c.ljust(cell_width) for c in cells[i : i + columns]).rstrip()
        for i in range(0, len(cells), columns)
    ] or ["Services UNKNOWN"]


def render(
    snapshot: FleetSnapshot,
    selected: int = 0,
    *,
    width: int = 100,
    height: int = 40,
    overlay: str | None = None,
    footer: bool = True,
) -> str:
    width = max(1, width)
    selected = max(0, min(selected, len(snapshot.projects) - 1))
    if width < 36 or height < 10:
        rows = ["SBFLEET · READ-ONLY"]
        if snapshot.projects:
            project = snapshot.projects[selected]
            rows.append(f"{project.state} {project.slug}")
        elif snapshot.errors or not snapshot.observation_complete:
            rows.append("Observation UNKNOWN")
        else:
            rows.append("No managed projects")
        rows.extend(
            [
                f"Projects {snapshot.totals.projects} / "
                f"Attention {snapshot.totals.needing_attention}",
                "Enlarge for panels",
            ]
        )
    elif overlay == "help":
        rows = _panel(
            "HELP · READ-ONLY",
            [
                "↑ / ↓       Select project",
                "Enter       Project details",
                "R / r       Refresh snapshot",
                "PgUp/PgDn   Scroll panels / details",
                "?           Help",
                "Esc         Close view, then exit",
                "Q / q       Quit dashboard",
                "Ctrl+C      Quit dashboard",
                "Returns to the SBfleet shell or calling terminal.",
                "Read-only: no lifecycle actions or automatic update checks.",
            ],
            width,
        )
    else:
        fleet_state = (
            "UNKNOWN"
            if not snapshot.observation_complete or snapshot.errors
            else "ATTENTION"
            if snapshot.totals.needing_attention
            else "HEALTHY"
            if snapshot.totals.projects and snapshot.totals.healthy == snapshot.totals.projects
            else "IDLE"
        )
        rows = _panel(
            "SBFLEET · READ-ONLY",
            [
                f"Fleet {fleet_state}   Projects {snapshot.totals.projects}   "
                f"Attention {snapshot.totals.needing_attention}",
                f"Updated {snapshot.observed_at}",
            ],
            width,
        )
        if snapshot.errors:
            rows.append("UNKNOWN: registry observation failed")
        if overlay != "details":
            count = max(1, min(7, height // 6))
            start = max(0, selected - count + 1)
            projects = []
            for index, p in enumerate(snapshot.projects[start : start + count], start):
                prefix = ">" if index == selected else " "
                slug_width = max(8, min(24, width - 20))
                row = f"{prefix} {_clip(p.slug, slug_width):{slug_width}} {p.state}"
                if width >= 76:
                    row = f"{row:40} {p.upstream_ref or 'UNKNOWN'}"
                projects.append(row)
            if len(snapshot.projects) > count:
                projects.append(
                    f"Showing {start + 1}–{min(start + count, len(snapshot.projects))} "
                    f"of {len(snapshot.projects)}"
                )
            rows += _panel("PROJECTS", projects or ["No managed projects."], width)
        if snapshot.projects:
            p = snapshot.projects[selected]
            details = [
                f"Selected: {p.display_name or p.slug}",
                f"Slug     {p.slug}",
                f"Runtime  {p.runtime_state}   Health {p.health_state}",
                f"Backup   {p.backup.status}",
                "Operation "
                + (
                    "UNRESOLVED"
                    if p.operation_unresolved
                    else "none"
                    if p.operation_unresolved is False
                    else "UNKNOWN"
                ),
                "Update   UNKNOWN (not checked)",
            ]
            if overlay == "details":
                details += [
                    f"Upstream {p.upstream_ref or 'UNKNOWN'}",
                    f"Commit   {p.upstream_sha or 'UNKNOWN'}",
                    f"Verified {p.backup.verified_at or 'UNKNOWN'}",
                ]
            if width >= 100:
                left_width = width // 2
                left = _panel(
                    "PROJECT DETAILS" if overlay else "SELECTED PROJECT", details, left_width
                )
                right = _panel("CONNECTIONS", _connections(p), width - left_width - 1)
                rows += [
                    f"{left[i] if i < len(left) else ' ' * left_width} "
                    f"{right[i] if i < len(right) else ''}"
                    for i in range(max(len(left), len(right)))
                ]
            else:
                rows += _panel("PROJECT DETAILS" if overlay else "SELECTED PROJECT", details, width)
                rows += _panel("CONNECTIONS", _connections(p), width)
            rows += _panel("SERVICES", _services(p, width), width)
            rows += _panel("ATTENTION", attention_reasons(p) or ["None recorded"], width)
    if footer:
        rows += [FOOTER, "PgUp/PgDn Scroll · Esc Back"]
    return "\n".join(_clip(row, width) for row in rows)


def _styled(text: str):
    fragments = []
    styles = {
        "HEALTHY": "good",
        "RUNNING": "good",
        "STOPPED": "muted",
        "UNKNOWN": "warning",
        "ATTENTION": "warning",
        "DEGRADED": "warning",
        "FAILED": "bad",
        "UNHEALTHY": "bad",
        "UNRESOLVED": "bad",
    }
    for line in text.splitlines():
        base = "class:selected" if line.startswith("│ >") else ""
        for part in re.split(r"(\b(?:" + "|".join(styles) + r")\b|[┌┐└┘│─])", line):
            style = (
                f"class:{styles[part]}"
                if part in styles
                else ("class:border" if part in "┌┐└┘│─" and part else base)
            )
            fragments.append((style, part))
        fragments.append(("", "\n"))
    return fragments


def make_application(root: Path, *, refresh: int = 0, input=None, output=None) -> Application:
    if refresh != 0 and not 5 <= refresh <= 3600:
        raise ValueError("refresh must be 0 or 5..3600 seconds")
    snapshot = FleetSnapshot(observed_at="pending", observation_complete=False)
    selected = 0
    overlay = None
    scroll = 0
    busy = False
    keys = KeyBindings()

    def content():
        nonlocal scroll
        size = app.output.get_size()
        text = render(
            snapshot, selected, width=size.columns, height=size.rows, overlay=overlay, footer=False
        )
        scroll = min(scroll, max(0, len(text.splitlines()) - size.rows + 2))
        return _styled(text)

    async def update() -> None:
        nonlocal snapshot, selected, busy
        if busy:
            return
        busy = True
        try:
            snapshot = await asyncio.to_thread(collect_snapshot, root)
            selected = min(selected, max(0, len(snapshot.projects) - 1))
            app.invalidate()
        finally:
            busy = False

    @keys.add("q")
    @keys.add("Q")
    @keys.add("c-c")
    def quit_(event):
        event.app.exit()

    @keys.add("escape")
    def back(event):
        nonlocal overlay, scroll
        if overlay:
            overlay, scroll = None, 0
        else:
            event.app.exit()

    @keys.add("?")
    @keys.add("enter")
    def show(event):
        nonlocal overlay, scroll
        overlay = "help" if event.key_sequence[0].key == "?" else "details"
        scroll = 0

    @keys.add("r")
    @keys.add("R")
    def refresh_(event):
        event.app.create_background_task(update())

    @keys.add("up")
    @keys.add("down")
    def navigate(event):
        nonlocal selected, scroll
        if overlay:
            return
        delta = -1 if event.key_sequence[0].key == "up" else 1
        selected = max(0, min(selected + delta, len(snapshot.projects) - 1))
        scroll = 0

    @keys.add("pageup")
    @keys.add("pagedown")
    def scroll_(event):
        nonlocal scroll
        size = app.output.get_size()
        total = len(
            render(
                snapshot,
                selected,
                width=size.columns,
                height=size.rows,
                overlay=overlay,
                footer=False,
            ).splitlines()
        )
        step = max(1, size.rows - 4)
        delta = -step if event.key_sequence[0].key == "pageup" else step
        scroll = max(0, min(scroll + delta, max(0, total - size.rows + 2)))

    async def initial() -> None:
        await update()
        while refresh:
            await asyncio.sleep(refresh)
            await update()

    def visible_content():
        # Slice lines so scrolling never depends on a text editor cursor.
        lines = content()
        start = 0
        for _ in range(scroll):
            while start < len(lines) and lines[start][1] != "\n":
                start += 1
            start += 1
        return lines[start:]

    def footer_content():
        width = app.output.get_size().columns
        text = (
            FOOTER + "\nPgUp/PgDn Scroll · Esc Back"
            if width >= len(FOOTER)
            else "↑↓ Select Enter Details R Refresh Pg Scroll\n? Help Q Quit ^C Quit Esc Back"
        )
        return [("class:footer", text)]

    app = Application(
        layout=Layout(
            HSplit(
                [
                    Window(FormattedTextControl(visible_content), wrap_lines=False),
                    Window(FormattedTextControl(footer_content), height=2, wrap_lines=False),
                ]
            )
        ),
        key_bindings=keys,
        full_screen=True,
        style=Style.from_dict(
            {
                "border": "ansibrightblack",
                "good": "ansigreen",
                "muted": "ansibrightblack",
                "warning": "ansiyellow",
                "bad": "ansired",
                "selected": "reverse",
                "footer": "bold",
            }
        ),
        input=input,
        output=output,
    )
    app.pre_run_callables.append(lambda: app.create_background_task(initial()))
    return app


def run_dashboard(root: Path, *, refresh: int = 0, once: bool = False) -> int:
    if refresh != 0 and not 5 <= refresh <= 3600:
        print("error: --refresh must be 0 or 5..3600 seconds", file=sys.stderr)
        return 2
    if once or not sys.stdin.isatty() or not sys.stdout.isatty():
        print(render(collect_snapshot(root)))
        return 0
    make_application(root, refresh=refresh).run()
    return 0
