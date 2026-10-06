"""Interactive UX context and progress reporting (lifecycle feedback only)."""

from __future__ import annotations

import sys
import threading
from contextvars import ContextVar
from typing import TextIO

_interactive: ContextVar[bool] = ContextVar("sbfleet_interactive", default=False)


def set_interactive(value: bool) -> object:
    """Set interactive UX mode; returns a token for reset()."""
    return _interactive.set(value)


def reset_interactive(token: object) -> None:
    _interactive.reset(token)  # type: ignore[arg-type]


def is_interactive() -> bool:
    return bool(_interactive.get())


def confirm(prompt: str, *, default_yes: bool = True, stream: TextIO | None = None) -> bool:
    """Ask a Y/n question. Non-TTY / EOF uses the default."""
    out = stream or sys.stderr
    suffix = "[Y/n]" if default_yes else "[y/N]"
    if not sys.stdin.isatty():
        return default_yes
    try:
        ans = input(f"{prompt} {suffix} ").strip().lower()
    except EOFError:
        print(file=out)
        return default_yes
    if not ans:
        return default_yes
    return ans in {"y", "yes"}


class Progress:
    """Progress reporter. Quiet by default for scriptable CLI."""

    def heading(self, text: str) -> None:
        return

    def step_ok(self, name: str) -> None:
        return

    def step_fail(self, name: str, detail: str = "") -> None:
        return

    def step_wait(self, name: str) -> None:
        return

    def note(self, text: str) -> None:
        return

    def clear_wait(self) -> None:
        return


class QuietProgress(Progress):
    """No decorative output (direct CLI)."""


class InteractiveProgress(Progress):
    """Concise live progress for the interactive shell."""

    def __init__(self, stream: TextIO | None = None) -> None:
        self._out = stream or sys.stderr
        self._lock = threading.Lock()
        self._waiting: str | None = None
        self._spin_i = 0
        self._frames = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
        self._stop_spin = threading.Event()
        self._spin_thread: threading.Thread | None = None

    def heading(self, text: str) -> None:
        with self._lock:
            self._clear_wait_unlocked()
            print(f"\n{text}", file=self._out, flush=True)

    def step_ok(self, name: str) -> None:
        with self._lock:
            self._clear_wait_unlocked()
            print(f"✓ {name}", file=self._out, flush=True)

    def step_fail(self, name: str, detail: str = "") -> None:
        with self._lock:
            self._clear_wait_unlocked()
            extra = f" — {detail}" if detail else ""
            print(f"✗ {name}{extra}", file=self._out, flush=True)

    def step_wait(self, name: str) -> None:
        with self._lock:
            if self._waiting == name:
                return
            self._clear_wait_unlocked()
            self._waiting = name
            self._spin_i = 0
            self._stop_spin.clear()
            self._render_wait_unlocked()
            if self._spin_thread is None or not self._spin_thread.is_alive():
                self._spin_thread = threading.Thread(
                    target=self._spin_loop, name="sbfleet-progress", daemon=True
                )
                self._spin_thread.start()

    def note(self, text: str) -> None:
        with self._lock:
            self._clear_wait_unlocked()
            print(text, file=self._out, flush=True)

    def clear_wait(self) -> None:
        with self._lock:
            self._clear_wait_unlocked()

    def _spin_loop(self) -> None:
        while not self._stop_spin.wait(0.08):
            with self._lock:
                if self._waiting is None:
                    continue
                self._spin_i = (self._spin_i + 1) % len(self._frames)
                self._render_wait_unlocked()

    def _render_wait_unlocked(self) -> None:
        if not self._waiting:
            return
        frame = self._frames[self._spin_i]
        # Carriage-return update on one line
        print(f"\r{frame} {self._waiting}   ", end="", file=self._out, flush=True)

    def _clear_wait_unlocked(self) -> None:
        self._stop_spin.set()
        if self._waiting is not None:
            print("\r" + " " * (len(self._waiting) + 8) + "\r", end="", file=self._out)
            self._waiting = None


def get_progress() -> Progress:
    if is_interactive() and sys.stderr.isatty():
        return InteractiveProgress()
    return QuietProgress()


# Friendly labels for major compose services during start progress.
SERVICE_LABELS: dict[str, str] = {
    "db": "PostgreSQL",
    "auth": "Auth",
    "rest": "REST",
    "api-gw": "Gateway",
    "studio": "Studio",
    "realtime": "Realtime",
    "storage": "Storage",
    "meta": "Meta",
    "functions": "Functions",
    "supavisor": "Pooler",
    "imgproxy": "Imgproxy",
}

# Order shown during start/health progress.
START_WATCH_ORDER: tuple[str, ...] = (
    "db",
    "auth",
    "rest",
    "api-gw",
    "studio",
)


def elapsed_note(seconds: float) -> str:
    return f"Ready in {seconds:.1f}s"
