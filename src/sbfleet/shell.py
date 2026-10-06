"""Interactive slash shell with prompt_toolkit completion."""

from __future__ import annotations

import argparse
import shlex
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from sbfleet.cli import EXIT_OK, EXIT_UNHEALTHY, EXIT_USAGE, build_parser, dispatch_namespace
from sbfleet.compose import STANDARD_SERVICES

# Project-scoped fleet commands: active project fills missing P.
_PROJECT_SCOPED = frozenset(
    {
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
        "nginx",
    }
)

# Host-level / meta commands never receive an injected project slug.
_NO_INJECT = frozenset({"projects", "create", "sandbox", "use", "help", "commands", "exit"})


@dataclass(frozen=True)
class SlashCommand:
    name: str
    description: str
    takes_project: bool = False
    takes_service: bool = False


SLASH_COMMANDS: tuple[SlashCommand, ...] = (
    SlashCommand("projects", "List fleet projects"),
    SlashCommand("create", "Create a project"),
    SlashCommand("use", "Select project (/use --clear returns to fleet root)", takes_project=True),
    SlashCommand("start", "Start project stack", takes_project=True),
    SlashCommand("stop", "Stop project stack", takes_project=True),
    SlashCommand("restart", "Restart project stack", takes_project=True),
    SlashCommand("status", "Show project health", takes_project=True),
    SlashCommand("studio", "Open Supabase Studio", takes_project=True),
    SlashCommand("logs", "Show service logs", takes_project=True, takes_service=True),
    SlashCommand("doctor", "Run diagnostics", takes_project=True),
    SlashCommand("configure", "Show or change presentation settings", takes_project=True),
    SlashCommand("connection", "Nonsecret connection info", takes_project=True),
    SlashCommand("env", "Run command with project env", takes_project=True),
    SlashCommand("secrets", "List or reveal secrets", takes_project=True),
    SlashCommand("backup", "Create encrypted backup", takes_project=True),
    SlashCommand("restore", "Restore encrypted backup", takes_project=True),
    SlashCommand("remove", "Remove project", takes_project=True),
    SlashCommand("update", "Staged official update", takes_project=True),
    SlashCommand("sandbox", "Local CLI sandbox"),
    SlashCommand("nginx", "Generate/validate nginx", takes_project=True),
    SlashCommand("help", "Show command help"),
    SlashCommand("commands", "Show command palette"),
    SlashCommand("exit", "Exit the shell"),
)

_BY_NAME = {c.name: c for c in SLASH_COMMANDS}


def slash_command_names() -> list[str]:
    return [c.name for c in SLASH_COMMANDS]


def filter_commands(prefix: str) -> list[SlashCommand]:
    """Prefix-filter slash commands (prefix may include leading '/')."""
    p = prefix[1:] if prefix.startswith("/") else prefix
    p = p.lower()
    return [c for c in SLASH_COMMANDS if c.name.startswith(p)]


def filter_names(candidates: Iterable[str], prefix: str) -> list[str]:
    p = prefix.lower()
    return [c for c in candidates if c.lower().startswith(p)]


def topic_help(topic: str) -> str:
    """Parser-backed help for slash topics (same argparse source as direct CLI)."""
    if topic == "use":
        return "\n".join(
            [
                "/use — Select session active project",
                "  /use <project>   select project",
                "  /use             show active project",
                "  /use --clear     return to fleet root",
                "Active selection is shell-only; direct CLI always needs an explicit project.",
            ]
        )
    spec = _BY_NAME.get(topic)
    if spec is None:
        return f"Unknown command '{topic}'. Type /commands for the palette."
    parser = build_parser()
    # Locate subparser actions
    lines = [f"/{spec.name} — {spec.description}"]
    for action in parser._actions:  # noqa: SLF001
        if not hasattr(action, "choices") or not isinstance(getattr(action, "choices", None), dict):
            continue
        choices = action.choices
        if topic not in choices:
            continue
        sub = choices[topic]
        # Option help from argparse
        opts = []
        for a in sub._actions:  # noqa: SLF001
            if not a.option_strings and not a.dest:
                continue
            if a.help in {argparse.SUPPRESS, None} and not a.option_strings:
                # positional
                if a.dest and a.dest not in {"help"}:
                    opts.append(f"  <{a.dest}>")
                continue
            if a.option_strings:
                flags = ", ".join(a.option_strings)
                help_txt = a.help or ""
                opts.append(f"  {flags}  {help_txt}")
        if opts:
            lines.append("Options:")
            lines.extend(opts)
        break
    if spec.takes_project:
        lines.append("(project optional when one is active via /use)")
    if spec.takes_service:
        lines.append("(optional service for /logs)")
    return "\n".join(lines)


def format_command_palette(*, active: str | None = None) -> str:
    lines = ["Slash command palette:"]
    width = max(len(c.name) for c in SLASH_COMMANDS)
    for c in SLASH_COMMANDS:
        if c.name == "use":
            lines.append(f"  {'/use <project>':<{width + 6}}  select project")
            lines.append(f"  {'/use --clear':<{width + 6}}  return to fleet root")
            continue
        lines.append(f"  /{c.name:<{width}}  {c.description}")
    lines.append("")
    lines.append(f"Active project: {active or '(none)'}")
    if active:
        lines.append("Use /use --clear to return to fleet root.")
    lines.append("Tip: type / then Tab, or start typing a command for live suggestions.")
    return "\n".join(lines)


class FleetShell:
    """Slash-command session state and dispatch (interactive or test-driven)."""

    def __init__(self, *, home: str | None = None) -> None:
        self.home = home
        self.active: str | None = None
        # Lifecycle from last authoritative status-path command in this session.
        # Never polled merely to decorate the prompt.
        self.lifecycle_cache: dict[str, str] = {}

    @property
    def intro(self) -> str:
        """Startup identity for TTY shells; empty when stdout is not a TTY."""
        from sbfleet.presentation import banner_for_shell

        text = banner_for_shell(home=self.home)
        return text if text is not None else ""

    @property
    def prompt(self) -> str:
        from sbfleet.presentation import format_prompt_text

        life = self.lifecycle_cache.get(self.active) if self.active else None
        return format_prompt_text(self.active, life)

    def prompt_message(self):
        """prompt_toolkit message (FormattedText when colors enabled)."""
        from sbfleet.presentation import format_prompt_message

        life = self.lifecycle_cache.get(self.active) if self.active else None
        return format_prompt_message(self.active, life)

    def _remember_lifecycle(self, slug: str | None) -> None:
        """Refresh session cache after a command that already probed health."""
        if not slug:
            return
        try:
            from sbfleet import registry as reg
            from sbfleet.health import collect_status

            root = reg.resolve_home(self.home)
            report = collect_status(root, slug)
            self.lifecycle_cache[slug] = report.lifecycle
        except Exception:  # noqa: BLE001 — presentation must never break the shell
            self.lifecycle_cache.pop(slug, None)

    def _project_slugs(self) -> list[str]:
        try:
            from sbfleet import registry as reg

            root = reg.resolve_home(self.home)
            if not root.is_dir():
                return []
            return [
                str(rec.data.get("slug") or rec.path.name)
                for rec in reg.list_projects(root)
                if not rec.error and rec.data.get("slug")
            ]
        except Exception:  # noqa: BLE001 — completion must never crash the shell
            return []

    def _services(self, project: str | None = None) -> list[str]:
        """Services for completion from project compose when available."""
        slug = project or self.active
        if slug:
            try:
                from sbfleet import registry as reg

                root = reg.resolve_home(self.home)
                compose = reg.project_dir(root, slug) / "deployment" / "docker-compose.yml"
                if compose.is_file():
                    text = compose.read_text(encoding="utf-8", errors="replace")
                    found = [
                        s
                        for s in STANDARD_SERVICES
                        if f"\n  {s}:" in text or text.startswith(f"{s}:")
                    ]
                    if found:
                        return list(found)
            except Exception:  # noqa: BLE001
                pass
        return list(STANDARD_SERVICES)

    def default(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        if line.startswith("/"):
            self._run_slash(line[1:])
            return
        print(f"error: unknown input {line!r}; use /commands (no bare shell execution)")

    def cmdloop(self, intro: str | None = None) -> None:  # noqa: ARG002
        run_interactive_shell(home=self.home)

    def _run_slash(self, body: str) -> None:
        body = body.strip()
        if body == "":
            print(format_command_palette(active=self.active))
            return

        try:
            tokens = shlex.split(body)
        except ValueError as exc:
            print(f"error: {exc}")
            return
        if not tokens:
            print(format_command_palette(active=self.active))
            return

        cmd_name = tokens[0]
        rest = tokens[1:]

        if cmd_name in {"help", "commands"}:
            self._help(rest)
            return
        if cmd_name == "exit":
            raise SystemExit(EXIT_OK)
        if cmd_name == "use":
            self._use(" ".join(rest) if rest else "")
            return
        # Common operator mistake: /project is not a command (active selection is /use).
        if cmd_name == "project":
            hint = " ".join(rest).strip()
            if hint:
                print(
                    f"error: unknown command '/project'. "
                    f"Use `/use {hint}` to select the active project."
                )
            else:
                print("error: unknown command '/project'. Use `/use <project>` (or `/projects`).")
            return

        argv = self._build_argv(cmd_name, rest)
        if argv is None:
            return
        parser = build_parser()
        try:
            args = parser.parse_args(argv)
        except SystemExit:
            return
        code = dispatch_namespace(args)
        if cmd_name == "create" and code in {EXIT_OK, EXIT_UNHEALTHY}:
            # Use argparse positional slug — not first non-option token.
            slug = getattr(args, "slug", None)
            if slug:
                self.active = slug
                self._remember_lifecycle(slug)
        elif cmd_name in {"status", "start", "stop", "restart"}:
            slug = getattr(args, "project", None) or getattr(args, "slug", None)
            if slug is None and rest and not rest[0].startswith("-"):
                slug = rest[0]
            if slug is None:
                slug = self.active
            self._remember_lifecycle(slug)
        elif cmd_name == "doctor":
            slug = getattr(args, "project", None)
            if slug is None and rest and not rest[0].startswith("-"):
                token = rest[0]
                if token not in {"--json", "--sandbox"}:
                    slug = token
            if slug is None:
                slug = self.active
            if slug:
                self._remember_lifecycle(slug)
        if code == EXIT_USAGE:
            print("error: usage — try /help or /commands")

    def _build_argv(self, cmd_name: str, rest: list[str]) -> list[str] | None:
        """Resolve active project into argv. None if a friendly error was printed."""
        argv: list[str] = []
        if self.home:
            argv.extend(["--home", self.home])

        if cmd_name in _NO_INJECT or cmd_name not in _PROJECT_SCOPED:
            argv.extend([cmd_name, *rest])
            return argv

        projects = set(self._project_slugs())
        resolved = self._resolve_project_args(cmd_name, rest, projects)
        if resolved is None:
            return None
        argv.extend([cmd_name, *resolved])
        return argv

    def _resolve_project_args(
        self,
        cmd_name: str,
        rest: list[str],
        projects: set[str],
    ) -> list[str] | None:
        """COMMAND_SPEC shell resolution. None ⇒ friendly error already printed."""
        if cmd_name == "env":
            return self._resolve_env_args(rest, projects)
        if cmd_name == "nginx":
            return self._resolve_nginx_args(rest, projects)
        if cmd_name == "doctor":
            return self._resolve_doctor_args(rest)

        if rest and not rest[0].startswith("-"):
            token = rest[0]
            if token in projects:
                # Explicit project wins (even if it also names a service).
                return rest
            if self.active:
                # Token is a remaining arg (service, archive, …).
                return [self.active, *rest]
            return rest

        if self.active:
            return [self.active, *rest]

        print("No active project.\nUse `/use <project>` or `/projects`.")
        return None

    def _resolve_env_args(self, rest: list[str], projects: set[str]) -> list[str] | None:
        for t in rest:
            if t == "--":
                break
            if not t.startswith("-") and t in projects:
                return rest
        if self.active:
            if "--" in rest:
                idx = rest.index("--")
                return [*rest[:idx], self.active, *rest[idx:]]
            return [*rest, self.active]
        positionals = [t for t in rest if not t.startswith("-") and t != "--"]
        if not positionals:
            print("No active project.\nUse `/use <project>` or `/projects`.")
            return None
        return rest

    def _resolve_nginx_args(self, rest: list[str], projects: set[str]) -> list[str] | None:
        if not rest:
            print("error: nginx requires an action (generate|validate|install)")
            return None
        action, *more = rest
        if action == "install":
            return rest
        if more and (more[0] in projects or not more[0].startswith("-")):
            return rest
        if self.active:
            return [action, self.active, *more]
        print("No active project.\nUse `/use <project>` or `/projects`.")
        return None

    def _resolve_doctor_args(self, rest: list[str]) -> list[str]:
        if rest and not rest[0].startswith("-"):
            return rest
        if self.active:
            return [self.active, *rest]
        return rest

    def _use(self, arg: str) -> None:
        arg = arg.strip()
        if arg in {"", "--"}:
            if self.active:
                print(f"Active project: {self.active}")
                print("Use /use --clear to return to fleet root.")
            else:
                print("Active project: (none)")
                print("Use `/use <project>` or `/projects`.")
            return
        if arg in {"--clear", "clear"}:
            self.active = None
            print("Active project cleared (fleet root).")
            return
        slugs = self._project_slugs()
        if slugs and arg not in slugs:
            print(f"error: project '{arg}' not found — try /projects")
            return
        self.active = arg

    def _help(self, rest: list[str] | None = None) -> None:
        rest = rest or []
        if rest:
            print(topic_help(rest[0]))
            return
        print(format_command_palette(active=self.active))


def _split_for_completion(text: str) -> tuple[list[str], str]:
    """Return (complete tokens, incomplete trailing token)."""
    if not text or text.endswith(" ") or text == "/":
        try:
            tokens = shlex.split(text) if text.strip() else []
        except ValueError:
            tokens = text.split()
        return tokens, ""
    try:
        head, _, tail = text.rpartition(" ")
        tokens = shlex.split(head) if head.strip() else []
        return tokens, tail
    except ValueError:
        parts = text.split()
        if text.endswith(" "):
            return parts, ""
        return parts[:-1], parts[-1] if parts else ""


class SlashCompleter:
    """prompt_toolkit Completer for slash commands, projects, and services."""

    def __init__(self, shell: FleetShell) -> None:
        self.shell = shell

    def get_completions(self, document, complete_event) -> Iterator:  # noqa: ANN001, ARG002
        from prompt_toolkit.completion import Completion

        text = document.text_before_cursor
        if text and not text.lstrip().startswith("/"):
            return

        stripped = text.lstrip()
        tokens, incomplete = _split_for_completion(stripped)

        if not tokens:
            prefix = incomplete if incomplete.startswith("/") else f"/{incomplete}"
            name_prefix = prefix[1:]
            for cmd in filter_commands(name_prefix):
                yield Completion(
                    f"/{cmd.name}",
                    start_position=-len(prefix),
                    display=f"/{cmd.name}",
                    display_meta=cmd.description,
                )
            return

        cmd_token = tokens[0]
        cmd_name = cmd_token[1:] if cmd_token.startswith("/") else cmd_token
        spec = _BY_NAME.get(cmd_name)
        if spec is None:
            return

        args_so_far = tokens[1:]
        projects = self.shell._project_slugs()
        project_set = set(projects)

        if spec.takes_service and cmd_name == "logs":
            if not args_so_far:
                for slug in filter_names(projects, incomplete):
                    yield Completion(
                        slug,
                        start_position=-len(incomplete),
                        display=slug,
                        display_meta="project",
                    )
                if self.shell.active:
                    for svc in filter_names(self.shell._services(), incomplete):
                        if svc in project_set:
                            continue
                        yield Completion(
                            svc,
                            start_position=-len(incomplete),
                            display=svc,
                            display_meta="service",
                        )
                return
            first = args_so_far[0]
            svc_project = first if first in project_set else self.shell.active
            if len(args_so_far) == 1:
                for svc in filter_names(self.shell._services(svc_project), incomplete):
                    yield Completion(
                        svc,
                        start_position=-len(incomplete),
                        display=svc,
                        display_meta="service",
                    )
            return

        if spec.takes_project and not args_so_far:
            if cmd_name == "use":
                for flag in filter_names(["--clear"], incomplete):
                    yield Completion(
                        flag,
                        start_position=-len(incomplete),
                        display=flag,
                        display_meta="return to fleet root",
                    )
            for slug in filter_names(projects, incomplete):
                yield Completion(
                    slug,
                    start_position=-len(incomplete),
                    display=slug,
                    display_meta="project",
                )


def run_interactive_shell(*, home: str | None = None) -> int:
    """Run the prompt_toolkit interactive loop. Returns process exit code."""
    from prompt_toolkit import PromptSession
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.completion import Completer as PTCompleter
    from prompt_toolkit.enums import EditingMode
    from prompt_toolkit.history import InMemoryHistory
    from prompt_toolkit.key_binding import KeyBindings

    from sbfleet.ux import reset_interactive, set_interactive

    shell = FleetShell(home=home)
    token = set_interactive(True)

    class _BoundCompleter(PTCompleter):
        def __init__(self) -> None:
            self._inner = SlashCompleter(shell)

        def get_completions(self, document, complete_event):  # noqa: ANN001
            yield from self._inner.get_completions(document, complete_event)

    kb = KeyBindings()

    @kb.add("c-c")
    def _(event) -> None:  # noqa: ANN001
        event.app.current_buffer.reset()

    session: PromptSession[str] = PromptSession(
        history=InMemoryHistory(),
        completer=_BoundCompleter(),
        complete_while_typing=True,
        auto_suggest=AutoSuggestFromHistory(),
        key_bindings=kb,
        editing_mode=EditingMode.EMACS,
    )

    banner = shell.intro
    if banner:
        print(banner, end="" if banner.endswith("\n") else "\n")
    try:
        while True:
            try:
                line = session.prompt(lambda: shell.prompt_message())
            except EOFError:
                print()
                return EXIT_OK
            except KeyboardInterrupt:
                print()
                continue
            try:
                shell.default(line)
            except SystemExit as exc:
                code = exc.code
                if code is None:
                    return EXIT_OK
                return int(code) if isinstance(code, int) else EXIT_OK
    finally:
        reset_interactive(token)
