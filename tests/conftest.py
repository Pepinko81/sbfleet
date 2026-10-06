"""Shared pytest hooks."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from sbfleet import upstream as up

# Repository under test (tests/ is one level below the checkout root).
_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC_PACKAGE = (_REPO_ROOT / "src" / "sbfleet").resolve()
_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))


def _assert_imported_from_checkout() -> None:
    """Fail the suite if Python imported a different installed sbfleet.

    Editable installs from this checkout resolve under ``<repo>/src/sbfleet``.
    A user-site or unrelated wheel install must not silently shadow the tree.
    Normal installed-wheel usage outside this test workflow is unaffected.
    """
    import sbfleet
    from sbfleet import authority

    pkg = Path(sbfleet.__file__).resolve()
    auth = Path(authority.__file__).resolve()
    try:
        pkg.relative_to(_SRC_PACKAGE)
        auth.relative_to(_SRC_PACKAGE)
    except ValueError as exc:
        raise RuntimeError(
            "imported sbfleet is not this repository checkout: "
            f"sbfleet={pkg} authority={auth} expected_under={_SRC_PACKAGE}. "
            "Create an isolated venv in the checkout and install editable: "
            "`python3 -m venv .venv && .venv/bin/python -m pip install -e '.[dev]'`, "
            "then run gates with `.venv/bin/python -m pytest ...`."
        ) from exc


def pytest_configure(config: pytest.Config) -> None:
    try:
        _assert_imported_from_checkout()
    except Exception as exc:  # noqa: BLE001 — abort collection with clear guidance
        pytest.exit(str(exc), returncode=2)


def ensure_critical_vendor_files(docker: Path) -> None:
    docker = Path(docker)
    docker.mkdir(parents=True, exist_ok=True)
    for rel in up.CRITICAL_VENDOR_FILES:
        path = docker / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            continue
        if rel.endswith(".sh"):
            path.write_text("#!/bin/sh\n", encoding="utf-8")
        else:
            path.write_text("services: {}\n" + ("x" * 120), encoding="utf-8")


def write_cache_marker(
    cache: Path,
    *,
    sha: str = up.PINNED_SHA,
    ref: str = up.PINNED_REF,
    repo: str = up.OFFICIAL_REPO,
) -> None:
    docker = Path(cache) / "docker"
    ensure_critical_vendor_files(docker)
    digests = up.critical_vendor_digests(docker)
    (Path(cache) / ".sbfleet-cache.json").write_text(
        json.dumps(
            {
                "format_version": 1,
                "ref": ref,
                "sha": sha,
                "repo": repo,
                "critical_digests": digests,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-docker",
        action="store_true",
        default=False,
        help="Run tests that require Docker Engine/Compose",
    )
    parser.addoption(
        "--run-sandbox",
        action="store_true",
        default=False,
        help="Run tests that require pinned Supabase CLI",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if not config.getoption("--run-docker"):
        skip = pytest.mark.skip(reason="needs --run-docker")
        for item in items:
            if item.get_closest_marker("docker") is not None:
                item.add_marker(skip)
    if not config.getoption("--run-sandbox"):
        skip = pytest.mark.skip(reason="needs --run-sandbox")
        for item in items:
            if item.get_closest_marker("sandbox") is not None:
                item.add_marker(skip)
