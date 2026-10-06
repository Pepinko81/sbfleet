"""G5–G8 acceptance entrypoints (Audit Readiness).

POINTER / HELPER EVIDENCE ONLY — not capability claims.
Executable modules under tests/acceptance/ hold the real proofs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_ACCEPTANCE = Path(__file__).resolve().parent


@pytest.mark.docker
def test_two_projects_g5() -> None:
    """Pointer: G5 executable module is tests/acceptance/test_two_projects.py"""
    assert (_ACCEPTANCE / "test_two_projects.py").is_file()


@pytest.mark.docker
def test_backup_restore_g6() -> None:
    """Pointer: G6 executable module is tests/acceptance/test_backup_restore.py"""
    assert (_ACCEPTANCE / "test_backup_restore.py").is_file()


@pytest.mark.docker
def test_update_g7() -> None:
    """Pointer: G7 executable module is tests/acceptance/test_update.py"""
    assert (_ACCEPTANCE / "test_update.py").is_file()


@pytest.mark.docker
@pytest.mark.sandbox
def test_sandbox_g8() -> None:
    """Pointer: G8 executable module is tests/acceptance/test_sandbox.py"""
    assert (_ACCEPTANCE / "test_sandbox.py").is_file()
