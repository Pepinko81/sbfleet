"""G10 acceptance pointer — POINTER / HELPER EVIDENCE ONLY.

Executable harness: tests/integration/test_adversarial_ownership.py
"""

from __future__ import annotations

from pathlib import Path

import pytest

_INTEGRATION = Path(__file__).resolve().parents[1] / "integration"


@pytest.mark.docker
def test_ownership_g10() -> None:
    """Pointer: G10 executable module is tests/integration/test_adversarial_ownership.py"""
    assert (_INTEGRATION / "test_adversarial_ownership.py").is_file()
