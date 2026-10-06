"""Regression: repository tests must import the checkout, not another install."""

from __future__ import annotations

from pathlib import Path

import sbfleet
from sbfleet import authority


def test_imported_sbfleet_is_this_checkout() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    expected = (repo_root / "src" / "sbfleet").resolve()
    pkg = Path(sbfleet.__file__).resolve()
    auth = Path(authority.__file__).resolve()
    assert pkg.is_relative_to(expected), f"sbfleet imported from {pkg}, expected under {expected}"
    assert auth.is_relative_to(expected), (
        f"authority imported from {auth}, expected under {expected}"
    )
    # Must not silently test a user/global site-packages install.
    assert "site-packages" not in str(pkg)
    assert "site-packages" not in str(auth)
