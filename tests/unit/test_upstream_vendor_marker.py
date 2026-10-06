"""Upstream vendor marker."""

from __future__ import annotations

import pytest

from sbfleet.upstream import (
    CRITICAL_VENDOR_FILES,
    KNOWN_REF_SHAS,
    PINNED_REF,
    PINNED_SHA,
    UpstreamError,
    validate_critical_digests_manifest,
)


def _complete_digests() -> dict[str, str]:
    return {p: "a" * 64 for p in CRITICAL_VENDOR_FILES}


def test_missing_ref_refuses() -> None:
    meta = {
        "format_version": 1,
        "sha": PINNED_SHA,
        "critical_digests": _complete_digests(),
    }
    with pytest.raises(UpstreamError, match="nonempty reviewed ref"):
        validate_critical_digests_manifest(meta, expected_sha=PINNED_SHA)


def test_empty_ref_refuses() -> None:
    meta = {
        "format_version": 1,
        "ref": "",
        "sha": PINNED_SHA,
        "critical_digests": _complete_digests(),
    }
    with pytest.raises(UpstreamError, match="nonempty reviewed ref"):
        validate_critical_digests_manifest(meta, expected_sha=PINNED_SHA)


def test_unknown_ref_refuses() -> None:
    meta = {
        "format_version": 1,
        "ref": "self-hosted/v9.9.9",
        "sha": PINNED_SHA,
        "critical_digests": _complete_digests(),
    }
    with pytest.raises(UpstreamError, match="no reviewed SHA"):
        validate_critical_digests_manifest(meta, expected_sha=PINNED_SHA)


def test_ref_sha_mismatch_refuses() -> None:
    # Known ref paired with a different SHA than KNOWN_REF_SHAS.
    other = next(iter(KNOWN_REF_SHAS))
    wrong_sha = "b" * 40 if PINNED_SHA != "b" * 40 else "c" * 40
    # Prefer a real known pair mismatch: use PINNED_REF with non-matching expected_sha.
    meta = {
        "format_version": 1,
        "ref": PINNED_REF,
        "sha": wrong_sha,
        "critical_digests": _complete_digests(),
    }
    with pytest.raises(UpstreamError, match="sha mismatch|does not match approved SHA"):
        validate_critical_digests_manifest(meta, expected_sha=wrong_sha)
    _ = other


def test_valid_reviewed_pair_passes() -> None:
    meta = {
        "format_version": 1,
        "ref": PINNED_REF,
        "sha": PINNED_SHA,
        "critical_digests": _complete_digests(),
    }
    out = validate_critical_digests_manifest(meta, expected_sha=PINNED_SHA)
    assert set(out) == set(CRITICAL_VENDOR_FILES)
