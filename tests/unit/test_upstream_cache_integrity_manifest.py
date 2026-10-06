"""Upstream cache integrity manifest."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.helpers_upstream import write_cache_marker

from sbfleet import upstream as up


def _full_marker(cache: Path) -> dict:
    return json.loads((cache / ".sbfleet-cache.json").read_text(encoding="utf-8"))


def _write_partial(cache: Path, digests: dict[str, str], **extra: object) -> None:
    body = {
        "format_version": 1,
        "ref": up.PINNED_REF,
        "sha": up.PINNED_SHA,
        "repo": up.OFFICIAL_REPO,
        "critical_digests": digests,
    }
    body.update(extra)
    (cache / ".sbfleet-cache.json").write_text(
        json.dumps(body, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def test_validate_critical_digests_exact_set(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    write_cache_marker(cache)
    meta = _full_marker(cache)
    got = up.validate_critical_digests_manifest(meta, expected_sha=up.PINNED_SHA)
    assert set(got) == set(up.CRITICAL_VENDOR_FILES)


@pytest.mark.parametrize("drop_rel", list(up.CRITICAL_VENDOR_FILES))
def test_incomplete_marker_refuses_each_required_path(tmp_path: Path, drop_rel: str) -> None:
    cache = tmp_path / "cache"
    write_cache_marker(cache)
    meta = _full_marker(cache)
    digests = dict(meta["critical_digests"])
    del digests[drop_rel]
    _write_partial(cache, digests)
    with pytest.raises(up.UpstreamError, match="incomplete critical_digests"):
        up.verify_cache(cache, sha=up.PINNED_SHA)


def test_malformed_digest_refuses(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    write_cache_marker(cache)
    meta = _full_marker(cache)
    digests = dict(meta["critical_digests"])
    digests["run.sh"] = "not-a-digest"
    _write_partial(cache, digests)
    with pytest.raises(up.UpstreamError, match="malformed critical digest"):
        up.verify_cache(cache, sha=up.PINNED_SHA)


def test_extra_unsafe_path_refuses(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    write_cache_marker(cache)
    meta = _full_marker(cache)
    digests = dict(meta["critical_digests"])
    digests["../escape"] = "a" * 64
    _write_partial(cache, digests)
    with pytest.raises(up.UpstreamError, match="unexpected critical_digests"):
        up.verify_cache(cache, sha=up.PINNED_SHA)


def test_wrong_ref_sha_association_refuses(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    write_cache_marker(cache)
    meta = _full_marker(cache)
    digests = dict(meta["critical_digests"])
    # Claim v0.8.1 ref while pinned to v0.8.2 SHA.
    _write_partial(cache, digests, ref="self-hosted/v0.8.1")
    with pytest.raises(up.UpstreamError, match="does not match approved SHA"):
        up.verify_cache(cache, sha=up.PINNED_SHA)


def test_partial_nonempty_marker_refuses_execution(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    write_cache_marker(cache)
    meta = _full_marker(cache)
    # Nonempty but missing run.sh — historical incomplete marker class.
    digests = {k: v for k, v in meta["critical_digests"].items() if k != "run.sh"}
    _write_partial(cache, digests)
    with pytest.raises(up.UpstreamError, match="incomplete"):
        up.verify_cache(cache, sha=up.PINNED_SHA)


def test_mutated_critical_script_after_marker_refuses(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    write_cache_marker(cache)
    run_sh = cache / "docker" / "run.sh"
    run_sh.write_text(run_sh.read_text(encoding="utf-8") + "\n# mutated\n", encoding="utf-8")
    with pytest.raises(up.UpstreamError, match="vendor drift"):
        up.verify_cache(cache, sha=up.PINNED_SHA)


def test_wrong_format_version_refuses(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    write_cache_marker(cache)
    meta = _full_marker(cache)
    _write_partial(cache, dict(meta["critical_digests"]), format_version=99)
    with pytest.raises(up.UpstreamError, match="format_version"):
        up.verify_cache(cache, sha=up.PINNED_SHA)


def test_incomplete_cache_not_trusted_until_complete_marker(tmp_path: Path) -> None:
    """Incomplete marker cannot authorize execution; complete rematerialized marker can."""
    root = tmp_path / "fleet"
    root.mkdir()
    dest = up.cache_dir(root, up.PINNED_SHA)
    dest.mkdir(parents=True)
    (dest / "docker").mkdir()
    (dest / "docker" / "docker-compose.yml").write_text("x" * 120, encoding="utf-8")
    # Partial marker only — nonempty but incomplete.
    _write_partial(dest, {"docker-compose.yml": "a" * 64})
    with pytest.raises(up.UpstreamError, match="incomplete"):
        up.verify_cache(dest, sha=up.PINNED_SHA)

    # Exact safe rematerialization of a complete marker (fixture, no network).
    import shutil

    shutil.rmtree(dest)
    write_cache_marker(dest, sha=up.PINNED_SHA, ref=up.PINNED_REF)
    up.verify_cache(dest, sha=up.PINNED_SHA)
    digests = up.validate_critical_digests_manifest(
        _full_marker(dest), expected_sha=up.PINNED_SHA, expected_ref=up.PINNED_REF
    )
    assert set(digests) == set(up.CRITICAL_VENDOR_FILES)
