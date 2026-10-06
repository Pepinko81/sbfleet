"""Module tests."""

from __future__ import annotations

from sbfleet.backup import manifest_for


def test_manifest_fields() -> None:
    m = manifest_for(project_id="p", backup_id="b", digest="abc", size=12)
    assert m["format_version"] == 1
    assert "postgres" in m["includes"] or "pgdata" in m["includes"]
    assert "storage" in m["includes"]
    assert m["verified"] is False
    assert m["verification"] == "none"
    assert m["method"] == "cold-physical"
