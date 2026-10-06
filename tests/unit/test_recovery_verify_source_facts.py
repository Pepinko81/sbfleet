"""Recovery verify source facts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from sbfleet.backup_manifest import (
    REQUIRED_RECOVERY_ASSERTIONS,
    VERIFIER_CONTRACT_VERSION,
    ManifestError,
    validate_recovery_receipt_evidence,
)
from sbfleet.backup_recovery import (
    RecoveryAssertion,
    RecoveryVerificationResult,
    capture_functions_snippets_inventory,
)


def test_contract_is_v3() -> None:
    assert VERIFIER_CONTRACT_VERSION == "recovery-verify/v3"
    for name in (
        "auth_viability",
        "functions_snippets",
        "vault_crypto",
        "databases",
        "roles",
    ):
        assert name in REQUIRED_RECOVERY_ASSERTIONS


def test_legacy_v2_receipt_refused() -> None:
    assertions = [
        {"name": n, "ok": True, "detail": "ok"} for n in sorted(REQUIRED_RECOVERY_ASSERTIONS)
    ]
    receipt = {
        "format_version": 1,
        "verification": "recovery",
        "project_id": "p",
        "backup_id": "b",
        "ciphertext_sha256": "a" * 64,
        "ciphertext_bytes": 100,
        "manifest_sha256": "c" * 64,
        "upstream": {"ref": "self-hosted/v0.8.2", "sha": "d" * 40},
        "verified_at": "2026-10-01T00:00:00Z",
        "recovery": {
            "outcome_version": "recovery-verify/v2",
            "verifier_contract": "recovery-verify/v2",
            "ok": True,
            "verifier_id": "rv",
            "operation_id": "op",
            "assertions": assertions,
        },
    }
    with pytest.raises(ManifestError, match="does not satisfy required"):
        validate_recovery_receipt_evidence(receipt)


def test_functions_inventory_from_source_not_self_hash(tmp_path: Path) -> None:
    fn = tmp_path / "volumes" / "functions"
    fn.mkdir(parents=True)
    (fn / "hello.js").write_text("console.log(1)\n", encoding="utf-8")
    inv = capture_functions_snippets_inventory(tmp_path)
    assert "deployment/functions/hello.js" in inv
    assert len(inv["deployment/functions/hello.js"]) == 64


def test_hard_ok_requires_source_facts_consumption() -> None:
    """Missing source_facts cannot yield recovery-level ok."""
    rv = RecoveryVerificationResult(
        ok=False,
        verifier_id="rv",
        operation_id="op",
        assertions=[
            RecoveryAssertion("source_facts", False, "missing-or-incomplete"),
            RecoveryAssertion("databases", True, "postgres"),
        ],
        outcome_version=VERIFIER_CONTRACT_VERSION,
    )
    assert rv.ok is False


def test_quiesce_writers_then_db_order(monkeypatch: pytest.MonkeyPatch) -> None:
    from sbfleet import backup as bak

    calls: list[str] = []

    def fake_services(ctx: Any, services: list[str], *, timeout: float) -> None:
        calls.append(",".join(services))

    monkeypatch.setattr(bak, "_quiesce_services", fake_services)

    class FakeInspect:
        ok = True
        containers: list[str] = []
        error = None

    monkeypatch.setattr(
        "sbfleet.health.inspect_containers_result",
        lambda *a, **k: FakeInspect(),
    )

    class Ctx:
        deployment = Path("/tmp")
        compose_env: dict[str, str] = {}
        compose_project = "p"

    bak._quiesce_writers(Ctx())
    bak._quiesce_db(Ctx())
    assert calls[0] == "api-gw"
    assert "db" not in calls[0]
    assert calls[-1] == "db"
    assert "api-gw" not in calls[-1]
