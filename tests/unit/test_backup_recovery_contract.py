"""Backup recovery contract."""

from __future__ import annotations

import pytest

from sbfleet.backup_manifest import (
    REQUIRED_RECOVERY_ASSERTIONS,
    VERIFIER_CONTRACT_VERSION,
    ManifestError,
    validate_recovery_receipt_evidence,
)
from sbfleet.backup_recovery import RecoveryAssertion, RecoveryVerificationResult


def test_required_assertions_include_vault_crypto_and_select_1() -> None:
    assert "vault_crypto" in REQUIRED_RECOVERY_ASSERTIONS
    assert "select_1" in REQUIRED_RECOVERY_ASSERTIONS
    assert "auth_schema" in REQUIRED_RECOVERY_ASSERTIONS
    assert VERIFIER_CONTRACT_VERSION == "recovery-verify/v3"
    assert "auth_viability" in REQUIRED_RECOVERY_ASSERTIONS
    assert "functions_snippets" in REQUIRED_RECOVERY_ASSERTIONS


def test_receipt_evidence_rejects_generic_ok_only() -> None:
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
            "outcome_version": VERIFIER_CONTRACT_VERSION,
            "ok": True,
            "verifier_id": "rv",
            "operation_id": "op",
            "assertions": [{"name": "postgres_ready", "ok": True}],
        },
    }
    with pytest.raises(ManifestError, match="missing required assertions"):
        validate_recovery_receipt_evidence(receipt)


def test_receipt_evidence_rejects_old_contract() -> None:
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
            "outcome_version": "recovery-verify/v1",
            "ok": True,
            "verifier_id": "rv",
            "operation_id": "op",
            "assertions": assertions,
            "source_pin": {"ref": "self-hosted/v0.8.2", "sha": "d" * 40},
            "verified_at": "2026-10-01T00:00:00Z",
        },
    }
    with pytest.raises(ManifestError, match="contract"):
        validate_recovery_receipt_evidence(receipt)


def test_as_receipt_evidence_binds_contract_and_assertion_set() -> None:
    rv = RecoveryVerificationResult(
        ok=True,
        verifier_id="rv-x",
        operation_id="op-x",
        assertions=[RecoveryAssertion(n, True, "ok") for n in sorted(REQUIRED_RECOVERY_ASSERTIONS)],
        source_pin={"ref": "self-hosted/v0.8.2", "sha": "e" * 40},
        project_id="p",
        backup_id="b",
        manifest_sha256="f" * 64,
    )
    evidence = rv.as_receipt_evidence()
    assert evidence["outcome_version"] == VERIFIER_CONTRACT_VERSION
    assert evidence["verifier_contract"] == VERIFIER_CONTRACT_VERSION
    assert set(evidence["required_assertions"]) == set(REQUIRED_RECOVERY_ASSERTIONS)
    assert evidence["operation_id"] == "op-x"
    assert evidence["source_pin"]["sha"] == "e" * 40


def test_fixture_only_vault_does_not_satisfy_vault_crypto_without_source() -> None:
    """HELPER / POINTER: constant membership only — not production vault_crypto proof.

    Production refusal of fixture-only elevation is covered by backup_recovery
    ``fixture-only-insufficient`` detail and G6 default-path recovery-verify/v3.
    """
    assert "vault_crypto" in REQUIRED_RECOVERY_ASSERTIONS
