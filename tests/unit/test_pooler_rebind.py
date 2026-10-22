"""Pin and identity refusals must happen before any database mutation."""

from types import SimpleNamespace

import pytest

from sbfleet import pooler_rebind as pooler

SOURCE = "11111111-1111-4111-8111-111111111111"
TARGET = "22222222-2222-4222-8222-222222222222"


@pytest.mark.parametrize("case", ["same_id", "manifest_id", "source_pin", "target_pin"])
def test_rebind_preconditions_refuse_before_authority_or_sql(monkeypatch, case):
    ctx = SimpleNamespace(project_id=TARGET, meta={"upstream": dict(pooler.SUPPORTED_PIN)})
    manifest = {"project_id": SOURCE, "upstream": dict(pooler.SUPPORTED_PIN)}
    if case == "same_id":
        ctx.project_id = SOURCE
    elif case == "manifest_id":
        manifest["project_id"] = TARGET
    elif case == "source_pin":
        manifest["upstream"]["sha"] = "0" * 40
    else:
        ctx.meta["upstream"]["sha"] = "0" * 40

    def forbidden(*args, **kwargs):
        pytest.fail("refusal reached mutation authority or SQL")

    monkeypatch.setattr(pooler.auth, "revalidate_deployment_authority", forbidden)
    monkeypatch.setattr(pooler, "sql", forbidden)
    with pytest.raises(pooler.RebindError):
        pooler.rebind_pooler(ctx, source_project_id=SOURCE, manifest=manifest)


@pytest.mark.parametrize("value", ["", "../project", "' OR true", "a" * 32])
def test_tenant_input_is_uuid_only(value):
    if value == "a" * 32:
        assert pooler.tenant_id(value) == value
    else:
        with pytest.raises(ValueError):
            pooler.tenant_id(value)


def test_database_error_does_not_expose_credentials(monkeypatch):
    ctx = SimpleNamespace(deployment="/unused", compose_env={})
    monkeypatch.setattr(
        pooler,
        "run",
        lambda *a, **k: SimpleNamespace(ok=False, stdout="private-secret", stderr="private-secret"),
    )
    with pytest.raises(pooler.RebindError) as failure:
        pooler.sql(ctx, "SELECT 1")
    assert "private-secret" not in str(failure.value)


def test_foreign_live_resources_refuse_before_sql(monkeypatch):
    from sbfleet import health

    ctx = SimpleNamespace(
        project_id=TARGET,
        meta={"upstream": pooler.SUPPORTED_PIN},
        deployment="/unused",
        compose_project="target",
        fleet_id="fleet",
        contract=None,
    )
    monkeypatch.setattr(pooler.auth, "revalidate_deployment_authority", lambda _: None)
    monkeypatch.setattr(
        health,
        "inspect_containers_result",
        lambda *a: SimpleNamespace(ok=True, containers={"db": {}}),
    )
    monkeypatch.setattr(
        pooler.auth,
        "invent_owned_resources",
        lambda **k: SimpleNamespace(residuals=["foreign volume"]),
    )

    def forbidden(*a, **k):
        pytest.fail("foreign resource refusal reached SQL")

    monkeypatch.setattr(pooler, "sql", forbidden)
    with pytest.raises(pooler.RebindError, match="authority"):
        pooler.rebind_pooler(
            ctx,
            source_project_id=SOURCE,
            manifest={"project_id": SOURCE, "upstream": pooler.SUPPORTED_PIN},
        )
