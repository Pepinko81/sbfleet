"""Canonical schema, diff, preview and safe failure contracts."""

import asyncio
import json
from importlib.resources import files

import pytest
from jsonschema import Draft202012Validator, ValidationError

from sbfleet import registry as reg
from sbfleet import schema as s
from sbfleet.cli import main
from sbfleet.mcp_server import create_server
from sbfleet.pooler_rebind import SUPPORTED_PIN
from sbfleet.schema_catalog import READ_SQL


def obj(object_kind="TABLE", name="orders", **facts):
    return s.SchemaObject(kind=object_kind, key=["public", name], facts=facts)


def snapshot(*objects):
    return s.SchemaSnapshot(project="p", pin=SUPPORTED_PIN, state="KNOWN", objects=list(objects))


def diff(new, old):
    return s.compare(snapshot(*new), snapshot(*old))


@pytest.mark.parametrize(
    "kind",
    [
        "SCHEMA",
        "TABLE",
        "COLUMN",
        "CONSTRAINT",
        "INDEX",
        "FUNCTION",
        "RLS",
        "POLICY",
        "VIEW",
        "MATERIALIZED_VIEW",
        "ENUM",
        "SEQUENCE",
        "TRIGGER",
    ],
)
def test_every_supported_kind_add_remove_change_identical(kind):
    before = obj(kind, kind="f") if kind == "FUNCTION" else obj(kind, value="before")
    after = before.model_copy(deep=True)
    after.facts["value"] = "after"
    assert diff([before], [before]).differences == []
    assert diff([before], []).differences[0].change == "ADDED"
    assert diff([], [before]).differences[0].change == "REMOVED"
    assert diff([after], [before]).differences[0].change == "CHANGED"


@pytest.mark.parametrize(
    "kind,field,before,after",
    [
        ("COLUMN", "nullable", True, False),
        ("COLUMN", "default_hash", None, "abc"),
        ("COLUMN", "data_type", "numeric(10,2)", "numeric(12,2)"),
        ("CONSTRAINT", "type", "p", "u"),
        ("CONSTRAINT", "type", "u", "f"),
        ("CONSTRAINT", "definition_hash", "old", "new"),
        ("INDEX", "unique", False, True),
        ("FUNCTION", "definition_hash", "old", "new"),
        ("RLS", "enabled", False, True),
        ("POLICY", "using_hash", "old", "new"),
    ],
)
def test_material_facts(kind, field, before, after):
    a = s.SchemaObject(kind=kind, key=["public", "t", "x"], facts={field: before})
    if kind == "FUNCTION":
        a.facts["kind"] = "f"
    b = a.model_copy(deep=True)
    b.facts[field] = after
    assert diff([b], [a]).differences[0].changed_fields == [field]


@pytest.mark.parametrize(
    "kind,change,facts,risk",
    [
        ("SCHEMA", "ADDED", {}, "SAFE"),
        ("TABLE", "ADDED", {}, "SAFE"),
        (
            "COLUMN",
            "ADDED",
            {
                "ordinary_table": True,
                "nullable": True,
                "default_hash": None,
                "type_schema": "pg_catalog",
                "type_name": "text",
            },
            "SAFE",
        ),
        ("COLUMN", "ADDED", {"nullable": False}, "REVIEW_REQUIRED"),
        ("COLUMN", "ADDED", {"nullable": True, "default_hash": "volatile"}, "REVIEW_REQUIRED"),
        ("COLUMN", "REMOVED", {}, "DESTRUCTIVE"),
        ("TABLE", "REMOVED", {}, "DESTRUCTIVE"),
        ("CONSTRAINT", "ADDED", {"type": "f"}, "REVIEW_REQUIRED"),
        ("CONSTRAINT", "ADDED", {"type": "u"}, "REVIEW_REQUIRED"),
        ("INDEX", "ADDED", {"unique": False}, "REVIEW_REQUIRED"),
        ("RLS", "CHANGED", {"enabled": True}, "REVIEW_REQUIRED"),
        ("POLICY", "ADDED", {}, "REVIEW_REQUIRED"),
        ("UNSUPPORTED", "UNSUPPORTED", {}, "UNSUPPORTED"),
    ],
)
def test_plan_rules(kind, change, facts, risk):
    d = s.Difference(
        kind=kind, key=["public", "x"], change=change, classification="APPLICATION", after=facts
    )
    assert s.classify(d)[0] == risk


def test_type_change_conservative_and_managed_review():
    d = s.Difference(
        kind="COLUMN",
        key=["public", "t", "c"],
        change="CHANGED",
        classification="APPLICATION",
        changed_fields=["data_type"],
    )
    assert s.classify(d)[0] == "DESTRUCTIVE"
    d.classification = "SUPABASE_MANAGED"
    assert s.classify(d)[0] == "DESTRUCTIVE"
    d.kind, d.change = "TABLE", "REMOVED"
    assert s.classify(d)[0] == "DESTRUCTIVE"
    d.change = "ADDED"
    assert s.classify(d)[0] == "REVIEW_REQUIRED"


def test_normalization_deterministic_and_unsupported():
    rows = [
        obj(name="z").model_dump(),
        obj(name="a").model_dump(),
        obj("EXTENSION", "extension").model_dump(),
        obj("UNSUPPORTED", "domain").model_dump(),
    ]
    raw = {
        "server_major": 17,
        "namespaces": ["storage", "public", "auth", "pg_catalog"],
        "objects": rows,
    }
    a = s.normalize(raw, "p", SUPPORTED_PIN)
    raw["objects"] = list(reversed(rows))
    assert a.model_dump_json() == s.normalize(raw, "p", SUPPORTED_PIN).model_dump_json()
    assert [n.classification for n in a.namespaces] == [
        "SUPABASE_MANAGED",
        "SYSTEM",
        "APPLICATION",
        "SUPABASE_MANAGED",
    ]
    assert len(s.compare(a, a).unsupported_objects) == 2
    assert s.compare(a, a).differences == []
    raw["objects"].append(rows[0])
    with pytest.raises(ValueError):
        s.normalize(raw, "p", SUPPORTED_PIN)


def test_unknown_and_pin_refusal():
    a = snapshot()
    a.pin = {"sha": "different"}
    assert s.compare(a, snapshot()).error == "UNSUPPORTED_PIN"
    a.state = "UNKNOWN"
    a.error = "DB_UNAVAILABLE"
    assert s.compare(a, snapshot()).state == "UNKNOWN"
    assert not s.plan_from_diff(s.compare(a, snapshot())).items


def test_packaged_json_schemas():
    for name, model in [
        ("schema-diff", s.SchemaDiff),
        ("migration-plan", s.MigrationPlan),
        ("schema-snapshot", s.SchemaSnapshot),
    ]:
        document = json.loads(files("sbfleet").joinpath(name + ".schema.json").read_text())
        assert document == model.model_json_schema()
        assert document["additionalProperties"] is False
    result = diff([obj()], [])
    assert s.SchemaDiff.model_validate_json(result.model_dump_json()) == result
    plan = s.plan_from_diff(result)
    assert s.MigrationPlan.model_validate_json(plan.model_dump_json()) == plan
    for model, value in (
        (s.SchemaDiff, result),
        (s.MigrationPlan, plan),
        (s.SchemaSnapshot, snapshot(obj())),
    ):
        validator = Draft202012Validator(model.model_json_schema())
        validator.check_schema(model.model_json_schema())
        validator.validate(value.model_dump())
        invalid = value.model_dump() | {"password": "must-not-be-a-contract-field"}
        with pytest.raises(ValidationError):
            validator.validate(invalid)


def test_static_sql_readonly_and_fingerprints():
    assert "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY" in READ_SQL
    assert "statement_timeout='15s'" in READ_SQL
    assert "sha256(" in READ_SQL
    assert "CREATE " not in READ_SQL and "ALTER " not in READ_SQL and "DROP " not in READ_SQL
    assert "last_value" not in READ_SQL


def test_missing_cli_no_initialization(tmp_path, capsys):
    root = tmp_path / "absent"
    assert main(["--home", str(root), "schema", "diff", "a", "b", "--json"]) == 5
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "UNKNOWN"
    assert not root.exists()
    assert main(["migrate", "apply", "a", "b"]) == 2


def test_missing_mcp_and_no_mutation(tmp_path, monkeypatch):
    root = reg.ensure_root(tmp_path / "fleet")

    def forbidden(*a, **k):
        pytest.fail("mutation dispatch")

    for name in ("ensure_root", "atomic_write_json", "project_lock", "registry_lock"):
        monkeypatch.setattr(reg, name, forbidden)

    async def exercise():
        server = create_server(root)
        for name in ("schema_diff", "migration_plan"):
            response = await server.call_tool(name, {"source": "missing", "target": "missing"})
            assert "NOT_FOUND" in str(response)
            assert "UNKNOWN" in str(response)

    asyncio.run(exercise())


@pytest.mark.parametrize("error", [None, "SCHEMA_OBSERVATION_FAILED"])
def test_cli_mcp_same_models_and_secret_negative(tmp_path, monkeypatch, capsys, error):
    marker = "private-password-never-print"
    data = snapshot(obj("UNSUPPORTED", "domain"))
    if error:
        data.state = "UNKNOWN"
        data.error = error
    monkeypatch.setattr(s, "collect_schema", lambda *a: data)

    def forbidden(*a, **k):
        raise RuntimeError(marker)

    monkeypatch.setattr(s, "run", forbidden)
    expected = s.schema_diff(tmp_path, "a", "b")
    assert main(["--home", str(tmp_path), "schema", "diff", "a", "b", "--json"]) == (
        5 if error else 0
    )
    assert json.loads(capsys.readouterr().out) == expected.model_dump()

    async def exercise():
        server = create_server(tmp_path)
        for name in ("schema_diff", "migration_plan"):
            response = await server.call_tool(name, {"source": "a", "target": "b"})
            assert marker not in str(response)
            assert ("UNKNOWN" if error else "KNOWN") in str(response)

    asyncio.run(exercise())


def test_partial_table_children_never_safe():
    parent = obj("TABLE", "t", partitioned=True)
    child = s.SchemaObject(
        kind="COLUMN", key=["public", "t", "x"], facts={"ordinary_table": False, "nullable": True}
    )
    result = diff([parent, child], [])
    assert all(d.change == "UNSUPPORTED" for d in result.differences)
    assert s.plan_from_diff(result).summary["UNSUPPORTED"] == 2
    view_column = s.Difference(
        kind="COLUMN",
        key=["public", "v", "x"],
        change="ADDED",
        classification="APPLICATION",
        after=child.facts,
    )
    assert s.classify(view_column)[0] == "REVIEW_REQUIRED"


def test_observation_failure_never_echoes_raw_diagnostic(tmp_path, monkeypatch):
    root = reg.ensure_root(tmp_path / "fleet")
    secret = "private-database-password-should-not-appear"

    def broken(*a, **k):
        raise RuntimeError(secret)

    monkeypatch.setattr(reg, "read_project", broken)
    (root / "projects" / "a").mkdir()
    result = s.collect_schema(root, "a")
    assert result.state == "UNKNOWN"
    assert secret not in result.model_dump_json()


def test_domain_and_array_additions_require_review():
    for namespace, name in [("app", "constrained_domain"), ("pg_catalog", "_int4")]:
        d = s.Difference(
            kind="COLUMN",
            key=["public", "t", "x"],
            change="ADDED",
            classification="APPLICATION",
            after={
                "ordinary_table": True,
                "nullable": True,
                "default_hash": None,
                "type_schema": namespace,
                "type_name": name,
            },
        )
        assert s.classify(d)[0] == "REVIEW_REQUIRED"


def test_unsupported_table_does_not_capture_same_named_function():
    table = obj("TABLE", "items", partitioned=True)
    function = obj("FUNCTION", "items", kind="f", definition_hash="before")
    changed = function.model_copy(deep=True)
    changed.facts["definition_hash"] = "after"
    result = diff([table, changed], [table, function])
    assert len(result.differences) == 1
    assert result.differences[0].kind == "FUNCTION"
    assert result.differences[0].change == "CHANGED"
    assert s.plan_from_diff(result).items[0].classification == "REVIEW_REQUIRED"
