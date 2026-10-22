"""Real PostgreSQL catalog integration, independent of managed CLI orchestration."""

import json
import os
import time
import uuid

import pytest

from sbfleet import schema as s
from sbfleet.pooler_rebind import SUPPORTED_PIN
from sbfleet.process import run
from sbfleet.schema_catalog import READ_SQL

pytestmark = pytest.mark.docker


def test_postgres_catalog_diff_and_readonly_transaction():
    # PostgreSQL 17.6 catalog semantics, no ports or bind mounts.
    image = "postgres:17.6-alpine"
    name = "sbfleet-schema-test-" + uuid.uuid4().hex[:12]
    created = run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "--label",
            "io.sbfleet.role=schema-test",
            "-e",
            "POSTGRES_PASSWORD=disposable-fixture-only",
            image,
        ],
        check=False,
        timeout=60,
    )
    assert created.ok, "disposable PostgreSQL fixture failed"
    cid = created.stdout.strip()

    def query(sql):
        return run(
            [
                "docker",
                "exec",
                "-i",
                "-e",
                "PGPASSWORD",
                cid,
                "psql",
                "-X",
                "-h",
                "127.0.0.1",
                "-U",
                "postgres",
                "-d",
                "postgres",
                "-v",
                "ON_ERROR_STOP=1",
                "-qAt",
            ],
            input_data=sql,
            env={
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "PGPASSWORD": "disposable-fixture-only",
            },
            check=False,
            timeout=30,
        )

    try:
        for _ in range(60):
            if query("SELECT 1").ok:
                break
            time.sleep(1)
        assert query(
            "CREATE TABLE public.items (id int PRIMARY KEY, amount int CHECK(amount>0)); "
            "INSERT INTO public.items VALUES(1,7)"
        ).ok
        before_result = query(READ_SQL)
        assert before_result.ok, "catalog query failed"
        before = s.normalize(json.loads(before_result.stdout), "target", SUPPORTED_PIN)
        assert query(
            "ALTER TABLE public.items ADD COLUMN note text; "
            "CREATE INDEX amounts ON public.items(amount); "
            "ALTER TABLE public.items ENABLE ROW LEVEL SECURITY; "
            "CREATE POLICY reader ON public.items USING (amount > 0)"
        ).ok
        after = s.normalize(json.loads(query(READ_SQL).stdout), "source", SUPPORTED_PIN)
        result = s.compare(after, before)
        assert {d.kind for d in result.differences} == {"COLUMN", "INDEX", "RLS", "POLICY"}
        assert s.plan_from_diff(result).summary["SAFE"] == 1
        assert query("SELECT amount FROM public.items").stdout.strip() == "7"
        assert s.normalize(json.loads(query(READ_SQL).stdout), "source", SUPPORTED_PIN) == after
        assert not query("BEGIN READ ONLY; CREATE TABLE public.forbidden(x int); ROLLBACK").ok
        assert (
            query("SELECT count(*) FROM pg_class WHERE relname='forbidden'").stdout.strip() == "0"
        )
    finally:
        inspected = run(
            ["docker", "inspect", "--format", '{{index .Config.Labels "io.sbfleet.role"}}', cid],
            check=False,
        )
        assert inspected.ok and inspected.stdout.strip() == "schema-test"
        assert run(["docker", "rm", "-fv", cid], check=False, timeout=60).ok
