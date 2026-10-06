# Test gates and evidence

All commands here are implementation targets; this planning baseline has no test suite/product code yet. pytest names below are contractual areas to create, not claims of existing tests. Tests must run on Python 3.10 and a current supported Python. Dev tools: pytest, ruff, build. No coverage percentage substitutes for behavioral acceptance.

**Checkout isolation (mandatory for development gates):** do not run tests with a bare system/user `python3` that may import another `sbfleet` from `~/.local` or site-packages. Use an isolated project venv and editable install of **this** checkout:

```bash
bash scripts/ensure-dev-env.sh
# or: python3 -m venv .venv && .venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -c "import sbfleet; print(sbfleet.__file__)"
.venv/bin/python -c "from sbfleet import authority; print(authority.__file__)"
# both paths must resolve under <checkout>/src/sbfleet/
```

**Supported full-suite collection command (repository contract):** duplicate basenames exist under `tests/process` and `tests/acceptance` (`test_sandbox`, `test_update`, and some V3 twins). Collection must use importlib mode (also set as `addopts` in `pyproject.toml`):

```bash
.venv/bin/python -m pytest --import-mode=importlib -q
# or with Docker/sandbox gates:
.venv/bin/python -m pytest --import-mode=importlib tests/unit tests/process -q
.venv/bin/python -m pytest --import-mode=importlib tests/integration -q -rs --run-docker
.venv/bin/python -m pytest --import-mode=importlib tests/acceptance -q -rs --run-docker --run-sandbox
```

Bare `python -m pytest` without importlib fails collection on those duplicate module names.

`tests/conftest.py` aborts collection if the imported package is not this repository's `src/sbfleet`. Installed-wheel end-user usage does not require the source tree; this guard is for the repository test workflow only.

## Gates

**G0 package/quality:** `bash scripts/ensure-dev-env.sh`; `.venv/bin/python -m ruff check .`; `.venv/bin/python -m ruff format --check .`; `.venv/bin/python -m build`; `.venv/bin/sbfleet --help`; wheel install in a **separate** fresh venv and console smoke. Compile/import must work without optional Node/Docker/CLI for help/registry commands.

**G1 unit:** `.venv/bin/python -m pytest tests/unit -q`. Slug/path/metadata version validation, atomic writes, malformed registry rows, XDG precedence, flock contention and lock order, port candidate/allocation races, parser/shell active state/slash discovery, env/JWK parsing and redaction, deterministic override/nginx generation, manifest/path/checksum safety, update plan/ref/compatibility and sandbox target guards. Include symlink/absolute path/traversal, newline/option injection and ambiguous dotenv fixtures.

**G2 process:** `python -m pytest tests/process -q`. Fake executables record exact argv/env/cwd and simulate stderr/exit/signal/timeouts without real Docker. Verify scripts get correct scope, no secret output on failure, partial create resume preserves keys, idempotent start/stop, all child pipeline failures, stdout JSON vs stderr, env child exit propagation, no shell interpolation, update phase journals, absent tool handling and no sudo. Assert denylisted remote/prune commands cannot be constructed.

**G3 Compose isolation contract:** `python -m pytest tests/integration/test_compose_contract.py -q --run-docker`. Config-only using exact upstream with placeholders in private files; validate all 11 services and two renders, unique names, scoped networks/volumes, Realtime alias, 4 loopback port mappings per project, no socket/host networking/escaped bind. Assert no upstream vendor bytes change after generator integration. Compose capability probe must fail for unsupported !override rather than merge unsafe ports. No secret config printed.

**G4 single real stack:** `python -m pytest tests/integration/test_project_lifecycle.py -q --run-docker`. Start official pinned stack, full health (not container existence), Studio unauthenticated rejection and authenticated HTML, Auth health, REST query fixture, Storage upload/download and Realtime websocket fixture; SQL marker survives stop/start. Deliberately stop auth and corrupt credential fixture to prove doctor/status distinguish degraded/unhealthy. Restore fixture after test. Direct DB/pooler test connections stay loopback.

**G5 two-project acceptance:** `python -m pytest tests/acceptance/test_two_projects.py -q --run-docker`. Start A and B simultaneously with unique test fleet/project IDs. Assert different UUIDs, Compose/container/network/volume identities, bind roots and every secret (compare in memory, report booleans only), different host ports and two original Studio instances. Insert same table/key with different values in each; create Auth user through each Admin API using unique email and verify no cross-query visibility; wrong project key must fail authentication. Upload same Storage object path with different bytes and compare downloads. Check Realtime alias resolves to own container inside each network. Stop/restart A while continuously reading B and checking Studio/Auth/DB. Backup/remove A, prove B data/resources/health unchanged. Assert by resource class after A removal: **A** containers absent; **B** container ID/fingerprint unchanged; unrelated sentinel volume ID/data unchanged (not a mixed global `before_ids - after_ids` claim).

**G6 backup/restore:** `python -m pytest tests/acceptance/test_backup_restore.py -q --run-docker`. Seed SQL marker, app role/grants, Auth user, Storage bucket+binary object, snippet/function artifact and Vault secret. Backup, record encrypted receipt with `verification=recovery` only after disposable recovery verification under contract `recovery-verify/v3` (ordinary production path: writer-quiesce then snapshot-bound `source_facts` + Vault challenge; fixtures may add probes but must not define a stronger recovery level). Mutate/delete data, restore A with two-phase prevalidation **plus requested-archive disposable recovery verification before target mutation**, verify exact SQL/roles/Auth/object SHA256 and decrypted Vault value where seeded. Encrypted archive must not contain known secret plaintext. Also cover STOPPED-source backup with **exit 0** and currently usable recovery archive (not a tolerated `{0,1,8}` range). Sentinel Docker resources must survive. Quarantine must protect original until verified restore. Backup/restore unit regressions: `tests/unit/test_recovery_verify_source_facts.py`, `test_restore_archive_before_mutation.py`, `test_backup_plaintext_cleanup.py`, `test_capacity_unknown_fail_closed.py`, `test_dotenv_grammar_compose.py`.

**G7 update safety:** `python -m pytest tests/process/test_update.py tests/unit/test_update_fault_injection.py tests/unit/test_update_target_surface_binding.py -q`; `python -m pytest tests/acceptance/test_update.py -q --run-docker`. Directed edge `self-hosted/v0.8.1`→`self-hosted/v0.8.2` only unless `REVIEWED_TRANSITIONS` extended. Dry-run live-unchanged; staging failure hash proof; timeout; plaintext backup containment; HEALTHY and STOPPED prior-state cases. Official updater staged output must bind to approved `to_sha` before promotion. Same-ref verified no-op is separate from transition proof.

**G8 sandbox safety:** `.venv/bin/python -m pytest tests/acceptance/test_sandbox.py -q --run-docker --run-sandbox`. Unique disposable app fixtures and CLI IDs under operation-owned temp roots; no Cloud login/link. Prove adoption uniqueness (duplicate ID / copy / symlink), foreign/wrong-option network refusal, linked/dotenv refusal, **stateful SQL via `sandbox env` (write → query → stop → start-as-existing-adoption → query → reset → query-absent)**, local Studio, destroy preserves app source and unrelated sentinels, ownership-bound inventory. Assert adopted-start live preflight refuses foreign/unknown runtime with zero unproven start/stop/destroy dispatch (V3-005). Assert repaired authority boundaries: project-ID revalidation collision refuse, ownership UNKNOWN/foreign blocks destructive dispatch, post-lock config reread, endpoint locality. Inspect published HostIp on start/reset; fail closed on inspect failure. Invalid Cloud token sentinel; Management API not required for lifecycle. If real Drizzle toolchain is unavailable, the stateful SQL/`sandbox env` stand-in is acceptable evidence; documented Drizzle workflow remains WAITING_EXTERNAL (do not claim Drizzle from SQL stand-in). Sandbox unit regressions: `tests/unit/test_sandbox_adopted_start_preflight.py`, `test_configured_diagnostic_boundary.py`, `test_doctor_compose_images.py`.

**G9 nginx (OPTIONAL TEMPLATE):** `python -m pytest tests/unit/test_nginx.py -q`; `python -m pytest tests/integration/test_nginx_fixture.py -q --run-docker`. Proves shipped private-prefix `nginx validate` (`nginx -t -p …` on SSL-listen-stripped generated text) when a host nginx binary exists — **not** `nginx -v` as integration/HTTPS/proxy acceptance. Skip OPTIONAL when binary absent. Never touches `/etc/nginx`, never reloads host, no TLS automation. Template output is not a validated installation.

**G10 destructive safety:** `python -m pytest tests/integration/test_adversarial_ownership.py -q --run-docker`. Compose live authority: `python -m pytest tests/integration/test_compose_authority_adversarial_docker.py -q --run-docker` (renamed Compose container, wrong labels, foreign net/vol, residual invent, daemon failure refuse, sentinel before/after). Also `tests/acceptance/test_ownership.py` points here. Test cross-project `.env` selector attack, copied identity, foreign/partial labels, renamed owned-looking resources, bind/symlink escape, unsafe lock files, start vs lock holder concurrency, interrupted journals, wrong namespace. Assert sentinel IDs/bytes unchanged; no prune / no `--remove-orphans`.

**G11 final:** run all focused suites, G0 checks and gates G3–G10; review docs/examples against --help, no architecture drift, no secrets staged, task ledger complete, evidence redacted and commit-linked. V1 COMPLETE only if every mandatory gate actually passed.

## Test harness safety and prerequisites

Real tests require explicit --run-docker, available local Docker, compatible Compose, sufficient observed disk/RAM, official images/network fetch and backup age identity created only for disposable fixtures. Sandbox additionally --run-sandbox and pinned CLI; Drizzle acceptance needs its app dev dependency. No fixed memory-per-project claim: inspect free resources and upstream image pulls, serialize suites, record measured docker stats --no-stream if useful. Two full stacks are compulsory evidence; low RAM means WAITING_EXTERNAL, never replace G5 with mocks.

Use unique `sbfleet-test-<runuuid>` root plus fleet/project IDs. Record every resource ID created in an ownership journal, apply labels including run UUID, verify labels before each delete. CLI-controlled resources lacking custom labels require exact project-id labels plus pre/post creation inventory and selected private network/mount evidence; names alone insufficient. Cleanup in finally/fixture teardown (including setup failure via fixture finalizers — see `tests/fixture_cleanup.py` label-proven fleet cleanup), no global discovery-based deletion, no global prune, no image cleanup, no --all, no broad --remove-orphans. A failed cleanup emits exact IDs and safe next steps, preserving journal. Never operate user's real projects or unrelated Supabase instances. Do not delete unrelated networks to solve Docker address-pool exhaustion.

Store evidence as redacted `docs/verification/<gate>-<date>.md` during implementation: command, date, git SHA, tool/upstream/CLI versions, fixtures/resource IDs, assertions and actual result; full secret-bearing stdout stays out of Git. If unavailable, record exact unmet prerequisite and code/unit completion separately in run state. No invented PASS or silently skipped mandatory test.
