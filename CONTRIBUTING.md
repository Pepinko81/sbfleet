# Contributing to SBfleet

Thank you for helping improve SBfleet. This project is a small Python CLI with strict safety contracts; changes should stay minimal and test-backed.

## Development setup

```bash
bash scripts/ensure-dev-env.sh
.venv/bin/ruff check src tests
.venv/bin/pytest
```

Use `.venv/bin/sbfleet` and `.venv/bin/python` so installed packages cannot shadow the checkout.

## Tests

See [docs/TESTING_STRATEGY.md](docs/TESTING_STRATEGY.md) for gate layers (unit, process, integration, acceptance). Docker-marked tests require `--run-docker`; sandbox tests require `--run-sandbox`.

Never run destructive tests against non-owned projects or production data.

## Documentation

User-facing behavior must match [docs/COMMAND_SPEC.md](docs/COMMAND_SPEC.md) and [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md). Architecture changes require alignment with [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Public export

Release maintainers produce the public tree with `scripts/export-public.sh` from a **clean** git working tree. See [docs/PUBLIC_RELEASE.md](docs/PUBLIC_RELEASE.md).

## Code of conduct

Be respectful and precise in review. SBfleet prioritizes operator safety over convenience shortcuts.
