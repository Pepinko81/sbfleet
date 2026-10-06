# Third-Party Notices

SBfleet is independent open-source software. Third-party names and marks belong to their respective owners.

This file lists materially downloaded, bundled, or interoperated third-party components. Checksum pins in `packaging/tool-pins.toml` verify integrity; they do not transfer ownership.

## SBfleet (this repository)

- **Component:** SBfleet source code
- **License:** MIT ([LICENSE](LICENSE))
- **Use:** Original CLI, registry, lifecycle, backup, sandbox wrapper

## Supabase CLI

- **Component:** Supabase CLI
- **Upstream:** https://github.com/supabase/cli
- **Pinned version:** 2.118.0 (see `packaging/tool-pins.toml`)
- **License:** MIT (license text in upstream `apps/cli-go/LICENSE` at tag v2.118.0)
- **Use:** Downloaded by `scripts/install-user.sh`; invoked by absolute path for sandbox and upstream operations
- **Notice:** Copyright (c) Supabase, Inc. and contributors — MIT terms apply to copies/redistributions of the CLI binary

## age

- **Component:** age and age-keygen
- **Upstream:** https://github.com/FiloSottile/age
- **Pinned version:** 1.3.2
- **License:** BSD-3-Clause ([LICENSE](https://github.com/FiloSottile/age/blob/v1.3.2/LICENSE))
- **Use:** Downloaded by installer; used for encrypted backup archives
- **Notice:** Retain copyright and license conditions when redistributing binaries

## Official self-hosted Supabase stack

- **Component:** Supabase self-hosted Docker stack (compose, scripts, vendor tree)
- **Upstream:** https://github.com/supabase/supabase
- **Pinned ref:** `self-hosted/v0.8.2` (commit `564eab8ad7840b13324f68b1bfac074ef8d51c21`)
- **License:** Apache-2.0 (upstream root `LICENSE` at that commit)
- **Use:** Fetched at runtime per project; upstream license file copied beside materialized deployment when present
- **Notice:** Container images pulled by Compose are separate works with their own licenses

## Python dependencies

Runtime dependencies are declared in `pyproject.toml` (for example `prompt_toolkit`, conditional `tomli`). Their licenses apply when those packages are installed via pip.

## Disclaimer

SBfleet is not affiliated with, sponsored by, or endorsed by Supabase or the age project authors. Compatibility with official Supabase tooling is intentional and documented.
