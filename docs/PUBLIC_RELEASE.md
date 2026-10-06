# Public release operator sequence

This document is for maintainers publishing SBfleet from the **private development repository** to a **clean public repository**. Do not flip the private repo public.

## Problem

The private GitHub slug `Pepinko81/sbfleet` holds full development history (internal audits, run evidence, personal paths). Publishing that history would expose material that the public tree intentionally omits.

## Safe sequence

1. Finish sanitization on a private branch; run the full test and lint gates.
2. Confirm **one semver everywhere** (`pyproject.toml`, `sbfleet --version`, CHANGELOG, release tag).
3. Ensure the working tree is **clean** (`git status --short` empty).
4. Run `scripts/export-public.sh --out ~/Projects/sbfleet-public-candidate` (no `--allow-dirty` for releases).
5. Review the candidate tree and public `EXPORT_MANIFEST.json` (release version + file list only). Confirm the sibling sidecar `sbfleet-public-candidate.PRIVATE_PROVENANCE.json` records the private `source_commit` and is **not** copied into the public repository.
6. Run `scripts/validate-public-candidate.sh` — must report zero workflow terms, zero private SHAs in the candidate, version `1.0.0`.
7. **Operator only:** rename the private GitHub repository (for example to `sbfleet-dev-private`) so the desired public slug is free.
8. **Operator only:** create a new empty public repository at `github.com/Pepinko81/sbfleet` (no README/license from template if the candidate already includes them).
9. **Operator only:** `git init` in the candidate, first commit, push `main`, tag `v1.0.0` (or chosen semver), create GitHub Release.
10. Update `pyproject.toml` `[project.urls]`, README links, `SECURITY.md`, and `sbfleet-site` `GITHUB_URL` to the public repo.
11. Deploy the landing site static build (landing source remains private; only `dist/` is published to nginx).

## Future updates

Develop in the private repo → scrub → export from clean commit → commit in public repo. Never force-push private history into the public repository.

## Autonomous agents

This repository does **not** perform remote rename, create, push, or visibility changes without explicit operator approval.
