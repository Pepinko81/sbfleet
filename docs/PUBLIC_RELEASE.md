# Public release operator sequence

Develop in the private repository and publish only a sanitized tree to the public
repository. Never publish private development history or change its visibility.

## Release preparation

1. Prepare the version, README, and changelog on a private release branch.
2. Confirm matching versions in `pyproject.toml`, package metadata, and `sbfleet --version`.
3. Run lint, unit/process, build, and isolated wheel-install gates; complete the separate installation gate before publication.
4. Validate the public allowlist and deny rules using `scripts/export-public.sh --out /tmp/sbfleet-public-check --dry-run` from a clean tracked tree. Known untracked private notes must remain excluded. Dry-run writes no candidate files.

## Later publication — explicit operator authorization required

1. After installation validation and publication approval, finalize the release status/date in release-facing documentation and commit it privately. Export from that approved clean commit with `scripts/export-public.sh --out /tmp/sbfleet-public-candidate`. Never use `--allow-dirty` for a release.
2. Review the public manifest (version and file list only). Keep its sibling private provenance sidecar outside the public repository.
3. Run `scripts/validate-public-candidate.sh /tmp/sbfleet-public-candidate`; require zero forbidden workflow terms, private SHAs, secrets, and symlinks, and the intended release version.
4. Commit the reviewed candidate tree into the existing public repository without importing private Git history. Preserve the public repository's own history.
5. Publish the approved public commit, tag the matching semver, and create the GitHub Release.

Website deployment and repository settings are separate operator actions. Release
preparation alone does not authorize public export, public push, tags, releases,
repository settings changes, or website deployment.
