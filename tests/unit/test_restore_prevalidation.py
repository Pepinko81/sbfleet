"""Restore prevalidation."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path
from unittest import mock

import pytest

from sbfleet.archive_safe import (
    ArchiveSafetyError,
    build_tar_from_tree,
    read_manifest_from_tar,
    safe_extract,
)
from sbfleet.backup_manifest import (
    ManifestError,
    bootstrap_expected_from_manifest,
    compatibility_matches,
    inventory_to_member_specs,
    project_identity_matches,
    require_recovery_files,
    require_same_pin,
    validate_internal_manifest,
)

PIN_REF = "self-hosted/v0.8.2"
PIN_SHA = "564eab8ad7840b13324f68b1bfac074ef8d51c21"


def _file_entry(path: str, data: bytes) -> dict:
    return {
        "path": path,
        "type": "file",
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _valid_env_bytes() -> bytes:
    env = {
        "JWT_SECRET": "j" * 32,
        "ANON_KEY": "anon-key-value-aaaaaaa",
        "SERVICE_ROLE_KEY": "service-role-key-bbbb",
        "SUPABASE_PUBLISHABLE_KEY": "pub-key-value-ccccccc",
        "SUPABASE_SECRET_KEY": "sec-key-value-dddddddd",
        "JWT_KEYS": '[{"kty":"oct","k":"x"}]',
        "JWT_JWKS": '{"keys":[{"kty":"oct","k":"x"}]}',
        "POSTGRES_PASSWORD": "postgres-password-1",
        "DASHBOARD_USERNAME": "admin",
        "DASHBOARD_PASSWORD": "dashboard-password1",
        "SECRET_KEY_BASE": "secret-key-base-123456789012",
        "VAULT_ENC_KEY": "vault-enc-key-1234567890",
        "POOLER_TENANT_ID": "tenantfromsource01",
    }
    return "".join(f"{k}={v}\n" for k, v in sorted(env.items())).encode()


def _minimal_manifest(inventory: list[dict], **overrides: object) -> dict:
    man = {
        "format_version": 1,
        "backup_id": "b1",
        "project_id": "p1",
        "fleet_id": "f1",
        "created_at": "2026-10-01T00:00:00Z",
        "method": "cold-physical",
        "profile": "standard",
        "upstream": {"ref": PIN_REF, "sha": PIN_SHA},
        "images": {
            "db": {
                "image_ref": "public.ecr.aws/supabase/postgres:15",
                "image_id": "sha256:" + "a" * 64,
                "platform": "linux/amd64",
            }
        },
        "postgres": {"pg_version": "15", "major": 15, "cluster_state": "shut down"},
        "inventory": inventory,
    }
    man.update(overrides)
    return man


def _base_inventory(*, env: bytes | None = None, project: bytes | None = None) -> list[dict]:
    env_b = env if env is not None else _valid_env_bytes()
    proj_b = project if project is not None else b'{"id":"p1"}\n'
    return [
        _file_entry("project.json", proj_b),
        _file_entry("deployment/.env", env_b),
        _file_entry("db-config/pgsodium_root.key", b"key-material"),
        _file_entry("postgres/PG_VERSION", b"15\n"),
        _file_entry("storage/.keep", b""),
        {"path": "postgres", "type": "dir", "size": 0},
        {"path": "db-config", "type": "dir", "size": 0},
        {"path": "storage", "type": "dir", "size": 0},
        {"path": "deployment", "type": "dir", "size": 0},
    ]


def _build_archive(tmp_path: Path, man: dict, files: dict[str, bytes]) -> Path:
    payload = tmp_path / "payload"
    payload.mkdir()
    for path, data in files.items():
        p = payload / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    for d in ("postgres", "db-config", "storage", "deployment"):
        (payload / d).mkdir(exist_ok=True)
    man_bytes = (json.dumps(man, indent=2, sort_keys=True) + "\n").encode()
    (payload / "manifest.json").write_bytes(man_bytes)
    tar_path = tmp_path / "a.tar"
    build_tar_from_tree(payload, tar_path)
    return tar_path


def test_read_manifest_requires_canonical_name(tmp_path: Path) -> None:
    tar_path = tmp_path / "t.tar"
    data = b'{"format_version":1}\n'
    with tarfile.open(tar_path, "w:") as tf:
        info = tarfile.TarInfo("./manifest.json")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    with pytest.raises(ArchiveSafetyError, match="alias|exactly one|missing"):
        read_manifest_from_tar(tar_path)


def test_path_alias_inventory_refused() -> None:
    man = _minimal_manifest(
        [
            _file_entry("project.json", b"{}"),
            _file_entry("deployment/.env", b"A=1\n"),
            _file_entry("db-config/pgsodium_root.key", b"k"),
            _file_entry("postgres/./x", b"WRONG"),
            {"path": "postgres", "type": "dir", "size": 0},
            {"path": "db-config", "type": "dir", "size": 0},
            {"path": "storage", "type": "dir", "size": 0},
            {"path": "deployment", "type": "dir", "size": 0},
        ]
    )
    with pytest.raises(ManifestError, match="normalized|alias|unsafe"):
        inventory_to_member_specs(man)


def test_undeclared_member_refused_on_expected_extract(tmp_path: Path) -> None:
    files = {
        "project.json": b'{"id":"p1"}\n',
        "deployment/.env": _valid_env_bytes(),
        "db-config/pgsodium_root.key": b"key-material",
        "postgres/PG_VERSION": b"15\n",
        "storage/.keep": b"",
    }
    inv = _base_inventory()
    man = _minimal_manifest(inv)
    tar_path = _build_archive(tmp_path, man, files)
    man_raw, man_spec, _ = read_manifest_from_tar(tar_path)
    internal = json.loads(man_raw.decode())
    expected, checksums = bootstrap_expected_from_manifest(
        internal, manifest_tar_size=man_spec.size
    )

    evil = tmp_path / "evil.tar"
    with tarfile.open(tar_path, "r:") as src, tarfile.open(evil, "w:") as dst:
        for m in src.getmembers():
            f = src.extractfile(m) if m.isreg() else None
            dst.addfile(m, f)
        extra = tarfile.TarInfo("postgres/undeclared")
        data = b"sneaky"
        extra.size = len(data)
        dst.addfile(extra, io.BytesIO(data))
    with pytest.raises(ArchiveSafetyError, match="outside declared|members outside"):
        safe_extract(evil, tmp_path / "out", expected=expected, verify_sha256=checksums)


def test_missing_required_file_refused_by_manifest() -> None:
    man = _minimal_manifest(
        [
            _file_entry("project.json", b"{}"),
            _file_entry("deployment/.env", b"A=1\n"),
            {"path": "postgres", "type": "dir", "size": 0},
            {"path": "db-config", "type": "dir", "size": 0},
            {"path": "storage", "type": "dir", "size": 0},
            {"path": "deployment", "type": "dir", "size": 0},
        ]
    )
    with pytest.raises(ManifestError, match="pgsodium_root.key"):
        validate_internal_manifest(man)
    with pytest.raises(ManifestError, match="pgsodium_root.key"):
        require_recovery_files(man)


def test_checksum_mismatch_refused(tmp_path: Path) -> None:
    files = {
        "project.json": b'{"id":"p1"}\n',
        "deployment/.env": _valid_env_bytes(),
        "db-config/pgsodium_root.key": b"key-material",
        "postgres/PG_VERSION": b"15\n",
        "storage/.keep": b"",
    }
    inv = _base_inventory()
    # Corrupt checksum for postgres/PG_VERSION
    for entry in inv:
        if entry.get("path") == "postgres/PG_VERSION":
            entry["sha256"] = "0" * 64
    man = _minimal_manifest(inv)
    tar_path = _build_archive(tmp_path, man, files)
    man_raw, man_spec, _ = read_manifest_from_tar(tar_path)
    internal = json.loads(man_raw.decode())
    expected, checksums = bootstrap_expected_from_manifest(
        internal, manifest_tar_size=man_spec.size
    )
    with pytest.raises(ArchiveSafetyError, match="checksum"):
        safe_extract(tar_path, tmp_path / "out", expected=expected, verify_sha256=checksums)


def test_invalid_env_refused_before_mutation(tmp_path: Path) -> None:
    from sbfleet import backup as bak
    from sbfleet import upstream as up

    bad_env = b"NOT_A_KEY\n"
    files = {
        "project.json": b'{"id":"p1"}\n',
        "deployment/.env": bad_env,
        "db-config/pgsodium_root.key": b"key-material",
        "postgres/PG_VERSION": b"15\n",
        "storage/.keep": b"",
    }
    inv = _base_inventory(env=bad_env)
    man = _minimal_manifest(inv)
    tar_path = _build_archive(tmp_path, man, files)
    dest = tmp_path / "dep"
    dest.mkdir()
    (dest / ".supabase-version").write_text(f"ref={PIN_REF}\n", encoding="utf-8")
    (dest / ".sbfleet-upstream").write_text(f"ref={PIN_REF}\nsha={PIN_SHA}\n", encoding="utf-8")
    meta = {
        "id": "p1",
        "upstream": {"ref": PIN_REF, "sha": PIN_SHA},
        "image_digests": {
            "db": {
                "image_ref": "public.ecr.aws/supabase/postgres:15",
                "image_id": "sha256:" + "a" * 64,
                "platform": "linux/amd64",
            }
        },
    }
    with mock.patch.object(bak, "_authoritative_destination_pin", return_value=meta["upstream"]):
        with pytest.raises((ManifestError, up.UpstreamError, bak.BackupError)):
            bak.prevalidate_restore_archive(
                tar_path=tar_path,
                extract_dir=tmp_path / "extract",
                destination_project_id="p1",
                destination_meta=meta,
                deployment=dest,
                root=tmp_path,
                ciphertext_sha256="c" * 64,
                filename_backup_id="b1",
                receipt=None,
            )


def test_wrong_project_identity_refused() -> None:
    with pytest.raises(ManifestError, match="identity mismatch"):
        project_identity_matches({"project_id": "aaa"}, "bbb")


def test_missing_pgsodium_key_refused() -> None:
    man = _minimal_manifest(
        [
            _file_entry("project.json", b"{}"),
            _file_entry("deployment/.env", b"A=1\n"),
            _file_entry("postgres/PG_VERSION", b"15\n"),
            _file_entry("storage/.keep", b""),
            {"path": "postgres", "type": "dir", "size": 0},
            {"path": "db-config", "type": "dir", "size": 0},
            {"path": "storage", "type": "dir", "size": 0},
            {"path": "deployment", "type": "dir", "size": 0},
        ]
    )
    with pytest.raises(ManifestError, match="pgsodium_root.key"):
        require_recovery_files(man)


def test_unknown_destination_pin_refuses() -> None:
    man = _minimal_manifest(_base_inventory())
    with pytest.raises(ManifestError, match="UNKNOWN|unavailable"):
        compatibility_matches(
            man,
            destination_images={
                "db": {"image_id": "UNKNOWN", "image_ref": "x", "platform": "linux/amd64"}
            },
            destination_upstream={"ref": PIN_REF, "sha": "UNKNOWN"},
        )
    with pytest.raises(ManifestError, match="UNKNOWN"):
        require_same_pin(man, destination_ref=PIN_REF, destination_sha="UNKNOWN")


def test_cross_pin_refuses() -> None:
    man = _minimal_manifest(_base_inventory())
    dest_images = {
        "db": {
            "image_ref": "public.ecr.aws/supabase/postgres:15",
            "image_id": "sha256:" + "a" * 64,
            "platform": "linux/amd64",
        }
    }
    with pytest.raises(ManifestError, match="cross-pin"):
        compatibility_matches(
            man,
            destination_images=dest_images,
            destination_upstream={
                "ref": "self-hosted/v0.8.1",
                "sha": "8c7a4d9dbbaf8b552893822e89d7bf06f33f9220",
            },
        )


def test_prevalidation_failure_skips_quarantine_and_stop(tmp_path: Path) -> None:
    from sbfleet import backup as bak

    root = tmp_path / "fleet"
    root.mkdir()
    with mock.patch.object(bak, "_require_age", return_value="/bin/true"):
        with mock.patch.object(bak, "_resolve_identity", return_value=tmp_path / "id"):
            (tmp_path / "id").write_text("AGE-SECRET-KEY-1\n", encoding="utf-8")
            arch = tmp_path / "x.tar.age"
            arch.write_bytes(b"ciphertext" * 20)
            with mock.patch("sbfleet.authority.authorize_mutation") as am:
                ctx = mock.Mock()
                ctx.meta = {
                    "id": "p1",
                    "upstream": {"ref": PIN_REF, "sha": PIN_SHA},
                }
                ctx.deployment = root / "dep"
                ctx.deployment.mkdir()
                ctx.root = root
                ctx.slug = "s"
                ctx.operation_id = "op"
                ctx.compose_project = "cp"
                cm = mock.MagicMock()
                cm.__enter__.return_value = ctx
                cm.__exit__.return_value = False
                am.return_value = cm
                with mock.patch("sbfleet.authority.begin_operation"):
                    with mock.patch("sbfleet.authority.fail_operation"):
                        with mock.patch("sbfleet.process.run") as run_mock:

                            def _run(argv, **kwargs):
                                out = Path(argv[argv.index("-o") + 1])
                                out.write_bytes(b"not-a-tar")
                                r = mock.Mock()
                                r.ok = True
                                r.stdout = ""
                                r.stderr = ""
                                return r

                            run_mock.side_effect = _run
                            with mock.patch.object(bak, "_create_backup_locked") as pre:
                                with mock.patch.object(bak, "_quiesce_ordered") as quiesce:
                                    with mock.patch.object(bak, "_quarantine_unit") as qq:
                                        code = bak.restore_backup(
                                            root,
                                            "s",
                                            str(arch),
                                            yes=True,
                                            identity=str(tmp_path / "id"),
                                        )
    assert code != 0
    pre.assert_not_called()
    quiesce.assert_not_called()
    qq.assert_not_called()


def test_authoritative_pin_unknown_without_stamps(tmp_path: Path) -> None:
    from sbfleet import backup as bak

    dep = tmp_path / "dep"
    dep.mkdir()
    meta = {"id": "p1", "upstream": {"ref": PIN_REF, "sha": PIN_SHA}}
    with pytest.raises(ManifestError, match="UNKNOWN"):
        bak._authoritative_destination_pin(tmp_path, dep, meta)
