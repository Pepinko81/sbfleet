"""Fail-closed archive build/extract and streaming digests .

Safety does not depend on Python tar extract defaults. Age decrypt provides
ciphertext confidentiality/integrity of the payload bytes; this module validates
archive member schema after decrypt — it does not claim cryptographic source
provenance.
"""

from __future__ import annotations

import hashlib
import io
import os
import tarfile
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

# Conservative defaults for V1 personal-project archives.
DEFAULT_MAX_MEMBER_BYTES = 64 * 1024 * 1024 * 1024  # 64 GiB single member
DEFAULT_MAX_TOTAL_BYTES = 128 * 1024 * 1024 * 1024  # 128 GiB expansion
DEFAULT_MAX_MEMBERS = 2_000_000
# Internal manifest.json is small JSON metadata — refuse oversized / non-file.
DEFAULT_MAX_MANIFEST_BYTES = 1 * 1024 * 1024  # 1 MiB
CHUNK = 1024 * 1024


class ArchiveSafetyError(Exception):
    """Archive schema / expansion / path safety refusal."""


@dataclass(frozen=True)
class MemberSpec:
    path: str  # normalized relative path, no leading ./
    type: str  # file | dir
    size: int
    sha256: str | None = None  # None for directories


def sha256_file(path: Path, *, chunk: int = CHUNK) -> str:
    """Stream SHA-256 of a file without loading it into memory."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def sha256_stream(fh: BinaryIO, *, chunk: int = CHUNK) -> str:
    h = hashlib.sha256()
    while True:
        block = fh.read(chunk)
        if not block:
            break
        h.update(block)
    return h.hexdigest()


def normalize_member_path(name: str) -> str:
    """Normalize a tar member name to a relative path; raise on unsafe forms."""
    raw = name.replace("\\", "/")
    if raw.startswith("./"):
        raw = raw[2:]
    if raw.startswith("/") or raw.startswith("../") or raw == ".." or "/../" in f"/{raw}/":
        raise ArchiveSafetyError(f"unsafe archive path: {name!r}")
    parts = [p for p in raw.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ArchiveSafetyError(f"path traversal in archive member: {name!r}")
    if not parts:
        raise ArchiveSafetyError(f"empty archive member path: {name!r}")
    return "/".join(parts)


def _assert_regular_or_dir(member: tarfile.TarInfo) -> str:
    if member.issym() or member.islnk():
        raise ArchiveSafetyError(f"symlink/hardlink refused: {member.name!r}")
    if member.isdev() or member.isfifo() or member.ischr() or member.isblk():
        raise ArchiveSafetyError(f"special member refused: {member.name!r}")
    # Prefer type flags; also refuse sockets if present via mode bits.
    if member.issock() if hasattr(member, "issock") else False:
        raise ArchiveSafetyError(f"socket member refused: {member.name!r}")
    if member.isdir():
        return "dir"
    if member.isfile() or member.type in {tarfile.REGTYPE, tarfile.AREGTYPE, b"0", b"\0", None}:
        return "file"
    # GNU longname etc. should already be resolved by tarfile; refuse unknowns.
    if member.type in {tarfile.DIRTYPE, b"5"}:
        return "dir"
    raise ArchiveSafetyError(f"unsupported member type {member.type!r}: {member.name!r}")


def validate_tar_members(
    tf: tarfile.TarFile,
    *,
    expected: dict[str, MemberSpec] | None = None,
    max_member_bytes: int = DEFAULT_MAX_MEMBER_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_members: int = DEFAULT_MAX_MEMBERS,
) -> list[MemberSpec]:
    """Validate tar member schema; optionally require exact inventory match."""
    seen: dict[str, MemberSpec] = {}
    total = 0
    count = 0
    for member in tf.getmembers():
        count += 1
        if count > max_members:
            raise ArchiveSafetyError(f"member count exceeds budget ({max_members})")
        kind = _assert_regular_or_dir(member)
        path = normalize_member_path(member.name)
        if path in seen:
            raise ArchiveSafetyError(f"duplicate archive member: {path}")
        size = int(member.size) if kind == "file" else 0
        if size < 0:
            raise ArchiveSafetyError(f"negative size for {path}")
        if size > max_member_bytes:
            raise ArchiveSafetyError(f"member {path} exceeds size budget")
        total += size
        if total > max_total_bytes:
            raise ArchiveSafetyError("archive expansion exceeds total budget")
        seen[path] = MemberSpec(path=path, type=kind, size=size, sha256=None)

    if expected is not None:
        exp_paths = set(expected)
        got_paths = set(seen)
        missing = sorted(exp_paths - got_paths)
        extra = sorted(got_paths - exp_paths)
        if missing:
            raise ArchiveSafetyError(f"undeclared manifest entries missing from tar: {missing[:5]}")
        if extra:
            raise ArchiveSafetyError(f"members outside declared manifest: {extra[:5]}")
        for path, spec in expected.items():
            got = seen[path]
            if got.type != spec.type:
                raise ArchiveSafetyError(f"member type mismatch for {path}")
            if spec.type == "file" and got.size != spec.size:
                raise ArchiveSafetyError(
                    f"member size mismatch for {path}: got {got.size} expected {spec.size}"
                )
    return list(seen.values())


def safe_extract(
    tar_path: Path,
    dest: Path,
    *,
    expected: dict[str, MemberSpec] | None = None,
    max_member_bytes: int = DEFAULT_MAX_MEMBER_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_members: int = DEFAULT_MAX_MEMBERS,
    verify_sha256: dict[str, str] | None = None,
) -> list[MemberSpec]:
    """Extract only after schema validation; write files via explicit open/write."""
    dest = dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tar_path, "r:") as tf:
        members = validate_tar_members(
            tf,
            expected=expected,
            max_member_bytes=max_member_bytes,
            max_total_bytes=max_total_bytes,
            max_members=max_members,
        )
        # Re-iterate for extraction (getmembers caches).
        for member in tf.getmembers():
            kind = _assert_regular_or_dir(member)
            path = normalize_member_path(member.name)
            target = (dest / path).resolve()
            try:
                target.relative_to(dest)
            except ValueError as exc:
                raise ArchiveSafetyError(f"extract escape: {path}") from exc
            if kind == "dir":
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                raise ArchiveSafetyError(f"cannot read member: {path}")
            h = hashlib.sha256()
            with open(target, "wb") as out:
                while True:
                    block = src.read(CHUNK)
                    if not block:
                        break
                    h.update(block)
                    out.write(block)
            digest = h.hexdigest()
            if verify_sha256 is not None and path in verify_sha256:
                if digest != verify_sha256[path]:
                    raise ArchiveSafetyError(f"checksum mismatch for {path}")
    return members


def build_tar_from_tree(
    source_root: Path,
    tar_path: Path,
    *,
    include_paths: Iterable[str] | None = None,
) -> dict[str, MemberSpec]:
    """Build an uncompressed tar of regular files/dirs under source_root.

    Paths are stored as normalized relatives. Symlinks and specials are refused.
    """
    source_root = source_root.resolve()
    inventory: dict[str, MemberSpec] = {}
    with tarfile.open(tar_path, "w:") as tf:
        if include_paths is None:
            walk_roots = [source_root]
            rel_bases = [""]
        else:
            walk_roots = []
            rel_bases = []
            for rel in include_paths:
                p = (source_root / rel).resolve()
                try:
                    p.relative_to(source_root)
                except ValueError as exc:
                    raise ArchiveSafetyError(f"include path escapes root: {rel}") from exc
                walk_roots.append(p)
                rel_bases.append(normalize_member_path(rel) if rel not in (".", "") else "")

        for base, _rel_base in zip(walk_roots, rel_bases, strict=True):
            if base.is_file():
                paths = [base]
            else:
                paths = []
                for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
                    # Refuse symlink directories.
                    dirnames[:] = [d for d in dirnames if not (Path(dirpath) / d).is_symlink()]
                    for d in dirnames:
                        paths.append(Path(dirpath) / d)
                    for f in filenames:
                        paths.append(Path(dirpath) / f)

            for path in paths:
                if path.is_symlink():
                    raise ArchiveSafetyError(f"symlink refused in payload: {path}")
                if (
                    path.is_fifo()
                    or path.is_socket()
                    or path.is_block_device()
                    or path.is_char_device()
                ):
                    raise ArchiveSafetyError(f"special file refused: {path}")
                rel = path.relative_to(source_root).as_posix()
                rel = normalize_member_path(rel)
                if path.is_dir():
                    info = tarfile.TarInfo(name=rel)
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    info.size = 0
                    tf.addfile(info)
                    inventory[rel] = MemberSpec(path=rel, type="dir", size=0, sha256=None)
                    continue
                digest = sha256_file(path)
                size = path.stat().st_size
                info = tarfile.TarInfo(name=rel)
                info.type = tarfile.REGTYPE
                info.mode = 0o644
                info.size = size
                with path.open("rb") as fh:
                    tf.addfile(info, fh)
                inventory[rel] = MemberSpec(path=rel, type="file", size=size, sha256=digest)
    return inventory


def iter_file_digests(root: Path) -> Iterator[tuple[str, int, str]]:
    """Yield (normalized_rel, size, sha256) for every regular file under root."""
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if not (Path(dirpath) / d).is_symlink()]
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink() or not path.is_file():
                continue
            rel = normalize_member_path(path.relative_to(root).as_posix())
            yield rel, path.stat().st_size, sha256_file(path)


def write_buffered_hash(data: bytes) -> str:
    """Hash small in-memory blobs (manifest JSON only — not archives)."""
    return hashlib.sha256(data).hexdigest()


def empty_bytes_hash() -> str:
    return hashlib.sha256(b"").hexdigest()


def hash_bytes_io(buf: io.BytesIO) -> str:
    buf.seek(0)
    return sha256_stream(buf)


def inspect_tar_members(
    tar_path: Path,
    *,
    max_member_bytes: int = DEFAULT_MAX_MEMBER_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_members: int = DEFAULT_MAX_MEMBERS,
) -> dict[str, MemberSpec]:
    """Inspect tar member schema WITHOUT extracting payloads to disk."""
    with tarfile.open(tar_path, "r:") as tf:
        members = validate_tar_members(
            tf,
            expected=None,
            max_member_bytes=max_member_bytes,
            max_total_bytes=max_total_bytes,
            max_members=max_members,
        )
    return {m.path: m for m in members}


def read_manifest_from_tar(
    tar_path: Path,
    *,
    max_manifest_bytes: int = DEFAULT_MAX_MANIFEST_BYTES,
    max_member_bytes: int = DEFAULT_MAX_MEMBER_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_members: int = DEFAULT_MAX_MEMBERS,
) -> tuple[bytes, MemberSpec, dict[str, MemberSpec]]:
    """Read exactly one regular ``manifest.json`` from tar without extracting the archive.

    Refuses duplicate normalized paths (including ``./manifest.json`` aliases),
    non-file manifest members, and oversized manifests.
    """
    with tarfile.open(tar_path, "r:") as tf:
        members = validate_tar_members(
            tf,
            expected=None,
            max_member_bytes=max_member_bytes,
            max_total_bytes=max_total_bytes,
            max_members=max_members,
        )
        by_path = {m.path: m for m in members}
        if "manifest.json" not in by_path:
            raise ArchiveSafetyError("archive missing regular manifest.json")
        man_spec = by_path["manifest.json"]
        if man_spec.type != "file":
            raise ArchiveSafetyError("manifest.json must be a regular file")
        if man_spec.size <= 0:
            raise ArchiveSafetyError("manifest.json empty")
        if man_spec.size > max_manifest_bytes:
            raise ArchiveSafetyError(
                f"manifest.json exceeds size limit ({max_manifest_bytes} bytes)"
            )
        # Count raw names that normalize to manifest.json (alias / duplicate guard).
        manifest_infos: list[tarfile.TarInfo] = []
        for info in tf.getmembers():
            try:
                path = normalize_member_path(info.name)
            except ArchiveSafetyError:
                continue
            if path == "manifest.json":
                manifest_infos.append(info)
        if len(manifest_infos) != 1:
            raise ArchiveSafetyError(
                f"expected exactly one manifest.json member, found {len(manifest_infos)}"
            )
        info = manifest_infos[0]
        kind = _assert_regular_or_dir(info)
        if kind != "file":
            raise ArchiveSafetyError("manifest.json must be a regular file")
        # Refuse alias forms that are not the canonical name (path collision risk).
        raw_name = info.name.replace("\\", "/")
        if raw_name != "manifest.json":
            raise ArchiveSafetyError(
                f"manifest.json alias refused: {info.name!r} (require exact manifest.json)"
            )
        src = tf.extractfile(info)
        if src is None:
            raise ArchiveSafetyError("cannot read manifest.json from tar")
        data = src.read(max_manifest_bytes + 1)
        if len(data) != man_spec.size:
            raise ArchiveSafetyError(
                f"manifest.json size mismatch while reading: got {len(data)} header {man_spec.size}"
            )
        if len(data) > max_manifest_bytes:
            raise ArchiveSafetyError(
                f"manifest.json exceeds size limit ({max_manifest_bytes} bytes)"
            )
    return data, man_spec, by_path
