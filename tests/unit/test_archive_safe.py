"""Fail-closed archive schema and streaming hash tests (regression suite)."""

from __future__ import annotations

import io
import os
import tarfile
from pathlib import Path
from unittest import mock

import pytest

from sbfleet.archive_safe import (
    ArchiveSafetyError,
    MemberSpec,
    build_tar_from_tree,
    normalize_member_path,
    safe_extract,
    sha256_file,
    validate_tar_members,
)


def test_normalize_refuses_absolute():
    with pytest.raises(ArchiveSafetyError):
        normalize_member_path("/etc/passwd")
    with pytest.raises(ArchiveSafetyError):
        normalize_member_path("//abs")


def test_normalize_refuses_traversal():
    with pytest.raises(ArchiveSafetyError):
        normalize_member_path("../x")
    with pytest.raises(ArchiveSafetyError):
        normalize_member_path("a/../../b")
    assert normalize_member_path("./foo/bar") == "foo/bar"


def test_safe_extract_refuses_symlink(tmp_path: Path):
    tar_path = tmp_path / "bad.tar"
    with tarfile.open(tar_path, "w:") as tf:
        info = tarfile.TarInfo(name="link")
        info.type = tarfile.SYMTYPE
        info.linkname = "target"
        tf.addfile(info)
    with pytest.raises(ArchiveSafetyError, match="symlink"):
        safe_extract(tar_path, tmp_path / "out")


def test_safe_extract_refuses_duplicate(tmp_path: Path):
    tar_path = tmp_path / "dup.tar"
    data = b"hello"
    with tarfile.open(tar_path, "w:") as tf:
        for _ in range(2):
            info = tarfile.TarInfo(name="file.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    with pytest.raises(ArchiveSafetyError, match="duplicate"):
        safe_extract(tar_path, tmp_path / "out")


def test_safe_extract_refuses_hardlink(tmp_path: Path):
    tar_path = tmp_path / "hl.tar"
    with tarfile.open(tar_path, "w:") as tf:
        info = tarfile.TarInfo(name="h")
        info.type = tarfile.LNKTYPE
        info.linkname = "other"
        tf.addfile(info)
    with pytest.raises(ArchiveSafetyError, match="hardlink|symlink"):
        safe_extract(tar_path, tmp_path / "out")


def test_safe_extract_refuses_fifo(tmp_path: Path):
    tar_path = tmp_path / "fifo.tar"
    with tarfile.open(tar_path, "w:") as tf:
        info = tarfile.TarInfo(name="f.fifo")
        info.type = tarfile.FIFOTYPE
        tf.addfile(info)
    with pytest.raises(ArchiveSafetyError, match="special"):
        safe_extract(tar_path, tmp_path / "out")


def test_safe_extract_refuses_device(tmp_path: Path):
    tar_path = tmp_path / "dev.tar"
    with tarfile.open(tar_path, "w:") as tf:
        info = tarfile.TarInfo(name="null.dev")
        info.type = tarfile.CHRTYPE
        info.devmajor = 1
        info.devminor = 3
        tf.addfile(info)
    with pytest.raises(ArchiveSafetyError, match="special"):
        safe_extract(tar_path, tmp_path / "out")


def test_per_member_size_limit(tmp_path: Path):
    tar_path = tmp_path / "mem.tar"
    payload = b"x" * 200
    with tarfile.open(tar_path, "w:") as tf:
        info = tarfile.TarInfo(name="chunk.bin")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    with pytest.raises(ArchiveSafetyError, match="size budget"):
        safe_extract(tar_path, tmp_path / "out", max_member_bytes=50)


def test_expansion_budget(tmp_path: Path):
    tar_path = tmp_path / "big.tar"
    payload = b"x" * 1000
    with tarfile.open(tar_path, "w:") as tf:
        info = tarfile.TarInfo(name="big.bin")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    with pytest.raises(ArchiveSafetyError, match="budget"):
        safe_extract(tar_path, tmp_path / "out", max_total_bytes=100)


def test_checksum_mismatch(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("secret-data", encoding="utf-8")
    tar_path = tmp_path / "a.tar"
    build_tar_from_tree(src, tar_path)
    with pytest.raises(ArchiveSafetyError, match="checksum"):
        safe_extract(
            tar_path,
            tmp_path / "out",
            verify_sha256={"a.txt": "0" * 64},
        )


def test_streaming_hash_not_whole_file_read(tmp_path: Path):
    path = tmp_path / "large.bin"
    path.write_bytes(b"a" * (8 * 1024 * 1024))
    chunk_sizes: list[int] = []

    class TrackingFile:
        def __init__(self, fh):
            self._fh = fh

        def read(self, n=-1):
            data = self._fh.read(n)
            chunk_sizes.append(len(data) if data else 0)
            return data

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self._fh.__exit__(*args)

    orig = Path.open

    def open_wrap(self, *args, **kwargs):
        fh = orig(self, *args, **kwargs)
        if self == path and "r" in (args[0] if args else kwargs.get("mode", "r")):
            return TrackingFile(fh)
        return fh

    with mock.patch.object(Path, "open", open_wrap):
        digest = sha256_file(path, chunk=1024 * 1024)
    assert len(digest) == 64
    assert len(chunk_sizes) >= 8
    assert max(chunk_sizes) <= 1024 * 1024
    assert sum(chunk_sizes) == 8 * 1024 * 1024


def test_build_tar_refuses_symlink_in_tree(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "real").write_text("x", encoding="utf-8")
    os.symlink("real", src / "link")
    with pytest.raises(ArchiveSafetyError, match="symlink"):
        build_tar_from_tree(src, tmp_path / "out.tar")


def test_members_outside_manifest(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("a", encoding="utf-8")
    (src / "b.txt").write_text("b", encoding="utf-8")
    tar_path = tmp_path / "t.tar"
    build_tar_from_tree(src, tar_path)
    expected = {
        "a.txt": MemberSpec(path="a.txt", type="file", size=1, sha256=None),
    }
    with tarfile.open(tar_path, "r:") as tf:
        with pytest.raises(ArchiveSafetyError, match="outside declared|undeclared"):
            validate_tar_members(tf, expected=expected)
