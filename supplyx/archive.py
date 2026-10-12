"""
Safe archive extraction.

Every archive the gate unpacks is untrusted, so extraction must never write outside the destination directory (tar-slip /
zip-slip) and must not be usable as a decompression bomb.
"""
import io
import os
import tarfile
import zipfile

MAX_UNPACKED_BYTES = 500 * 1024 * 1024  # 500 MB hard cap on extracted size
MAX_MEMBERS = 20_000


class UnsafeArchiveError(Exception):
    pass


def _unpack_tar(buf: io.BytesIO, dest: str) -> None:
    with tarfile.open(fileobj=buf) as tf:
        members = tf.getmembers()
        if len(members) > MAX_MEMBERS:
            raise UnsafeArchiveError(f"too many members ({len(members)})")
        if sum(m.size for m in members) > MAX_UNPACKED_BYTES:
            raise UnsafeArchiveError("unpacked size exceeds limit")
        # filter="data" rejects absolute paths, `..` traversal, links that
        # escape dest, and device/special files.
        try:
            tf.extractall(dest, filter="data")
        except tarfile.FilterError as exc:
            raise UnsafeArchiveError(str(exc)) from exc


def _unpack_zip(buf: io.BytesIO, dest: str) -> None:
    root = os.path.realpath(dest)
    with zipfile.ZipFile(buf) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_MEMBERS:
            raise UnsafeArchiveError(f"too many members ({len(infos)})")
        if sum(i.file_size for i in infos) > MAX_UNPACKED_BYTES:
            raise UnsafeArchiveError("unpacked size exceeds limit")
        for info in infos:
            target = os.path.realpath(os.path.join(root, info.filename))
            if target != root and not target.startswith(root + os.sep):
                raise UnsafeArchiveError(f"path escapes destination: {info.filename}")
        for info in infos:
            zf.extract(info, root)


def safe_unpack(data: bytes, dest: str) -> None:
    """Unpack a tar/zip archive into dest, refusing anything that escapes it."""
    buf = io.BytesIO(data)
    # Detect format by magic bytes; fall back to tarfile's own detection
    if data[:4] == b"PK\x03\x04":
        _unpack_zip(buf, dest)
    else:
        _unpack_tar(buf, dest)
