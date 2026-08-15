"""Streaming hashes used by binary identity and snapshot metadata."""

from __future__ import annotations

import hashlib
import zlib
from pathlib import Path

HASH_CHUNK_SIZE = 1024 * 1024
CRC64_POLY = 0xC96C5795D7870F42


def _crc64_xz_update(checksum: int, data: bytes) -> int:
    value = checksum
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (CRC64_POLY if value & 1 else 0)
    return value


def hash_file(path: str | Path) -> dict[str, str | int]:
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    crc32 = 0
    crc64 = 0xFFFFFFFFFFFFFFFF
    size = 0
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(HASH_CHUNK_SIZE), b""):
            md5_hash.update(chunk)
            sha256_hash.update(chunk)
            crc32 = zlib.crc32(chunk, crc32)
            crc64 = _crc64_xz_update(crc64, chunk)
            size += len(chunk)
    return {
        "md5": md5_hash.hexdigest(),
        "sha256": sha256_hash.hexdigest(),
        "crc32": f"{crc32 & 0xFFFFFFFF:08x}",
        "crc64": f"{crc64 ^ 0xFFFFFFFFFFFFFFFF:016x}",
        "size": size,
    }
