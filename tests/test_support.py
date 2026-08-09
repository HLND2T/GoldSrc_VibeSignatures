from __future__ import annotations

import struct
from pathlib import Path

import yaml


def write_pe32(path: Path, payload: bytes = b"") -> Path:
    data = bytearray(0x200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84, 0x14C)
    struct.pack_into("<H", data, 0x94, 0xE0)
    struct.pack_into("<H", data, 0x98, 0x10B)
    data.extend(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def write_pe64(path: Path) -> Path:
    write_pe32(path)
    data = bytearray(path.read_bytes())
    struct.pack_into("<H", data, 0x84, 0x8664)
    struct.pack_into("<H", data, 0x98, 0x20B)
    path.write_bytes(data)
    return path


def write_elf32(path: Path, payload: bytes = b"") -> Path:
    data = bytearray(64)
    data[:6] = b"\x7fELF\x01\x01"
    struct.pack_into("<H", data, 16, 2)
    struct.pack_into("<H", data, 18, 3)
    data.extend(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def write_config(path: Path, *, skill=None, symbols=None, both_platforms=True) -> Path:
    module = {
        "name": "engine",
        "path_windows": "Game/hw.dll",
        "skills": [] if skill is None else [skill],
        "symbols": [] if symbols is None else symbols,
    }
    if both_platforms:
        module["path_linux"] = "Game/hw.so"
    path.write_text(yaml.safe_dump({"modules": [module]}, sort_keys=False), encoding="utf-8")
    return path
