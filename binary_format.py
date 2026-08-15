"""Strict PE32/I386 and ELF32/I386 input validation."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path


class BinaryFormatError(ValueError):
    pass


@dataclass(frozen=True)
class BinaryInfo:
    path: Path
    platform: str
    container: str
    bits: int
    machine: str


def inspect_binary(path: str | Path) -> BinaryInfo:
    target = Path(path)
    if not target.is_file():
        raise BinaryFormatError(f"Binary file not found: {target}")
    with target.open("rb") as handle:
        header = handle.read(64)
        if header.startswith(b"MZ"):
            if len(header) < 64:
                raise BinaryFormatError(f"Truncated DOS header: {target}")
            pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
            handle.seek(pe_offset)
            pe_header = handle.read(26)
            if len(pe_header) < 26 or pe_header[:4] != b"PE\0\0":
                raise BinaryFormatError(f"Invalid PE signature: {target}")
            machine = struct.unpack_from("<H", pe_header, 4)[0]
            optional_magic = struct.unpack_from("<H", pe_header, 24)[0]
            if machine != 0x014C or optional_magic != 0x010B:
                raise BinaryFormatError(
                    f"Unsupported PE architecture for {target}: machine=0x{machine:04x}, magic=0x{optional_magic:04x}"
                )
            return BinaryInfo(target.resolve(), "windows", "PE", 32, "I386")
        if header.startswith(b"\x7fELF"):
            if len(header) < 20:
                raise BinaryFormatError(f"Truncated ELF header: {target}")
            elf_class, byte_order = header[4], header[5]
            endian = "<" if byte_order == 1 else ">" if byte_order == 2 else None
            machine = struct.unpack_from(f"{endian}H", header, 18)[0] if endian else -1
            if elf_class != 1 or byte_order != 1 or machine != 3:
                raise BinaryFormatError(
                    f"Unsupported ELF architecture for {target}: class={elf_class}, data={byte_order}, machine={machine}"
                )
            return BinaryInfo(target.resolve(), "linux", "ELF", 32, "I386")
    raise BinaryFormatError(f"Unsupported binary format: {target}")


def validate_binary(path: str | Path, platform: str) -> BinaryInfo:
    if platform not in {"windows", "linux"}:
        raise BinaryFormatError(f"Unsupported platform: {platform}")
    info = inspect_binary(path)
    if info.platform != platform:
        raise BinaryFormatError(f"Binary/platform mismatch: expected {platform}, found {info.platform}: {path}")
    return info
