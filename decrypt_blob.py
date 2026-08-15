"""Decrypt a Metahook "blob" file into a regular PE32 DLL.

The blob format is the obfuscated DLL image used for protected GoldSrc client
modules (e.g. engine\\hw.dll in older builds). This module reverses the loader
implemented in MetaHook's src/LoadBlob.cpp:

  * BlobInfo_t  (68 B, unencrypted)  -- path/describe/company + algorithm marker.
  * BlobHeader_t (24 B, encrypted)   -- checksum, section count, export point,
    image base, entry point, import table.
  * BlobSection_t (20 B each)        -- sectionCount+1 entries mapping the
    encrypted payload into RVA-aligned sections.

The payload after the header is XOR-decrypted with a running key; the header
DWORDs are then de-obfuscated. The sections, entry point and (already on-disk
formatted) import table are rebuilt into a standard PE32 DLL suitable for IDA
or any PE tooling.

Usage:
    python decrypt_blob.py <input.blob> [output.dll]
"""

from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

BLOB_ALGORITHM = 0x12345678
BLOB_INFO_SIZE = 68
BLOB_HEADER_SIZE = 24
BLOB_SECTION_SIZE = 20
XOR_KEY = 0x57
SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x1000
PE_OFFSET = 0x80
OPT_HEADER_SIZE = 0xE0
SIZE_OF_HEADERS = 0x1000
CHECKSUM_OFFSET = PE_OFFSET + 0x18 + 0x40  # 0xD8, CheckSum field in optional header

_BLOB_INFO = "<10s32s22sI"
_BLOB_HEADER = "<IH2xIIII"
_BLOB_SECTION = "<IIIIi"
_IMPORT_DESCRIPTOR = "<IIIII"

CNT_CODE = 0x00000020
CNT_INITIALIZED_DATA = 0x00000040
MEM_EXECUTE = 0x20000000
MEM_READ = 0x40000000
MEM_WRITE = 0x80000000
CHAR_CODE_EXEC_READ = CNT_CODE | MEM_EXECUTE | MEM_READ
CHAR_INIT_READ = CNT_INITIALIZED_DATA | MEM_READ
CHAR_INIT_READ_WRITE = CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE

CHARACTERISTICS_DLL = 0x2102
SUBSYSTEM_WINDOWS_GUI = 2
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_OPTIONAL_MAGIC_PE32 = 0x010B

_EXPORT_OBFUSCATION = 0x7A32BC85
_IMAGEBASE_OBFUSCATION = 0x49C042D1
_IMPORT_OBFUSCATION = 0x872C3D47
_ENTRY_DELTA = 12

# Markers used by LoadBlob to tell .rdata apart from .data. The Heap* strings
# are searched including their NUL terminator (sizeof), the CRT strings without.
_RDATA_MARKERS = (
    b"HeapAlloc\0",
    b"HeapFree\0",
    b"Microsoft Visual C++ Runtime Library",
    b"JanFebMarAprMayJunJulAugSepOctNovDec",
)


class BlobFormatError(ValueError):
    pass


@dataclass
class BlobInfo:
    path: bytes
    describe: bytes
    company: bytes


@dataclass
class BlobHeader:
    check_sum: int
    section_count: int
    export_point: int
    image_base: int
    entry_point: int
    import_table: int


@dataclass(frozen=True)
class BlobSection:
    virtual_address: int
    virtual_size: int
    data_size: int
    data_address: int
    is_special: bool


@dataclass
class ParsedBlob:
    info: BlobInfo
    header: BlobHeader
    sections: list[BlobSection]
    buffer: bytes
    blob_info_offset: int


def find_blob_info_offset(data: bytes) -> int | None:
    """Return the file offset of BlobInfo_t, or None if not a Metahook blob.

    The algorithm marker (0x12345678) is the last DWORD of BlobInfo_t, so the
    struct starts 64 bytes earlier. Scanning instead of assuming offset 0 keeps
    the script robust to a leading header that a future blob maker might emit.
    """
    hit = data.find(struct.pack("<I", BLOB_ALGORITHM))
    if hit < 0:
        return None
    offset = hit - (BLOB_INFO_SIZE - 4)
    if offset < 0:
        return None
    return offset


def decrypt_buffer(data: bytes, blob_info_offset: int) -> bytes:
    """XOR-decrypt the blob payload exactly as LoadBlobFromBuffer does."""
    buf = bytearray(data)
    key = XOR_KEY
    for i in range(blob_info_offset + BLOB_INFO_SIZE, len(buf)):
        buf[i] ^= key
        key = (key + buf[i] + XOR_KEY) & 0xFF  # key advances over the DECRYPTED byte
    return bytes(buf)


def _validate_blob(header: BlobHeader, sections: list[BlobSection], buf: bytes) -> None:
    if not 1 <= header.section_count <= 64:
        raise BlobFormatError(f"invalid section count {header.section_count}")
    if header.image_base % 0x1000 != 0 or not 0x100000 <= header.image_base < 0x80000000:
        raise BlobFormatError(f"invalid image base 0x{header.image_base:08x}")
    if not sections:
        raise BlobFormatError("blob has no sections")
    image_end = 0
    for sec in sections:
        if sec.virtual_address < header.image_base:
            raise BlobFormatError(f"section VA 0x{sec.virtual_address:08x} below image base")
        if sec.virtual_address % 0x1000 != 0:
            raise BlobFormatError(f"section VA 0x{sec.virtual_address:08x} not aligned")
        if sec.data_address < 0 or sec.data_address + sec.data_size > len(buf):
            raise BlobFormatError(f"section data out of range (off 0x{sec.data_address:x} size 0x{sec.data_size:x})")
        image_end = max(image_end, sec.virtual_address + sec.virtual_size)
    for name, value in (
        ("entry point", header.entry_point),
        ("export point", header.export_point),
        ("import table", header.import_table),
    ):
        if not header.image_base <= value < image_end:
            raise BlobFormatError(f"{name} 0x{value:08x} outside image [0x{header.image_base:08x}, 0x{image_end:08x})")


def parse_blob(data: bytes) -> ParsedBlob:
    offset = find_blob_info_offset(data)
    if offset is None:
        raise BlobFormatError("not a Metahook blob (no 0x12345678 algorithm marker)")
    if len(data) < offset + BLOB_INFO_SIZE + BLOB_HEADER_SIZE + BLOB_SECTION_SIZE:
        raise BlobFormatError("truncated blob file")

    buf = decrypt_buffer(data, offset)

    path, describe, company, algorithm = struct.unpack_from(_BLOB_INFO, buf, offset)
    if algorithm != BLOB_ALGORITHM:
        raise BlobFormatError(f"bad algorithm marker 0x{algorithm:08x}")

    check_sum, section_count, export_raw, base_raw, entry_raw, import_raw = struct.unpack_from(
        _BLOB_HEADER, buf, offset + BLOB_INFO_SIZE
    )
    header = BlobHeader(
        check_sum=check_sum,
        section_count=section_count,
        export_point=export_raw ^ _EXPORT_OBFUSCATION,
        image_base=base_raw ^ _IMAGEBASE_OBFUSCATION,
        entry_point=(entry_raw - _ENTRY_DELTA) & 0xFFFFFFFF,
        import_table=import_raw ^ _IMPORT_OBFUSCATION,
    )

    table_off = offset + BLOB_INFO_SIZE + BLOB_HEADER_SIZE
    if len(buf) < table_off + (section_count + 1) * BLOB_SECTION_SIZE:
        raise BlobFormatError("truncated blob section table")
    sections = [
        BlobSection(*struct.unpack_from(_BLOB_SECTION, buf, table_off + j * BLOB_SECTION_SIZE))
        for j in range(section_count + 1)
    ]

    _validate_blob(header, sections, buf)
    return ParsedBlob(BlobInfo(path, describe, company), header, sections, buf, offset)


def _section_data(buffer: bytes, section: BlobSection) -> bytes:
    return buffer[section.data_address : section.data_address + section.data_size]


def _rdata_markers_match(data: bytes) -> bool:
    return all(marker in data for marker in _RDATA_MARKERS)


def _looks_like_reloc(data: bytes) -> bool:
    """True when most DWORDs carry a relocation-style 0x800000xx tag."""
    if len(data) < 8:
        return False
    words = [struct.unpack_from("<I", data, i)[0] for i in range(0, len(data) - 3, 4)]
    if not words:
        return False
    reloc_like = sum(1 for w in words if (w >> 28) == 0x8)
    return reloc_like / len(words) > 0.5


def _looks_like_resource(data: bytes) -> bool:
    """True when `data` starts with a plausible IMAGE_RESOURCE_DIRECTORY root.

    The root of a Win32 resource tree has zero Characteristics and a small set
    of entries (resource-type IDs such as 3=ICON, 6=STRING, 14=GROUP_ICON,
    16=VERSION) whose Name/Id and OffsetToData pointers stay inside the section.
    """
    if len(data) < 16:
        return False
    characteristics, _timestamp = struct.unpack_from("<II", data, 0)
    if characteristics != 0:
        return False
    named, by_id = struct.unpack_from("<HH", data, 12)
    if not 0 <= named <= 16 or not 1 <= by_id <= 16:
        return False
    count = named + by_id
    if len(data) < 16 + count * 8:
        return False
    for i in range(count):
        name_or_id, offset_to_data = struct.unpack_from("<II", data, 16 + i * 8)
        if name_or_id & 0x80000000:  # named entry: offset of the name string
            if (name_or_id & 0x7FFFFFFF) >= len(data):
                return False
        elif not 1 <= name_or_id <= 0x10000:
            return False
        if (offset_to_data & 0x7FFFFFFF) >= len(data):  # subdir flag lives in bit 31
            return False
    return True


def classify_section(index: int, section: BlobSection, buffer: bytes) -> tuple[str, int]:
    """Return (name, characteristics) mirroring LoadBlob's heuristic."""
    if index == 0:
        return ".text", CHAR_CODE_EXEC_READ
    data = _section_data(buffer, section)
    if section.virtual_size > 0x10000:
        if _rdata_markers_match(data):
            return ".rdata", CHAR_INIT_READ
        return ".data", CHAR_INIT_READ_WRITE
    if _looks_like_resource(data):
        return ".rsrc", CHAR_INIT_READ
    if _looks_like_reloc(data):
        return ".reloc", CHAR_INIT_READ
    return ".rdata", CHAR_INIT_READ


def _rva_to_blob_offset(parsed: ParsedBlob, rva: int) -> int | None:
    image_base = parsed.header.image_base
    for sec in parsed.sections:
        sec_rva = sec.virtual_address - image_base
        if sec_rva <= rva < sec_rva + sec.virtual_size:
            delta = rva - sec_rva
            if delta < sec.data_size:
                return sec.data_address + delta
            return None
    return None


def _walk_imports(parsed: ParsedBlob) -> list[str]:
    """Return the DLL names in the import table (already in on-disk form)."""
    entries: list[str] = []
    off = _rva_to_blob_offset(parsed, parsed.header.import_table - parsed.header.image_base)
    if off is None:
        raise BlobFormatError("import table outside image")
    buf = parsed.buffer
    while True:
        if off + 20 > len(buf):
            raise BlobFormatError("import descriptor out of range")
        original_first_thunk, _ts, _forwarder, name, _first_thunk = struct.unpack_from(_IMPORT_DESCRIPTOR, buf, off)
        if original_first_thunk == 0 and name == 0:
            break
        name_off = _rva_to_blob_offset(parsed, name)
        if name_off is None:
            raise BlobFormatError("import DLL name outside image")
        end = buf.find(b"\0", name_off, min(name_off + 256, len(buf)))
        if end < 0:
            raise BlobFormatError("import DLL name not NUL-terminated")
        entries.append(buf[name_off:end].decode("latin-1"))
        off += 20
        if len(entries) > 1024:
            raise BlobFormatError("too many import descriptors")
    return entries


def _size_of_image(parsed: ParsedBlob) -> int:
    image_end = max(sec.virtual_address + sec.virtual_size for sec in parsed.sections)
    return (image_end - parsed.header.image_base + FILE_ALIGNMENT - 1) & ~(FILE_ALIGNMENT - 1)


def pe_checksum(data: bytes) -> int:
    """Standard PE CheckSumMappedFile algorithm (16-bit one's-complement sum)."""
    size = len(data)
    total = 0
    for off in range(0, size - 1, 2):
        if CHECKSUM_OFFSET <= off < CHECKSUM_OFFSET + 4:
            val = 0  # the CheckSum field itself is excluded from the sum
        else:
            val = data[off] | (data[off + 1] << 8)
        total += val
        total = (total & 0xFFFF) + (total >> 16)
    if size & 1:
        total += data[size - 1]
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (total + size) & 0xFFFFFFFF


def build_pe(parsed: ParsedBlob) -> bytes:
    """Reconstruct a standard PE32 DLL from a decrypted blob."""
    header = parsed.header
    image_base = header.image_base
    names_flags = [classify_section(i, sec, parsed.buffer) for i, sec in enumerate(parsed.sections)]
    count = len(parsed.sections)

    # Raw sizes derive from the stored bytes only. VirtualSize may be far larger
    # (e.g. hl-3647's .data: 0x10b6fd4 virtual vs 0x39000 stored); the PE loader
    # zero-fills VirtualSize beyond aligned SizeOfRawData, so padding the file to
    # VirtualSize would balloon the output with dead zeros for no benefit.
    raw_sizes = [(sec.data_size + FILE_ALIGNMENT - 1) & ~(FILE_ALIGNMENT - 1) for sec in parsed.sections]
    size_of_image = _size_of_image(parsed)
    imports = _walk_imports(parsed)

    headers_end = PE_OFFSET + 4 + 20 + OPT_HEADER_SIZE + count * 40
    size_of_headers = (headers_end + FILE_ALIGNMENT - 1) & ~(FILE_ALIGNMENT - 1)
    size_of_code = sum(raw_sizes[i] for i, (_name, flags) in enumerate(names_flags) if flags & CNT_CODE)
    size_of_init_data = sum(
        raw_sizes[i] for i, (_name, flags) in enumerate(names_flags) if flags & CNT_INITIALIZED_DATA
    )

    pe = bytearray(size_of_headers)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, PE_OFFSET)
    pe[PE_OFFSET : PE_OFFSET + 4] = b"PE\0\0"

    coff = PE_OFFSET + 4
    opt = coff + 20
    struct.pack_into("<H", pe, coff, IMAGE_FILE_MACHINE_I386)
    struct.pack_into("<H", pe, coff + 2, count)
    struct.pack_into("<I", pe, coff + 4, 0)  # TimeDateStamp
    struct.pack_into("<I", pe, coff + 8, 0)  # PointerToSymbolTable
    struct.pack_into("<I", pe, coff + 12, 0)  # NumberOfSymbols
    struct.pack_into("<H", pe, coff + 16, OPT_HEADER_SIZE)
    struct.pack_into("<H", pe, coff + 18, CHARACTERISTICS_DLL)

    base_of_code = next(
        (sec.virtual_address - image_base for sec in parsed.sections if sec.virtual_address - image_base > 0), 0
    )
    base_of_data = next(
        (
            sec.virtual_address - image_base
            for sec in parsed.sections
            if sec.virtual_address - image_base > 0 and sec.virtual_address != parsed.sections[0].virtual_address
        ),
        0,
    )

    struct.pack_into("<H", pe, opt, IMAGE_OPTIONAL_MAGIC_PE32)
    pe[opt + 2] = 8  # MajorLinkerVersion
    pe[opt + 3] = 0  # MinorLinkerVersion
    struct.pack_into("<I", pe, opt + 4, size_of_code)
    struct.pack_into("<I", pe, opt + 8, size_of_init_data)
    struct.pack_into("<I", pe, opt + 12, 0)  # SizeOfUninitializedData
    struct.pack_into("<I", pe, opt + 16, header.entry_point - image_base)
    struct.pack_into("<I", pe, opt + 20, base_of_code)
    struct.pack_into("<I", pe, opt + 24, base_of_data)
    struct.pack_into("<I", pe, opt + 28, image_base)
    struct.pack_into("<I", pe, opt + 32, SECTION_ALIGNMENT)
    struct.pack_into("<I", pe, opt + 36, FILE_ALIGNMENT)
    struct.pack_into("<H", pe, opt + 40, 4)  # MajorOperatingSystemVersion
    struct.pack_into("<H", pe, opt + 42, 0)  # MinorOperatingSystemVersion
    struct.pack_into("<H", pe, opt + 44, 0)  # MajorImageVersion
    struct.pack_into("<H", pe, opt + 46, 0)  # MinorImageVersion
    struct.pack_into("<H", pe, opt + 48, 4)  # MajorSubsystemVersion
    struct.pack_into("<H", pe, opt + 50, 0)  # MinorSubsystemVersion
    struct.pack_into("<I", pe, opt + 52, 0)  # Win32VersionValue
    struct.pack_into("<I", pe, opt + 56, size_of_image)
    struct.pack_into("<I", pe, opt + 60, size_of_headers)
    struct.pack_into("<I", pe, opt + 64, 0)  # CheckSum (filled below)
    struct.pack_into("<H", pe, opt + 68, SUBSYSTEM_WINDOWS_GUI)
    struct.pack_into("<H", pe, opt + 70, 0)  # DllCharacteristics
    struct.pack_into("<I", pe, opt + 72, 0x100000)  # SizeOfStackReserve
    struct.pack_into("<I", pe, opt + 76, 0x1000)  # SizeOfStackCommit
    struct.pack_into("<I", pe, opt + 80, 0x100000)  # SizeOfHeapReserve
    struct.pack_into("<I", pe, opt + 84, 0x1000)  # SizeOfHeapCommit
    struct.pack_into("<I", pe, opt + 88, 0)  # LoaderFlags
    struct.pack_into("<I", pe, opt + 92, 16)  # NumberOfRvaAndSizes
    struct.pack_into("<II", pe, opt + 96, 0, 0)  # DataDirectory[0] Export: not synthesized
    struct.pack_into(
        "<II", pe, opt + 104, header.import_table - image_base, (len(imports) + 1) * 20
    )  # DataDirectory[1] Import (includes the all-zero terminator descriptor)

    # DataDirectory[2] Resource: expose a recovered .rsrc section so resource and
    # version-information APIs can find it. Size mirrors the materialized bytes.
    resource = next(
        (
            (sec.virtual_address - image_base, raw_size)
            for sec, (_name, _flags), raw_size in zip(parsed.sections, names_flags, raw_sizes)
            if sec.virtual_address - image_base != 0 and _name == ".rsrc"
        ),
        (0, 0),
    )
    struct.pack_into("<II", pe, opt + 112, *resource)  # DataDirectory[2] Resource

    section_header_start = opt + OPT_HEADER_SIZE
    file_off = size_of_headers
    for i, (sec, (name, flags)) in enumerate(zip(parsed.sections, names_flags)):
        sh = section_header_start + i * 40
        struct.pack_into("<8s", pe, sh, name.encode("ascii")[:8].ljust(8, b"\0"))
        struct.pack_into("<I", pe, sh + 8, sec.virtual_size)
        struct.pack_into("<I", pe, sh + 12, sec.virtual_address - image_base)
        struct.pack_into("<I", pe, sh + 16, raw_sizes[i])
        struct.pack_into("<I", pe, sh + 20, file_off)
        struct.pack_into("<I", pe, sh + 24, 0)  # PointerToRelocations
        struct.pack_into("<I", pe, sh + 28, 0)  # PointerToLinenumbers
        struct.pack_into("<H", pe, sh + 32, 0)  # NumberOfRelocations
        struct.pack_into("<H", pe, sh + 34, 0)  # NumberOfLinenumbers
        struct.pack_into("<I", pe, sh + 36, flags)
        file_off += raw_sizes[i]

    total = size_of_headers + sum(raw_sizes)
    out = bytearray(pe)
    out.extend(b"\0" * (total - len(out)))
    file_off = size_of_headers
    for sec, raw_size in zip(parsed.sections, raw_sizes):
        data = _section_data(parsed.buffer, sec)
        out[file_off : file_off + len(data)] = data
        file_off += raw_size

    struct.pack_into("<I", out, opt + 64, pe_checksum(bytes(out)))
    return bytes(out)


def verify_pe(pe: bytes, parsed: ParsedBlob) -> None:
    """Structural self-check of the freshly written DLL."""
    if len(pe) < PE_OFFSET + 4 + 20 + OPT_HEADER_SIZE:
        raise BlobFormatError("output too short")
    if pe[:2] != b"MZ":
        raise BlobFormatError("output missing MZ signature")
    e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
    if pe[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise BlobFormatError("output missing PE signature")
    if struct.unpack_from("<H", pe, e_lfanew + 4)[0] != IMAGE_FILE_MACHINE_I386:
        raise BlobFormatError("output machine is not I386")
    opt = e_lfanew + 4 + 20
    if struct.unpack_from("<H", pe, opt)[0] != IMAGE_OPTIONAL_MAGIC_PE32:
        raise BlobFormatError("output optional magic is not PE32")
    count = struct.unpack_from("<H", pe, e_lfanew + 6)[0]
    if count != len(parsed.sections):
        raise BlobFormatError("output section count mismatch")
    if struct.unpack_from("<I", pe, opt + 28)[0] != parsed.header.image_base:
        raise BlobFormatError("output image base mismatch")
    size_of_image = struct.unpack_from("<I", pe, opt + 56)[0]
    entry_rva = struct.unpack_from("<I", pe, opt + 16)[0]
    if not 0 < entry_rva < size_of_image:
        raise BlobFormatError("output entry outside image")
    import_rva, _import_size = struct.unpack_from("<II", pe, opt + 104)
    if import_rva and not 0 < import_rva < size_of_image:
        raise BlobFormatError("output import directory outside image")
    resource_rva, resource_size = struct.unpack_from("<II", pe, opt + 112)
    if resource_rva and (not 0 < resource_rva < size_of_image or resource_size == 0):
        raise BlobFormatError("output resource directory outside image")
    sh = opt + OPT_HEADER_SIZE
    for i in range(count):
        if struct.unpack_from("<I", pe, sh + i * 40 + 12)[0] % 0x1000 != 0:
            raise BlobFormatError("output section not aligned")
        raw = struct.unpack_from("<I", pe, sh + i * 40 + 16)[0]
        ptr = struct.unpack_from("<I", pe, sh + i * 40 + 20)[0]
        if ptr + raw > len(pe):
            raise BlobFormatError("output section data exceeds file size")
    covered = any(
        sec.virtual_address - parsed.header.image_base
        <= entry_rva
        < sec.virtual_address - parsed.header.image_base + sec.virtual_size
        for sec in parsed.sections
    )
    if not covered:
        raise BlobFormatError("output entry point not inside a section")


def _cstr(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("latin-1", "replace")


def summarize(parsed: ParsedBlob, pe: bytes, output: Path) -> None:
    info = parsed.info
    header = parsed.header
    imports = _walk_imports(parsed)
    print(f"Blob: info at file offset 0x{parsed.blob_info_offset:04x}")
    print(f"  path:     {_cstr(info.path)!r}")
    print(f"  describe: {_cstr(info.describe)!r}")
    print(f"  company:  {_cstr(info.company)!r}")
    print(f"  algorithm 0x{BLOB_ALGORITHM:08x} OK")
    print(
        f"  image base 0x{header.image_base:08x}  sections {len(parsed.sections)}  DllMain(entry) 0x{header.entry_point:08x}"
    )
    print(f"  export init fn 0x{header.export_point:08x}   (no PE export directory synthesized)")
    print(f"  imports: {len(imports)} DLLs ({', '.join(imports)})")
    print("  #  name     rva       vsize     dsize     flags")
    for i, sec in enumerate(parsed.sections):
        name, flags = classify_section(i, sec, parsed.buffer)
        print(
            f"  {i}  {name:<8} 0x{sec.virtual_address - header.image_base:08x} "
            f"0x{sec.virtual_size:06x} 0x{sec.data_size:06x} 0x{flags:08x}"
        )
    print(f"wrote {output} (size={len(pe)}, size_of_image=0x{_size_of_image(parsed):x})")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Decrypt a Metahook blob into a regular PE32 DLL")
    parser.add_argument("input", help="Metahook blob file (e.g. engine/hw.dll)")
    parser.add_argument("output", nargs="?", help="output DLL path (default: <input>.decrypted)")
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    output_path = Path(args.output) if args.output else input_path.with_suffix(input_path.suffix + ".decrypted")
    if input_path.resolve() == output_path.resolve():
        parser.error("input and output are the same file")

    try:
        data = input_path.read_bytes()
    except OSError as exc:
        print(f"error: cannot read {input_path}: {exc}", file=sys.stderr)
        return 1

    try:
        parsed = parse_blob(data)
        pe = build_pe(parsed)
        verify_pe(pe, parsed)
    except BlobFormatError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    output_path.write_bytes(pe)
    summarize(parsed, pe, output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
