from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from binary_format import inspect_binary
from decrypt_blob import (
    BLOB_ALGORITHM,
    BLOB_HEADER_SIZE,
    BLOB_INFO_SIZE,
    BlobFormatError,
    build_pe,
    classify_section,
    parse_blob,
    verify_pe,
)

ROOT = Path(__file__).resolve().parent.parent

IMAGE_BASE = 0x01D00000
_EXPORT_XOR = 0x7A32BC85
_BASE_XOR = 0x49C042D1
_IMPORT_XOR = 0x872C3D47
_ENTRY_DELTA = 12

# (rva, virtual_size, data_size) -- first is .text, rest are data/aux.
# The blob stores m_wSectionCount = numberOfSections - 1 (the loader iterates
# `j <= count`), so a count of len(SECTIONS)-1 yields len(SECTIONS) sections.
SECTIONS = [
    (0x1000, 0x2000, 0x1800),  # .text
    (0x4000, 0x3000, 0x2000),  # .rdata (import metadata lives here)
    (0x8000, 0x5000, 0x3000),  # data
    (0xE000, 0x1000, 0x20),  # aux: RVA-pointer table
    (0xF000, 0x1000, 0x80),  # aux: reloc-style entries
    (0x10000, 0x1000, 0x100),  # .rsrc: minimal version-info resource root
]

RESOURCE_INDEX = len(SECTIONS) - 1

IMPORT_RVA = SECTIONS[1][0] + 0x10  # 0x4010
ENTRY_RVA = 0x2000
EXPORT_RVA = 0x1000


def _encrypt(data: bytes, blob_info_offset: int) -> bytes:
    """Inverse of decrypt_buffer: obfuscate a plaintext blob for a fixture.

    The running key advances over the PLAINTEXT byte (decrypt_buffer advances
    over the byte it just decrypted), so encrypt applies the same key schedule
    before XORing each byte.
    """
    buf = bytearray(data)
    key = 0x57
    for i in range(blob_info_offset + BLOB_INFO_SIZE, len(buf)):
        plain = buf[i]
        buf[i] ^= key
        key = (key + plain + 0x57) & 0xFF
    return bytes(buf)


def _build_import_region() -> bytes:
    """Import table + names + hint/name + thunk arrays, anchored at IMPORT_RVA.

    Two DLLs (TEST1.dll / TEST2.dll), one named import each.
    """
    region = bytearray(0x98)  # IMPORT_RVA .. +0x98
    desc0_off = IMPORT_RVA - IMPORT_RVA
    desc1_off = desc0_off + 20
    term_off = desc1_off + 20
    dll1 = IMPORT_RVA + 0x40
    dll2 = IMPORT_RVA + 0x50
    hint1 = IMPORT_RVA + 0x60
    hint2 = IMPORT_RVA + 0x70
    iat = IMPORT_RVA + 0x80
    oft = IMPORT_RVA + 0x90
    # descriptors: (OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk)
    struct.pack_into("<IIIII", region, desc0_off, oft, 0, 0, dll1, iat)
    struct.pack_into("<IIIII", region, desc1_off, oft + 4, 0, 0, dll2, iat + 4)
    struct.pack_into("<IIIII", region, term_off, 0, 0, 0, 0, 0)
    region[dll1 - IMPORT_RVA : dll1 - IMPORT_RVA + 9] = b"TEST1.dll\0"
    region[dll2 - IMPORT_RVA : dll2 - IMPORT_RVA + 9] = b"TEST2.dll\0"
    region[hint1 - IMPORT_RVA : hint1 - IMPORT_RVA + 8] = struct.pack("<H", 0) + b"FuncA\0"
    region[hint2 - IMPORT_RVA : hint2 - IMPORT_RVA + 8] = struct.pack("<H", 0) + b"FuncB\0"
    struct.pack_into("<II", region, iat - IMPORT_RVA, hint1, hint2)
    struct.pack_into("<II", region, oft - IMPORT_RVA, hint1, hint2)
    return bytes(region)


def _build_resource_root() -> bytes:
    """Minimal IMAGE_RESOURCE_DIRECTORY root with one VERSION(16) subdir entry."""
    root = bytearray(24)
    # Characteristics=0, TimeDateStamp=0, MajorVersion=1, MinorVersion=0,
    # NumberOfNamedEntries=0, NumberOfIdEntries=1.
    struct.pack_into("<IIHHHH", root, 0, 0, 0, 1, 0, 0, 1)
    struct.pack_into("<II", root, 16, 16, 0x80000008)  # id=VERSION, subdirectory @8
    return bytes(root)


def make_blob(prefix: bytes = b"") -> bytes:
    """Build a synthetic, encrypted Metahook blob for test fixtures."""
    prefix_len = len(prefix)
    table_off = prefix_len + BLOB_INFO_SIZE + BLOB_HEADER_SIZE
    body_off = table_off + len(SECTIONS) * 20

    # Section payloads, laid out contiguously; .rdata embeds the import region.
    sec_datas: list[bytes] = []
    sections: list[tuple[int, int, int, int, int]] = []
    data_addr = body_off
    for idx, (rva, v_size, d_size) in enumerate(SECTIONS):
        if idx == 1:
            data = bytearray(d_size)
            region = _build_import_region()
            data[IMPORT_RVA - SECTIONS[1][0] : IMPORT_RVA - SECTIONS[1][0] + len(region)] = region
        elif idx == RESOURCE_INDEX:
            data = _build_resource_root() + bytes(d_size - 24)
        else:
            data = bytearray(bytes([(i * 7 + 13) & 0xFF for i in range(d_size)]))
        sections.append((IMAGE_BASE + rva, v_size, d_size, data_addr, 0))
        sec_datas.append(bytes(data))
        data_addr += d_size

    blob = bytearray(data_addr)
    blob[:prefix_len] = prefix
    struct.pack_into("<10s32s22sI", blob, prefix_len, b"test", b"fixture", b"goldsrc", BLOB_ALGORITHM)
    export = (IMAGE_BASE + EXPORT_RVA) ^ _EXPORT_XOR
    base = IMAGE_BASE ^ _BASE_XOR
    entry = (IMAGE_BASE + ENTRY_RVA + _ENTRY_DELTA) & 0xFFFFFFFF  # parser subtracts _ENTRY_DELTA
    import_tab = (IMAGE_BASE + IMPORT_RVA) ^ _IMPORT_XOR
    struct.pack_into(
        "<IH2xIIII", blob, prefix_len + BLOB_INFO_SIZE, 0, len(SECTIONS) - 1, export, base, entry, import_tab
    )
    for i, (va, v_size, d_size, addr, special) in enumerate(sections):
        struct.pack_into("<IIIIi", blob, table_off + i * 20, va, v_size, d_size, addr, special)
    for (va, v_size, d_size, addr, special), data in zip(sections, sec_datas):
        blob[addr : addr + len(data)] = data
    return _encrypt(bytes(blob), prefix_len)


class BlobDecryptionTests(unittest.TestCase):
    def _assert_import_dir(self, pe: bytes, exp_rva: int, exp_size: int) -> None:
        opt = 0x98
        rva, size = struct.unpack_from("<II", pe, opt + 104)
        self.assertEqual(exp_rva, rva)
        self.assertEqual(exp_size, size)

    def test_roundtrip_synthetic(self):
        blob = make_blob()
        parsed = parse_blob(blob)
        self.assertEqual(0, parsed.blob_info_offset)
        self.assertEqual(IMAGE_BASE, parsed.header.image_base)
        self.assertEqual(len(SECTIONS), len(parsed.sections))

        pe = build_pe(parsed)
        verify_pe(pe, parsed)
        # entry point RVA
        self.assertEqual(ENTRY_RVA, struct.unpack_from("<I", pe, 0x98 + 16)[0])
        # section[0] = .text, exec+read
        self.assertEqual(b".text", struct.unpack_from("<8s", pe, 0x178)[0].rstrip(b"\0"))
        self.assertEqual(0x60000020, struct.unpack_from("<I", pe, 0x178 + 36)[0])
        # import directory (2 DLLs + the all-zero terminator descriptor)
        self._assert_import_dir(pe, IMPORT_RVA, 3 * 20)
        # resource directory: .rsrc classified and exposed via DataDirectory[2]
        self.assertEqual(".rsrc", classify_section(RESOURCE_INDEX, parsed.sections[RESOURCE_INDEX], parsed.buffer)[0])
        opt = 0x98
        res_rva, res_size = struct.unpack_from("<II", pe, opt + 112)
        self.assertEqual(SECTIONS[RESOURCE_INDEX][0], res_rva)
        self.assertEqual(0x1000, res_size)  # aligned raw size of the .rsrc section
        # .rsrc raw bytes materialized verbatim: find its section header, then check the root.
        rsrc_ptr = rsrc_raw = None
        for i in range(len(parsed.sections)):
            sh = opt + 0xE0 + i * 40
            if pe[sh : sh + 8].rstrip(b"\0") == b".rsrc":
                rsrc_raw = struct.unpack_from("<I", pe, sh + 16)[0]
                rsrc_ptr = struct.unpack_from("<I", pe, sh + 20)[0]
        self.assertEqual(0x1000, rsrc_raw)
        self.assertEqual(_build_resource_root(), pe[rsrc_ptr : rsrc_ptr + 24])
        # binary_format.inspect_binary structural check
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "hw.dll"
            out.write_bytes(pe)
            info = inspect_binary(out)
            self.assertEqual(("windows", 32, "I386"), (info.platform, info.bits, info.machine))

    def test_leading_header_variant(self):
        blob = make_blob(b"\x90" * 0x60)
        parsed = parse_blob(blob)
        self.assertEqual(0x60, parsed.blob_info_offset)
        self.assertEqual(IMAGE_BASE, parsed.header.image_base)
        verify_pe(build_pe(parsed), parsed)

    def test_not_a_blob(self):
        with self.assertRaises(BlobFormatError):
            parse_blob(b"MZ" + b"\0" * 100)

    def test_truncated(self):
        blob = make_blob()
        for cut in (10, 60, 100, len(blob) - 5):
            with self.subTest(cut=cut), self.assertRaises(BlobFormatError):
                parse_blob(blob[:cut])

    def test_wrong_algorithm(self):
        blob = bytearray(make_blob())
        struct.pack_into("<I", blob, 64, 0xDEADBEEF)
        with self.assertRaises(BlobFormatError):
            parse_blob(bytes(blob))


class RealSampleTests(unittest.TestCase):
    SAMPLE = ROOT / "bin/hl-3266/engine/hw.dll"

    @unittest.skipUnless(SAMPLE.is_file(), "sample not downloaded")
    def test_real_sample(self):
        parsed = parse_blob(self.SAMPLE.read_bytes())
        self.assertEqual(0x01D00000, parsed.header.image_base)
        self.assertEqual(5, len(parsed.sections))
        entry_rva = parsed.header.entry_point - parsed.header.image_base
        covered = any(
            sec.virtual_address - parsed.header.image_base
            <= entry_rva
            < sec.virtual_address - parsed.header.image_base + sec.virtual_size
            for sec in parsed.sections
        )
        self.assertTrue(covered)
        pe = build_pe(parsed)
        verify_pe(pe, parsed)
        self.assertEqual(b"PE\0\0", pe[0x80:0x84])
        self.assertEqual(0x14C, struct.unpack_from("<H", pe, 0x84)[0])


if __name__ == "__main__":
    unittest.main()
