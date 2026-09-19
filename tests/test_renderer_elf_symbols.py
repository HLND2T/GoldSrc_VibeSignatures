import ast
import contextlib
import io
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ida_preprocessor_scripts.renderer_elf_symbols import (
    current_elf_symbols,
    object_identity,
    read_symbols,
    select_symbol,
)


def elf_fixture(symbols, *, elf_type=3, load_base=0):
    strings = bytearray(b"\0")
    entries = bytearray(16)
    for name, value, kind in symbols:
        offset = len(strings)
        strings.extend(name.encode() + b"\0")
        entries.extend(struct.pack("<IIIBBH", offset, value, 4, kind, 0, 1))
    header = bytearray(52)
    header[:7] = b"\x7fELF\x01\x01\x01"
    struct.pack_into("<HHI", header, 16, elf_type, 3, 1)
    struct.pack_into("<II", header, 28, 52, 84)
    struct.pack_into("<HHH", header, 40, 52, 32, 1)
    struct.pack_into("<HHH", header, 46, 40, 3, 0)
    sections = bytes(40)
    sections += struct.pack("<10I", 0, 3, 0, 0, 204, len(strings), 0, 0, 1, 0)
    sections += struct.pack("<10I", 0, 2, 0, 0, 204 + len(strings), len(entries), 1, 0, 4, 16)
    size = 204 + len(strings) + len(entries)
    program_header = struct.pack("<8I", 1, 0, load_base, load_base, size, size, 5, 4096)
    return bytes(header) + program_header + sections + strings + entries


class RendererElfSymbolsTests(unittest.TestCase):
    def test_exact_function_selection_ignores_object_and_duplicate_tables(self):
        data = elf_fixture([("Target", 0x100, 2), ("Target", 0x100, 2), ("Target", 0x200, 1)])
        self.assertEqual(0x100, select_symbol(read_symbols(data), "Target", 2))

    def test_ambiguous_or_missing_function_is_rejected(self):
        symbols = read_symbols(elf_fixture([("Target", 0x100, 2), ("Target", 0x200, 2)]))
        with self.assertRaises(ValueError):
            select_symbol(symbols, "Target", 2)
        with self.assertRaises(ValueError):
            select_symbol(symbols, "Absent", 2)

    def test_local_object_name_is_preserved(self):
        name = "_ZZ18R_TextureAnimationP10msurface_sE6rtable"
        self.assertEqual([(name, 0x1234, 1)], read_symbols(elf_fixture([(name, 0x1234, 1)])))

    def test_retained_object_symbol_cross_checks_discovered_address(self):
        symbols = [("rtable.12345", 0x100, 1)]
        self.assertEqual("rtable.12345", object_identity(symbols, "rtable", 0x100))
        self.assertEqual("rtable", object_identity([], "rtable", 0x100))
        with self.assertRaises(ValueError):
            object_identity(symbols, "rtable", 0x104)

    def test_invalid_architecture_and_truncated_tables_fail_closed(self):
        data = elf_fixture([("Target", 0x100, 2)])
        invalid = bytearray(data)
        invalid[4] = 2
        for malformed in (bytes(invalid), data[:20], data[:-1]):
            with self.subTest(length=len(malformed)), self.assertRaises(ValueError):
                read_symbols(malformed)

    def test_nonzero_link_base_and_executable_address_space_are_rejected(self):
        for data in (elf_fixture([], elf_type=2), elf_fixture([], load_base=0x8048000)):
            with self.assertRaises(ValueError):
                read_symbols(data)


class CurrentElfInputTests(unittest.IsolatedAsyncioTestCase):
    async def test_reads_bound_input_using_mcp_last_expression_result(self):
        async def call_tool(_name, arguments):
            tree = ast.parse(arguments["code"])
            namespace = {}
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                exec(compile(ast.Module(body=tree.body[:-1], type_ignores=[]), "<mcp>", "exec"), namespace)  # noqa: S102 - trusted generated MCP code
                value = eval(compile(ast.Expression(tree.body[-1].value), "<mcp>", "eval"), namespace)
            return SimpleNamespace(structured_content={"result": str(value), "stdout": stdout.getvalue(), "stderr": ""})

        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "input.so"
            binary.write_bytes(elf_fixture([("Target", 0x100, 2)]))
            with patch.dict(sys.modules, {"ida_nalt": SimpleNamespace(get_input_file_path=lambda: str(binary))}):
                actual = await current_elf_symbols(SimpleNamespace(call_tool=call_tool), ["Target"])
            self.assertEqual([("Target", 0x100, 2)], actual)


if __name__ == "__main__":
    unittest.main()
