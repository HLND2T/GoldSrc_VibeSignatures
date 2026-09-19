"""Read current ELF32 symbol identities for the approved renderer locators.

Addresses are read from the current binary, never from a reference build.
The symbol table is a discovery anchor only for HL25 Linux's retained,
uncalled R_RenderDynamicLightmaps entry. GV discovery remains LLM-based;
retained ELF object names are applied after operand validation.
"""

import inspect
import struct
import textwrap
from pathlib import Path

import yaml

from ida_analyze_util import parse_mcp_result, write_gv_yaml

ELF_HEADER_SIZE = 52
SECTION_SIZE = 40
SYMBOL_SIZE = 16
PROGRAM_HEADER_SIZE = 32
STT_OBJECT = 1
STT_FUNC = 2


def read_symbols(data):
    def region(offset, size):
        if offset < 0 or size < 0 or offset + size > len(data):
            raise ValueError("ELF table extends beyond the current binary")
        return data[offset : offset + size]

    header = region(0, ELF_HEADER_SIZE)
    if header[:7] != b"\x7fELF\x01\x01\x01" or struct.unpack_from("<HH", header, 16) != (3, 3):
        raise ValueError("expected little-endian ELF32/I386 ET_DYN")
    program_offset = struct.unpack_from("<I", header, 28)[0]
    program_size, program_count = struct.unpack_from("<HH", header, 42)
    if program_size != PROGRAM_HEADER_SIZE or not program_count:
        raise ValueError("unsupported ELF program headers")
    programs = struct.iter_unpack("<8I", region(program_offset, program_size * program_count))
    load_addresses = [entry[2] for entry in programs if entry[0] == 1]
    if not load_addresses or min(load_addresses) != 0:
        raise ValueError("renderer ELF symbols require a zero link-time load base")
    offset = struct.unpack_from("<I", header, 32)[0]
    entry_size, count = struct.unpack_from("<HH", header, 46)
    if entry_size != SECTION_SIZE or not count:
        raise ValueError("unsupported ELF section table")
    table = region(offset, entry_size * count)
    sections = [struct.unpack_from("<10I", table, i * entry_size) for i in range(count)]
    result = set()
    for section in sections:
        if section[1] not in (2, 11):  # SHT_SYMTAB, SHT_DYNSYM
            continue
        if section[9] != SYMBOL_SIZE or section[5] % SYMBOL_SIZE or section[6] >= count:
            raise ValueError("invalid ELF symbol table")
        string_section = sections[section[6]]
        if string_section[1] != 3:
            raise ValueError("invalid ELF symbol string table")
        strings = region(string_section[4], string_section[5])
        symbols = region(section[4], section[5])
        for entry in struct.iter_unpack("<IIIBBH", symbols):
            name_offset, value, _, info, _, section_index = entry
            if not name_offset or not section_index:
                continue
            end = strings.find(b"\0", name_offset)
            if name_offset >= len(strings) or end < 0:
                raise ValueError("unterminated ELF symbol name")
            name = strings[name_offset:end].decode("utf-8", errors="strict")
            result.add((name, value, info & 15))
    return sorted(result)


def select_symbol(symbols, name, kind):
    addresses = {value for symbol, value, symbol_kind in symbols if symbol == name and symbol_kind == kind}
    if len(addresses) != 1:
        raise ValueError(f"expected one defined ELF symbol: {name}")
    return addresses.pop()


async def current_elf_symbols(session, names, prefixes=()):
    # Read in the IDA process: a remote worker's input path need not be shared
    # with the controller. Return only relevant rows to keep MCP output bounded.
    body = (
        "import struct, json, ida_nalt\nfrom pathlib import Path\n"
        f"ELF_HEADER_SIZE = {ELF_HEADER_SIZE}\nSECTION_SIZE = {SECTION_SIZE}\n"
        f"SYMBOL_SIZE = {SYMBOL_SIZE}\nPROGRAM_HEADER_SIZE = {PROGRAM_HEADER_SIZE}\n"
        + inspect.getsource(read_symbols)
        + f"\nnames = {tuple(names)!r}\nprefixes = {tuple(prefixes)!r}\n"
        "symbols = read_symbols(Path(ida_nalt.get_input_file_path()).read_bytes())\n"
        "return json.dumps([row for row in symbols if row[0] in names or row[0].startswith(prefixes)])\n"
    )
    code = (
        "def _current_renderer_elf_symbols():\n" + textwrap.indent(body, "    ") + "\n_current_renderer_elf_symbols()"
    )
    result = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    if not isinstance(result, list):
        raise TypeError("missing current IDB ELF symbol result")
    return [tuple(row) for row in result]


def object_identity(symbols, logical_name, address):
    candidates = {
        (name, value)
        for name, value, kind in symbols
        if kind == STT_OBJECT
        and (
            name == logical_name
            or name == f"_ZL{len(logical_name)}{logical_name}"
            or (
                logical_name == "rtable"
                and (name.startswith("rtable.") or name == "_ZZ18R_TextureAnimationP10msurface_sE6rtable")
            )
        )
    }
    if not candidates:
        return logical_name  # Stripped binary: retain the verified source-level identity.
    if len(candidates) != 1 or next(iter(candidates))[1] != address:
        raise ValueError(f"ELF object identity disagrees with discovered address: {logical_name}")
    return candidates.pop()[0]


async def preserve_global_identities(session, outputs, platform):
    if platform != "linux":
        return True
    documents = [(Path(output), yaml.safe_load(Path(output).read_text(encoding="utf-8"))) for output in outputs]
    logical_names = [payload["gv_name"] for _, payload in documents]
    names = logical_names + [f"_ZL{len(name)}{name}" for name in logical_names]
    prefixes = ()
    if "rtable" in logical_names:
        names.append("_ZZ18R_TextureAnimationP10msurface_sE6rtable")
        prefixes = ("rtable.",)
    symbols = await current_elf_symbols(session, names, prefixes)
    for path, payload in documents:
        logical_name = payload["gv_name"]
        address = int(str(payload["gv_rva"]), 0)
        identity = object_identity(symbols, logical_name, address)
        if identity != logical_name:
            payload["gv_name"] = identity
            write_gv_yaml(path, payload)
    return True
