#!/usr/bin/env python3
"""Recover the primary CEngine and CGame tables from exact current-binary RTTI.

MSVC uses the exact TypeDescriptor names .?AVCEngine@@ / .?AVCGame@@ and a
primary Complete Object Locator (offset zero). HL25 Windows retains that RTTI
without IDA naming the tables, so walk its data references as well as exact
table names. Never fall back to a substring such as CEngine (CEnginePanel).
Itanium tables use _ZTV7CEngine / _ZTV5CGame; their address points skip the two
metadata words and their typeinfo must name the requested class.

All 15 engine/platform pairs were checked. Entry counts vary by ABI and CGame
revision; scan the current table, without inheriting another build's length.
Do not require eng's static object vptr to hold the final derived table before
constructors run: old BLOB objects are uninitialized and Sven starts at IEngine.
"""

from ida_analyze_util import _output_for_symbol, write_vtable_yaml
from ida_preprocessor_scripts._engine_private_globals_common import run_walk


CLASSES = ("CEngine", "CGame")
LOCATE = r"""
import ida_name

WORD = 4
MAX_SLOTS = 512
ITANIUM_HEADER_WORDS = 2
TYPE_DESCRIPTOR_HEADER_WORDS = 2
COL_TYPE_DESCRIPTOR_WORD = 3
COL_OBJECT_OFFSET_WORD = 1

def executable_pointer(ea):
    return ea not in (0, idaapi.BADADDR) and is_code_address(ea)

def string_at(ea):
    return idc.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C)

def pe_identity(address, expected):
    locator = int(ida_bytes.get_dword(address - WORD))
    if not locator or ida_segment.getseg(locator) is None:
        return False
    if ida_bytes.get_dword(locator) != 0 or ida_bytes.get_dword(locator + COL_OBJECT_OFFSET_WORD * WORD) != 0:
        return False
    descriptor = int(ida_bytes.get_dword(locator + COL_TYPE_DESCRIPTOR_WORD * WORD))
    return string_at(descriptor + TYPE_DESCRIPTOR_HEADER_WORDS * WORD) == expected.encode('ascii')

def locate(class_name):
    pe_name = '??_7' + class_name + '@@6B@'
    elf_name = '_ZTV' + str(len(class_name)) + class_name
    descriptor_name = '.?AV' + class_name + '@@'
    candidates = {}
    if values['platform'] == 'linux':
        raw = ida_name.get_name_ea(idaapi.BADADDR, elf_name)
        if raw != idaapi.BADADDR:
            address = int(raw) + ITANIUM_HEADER_WORDS * WORD
            typeinfo = int(ida_bytes.get_dword(int(raw) + WORD))
            type_name = int(ida_bytes.get_dword(typeinfo + WORD))
            if ida_bytes.get_dword(int(raw)) == 0 and string_at(type_name) == (str(len(class_name)) + class_name).encode('ascii'):
                candidates[address] = elf_name
    else:
        named = ida_name.get_name_ea(idaapi.BADADDR, pe_name)
        if named != idaapi.BADADDR and pe_identity(int(named), descriptor_name):
            candidates[int(named)] = pe_name
        strings = idautils.Strings(default_setup=False)
        strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
        for item in strings:
            if str(item) != descriptor_name:
                continue
            descriptor = int(item.ea) - TYPE_DESCRIPTOR_HEADER_WORDS * WORD
            for ref in idautils.XrefsTo(descriptor):
                locator = int(ref.frm) - COL_TYPE_DESCRIPTOR_WORD * WORD
                for pointer in idautils.XrefsTo(locator):
                    address = int(pointer.frm) + WORD
                    if address % WORD == 0 and pe_identity(address, descriptor_name):
                        if executable_pointer(int(ida_bytes.get_dword(address))):
                            candidates[address] = pe_name
    if len(candidates) != 1:
        raise ValueError('primary RTTI table is not unique: ' + class_name)
    address, symbol = next(iter(candidates.items()))
    entries = {}
    for index in range(MAX_SLOTS):
        target = int(ida_bytes.get_dword(address + index * WORD))
        if not executable_pointer(target):
            break
        entries[index] = hex(target)
    else:
        raise ValueError('unterminated primary vtable: ' + class_name)
    if not entries:
        raise ValueError('empty primary vtable: ' + class_name)
    return dict(vtable_class=class_name, vtable_symbol=symbol,
                vtable_va=hex(address), vtable_rva=hex(address - ida_nalt.get_imagebase()),
                vtable_size=hex(len(entries) * WORD), vtable_numvfunc=len(entries),
                vtable_entries=entries)

if idaapi.inf_is_64bit():
    raise ValueError('expected 32-bit engine')
result = {name: locate(name) for name in values['classes']}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map, new_binary_dir, image_base
    if platform not in {"windows", "linux"}:
        return False
    outputs = {name: _output_for_symbol(expected_outputs, name + "_vtable") for name in CLASSES}
    if not all(outputs.values()):
        return False
    tables = await run_walk(session, LOCATE, {"classes": CLASSES, "platform": platform})
    if tables.get("error") or any(not tables.get(name, {}).get("vtable_entries") for name in CLASSES):
        if debug:
            print(f"{skill_name}: {tables}")
        return False
    for name in CLASSES:
        write_vtable_yaml(outputs[name], tables[name])
        if debug:
            print(f"{skill_name}: {name}={tables[name]['vtable_va']} slots={tables[name]['vtable_numvfunc']}")
    return True
