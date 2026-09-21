#!/usr/bin/env python3
"""Locate the CVideoMode_OpenGL vtable through its MSVC/Itanium name.

``CVideoMode_OpenGL::GetName`` returns the exact renderer label ``gl``. The
vtable is named ``??_7CVideoMode_OpenGL@@6B@`` on Windows and
``_ZTV17CVideoMode_OpenGL`` on Linux (Itanium metadata skipped by
``preprocess_vtable_via_mcp``). Slot 0 must reference that ``gl`` literal so a
sibling ``CVideoMode_Direct3DFullScreen`` table cannot be selected. BLOB
Windows still carries both classes.
"""

from ida_analyze_util import (
    _output_for_symbol,
    preprocess_vtable_via_mcp,
    write_vtable_yaml,
)
from ida_preprocessor_scripts._engine_private_globals_common import run_walk

CLASS_NAME = "CVideoMode_OpenGL"
OUTPUT_STEM = "CVideoMode_OpenGL_vtable"
GL_LITERAL = "gl"

VERIFY = r"""
SLOT0 = int(values['slot0'], 0)
LITERAL = values['literal']
fn = ida_funcs.get_func(SLOT0)
if fn is None or int(fn.start_ea) != SLOT0:
    result = {'error': 'GetName slot is not a function start'}
else:
    hits = []
    for ea in idautils.FuncItems(int(fn.start_ea)):
        insn = idautils.DecodeInstruction(int(ea))
        if not insn:
            continue
        for op in insn.ops:
            if int(op.type) == int(idaapi.o_void):
                break
            addr = None
            if int(op.type) == int(idaapi.o_imm):
                addr = int(op.value) & 0xFFFFFFFF
            elif int(op.type) == int(idaapi.o_mem):
                addr = int(op.addr) & 0xFFFFFFFF
            if addr is None:
                continue
            raw = idc.get_strlit_contents(addr)
            if raw is None:
                continue
            text = raw.decode('latin1', 'replace') if isinstance(raw, (bytes, bytearray)) else str(raw)
            if text == LITERAL:
                hits.append(hex(int(ea)))
    if not hits:
        result = {'error': 'GetName does not return the gl renderer label'}
    else:
        result = {'pointer_size': 4, 'hits': hits}
"""


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    debug=False,
):
    _ = skill_name, old_yaml_map, new_binary_dir
    output = _output_for_symbol(expected_outputs, OUTPUT_STEM) or _output_for_symbol(expected_outputs, CLASS_NAME)
    if output is None:
        return False
    table = await preprocess_vtable_via_mcp(session, CLASS_NAME, image_base, platform, debug=debug)
    if not table:
        if debug:
            print(f"{skill_name}: named {CLASS_NAME} vtable was not unique")
        return False
    entries = table.get("vtable_entries") or {}
    slot0 = entries.get(0, entries.get("0"))
    if slot0 is None:
        return False
    symbol = str(table.get("vtable_symbol") or "")
    named_opengl = "CVideoMode_OpenGL" in symbol and (symbol.startswith("??_7") or symbol.startswith("_ZTV"))
    if not named_opengl:
        verified = await run_walk(session, VERIFY, {"slot0": str(slot0), "literal": GL_LITERAL})
        if verified.get("error") or verified.get("pointer_size") != 4:
            if debug:
                print(f"{skill_name}: {verified.get('error')}")
            return False
    write_vtable_yaml(
        output,
        {
            "vtable_class": CLASS_NAME,
            "vtable_symbol": table.get("vtable_symbol") or CLASS_NAME,
            "vtable_va": table["vtable_va"],
            "vtable_rva": table["vtable_rva"],
            "vtable_size": table["vtable_size"],
            "vtable_numvfunc": table["vtable_numvfunc"],
            "vtable_entries": table["vtable_entries"],
        },
    )
    if debug:
        print(
            f"{skill_name}: va={table['vtable_va']} "
            f"symbol={table.get('vtable_symbol')} slots={table['vtable_numvfunc']}"
        )
    return True
