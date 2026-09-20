#!/usr/bin/env python3
"""Recover cl_funcs from the client Initialize dispatch in ClientDLL_Init.

``engine/cdll_int.c`` ends ``ClientDLL_Init`` with

    cl_funcs.pInitFunc( &cl_enginefuncs, CLDLL_INTERFACE_VERSION );

``pInitFunc`` is the first member of ``cldll_func_t``, so the address of the
called function pointer *is* ``&cl_funcs``. The call is identified by its two
arguments — the literal interface version 7 and a table whose first twelve
dwords all point into executable memory — which is the same validated shape
``find-ClientDLL_Init-pic-enginefuncs`` already uses for the other operand.

This covers the SvEngine Linux builds, whose ``ClientDLL_HudInit`` path is not
analysed, so ``find-ClientDLL_HudInit-decompiles`` cannot supply ``cl_funcs``
there. The three GoldSrc call forms are all handled: an absolute
``call ds:cl_funcs.pInitFunc``, an MSVC ``call dword_XXXXXXXX``, and the GCC PIC
``call ds:(cl_funcs - GOT)[ebx]``.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping
from ida_preprocessor_scripts._direct_gv_common import write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import owner_context, run_walk

GV_NAME = "cl_funcs"
OWNER_FUNC_NAME = "ClientDLL_Init"
CLDLL_INTERFACE_VERSION = 7
# cl_enginefuncs' leading entries are function pointers on every x86 peer.
ENGINE_TABLE_PROBE_ENTRIES = 12

WALK = r"""
import ida_gdl

OWNER = int(values['owner'], 0)
VERSION = int(values['version'])
PROBE = int(values['probe'])


def engine_table(ea):
    if not is_readable_data(ea) or ea % 4:
        return False
    for index in range(PROBE):
        if not is_code_address(ida_bytes.get_dword(ea + index * 4)):
            return False
    return True


owner = ida_funcs.get_func(OWNER)
if owner is None or int(owner.start_ea) != OWNER:
    result = {'error': 'ClientDLL_Init artifact is not a function start'}
else:
    got_base, got_register = got_anchor(OWNER)
    candidates = []
    for block in ida_gdl.FlowChart(owner):
        registers = {}
        stack = {}
        pushed = []
        for ea in idautils.Heads(block.start_ea, block.end_ea):
            insn = idautils.DecodeInstruction(int(ea))
            if not insn:
                break
            mnemonic = (idc.print_insn_mnem(int(ea)) or '').lower()
            destination = insn.ops[0]
            source = insn.ops[1]
            if mnemonic == 'call':
                pointer = None
                if int(destination.type) == int(idaapi.o_mem) and is_writable_data(int(destination.addr)):
                    pointer = int(destination.addr)
                elif int(destination.type) in (int(idaapi.o_displ), int(idaapi.o_phrase)):
                    base = reg4(destination)
                    resolved = None
                    if got_base is not None and base == got_register:
                        resolved = (got_base + signed32(destination.addr)) & 0xFFFFFFFF
                    elif base in registers and registers[base] is not None:
                        resolved = (int(registers[base][0]) + signed32(destination.addr)) & 0xFFFFFFFF
                    if resolved is not None and is_writable_data(resolved):
                        pointer = resolved
                table = stack.get(0)
                version = stack.get(4)
                if table is None and len(pushed) >= 2:
                    table, version = pushed[-1], pushed[-2]
                if (pointer is not None and table is not None and version is not None
                        and int(version[0]) == VERSION and engine_table(int(table[0]))):
                    offb = int(getattr(destination, 'offb', 0) or 0)
                    if offb and int(insn.size) - offb >= 4:
                        candidates.append((pointer, int(ea), int(insn.size), offb))
                registers, stack, pushed = {}, {}, []
                continue
            value = None
            if mnemonic == 'mov' and int(source.type) == int(idaapi.o_imm):
                value = (int(source.value), int(ea))
            elif mnemonic == 'mov' and int(source.type) == int(idaapi.o_reg):
                value = registers.get(reg4(source))
            elif mnemonic == 'lea':
                refs = {int(x) for x in idautils.DataRefsFrom(int(ea)) if is_readable_data(x)}
                if len(refs) == 1 and int(getattr(source, 'offb', 0) or 0):
                    value = (refs.pop(), int(ea))
            if mnemonic == 'push':
                if int(destination.type) == int(idaapi.o_imm):
                    pushed.append((int(destination.value), int(ea)))
                elif int(destination.type) == int(idaapi.o_reg):
                    pushed.append(registers.get(reg4(destination)))
                else:
                    pushed.append(None)
                continue
            if int(destination.type) == int(idaapi.o_reg):
                registers.pop(reg4(destination), None)
                if value is not None:
                    registers[reg4(destination)] = value
            elif int(destination.type) in (int(idaapi.o_displ), int(idaapi.o_phrase)) and '[esp' in (
                    idc.print_operand(int(ea), 0) or '').lower():
                offset = signed32(destination.addr) if int(destination.type) == int(idaapi.o_displ) else 0
                stack.pop(offset, None)
                if value is not None:
                    stack[offset] = value
    unique = {item[0] for item in candidates}
    if len(unique) != 1:
        result = {'error': 'Initialize dispatch is not unique: %s' % [hex(x) for x in sorted(unique)]}
    else:
        pointer, ea, size, offb = candidates[0]
        result = {
            'pointer_size': 4,
            'gv': {
                'gv_ea': hex(pointer),
                'insn_ea': hex(ea),
                'insn_len': hex(size),
                'insn_disp': hex(offb),
                'insn_disasm': idc.generate_disasm_line(ea, 0) or '',
            },
        }
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
    _ = old_yaml_map
    artifact = _load_yaml_mapping(Path(new_binary_dir) / f"{OWNER_FUNC_NAME}.{platform}.yaml")
    if not artifact or artifact.get("func_name") != OWNER_FUNC_NAME:
        if debug:
            print(f"{skill_name}: missing {OWNER_FUNC_NAME} artifact")
        return False
    try:
        owner_ea = int(artifact["func_va"], 0)
    except (KeyError, TypeError, ValueError):
        return False
    if owner_ea < int(image_base):
        return False

    located = await run_walk(
        session,
        WALK,
        {
            "owner": hex(owner_ea),
            "version": CLDLL_INTERFACE_VERSION,
            "probe": ENGINE_TABLE_PROBE_ENTRIES,
        },
    )
    if located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"{skill_name}: {located.get('error')}")
        return False

    owner = await owner_context(session, owner_ea, image_base, OWNER_FUNC_NAME)
    if owner is None:
        return False
    if debug:
        print(f"{skill_name}: {GV_NAME}={located['gv']['gv_ea']} via {located['gv']['insn_disasm']}")
    return await write_located_globals(session, expected_outputs, platform, image_base, owner, {GV_NAME: located["gv"]})
