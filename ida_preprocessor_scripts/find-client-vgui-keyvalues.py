#!/usr/bin/env python3
"""Recover the client-side KeyValues vtable from MenuButton's hover tooltip.

``vgui2::MenuButton::OnCursorEntered`` constructs a ``KeyValues("CursorEnteredMenuButton")``
action message. The literal occurs once per verified client build and identifies that
owner; its first direct constructor call is ``KeyValues::KeyValues(const char*)``, whose
vptr store yields the KeyValues primary vtable. Slot 2 of that table is
``KeyValues::LoadFromFile`` on every verified build (MSVC and Itanium ABI alike),
matching MetaHookSv's ``vftable[2]`` consumption.

The slot is read from the emitted table entries rather than assumed from source order;
the walk fails closed when the anchor literal, owner, constructor, or vptr store is
ambiguous.
"""

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _output_for_symbol,
    write_func_yaml,
    write_vtable_yaml,
)
from ida_preprocessor_scripts._client_vgui_private_common import (
    LOADFROMFILE_SLOT_INDEX,
    run_walk,
)

VTABLE_SYMBOL = "ClientVGUI_KeyValues_vftable"
VFUNC_SYMBOL = "ClientVGUI_KeyValues_LoadFromFile"
VTABLE_CLASS = "KeyValues"
FUNCTION_NAME = "KeyValues::LoadFromFile(IFileSystem*, char const*, char const*)"
ANCHOR_LITERAL = "CursorEnteredMenuButton"

# The constructor installs its primary vptr into the ABI this object before any
# other work. Track the this register through the prologue (MSVC keeps it in ecx,
# GCC copies the stack argument into a callee-saved register) and accept the first
# imm32 store into [this] whose target is a table of function pointers.
WALK = r"""
def prologue_first_arg_disp(ctor_ea):
    # [esp+disp] of the first incoming cdecl argument after push/sub prologue
    # instructions: saved registers (4 bytes each) + frame size + return address.
    pushed = 0
    frame = 0
    cursor = int(ctor_ea)
    for _ in range(16):
        insn = idautils.DecodeInstruction(cursor)
        if insn is None:
            break
        mnemonic = insn.get_canon_mnem()
        if mnemonic == 'push':
            pushed += 4
        elif (mnemonic == 'sub' and insn.ops[0].type == ida_ua.o_reg
                and 'esp' in idc.print_operand(cursor, 0).lower()
                and insn.ops[1].type == ida_ua.o_imm):
            frame = int(insn.ops[1].value)
        else:
            break
        cursor += insn.size
    return pushed + frame + 4


def ctor_vptr_store(ctor_ea, first_arg_disp):
    # MSVC passes this in ecx; GCC loads it from the first stack argument once
    # the prologue has settled. Both ABIs install the primary vptr through the
    # first imm32 store into [this]; its target must be a table of function
    # pointers (MSVC vftable, Itanium _ZTV+8).
    this_regs = {'ecx'}
    loaded_from_stack = set()
    cursor = int(ctor_ea)
    for _ in range(48):
        insn = idautils.DecodeInstruction(cursor)
        if insn is None:
            return None
        mnemonic = insn.get_canon_mnem()
        if mnemonic.startswith('ret'):
            return None
        if mnemonic == 'mov' and len(insn.ops) >= 2:
            dest, source = insn.ops[0], insn.ops[1]
            dest_text = idc.print_operand(cursor, 0).lower()
            source_text = idc.print_operand(cursor, 1).lower()
            if dest.type == ida_ua.o_reg:
                if (source.type in (ida_ua.o_displ, ida_ua.o_phrase) and '[esp' in source_text
                        and int(source.addr) == first_arg_disp):
                    this_regs.discard(dest_text)
                    loaded_from_stack.add(dest_text)
                else:
                    aliased = (source.type == ida_ua.o_reg
                               and (source_text in this_regs or source_text in loaded_from_stack))
                    if dest_text in this_regs and not aliased:
                        this_regs.discard(dest_text)
                    if aliased:
                        this_regs.add(dest_text)
            if (dest.type in (ida_ua.o_displ, ida_ua.o_phrase) and int(dest.addr) == 0
                    and source.type == ida_ua.o_imm):
                operand = dest_text.replace('dword ptr ', '')
                base = operand.strip('[]')
                if base in this_regs or base in loaded_from_stack:
                    table = imm_value(source)
                    slots = valid_vtable_slots(table)
                    if slots:
                        return {'insn': int(cursor), 'vtable': int(table), 'slots': slots}
        elif mnemonic == 'call':
            for register in ('eax', 'ecx', 'edx'):
                this_regs.discard(register)
        cursor += insn.size
    return None


values.update(string_owner_evidence(values['literal']))
owner = require_single_owner(values, values['literal'])
ctors = first_direct_call_targets(values['ref_sites'], 0x40)
if not ctors or len(set(ctors)) != 1:
    raise ValueError('constructor call after anchor is not unique: ' + json.dumps(ctors))
store = ctor_vptr_store(ctors[0], prologue_first_arg_disp(ctors[0]))
if store is None:
    raise ValueError('constructor vptr store not found at ' + hex(ctors[0]))
result = {
    'owner': hex(owner),
    'ctor': hex(ctors[0]),
    'vtable': hex(store['vtable']),
    'vtable_insn': hex(store['insn']),
    'entries': {index: hex(target) for index, target in enumerate(store['slots'])},
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
    _ = skill_name, old_yaml_map, new_binary_dir
    located = await run_walk(session, WALK, {"literal": ANCHOR_LITERAL})
    if located.get("error") or "vtable" not in located:
        if debug:
            print(f"  {VTABLE_SYMBOL}: locator failed: {located.get('error', located)}")
        return False
    result = located
    entries = {int(index): str(value) for index, value in result["entries"].items()}
    raw_slot = entries.get(LOADFROMFILE_SLOT_INDEX)
    if raw_slot is None:
        if debug:
            print(f"  {VTABLE_SYMBOL}: no slot {LOADFROMFILE_SLOT_INDEX} entry")
        return False
    vtable_va = int(result["vtable"], 0)
    vtable = {
        "vtable_class": VTABLE_CLASS,
        "vtable_symbol": "??_7KeyValues@@6B@" if platform == "windows" else "_ZTV9KeyValues + 0x8",
        "vtable_va": hex(vtable_va),
        "vtable_rva": hex(vtable_va - int(image_base)),
        "vtable_size": hex(len(entries) * 4),
        "vtable_numvfunc": len(entries),
        "vtable_entries": entries,
    }
    load_target = int(raw_slot, 0)
    function = await _inspect_function_via_mcp(session, load_target, image_base, FUNCTION_NAME)
    allow_across = function is None or not function.get("func_sig")
    if allow_across:
        function = await _inspect_function_via_mcp(
            session, load_target, image_base, FUNCTION_NAME, allow_across_function_boundary=True
        )
    if not function or not function.get("func_sig"):
        if debug:
            print(f"  {VFUNC_SYMBOL}: no unique signature at {hex(load_target)}")
        return False
    vfunc = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size")}
    vfunc.update(
        vtable_name=VTABLE_CLASS,
        vfunc_index=LOADFROMFILE_SLOT_INDEX,
        vfunc_offset=hex(LOADFROMFILE_SLOT_INDEX * 4),
        vfunc_sig=function["func_sig"],
    )
    if allow_across:
        vfunc["vfunc_sig_allow_across_function_boundary"] = True
    outputs = {name: _output_for_symbol(expected_outputs, name) for name in (VTABLE_SYMBOL, VFUNC_SYMBOL)}
    if not all(outputs.values()):
        return False
    write_vtable_yaml(outputs[VTABLE_SYMBOL], vtable)
    write_func_yaml(outputs[VFUNC_SYMBOL], vfunc)
    return True
