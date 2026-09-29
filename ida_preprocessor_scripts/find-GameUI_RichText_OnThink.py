#!/usr/bin/env python3
"""Find inherited RichText::OnThink in the console-history object's vtable.

The console creates CNoKeyboardInputRichText as ``ConsoleHistory``. Its RTTI
vtable inherits RichText::OnThink. Scan the table for the source behavior:
read the line-break flag, set the saved-render-state flag, then read the
scrollbar-invalidation flag. Their ordered, distinct byte-member accesses
identify one entry on every configured PE32/ELF32 build without assuming a
fixed vtable index or member offset. The entry must also equal the base
RichText table entry at the same index.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._client_vgui_private_common import inspect_unique_function, run_walk
from ida_preprocessor_scripts._gameui_dialog_common import prepare_c_strings


TARGET = "GameUI_RichText_OnThink"
REAL_NAME = "vgui2::RichText::OnThink()"
MAX_VTABLE_SLOTS = 256


LOCATE = r"""
import ida_name

console = int(values['console'])
history = string_owner_evidence('ConsoleHistory')
if history['count'] != 1 or history['owners'] != [console] or len(history['ref_sites']) != 1:
    raise ValueError('ConsoleHistory does not uniquely identify the validated console constructor')

if values['platform'] == 'windows':
    names = ('??_7CNoKeyboardInputRichText@@6B@', '??_7RichText@vgui2@@6B@')
else:
    names = ('_ZTV24CNoKeyboardInputRichText', '_ZTVN5vgui28RichTextE')
tables = [int(ida_name.get_name_ea(idaapi.BADADDR, name)) for name in names]
if any(table == idaapi.BADADDR for table in tables):
    raise ValueError('derived or base RichText RTTI vtable missing')
if values['platform'] == 'linux':
    tables = [table + 8 for table in tables]
derived = valid_vtable_slots(tables[0], maximum=values['max_slots'])
base = valid_vtable_slots(tables[1], maximum=values['max_slots'])
if not derived or not base:
    raise ValueError('RichText RTTI vtable has no valid executable entries')

candidates = []
for index, target in enumerate(derived):
    if index >= len(base) or target != base[index]:
        continue
    function = ida_funcs.get_func(target)
    if function is None or int(function.start_ea) != target:
        continue
    reads, stores, branches, calls = [], [], [], []
    for ea in function_body(target):
        instruction = idautils.DecodeInstruction(ea)
        if instruction is None:
            continue
        mnemonic = instruction.get_canon_mnem()
        if mnemonic in ('cmp', 'test', 'mov', 'movzx'):
            for operand_index in range(2):
                operand = instruction.ops[operand_index]
                if (operand.type == ida_ua.o_displ
                        and operand.dtype == ida_ua.dt_byte
                        and 0 <= int(operand.addr) <= 0xFFFFFFFF
                        and (mnemonic in ('cmp', 'test', 'movzx') or operand_index == 1)):
                    reads.append((int(ea), int(operand.addr)))
        if (mnemonic == 'mov'
                and instruction.ops[0].type == ida_ua.o_displ
                and instruction.ops[0].dtype == ida_ua.dt_byte
                and 0 <= int(instruction.ops[0].addr) <= 0xFFFFFFFF
                and instruction.ops[1].type == ida_ua.o_imm
                and (int(instruction.ops[1].value) & 0xFF) == 1):
            stores.append((int(ea), int(instruction.ops[0].addr)))
        if mnemonic.startswith('j') and mnemonic != 'jmp':
            branches.append(int(ea))
        if (mnemonic in ('call', 'jmp')
                and instruction.ops[0].type in (ida_ua.o_near, ida_ua.o_far)):
            calls.append(int(ea))
    # The three byte members have a source-level order, but their numeric
    # offsets and the ABI's vtable index are discovered from this IDB.
    triples = [(first, store, second)
               for first in reads for store in stores for second in reads
               if first[0] < store[0] < second[0]
               and first[1] < second[1] < store[1]]
    if triples and len(branches) >= 2 and calls:
        candidates.append({'index': index, 'target': target, 'members': sorted(set(
            (first[1], store[1], second[1]) for first, store, second in triples))})
if len(candidates) != 1:
    raise ValueError('OnThink behavior is not unique in inherited RTTI table: '+repr(candidates))
result = {'target': candidates[0]['target'], 'index': candidates[0]['index'],
          'vtable': tables[0], 'members': candidates[0]['members']}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    if not await prepare_c_strings(session):
        return False
    console = _load_yaml_mapping(Path(new_binary_dir) / f"CGameConsoleDialog_ctor.{platform}.yaml")
    output = _output_for_symbol(expected_outputs, TARGET)
    if console is None or output is None:
        return False
    found = await run_walk(
        session,
        LOCATE,
        {"console": int(console["func_va"], 0), "platform": platform, "max_slots": MAX_VTABLE_SLOTS},
    )
    if found.get("error") or not isinstance(found.get("target"), int):
        if debug:
            print(f"  Console RichText OnThink validation failed: {found}")
        return False
    inspected = await inspect_unique_function(session, REAL_NAME, found["target"], image_base, debug)
    if inspected is None:
        return False
    index = found["index"]
    inspected.update(vtable_name="CNoKeyboardInputRichText", vfunc_index=index, vfunc_offset=hex(index * 4))
    write_func_yaml(output, inspected)
    return True
