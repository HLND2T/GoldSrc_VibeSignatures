#!/usr/bin/env python3
"""Recover the IGameConsole pointer from its BaseUI factory assignment.

``CBaseUI::Initialize`` queries ``GameConsole003`` and caches that call's
return value in ``staticGameConsole``. The literal can also appear on an error
path, so the locator follows the indirect factory call and its return-value
store rather than choosing the closest writable operand.
"""

from ida_preprocessor_scripts._direct_gv_common import write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import owner_context, run_walk

NAME = "staticGameConsole"

WALK = r"""
import ida_funcs, ida_nalt, idautils

owners = {}
strings = idautils.Strings(default_setup=False)
strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
for item in strings:
    if str(item) != 'GameConsole003':
        continue
    for ref in idautils.XrefsTo(int(item.ea), 0):
        function = ida_funcs.get_func(int(ref.frm))
        if function is not None:
            owners.setdefault(int(function.start_ea), set()).add(int(ref.frm))

candidates = []
for owner, sites in owners.items():
    entries = scan(owner)
    if entries is None:
        continue
    positions = {int(entry['ea']): i for i, entry in enumerate(entries)}
    for site in sites:
        if site not in positions:
            continue
        index = positions[site]
        for call_index in range(index + 1, min(index + 9, len(entries))):
            call = entries[call_index]
            if call['mnem'] != 'call':
                continue
            kind = int(call['insn'].ops[0].type)
            if kind not in (int(idaapi.o_reg), int(idaapi.o_displ), int(idaapi.o_phrase)):
                break
            for store_index in range(call_index + 1, min(call_index + 13, len(entries))):
                entry = entries[store_index]
                if entry['mnem'] == 'call':
                    break
                if entry['mnem'] != 'mov' or not entry['written']:
                    continue
                source = entry['insn'].ops[1]
                if int(source.type) != int(idaapi.o_reg) or reg4(source) != 'eax':
                    continue
                if len(entry['written']) == 1:
                    gv = int(next(iter(entry['written'])))
                    if entry['disp']:
                        candidates.append((owner, gv, entry))
                break
            break

unique = {(owner, gv) for owner, gv, _ in candidates}
if len(unique) != 1:
    result = {'error': 'GameConsole003 factory result is ambiguous',
              'owners': [hex(x) for x in sorted(owners)],
              'candidates': [(hex(o), hex(g)) for o, g in sorted(unique)]}
else:
    owner, gv = next(iter(unique))
    carrier = next(entry for o, g, entry in candidates if o == owner and g == gv)
    result = {'pointer_size': 4, 'owner_ea': hex(owner), 'gv': access(carrier, gv)}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map, new_binary_dir
    located = await run_walk(session, WALK)
    if debug:
        print(f"{skill_name}: {located}")
    if located.get("pointer_size") != 4 or not isinstance(located.get("gv"), dict):
        return False
    owner = await owner_context(session, int(located["owner_ea"], 0), image_base, "CBaseUI__Initialize")
    if owner is None:
        return False
    return await write_located_globals(session, expected_outputs, platform, image_base, owner, {NAME: located["gv"]})
