#!/usr/bin/env python3
"""Find the packet-entity model interpolator from its verified caller.

The exact diagnostic in CL_LinkPacketEntities provides the predecessor. Its
model interpolator copies the packet pose, checks ``model->name[0] == '*'``,
then calls the 64-slot history search before angle interpolation. The unique
callee with that star check and history call is the normal entry on 14 engine
builds. hl-8684 Linux instead calls ``CL_InterpolateModel.part.1`` directly:
the only other caller with the star check is the public wrapper. Both entries
are emitted there under their real ELF symbol names. The 180/360 degree pool
values did not uniquely resolve the shipped builds, so the finder uses the
caller and history-search structure. No byte signature or old YAML is a
discovery anchor.
"""

from pathlib import Path

import ida_analyze_util as u
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact
from ida_preprocessor_scripts._engine_private_globals_common import inspect_func, run_walk
from ida_preprocessor_scripts._engine_entity_interpolation_common import function_identity

OWNER = "CL_LinkPacketEntities"
TARGET = "CL_InterpolateModel"
PART = "CL_InterpolateModel.part.1"

WALK = r"""
import idaapi, ida_funcs, idc

owner = int(values['owner'], 0)

def has_star(start):
    entries = scan(start)
    if entries is None:
        return False
    return any(
        entry['mnem'] == 'cmp'
        and any(int(op.type) == int(idaapi.o_imm) and int(op.value) == ord('*')
                for op in entry['insn'].ops)
        for entry in entries
    )

def history_callees(start):
    found = []
    for callee in direct_calls(start):
        entries = scan(callee)
        if entries is None:
            continue
        masks = [entry for entry in entries if any(
            int(op.type) == int(idaapi.o_imm) and int(op.value) == 63
            for op in entry['insn'].ops)]
        # HISTORY_MASK appears in the initial two ring indices, the scan,
        # and the output index. Require multiple uses, not an incidental 63.
        if len(masks) >= 4:
            found.append(callee)
    return found

direct = []
split = []
for callee in direct_calls(owner):
    history = history_callees(callee)
    if len(history) != 1:
        continue
    if has_star(callee):
        direct.append((callee, history[0]))
        continue
    wrappers = sorted({caller for caller, _ in callers(callee)
                       if caller != owner and has_star(caller)})
    if len(wrappers) == 1:
        split.append((wrappers[0], callee, history[0]))

if len(direct) == 1 and not split:
    result = {'entry': hex(direct[0][0]), 'history': hex(direct[0][1])}
elif len(split) == 1 and not direct:
    result = {'entry': hex(split[0][0]), 'part': hex(split[0][1]),
              'history': hex(split[0][2])}
else:
    result = {'error': 'model interpolator is absent or ambiguous',
              'direct': len(direct), 'split': len(split)}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    output = u._output_for_symbol(expected_outputs, TARGET)
    part_output = u._output_for_symbol(expected_outputs, PART)
    if output is None:
        return False
    owner = await inspect_owner_artifact(
        session,
        new_binary_dir,
        platform,
        image_base,
        OWNER,
        func_name=function_identity(new_binary_dir, platform, OWNER),
    )
    if owner is None:
        return False
    found = await run_walk(session, WALK, {"owner": hex(owner["owner_ea"])})
    if not isinstance(found, dict) or found.get("error"):
        if debug:
            print(f"  {TARGET}: locator failed {found}")
        return False
    has_part = "part" in found
    # Only this current-binary split has a separate public wrapper and core.
    is_hl8684_linux = platform == "linux" and Path(new_binary_dir).parent.name == "hl-8684"
    if has_part != is_hl8684_linux or (part_output is not None) != has_part:
        return False
    try:
        entry_ea = int(found["entry"], 0)
        part_ea = int(found["part"], 0) if has_part else None
    except (KeyError, TypeError, ValueError):
        return False
    identity = function_identity(new_binary_dir, platform, TARGET)
    entry = await inspect_func(session, entry_ea, image_base, identity)
    if entry is None:
        return False
    part = await inspect_func(session, part_ea, image_base, PART) if has_part else None
    if has_part and part is None:
        return False
    u.write_func_yaml(output, entry)
    if has_part:
        u.write_func_yaml(part_output, part)
    return True
