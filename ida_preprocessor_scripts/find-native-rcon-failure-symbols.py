#!/usr/bin/env python3
"""Recover the retained read-only failure query from current AddFailedRcon xrefs.

The independently anchored mutator owns the record references/comparison call.
Require a separate read-only Boolean loop using that storage and comparator;
reject the mutator, reset callback and inline authentication/logging paths.
Intermediate table addresses are evidence only. HL25 Windows has no output.
"""

from ida_preprocessor_scripts._native_rcon_common import verify_function
from ida_preprocessor_scripts._native_rcon_path_common import locate_path_functions, write_path_functions

WALK = r"""
add=int(values['add'])
storage=all_globals(add)
calls=semantic_calls(add)
candidates=set()
for address in storage:
    for nearby in range(address-8,address+9,4):
        candidates.update(functions_referencing(nearby))
candidates-=literal_owners('Banning %s for rcon hacking attempts\n')
candidates-=literal_owners('Empty rcon\n')
found=[]
for candidate in candidates:
    if candidate==add or global_writes(candidate) or not return_boolean_body(candidate):
        continue
    edges=semantic_calls(candidate)
    if len(edges)!=1 or not edges<=calls or not shared_storage(all_globals(candidate),storage):
        continue
    entries=scan(candidate) or []
    tests=[entry for entry in entries if entry['mnem'] in ('test','cmp') and
           (entry['mnem']=='test' or immediate(entry)==0)]
    if len(tests)<2:
        continue
    # There must be a backwards control edge: this is a record loop, not a
    # scalar getter/boolean wrapper or a single-address comparison thunk.
    if not any(int(ref)<int(ea) for ea in idautils.FuncItems(candidate)
               if (idc.print_insn_mnem(ea) or '').lower().startswith('j')
               for ref in idautils.CodeRefsFrom(ea,False)
               if ida_funcs.get_func(ref) is not None and int(ida_funcs.get_func(ref).start_ea)==candidate):
        continue
    found.append(candidate)
if len(found)!=1:
    raise ValueError('ambiguous read-only RCON failure query: %r' % found)
result={'functions':{'SV_CheckRconFailure':hex(found[0])}}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map
    owner = await verify_function(session, new_binary_dir, platform, image_base, "SV_AddFailedRcon")
    if owner is None:
        return False
    located = await locate_path_functions(session, WALK, {"add": owner["owner_ea"]})
    if debug:
        print(f"{skill_name}: {located}")
    return await write_path_functions(session, expected_outputs, new_binary_dir, platform, image_base, located)
