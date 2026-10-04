#!/usr/bin/env python3
"""Recover separate Begin/EndRedirect entries from current FlushRedirect storage.

Mode comparisons and the terminal output-byte clear identify current operands.
Begin must store its incoming mode, copy the incoming reply address, and clear
that buffer; End must only flush and zero that mode. Inline Rcon/Drop/printf
owners cannot substitute for a callable helper. HL25 Windows is not registered.
"""

from ida_preprocessor_scripts._native_rcon_common import verify_function
from ida_preprocessor_scripts._native_rcon_path_common import locate_path_functions, write_path_functions

WALK = r"""
flush=int(values['flush'])
mode,buffer=redirect_storage(flush)
begin=[]
for candidate in functions_referencing(mode)&functions_referencing(buffer):
    if candidate==flush or semantic_calls(candidate):
        continue
    states=register_values(candidate)
    entries=scan(candidate) or []
    stores=[entry for entry in entries if mode in entry['written']]
    if len(stores)!=1 or stored_value(stores[0],states[stores[0]['ea']])!=('argument',0):
        continue
    if not any(is_zero_byte_store(entry,buffer) for entry in entries):
        continue
    # The reply object must be used by Flush and by the helper's copy. Different
    # compilers emit REP MOVSD, scalar stores or a PIC loop; no fixed width/offset
    # is used to discover an entry.
    reply=(all_globals(candidate)&all_globals(flush))-{mode,buffer}
    if reply and any(value==('argument',1) for state in states.values() for value in state.values()):
        begin.append(candidate)
ends=set()
for ref in elf_code_refs_to(flush):
    function=ida_funcs.get_func(ref)
    candidate=int(function.start_ea) if function is not None else recover_end_redirect(ref,flush,mode)
    if candidate is None or is_plt(candidate) or semantic_calls(candidate)!={flush}:
        continue
    entries=scan(candidate) or []
    states=register_values(candidate)
    stores=[entry for entry in entries if mode in entry['written']]
    if len(stores)==1 and stored_value(stores[0],states[stores[0]['ea']])==('constant',0):
        ends.add(candidate)
if len(begin)!=1 or len(ends)!=1:
    raise ValueError('ambiguous separate redirect helpers: begin=%r end=%r' % (begin,sorted(ends)))
result={'functions':{'SV_BeginRedirect':hex(begin[0]),'SV_EndRedirect':hex(next(iter(ends)))}}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map
    owner = await verify_function(session, new_binary_dir, platform, image_base, "SV_FlushRedirect")
    if owner is None:
        return False
    located = await locate_path_functions(session, WALK, {"flush": owner["owner_ea"]})
    if debug:
        print(f"{skill_name}: {located}")
    return await write_path_functions(session, expected_outputs, new_binary_dir, platform, image_base, located)
