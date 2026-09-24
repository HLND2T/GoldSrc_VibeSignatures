#!/usr/bin/env python3
"""Locate the standalone game-DLL initializer from its duplicate-init guard.

The exact diagnostic belongs to one function on every configured target except
HL 8684 Linux. GCC also inlined the same source body into Host_Load_0 and
Host_Map_f_0 there; the real ELF symbol names the standalone entry. We select
that symbol only when it is itself one of the diagnostic's code owners.
"""

from ida_analyze_util import _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._engine_private_globals_common import inspect_func, run_walk

NAME = "Host_InitializeGameDLL"
DIAGNOSTIC = "Sys_InitializeGameDLL called twice, skipping second call\n"

WALK = r"""
import ida_name

literal = values['literal']
matches = [int(item.ea) for item in idautils.Strings() if str(item) == literal]
owners = set()
for string_ea in matches:
    for ref in idautils.DataRefsTo(string_ea):
        function = ida_funcs.get_func(int(ref))
        if function is not None:
            owners.add(int(function.start_ea))
if len(matches) != 1 or not owners:
    result = {'error': 'expected one referenced diagnostic string', 'matches': len(matches), 'owners': [hex(x) for x in sorted(owners)]}
elif len(owners) == 1:
    result = {'function': hex(next(iter(owners))), 'matches': 1, 'owners': 1, 'selection': 'unique string owner'}
else:
    # The sole supported ambiguity is the unstripped HL 8684 Linux ELF.
    named = ida_name.get_name_ea(idaapi.BADADDR, values['name'])
    if values['platform'] != 'linux' or named not in owners or len(owners) != 3:
        result = {'error': 'ambiguous diagnostic owners', 'owners': [hex(x) for x in sorted(owners)]}
    else:
        result = {'function': hex(named), 'matches': 1, 'owners': len(owners), 'selection': 'ELF standalone symbol'}
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
    _ = old_yaml_map, new_binary_dir
    output = _output_for_symbol(expected_outputs, NAME)
    if output is None:
        return False
    located = await run_walk(session, WALK, {"literal": DIAGNOSTIC, "name": NAME, "platform": platform})
    if located.get("error") or not located.get("function"):
        if debug:
            print(f"{skill_name}: {located}")
        return False
    function = await inspect_func(session, int(located["function"], 0), image_base, NAME)
    if not function:
        return False
    write_func_yaml(output, function)
    if debug:
        print(f"{skill_name}: {function['func_va']} via {located['selection']}")
    return True
