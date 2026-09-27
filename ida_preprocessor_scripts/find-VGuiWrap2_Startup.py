#!/usr/bin/env python3
"""Locate the BaseUI startup wrapper through its interface query and vcall roles.

The ``BaseUI001`` literal also belongs to an interface registrar. Windows puts
``VEngineVGui001`` in another registrar function, so excluding that string does
not distinguish the two. The wrapper alone passes factory count 2 and client
interface version 7 to consecutive IBaseUI calls after the query.
"""

from ida_analyze_util import _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._engine_private_globals_common import inspect_func, run_walk

NAME = "VGuiWrap2_Startup"

WALK = r"""
import ida_funcs, ida_nalt, idautils, idc

literal = values['literal']
offsets = tuple(values['offsets'])
owners = set()
strings = idautils.Strings(default_setup=False)
strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
for item in strings:
    if str(item) != literal:
        continue
    for ref in idautils.XrefsTo(int(item.ea), 0):
        function = ida_funcs.get_func(int(ref.frm))
        if function is not None:
            owners.add(int(function.start_ea))

candidates = []
for start in sorted(owners):
    entries = scan(start)
    if entries is None:
        continue
    calls = []
    arguments = set()
    for entry in entries:
        insn = entry['insn']
        if entry['mnem'] == 'call' and int(insn.ops[0].type) == int(idaapi.o_displ):
            if int(insn.ops[0].addr) in offsets:
                calls.append((int(entry['ea']), int(insn.ops[0].addr)))
        if entry['mnem'] in ('push', 'mov'):
            for op in (insn.ops[0], insn.ops[1]):
                if int(op.type) == int(idaapi.o_imm) and int(op.value) in (2, 7):
                    arguments.add(int(op.value))
    if (len(calls) == 2 and [slot for _, slot in calls] == list(offsets)
            and arguments == {2, 7}):
        candidates.append({'ea': hex(start), 'name': idc.get_func_name(start)})

result = {'pointer_size': 4, 'owners': [hex(o) for o in sorted(owners)],
          'candidates': candidates}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map, new_binary_dir
    output = _output_for_symbol(expected_outputs, NAME)
    if output is None or platform not in {"windows", "linux"}:
        return False
    offsets = (4, 8) if platform == "windows" else (8, 12)
    located = await run_walk(session, WALK, {"literal": "BaseUI001", "offsets": offsets})
    if debug:
        print(f"{skill_name}: {located}")
    candidates = located.get("candidates")
    if located.get("pointer_size") != 4 or not isinstance(candidates, list) or len(candidates) != 1:
        return False
    candidate = candidates[0]
    ida_name = candidate.get("name")
    display_name = (
        ida_name if platform == "linux" and isinstance(ida_name, str) and not ida_name.startswith("sub_") else NAME
    )
    function = await inspect_func(session, int(candidate["ea"], 0), image_base, display_name)
    if function is None:
        return False
    write_func_yaml(output, function)
    return True
