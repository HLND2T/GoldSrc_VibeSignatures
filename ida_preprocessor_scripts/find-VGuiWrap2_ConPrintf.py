#!/usr/bin/env python3
"""Locate the console wrapper from its global pointer and Printf dispatch.

The two sibling wrappers share the same fallback buffer and format string;
ConDPrintf calls the next vtable slot. Some startup bodies inline ConPrintf,
so that body is excluded rather than assumed to call the standalone wrapper.
"""

from pathlib import Path

from ida_analyze_util import _inspect_function_via_mcp, _load_yaml_mapping, _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._engine_private_globals_common import func_payload, inspect_func, run_walk
from ida_preprocessor_scripts._vgui_console_common import recover_console_entry

NAME = "VGuiWrap2_ConPrintf"

WALK = r"""
import ida_funcs, ida_segment, idautils, idc

gv = int(values['gv'], 0)
startup = int(values['startup'], 0)
slot = int(values['slot'])
owners = set()
for ref in idautils.DataRefsTo(gv):
    function = ida_funcs.get_func(int(ref))
    if function is not None:
        owners.add(int(function.start_ea))
    elif is_got(int(ref)):
        for user in idautils.DataRefsTo(int(ref)):
            function = ida_funcs.get_func(int(user))
            if function is not None:
                owners.add(int(function.start_ea))

candidates = []
startup_entries = scan(startup)
startup_globals = ({target for entry in startup_entries for target in entry['targets']} - {gv}
                   if startup_entries is not None else set())
for start in sorted(owners - {startup}):
    entries = scan(start)
    if entries is None or not any(gv in entry['targets'] for entry in entries):
        continue
    matches = [entry for entry in entries if entry['mnem'] == 'call'
               and int(entry['insn'].ops[0].type) == int(idaapi.o_displ)
               and int(entry['insn'].ops[0].addr) == slot]
    if len(matches) == 1:
        shared = sorted(
            target for target in startup_globals & {target for entry in entries for target in entry['targets']}
            if (segment := ida_segment.getseg(target)) is not None
            and ida_segment.get_segm_name(segment).startswith(('.data', '.bss'))
        )
        # The console wrapper and startup both manipulate the temporary
        # console buffer. A BaseUI shutdown path can touch this same console
        # pointer and slot while sharing only a PIC metadata object in LOAD.
        if not shared:
            continue
        candidates.append({'ea': hex(start), 'vcall': hex(int(matches[0]['ea'])),
                           'name': idc.get_func_name(start), 'shared': [hex(x) for x in shared]})

result = {'pointer_size': 4, 'owners': [hex(x) for x in sorted(owners)],
          'candidates': candidates}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map
    output = _output_for_symbol(expected_outputs, NAME)
    if output is None or platform not in {"windows", "linux"}:
        return False
    directory = Path(new_binary_dir)
    gv_artifact = _load_yaml_mapping(directory / f"staticGameConsole.{platform}.yaml")
    startup_artifact = _load_yaml_mapping(directory / f"VGuiWrap2_Startup.{platform}.yaml")
    if not gv_artifact or gv_artifact.get("gv_name") != "staticGameConsole" or not startup_artifact:
        return False
    try:
        gv = int(gv_artifact["gv_va"], 0)
        startup = int(startup_artifact["func_va"], 0)
        if int(gv_artifact["gv_rva"], 0) != gv - int(image_base):
            return False
    except (KeyError, TypeError, ValueError):
        return False
    slot = 0x18 if platform == "windows" else 0x1C
    located = await run_walk(session, WALK, {"gv": hex(gv), "startup": hex(startup), "slot": slot})
    if debug:
        print(f"{skill_name}: {located}")
    candidates = located.get("candidates")
    if located.get("pointer_size") != 4 or not isinstance(candidates, list) or len(candidates) != 1:
        return False
    candidate = candidates[0]
    entry = await recover_console_entry(session, int(candidate["vcall"], 0))
    if entry is None:
        return False
    ida_name = candidate.get("name")
    display_name = (
        ida_name if platform == "linux" and isinstance(ida_name, str) and not ida_name.startswith("sub_") else NAME
    )
    function = await inspect_func(session, entry, image_base, display_name)
    if function is None:
        # Some stripped GCC builds give ConPrintf and ConDPrintf the same
        # wildcarded entry bytes. A unique relative thunk call discriminates
        # their generated runtime signatures after semantic discovery.
        inspected = await _inspect_function_via_mcp(
            session,
            entry,
            image_base,
            display_name,
            allow_relative_call_discriminator=True,
            signature_byte_limit=128,
        )
        if inspected:
            function = func_payload(inspected)
    if function is None:
        return False
    write_func_yaml(output, function)
    return True
