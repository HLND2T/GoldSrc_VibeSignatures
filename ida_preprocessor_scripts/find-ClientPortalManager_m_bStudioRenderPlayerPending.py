#!/usr/bin/env python3
"""Locate the reset-initialized, read-and-cleared portal studio state byte.

The name describes observed behavior, not a recovered source member name.
Neither the Windows nor Linux member displacement is a discovery constant.
"""

import inspect
from pathlib import Path

import ida_analyze_util as u
import ida_preprocessor_scripts._portal_studio_state as studio_state
from ida_preprocessor_scripts._patch_signature_common import run_signature
from ida_preprocessor_scripts._portal_layout_ida import run_layout_walk

TARGET = "ClientPortalManager_m_bStudioRenderPlayerPending"

BODY = r"""
reset = values['reset']
owners, frontier = set(), {reset}
for _ in range(3):
    following = set()
    for target in frontier:
        for ref in elf_code_refs_to(target):
            if (idc.print_insn_mnem(ref) or '').lower() != 'call':
                continue
            function = ida_funcs.get_func(ref)
            if function and int(function.start_ea) != reset:
                following.add(int(function.start_ea))
    frontier = following - owners
    owners.update(frontier)
    if len(owners) > 200:
        raise ValueError('portal reset caller graph exceeds its bound')
callers = {ea: decode_function(ea) for ea in sorted(owners)}
result = recover_studio_member(reset, decode_function(reset), callers, values['platform'])
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    output = u._output_for_symbol(expected_outputs, TARGET)
    if not output:
        return False
    name = "ClientPortalManager_ResetAll"
    payload = u._load_yaml_mapping(Path(new_binary_dir) / f"{name}.{platform}.yaml")
    if not payload or payload.get("func_name") != name:
        return False
    try:
        reset = u._parse_int(payload["func_va"], "func_va")
        if reset < image_base:
            return False
        source = inspect.getsource(studio_state).replace(
            "from ida_preprocessor_scripts._portal_layout import Trace", ""
        )
        located = await run_layout_walk(session, {"reset": reset, "platform": platform}, source + "\n" + BODY)
        signature = await run_signature(session, located["instruction"], fixed_target=True)
        if not signature:
            return False
        u.write_struct_offset_yaml(
            output,
            {
                "struct_name": "ClientPortalManager",
                "member_name": "m_bStudioRenderPlayerPending",
                "offset": hex(located["offset"]),
                "size": located["size"],
                "offset_sig": signature["patch_sig"],
                "offset_sig_disp": 0,
            },
        )
    except (KeyError, TypeError, ValueError) as exc:
        if debug:
            print(f"{skill_name}: {exc}")
        return False
    if debug:
        print(f"{skill_name}: {located}")
    return True
