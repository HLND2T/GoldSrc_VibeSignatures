#!/usr/bin/env python3
"""Publish the behavior-recovered shader availability byte, not link status.

Reuse the shader chain's InitShader and prove its writes agree with both live
UseProgram branches, including Windows inlining and Linux's split reset helper.
"""

from pathlib import Path

import ida_analyze_util as u
from ida_preprocessor_scripts._portal_render_state_ida import run_render_state_walk

TARGET = "ClientPortalManager_m_bShadersAvailable"


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    output = u._output_for_symbol(expected_outputs, TARGET)
    if not output:
        return False
    values = {"mode": "shader", "platform": platform}
    for key, name in [("init", "ClientPortalManager_InitShader"), ("draw", "ClientPortalManager_DrawPortals")]:
        payload = u._load_yaml_mapping(Path(new_binary_dir) / f"{name}.{platform}.yaml")
        if not payload or payload.get("func_name") != name:
            return False
        values[key] = u._parse_int(payload["func_va"], "func_va")
    try:
        located = await run_render_state_walk(session, values)
    except ValueError as exc:
        if debug:
            print(f"{skill_name}: {exc}")
        return False
    u.write_struct_offset_yaml(
        output,
        {
            "struct_name": "ClientPortalManager",
            "member_name": "m_bShadersAvailable",
            "offset": hex(located["offset"]),
            "size": located["size"],
        },
    )
    if debug:
        print(f"{skill_name}: {located}")
    return True
