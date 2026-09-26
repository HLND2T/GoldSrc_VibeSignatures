#!/usr/bin/env python3
"""Recover GL clip setup from RenderPortals, through SetupRendering on Linux.

Require index/viewangles/view/plane arguments plus LoadIdentity, ClipPlane and
Enable behavior. The diagnostic-string owner is a separate calculation finder.
"""

from pathlib import Path
import ida_analyze_util as u
from ida_preprocessor_scripts._portal_render_state_ida import run_render_state_walk

TARGET = "ClientPortalManager_EnableClipPlane"


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
    output = u._output_for_symbol(expected_outputs, TARGET)
    name = "ClientPortalManager_RenderPortals"
    predecessor = u._load_yaml_mapping(Path(new_binary_dir) / f"{name}.{platform}.yaml")
    if not output or not predecessor or predecessor.get("func_name") != name:
        return False
    try:
        located = await run_render_state_walk(
            session, {"mode": "clip", "platform": platform, "render": u._parse_int(predecessor["func_va"], "func_va")}
        )
    except ValueError as exc:
        if debug:
            print(f"{skill_name}: {exc}")
        return False
    payload = await u._inspect_function_via_mcp(session, located["function"], image_base, TARGET)
    if not payload:
        return False
    u.write_func_yaml(
        output, {key: payload[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    )
    if debug:
        print(f"{skill_name}: {payload['func_va']}")
    return True
