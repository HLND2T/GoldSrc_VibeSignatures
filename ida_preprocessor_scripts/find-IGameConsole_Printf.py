#!/usr/bin/env python3
"""Read the sole IGameConsole virtual call in VGuiWrap2_ConPrintf."""

from pathlib import Path

from ida_analyze_util import _find_unique_bytes, _load_yaml_mapping, _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._indirect_vcall_target_common import preprocess_indirect_vcall_target_skill
from ida_preprocessor_scripts._vgui_console_common import recover_console_entry

NAME = "IGameConsole_Printf"


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map, image_base
    source = _load_yaml_mapping(Path(new_binary_dir) / f"VGuiWrap2_ConPrintf.{platform}.yaml")
    if not source or not isinstance(source.get("func_sig"), str):
        return False
    try:
        source_ea = int(source["func_va"], 0)
        source_end = source_ea + int(source["func_size"], 0)
    except (KeyError, TypeError, ValueError):
        return False
    if await _find_unique_bytes(session, source["func_sig"]) != source_ea:
        return False
    if await recover_console_entry(session, source_ea, expected_entry=source_ea, expected_end=source_end) != source_ea:
        return False
    found = await preprocess_indirect_vcall_target_skill(
        session,
        expected_outputs,
        new_binary_dir,
        platform,
        source_yaml_stem="VGuiWrap2_ConPrintf",
        target_name=NAME,
        vtable_name="IGameConsole",
        generate_yaml_desired_fields=[(NAME, ["func_name", "vtable_name", "vfunc_offset", "vfunc_index"])],
        debug=debug,
    )
    if not found:
        return False
    output = _output_for_symbol(expected_outputs, NAME)
    payload = _load_yaml_mapping(output) if output else None
    if not payload:
        return False
    expected_offset = 0x18 if platform == "windows" else 0x1C
    if int(payload["vfunc_offset"], 0) != expected_offset:
        return False
    payload["func_name"] = "IGameConsole::Printf"
    write_func_yaml(output, payload)
    return True
