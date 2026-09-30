#!/usr/bin/env python3
"""Inherit IVideoMode::UpdateWindowPosition from the existing concrete vfunc.

The current-version CVideoMode_Common_UpdateWindowPosition artifact already
accounts for HL25's inserted PlayStartupSequence slot. Pattern F copies its
validated index/offset without locating a second body or hardcoding an index.
"""

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, preprocess_common_skill, write_func_yaml


TARGET = "IVideoMode_UpdateWindowPosition"
INHERIT_VFUNCS = [(TARGET, "IVideoMode", "CVideoMode_Common_UpdateWindowPosition", False)]
GENERATE_YAML_DESIRED_FIELDS = [(TARGET, ["func_name", "vtable_name", "vfunc_offset", "vfunc_index"])]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    found = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        inherit_vfuncs=INHERIT_VFUNCS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
    if not found:
        return False
    output = _output_for_symbol(expected_outputs, TARGET)
    data = _load_yaml_mapping(output)
    if not data:
        return False
    data["func_name"] = "IVideoMode::UpdateWindowPosition"
    write_func_yaml(output, data)
    return True
