#!/usr/bin/env python3
"""Locate the engine's control factory, not the separately linked gameui copy.

MessageBoxText and ResourceImagePanel are target-owned constructor arguments.
Unlike BitmapImagePanel, each occurs once even in the non-string-pooled CoF DLL.
"""

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, preprocess_common_skill, write_func_yaml


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    name = "vgui2_EditablePanel_CreateControlByName"
    found = await preprocess_common_skill(
        session,
        expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[name],
        func_xrefs=[dict(func_name=name, xref_strings=["FULLMATCH:MessageBoxText", "FULLMATCH:ResourceImagePanel"])],
        generate_yaml_desired_fields=[(name, ["func_name", "func_va", "func_rva", "func_size", "func_sig"])],
        debug=debug,
    )
    if not found:
        return False
    output = _output_for_symbol(expected_outputs, name)
    data = _load_yaml_mapping(output)
    data["func_name"] = "vgui2::EditablePanel::CreateControlByName(char const*)"
    write_func_yaml(output, data)
    return True
