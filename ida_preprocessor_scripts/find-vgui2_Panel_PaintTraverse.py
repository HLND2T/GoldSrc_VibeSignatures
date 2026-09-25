#!/usr/bin/env python3
"""Inherit the verified IClientPanel slot; preserve the actual vtable entry.

Optimized Linux builds also contain .part/.constprop bodies. Those are not the
callable entry advertised by the Panel vtable and must not replace it.
"""

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, preprocess_common_skill, write_func_yaml


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    name = "vgui2_Panel_PaintTraverse"
    found = await preprocess_common_skill(
        session,
        expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        inherit_vfuncs=[(name, "vgui2_Panel_vtable", "../vgui2/vgui2_IClientPanel_PaintTraverse", True)],
        generate_yaml_desired_fields=[
            (
                name,
                [
                    "func_name",
                    "func_va",
                    "func_rva",
                    "func_size",
                    "func_sig",
                    "vtable_name",
                    "vfunc_offset",
                    "vfunc_index",
                ],
            )
        ],
        debug=debug,
    )
    if not found:
        return False
    output = _output_for_symbol(expected_outputs, name)
    data = _load_yaml_mapping(output)
    data.update(func_name="vgui2::Panel::PaintTraverse(bool, bool)", vtable_name="vgui2::Panel")
    write_func_yaml(output, data)
    return True
