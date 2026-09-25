#!/usr/bin/env python3
"""Inherit the current gameui ISurface slot into the existing engine primary table."""

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, preprocess_common_skill, write_func_yaml


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    name = "BaseUISurface_PaintTraverse"
    found = await preprocess_common_skill(
        session,
        expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        inherit_vfuncs=[(name, "BaseUISurface_vtable", "../gameui/ISurface_PaintTraverse", True)],
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
    data.update(func_name="BaseUISurface::PaintTraverse(unsigned int)", vtable_name="BaseUISurface")
    write_func_yaml(output, data)
    return True
