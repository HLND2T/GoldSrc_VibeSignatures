#!/usr/bin/env python3
"""Resolve EngineSurface::drawFlushText from its verified interface slot."""

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, preprocess_common_skill, write_func_yaml


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
    _ = skill_name, old_yaml_map
    found = await preprocess_common_skill(
        session,
        expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        inherit_vfuncs=[("EngineSurface_drawFlushText", "EngineSurface", "IEngineSurface_drawFlushText", True)],
        generate_yaml_desired_fields=[
            (
                "EngineSurface_drawFlushText",
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
    output = _output_for_symbol(expected_outputs, "EngineSurface_drawFlushText")
    payload = _load_yaml_mapping(output) if output else None
    if not payload:
        return False
    payload["func_name"] = "EngineSurface::drawFlushText()"
    write_func_yaml(output, payload)
    return True
