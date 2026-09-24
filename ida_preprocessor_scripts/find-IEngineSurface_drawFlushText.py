#!/usr/bin/env python3
"""Read the sole forwarded IEngineSurface vcall from BaseUISurface::DrawFlushText."""

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._indirect_vcall_target_common import (
    preprocess_indirect_vcall_target_skill,
)


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
    _ = skill_name, old_yaml_map, image_base
    found = await preprocess_indirect_vcall_target_skill(
        session,
        expected_outputs,
        new_binary_dir,
        platform,
        source_yaml_stem="BaseUISurface_DrawFlushText",
        target_name="IEngineSurface_drawFlushText",
        vtable_name="IEngineSurface",
        generate_yaml_desired_fields=[
            (
                "IEngineSurface_drawFlushText",
                ["func_name", "vtable_name", "vfunc_offset", "vfunc_index"],
            )
        ],
        resolve_load_then_branch=True,
        debug=debug,
    )
    if not found:
        return False
    output = _output_for_symbol(expected_outputs, "IEngineSurface_drawFlushText")
    payload = _load_yaml_mapping(output) if output else None
    if not payload:
        return False
    payload["func_name"] = "IEngineSurface::drawFlushText"
    write_func_yaml(output, payload)
    return True
