#!/usr/bin/env python3
"""Intersect shellchrome and chrome-origin accesses to find the studio render pass.

The standalone renderer resets chrome state and renders the glowshell pass.
Compilers also inline it into the top-level DrawModel/DrawPlayer paths; those
paths own bone setup/attachment calls and are excluded by their source role.
"""

from ida_analyze_util import preprocess_common_skill

FUNC_XREFS = [
    {
        "func_name": "R_StudioRenderModel",
        "xref_strings": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "xref_gvs": ["cl_sprite_shell", "g_ChromeOrigin"],
        "exclude_funcs": ["R_StudioDrawModel", "R_StudioDrawPlayer"],
        "exclude_callees": ["R_StudioSetupBones", "R_StudioCalcAttachments"],
    }
]


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
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=["R_StudioRenderModel"],
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=[
            (
                "R_StudioRenderModel",
                [
                    "func_name",
                    "func_va",
                    "func_rva",
                    "func_size",
                    "func_sig",
                    "func_sig_allow_across_function_boundary:true",
                ],
            )
        ],
        debug=debug,
    )
