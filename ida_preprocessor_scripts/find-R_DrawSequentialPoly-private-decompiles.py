#!/usr/bin/env python3
"""Recover lightmap storage and the decal queue from the existing surface renderer.

Issue #156: GL_BuildLightmaps does not reset the dirty rectangles in HL25.
Use the surface renderer's GL_Bind, glTexSubImage2D and decal enqueue dataflow
on every branch. The multi-owner decal diagnostic is not a discovery anchor.
The existing mtexenabled producer has different platform gating.
"""

from ida_analyze_util import preprocess_common_skill
from ida_preprocessor_scripts.renderer_elf_symbols import preserve_global_identities

TARGET_NAMES = ["lightmap_textures", "lightmap_rectchange", "lightmaps", "gDecalSurfs", "gDecalSurfCount"]
FIELDS = ["gv_name", "gv_va", "gv_rva", "gv_sig", "gv_sig_va", "gv_inst_offset", "gv_inst_length", "gv_inst_disp"]
LLM_DECOMPILE = [
    {
        "symbol_name": name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/R_DrawSequentialPoly.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"R_DrawSequentialPoly.{platform}.yaml": "required"},
    }
    for name in TARGET_NAMES
]
for spec in LLM_DECOMPILE:
    if spec["symbol_name"] == "lightmap_rectchange":
        spec["instruction_rules"] = [
            {
                "regex": r"(?i)^\s*(?:lea|add)\s+.+$",
                "text": "Select the LEA/ADD forming the whole lightmap_rectchange array base for upload/reset. "
                "Do not return MOV reads of rectangle t/h members, which embed base+4/base+12.",
            }
        ]
    elif spec["symbol_name"] == "gDecalSurfCount":
        spec["instruction_rules"] = [
            {
                "regex": r"(?i)^\s*mov\s+(?:eax|ebx|ecx|edx|esi|edi|ebp),\s*.+$",
                "text": "Select the MOV loading the decal count into a register before enqueueing the surface. "
                "Do not return count stores: their PIC base can be unavailable after control-flow joins.",
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
    llm_config=None,
    debug=False,
):
    success = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        gv_names=TARGET_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(name, FIELDS) for name in TARGET_NAMES],
        debug=debug,
    )
    return success and await preserve_global_identities(session, expected_outputs, platform)
