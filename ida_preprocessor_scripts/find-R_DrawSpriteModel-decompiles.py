#!/usr/bin/env python3
"""Recover the sprite renderer's entity origin.

``r_entorigin`` (``engine/gl_rmain.c``) is the origin each sprite quad corner is
offset from; ``R_DrawSpriteModel`` reads it four times in the quad emission
(``VectorMA(r_entorigin, scale * frame->..., ...)``), so the sprite renderer is
the least ambiguous predecessor. The read form is not portable: MSVC emits
``push offset``, GCC non-PIC uses ``mov [esp], offset``, and the SvEngine Linux
PIC builds only reach the object through a ``.got`` slot
(``lea eax, (r_entorigin - GOT)[ebx]``). The shared LLM global resolver already
models all of them, including the GOT-indirect form used by the sibling
``r_visframecount`` locator, so no operand form is hardcoded here.

The sibling ``r_blend`` is no longer recovered here: it is the sole
writable-data store target of ``studioapi_StudioSetRenderamt``, so
find-studioapi_StudioSetRenderamt emits it structurally instead.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping, preprocess_common_skill

LLM_DECOMPILE = [
    {
        "symbol_name": "r_entorigin",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/R_DrawSpriteModel.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"R_DrawSpriteModel.{platform}.yaml": "required"},
    },
]
GV_FIELDS = [
    "gv_name",
    "gv_va",
    "gv_rva",
    "gv_sig",
    "gv_sig_va",
    "gv_inst_offset",
    "gv_inst_length",
    "gv_inst_disp",
    "gv_sig_allow_across_function_boundary:true",
]
TARGET_GLOBAL_NAMES = ["r_entorigin"]


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
    _ = skill_name, old_yaml_map
    predecessor = _load_yaml_mapping(Path(new_binary_dir) / f"R_DrawSpriteModel.{platform}.yaml")
    if not predecessor:
        return False
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        gv_names=list(TARGET_GLOBAL_NAMES),
        llm_decompile_specs=[dict(spec) for spec in LLM_DECOMPILE],
        llm_config=llm_config,
        generate_yaml_desired_fields=[(name, GV_FIELDS) for name in TARGET_GLOBAL_NAMES],
        debug=debug,
    )
