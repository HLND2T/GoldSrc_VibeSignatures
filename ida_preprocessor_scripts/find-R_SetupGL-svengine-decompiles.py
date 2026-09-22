#!/usr/bin/env python3
"""Recover SvEngine's gmodinfo.vertical_fov boolean field address.

The ELF object is gmodinfo; vertical_fov is a four-byte field populated from
the liblist key, not an independent symbol or an angle. R_SetupGL reads it
to select horizontal/vertical projection math (inlined or a helper argument).
Select the field read, never the gmodinfo base or its GOT pointer. Derive the
effective address from current instructions; no reference member offset is
reused. This finder is registered only for SvEngine, separately from matrices
because its game-family applicability differs.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_GLOBAL_NAME = "gmodinfo_vertical_fov"
GV_FIELDS = [
    "gv_name",
    "gv_va",
    "gv_rva",
    "gv_sig",
    "gv_sig_va",
    "gv_inst_offset",
    "gv_inst_length",
    "gv_inst_disp",
]
LLM_DECOMPILE = [
    {
        "symbol_name": TARGET_GLOBAL_NAME,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/R_SetupGL.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"R_SetupGL.{platform}.yaml": "required"},
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
    _ = skill_name, old_yaml_map
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        gv_names=[TARGET_GLOBAL_NAME],
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(TARGET_GLOBAL_NAME, GV_FIELDS)],
        debug=debug,
    )
