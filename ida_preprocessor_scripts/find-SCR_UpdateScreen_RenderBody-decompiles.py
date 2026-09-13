#!/usr/bin/env python3
"""Recover the per-frame GL pipeline entries from the verified screen body.

SCR_UpdateScreen_RenderBody frames every rendered frame with
GL_BeginRendering (four output pointers: zeroed x/y plus window-rectangle
width/height), then GL_Finish2D for the HUD pass (two HUD call sites converge
on the same entry), and finally GL_EndRendering (older builds keep a wrapper
that forwards through the VID_FlipScreen pointer). GL_Set2D is the HUD 2D
projection setup entered through the same pipeline (MetaHook field
GLBeginHud; two HUD call sites converge on the same entry). The four are
mined as found_call targets from one annotated reference body.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["GL_BeginRendering", "GL_EndRendering", "GL_Finish2D", "GL_Set2D"]
REFERENCE = "SCR_UpdateScreen_RenderBody"
LLM_DECOMPILE = [
    {
        "symbol_name": name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            f"references/{{gamever}}/engine/{REFERENCE}.{{platform}}.yaml",
        ],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {f"{REFERENCE}.{{platform}}.yaml": "required"},
    }
    for name in TARGET_FUNCTION_NAMES
]
FUNC_FIELDS = ["func_name", "func_sig", "func_va", "func_rva", "func_size"]
# Legacy GL_EndRendering entries are 6-11 byte VID_FlipScreen forwarding
# wrappers whose unique signature necessarily crosses the function boundary.
END_RENDERING_FIELDS = [
    "func_name",
    "func_sig",
    "func_va",
    "func_rva",
    "func_size",
    "func_sig_allow_across_function_boundary:true",
]
# GL_Set2D bodies end in a tail jump and mirror the adjacent HUD pass
# helpers closely enough that only an across-boundary window stays unique.
SET_2D_FIELDS = [
    "func_name",
    "func_sig",
    "func_va",
    "func_rva",
    "func_size",
    "func_sig_allow_across_function_boundary:true",
]
GENERATE_YAML_DESIRED_FIELDS = [
    *((name, FUNC_FIELDS) for name in TARGET_FUNCTION_NAMES if name not in {"GL_EndRendering", "GL_Set2D"}),
    ("GL_EndRendering", END_RENDERING_FIELDS),
    ("GL_Set2D", SET_2D_FIELDS),
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
        func_names=TARGET_FUNCTION_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
