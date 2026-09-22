#!/usr/bin/env python3
"""Recover FBO configuration and containers from the existing GL_SetMode artifact.

The -stretchaspect, -nomsaa and -nofbo branches distinguish the first three
flags. The blit-scaled extension and -directblit/-nodirectblit overrides
identify s_bSupportsBlitTexturing. MSAA renderbuffer attachments distinguish
s_MSAAFBO from the rectangle-texture s_BackBufferFBO; recover each complete
container base, not its runtime handle, interior attachment or a GOT slot.
Only FBO-capable builds register this group. No addresses, access ordinals,
relative container positions or discovery signatures are used.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_GLOBAL_NAMES = [
    "s_bEnforceAspect",
    "bDoMSAAFBO",
    "bDoScaledFBO",
    "s_bSupportsBlitTexturing",
    "s_MSAAFBO",
    "s_BackBufferFBO",
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
]

FBO_ADDRESS_RULES = [
    {
        "regex": (
            r"(?i)(?:push\s+(?:offset\s+)?\w+"
            r"|mov\s+(?:dword ptr\s+)?\[esp[^\]]*\],\s+(?:offset\s+)?\w+"
            r"|mov\s+\w+,\s+offset\s+\w+"
            r"|lea\s+\w+,\s+(?:ds:)?"
            r"(?:\([^,+\[\]]+\s-\s[^,\[\]]+\)\[ebx\]|\[ebx[+-][^,\[\]]+\]))"
        ),
        "text": (
            "Select the instruction preparing the complete FBO container's address "
            "as the output argument to GenFramebuffersEXT. Corroborate its identity "
            "by multisample renderbuffer attachments for s_MSAAFBO, or the rectangle "
            "texture attachment for s_BackBufferFBO. On PIC select the object-address "
            "LEA. Do not return a framebuffer handle value, an attachment member, "
            "a GOT slot, or an address inferred from the other container."
        ),
    }
]
LLM_DECOMPILE = [
    {
        "symbol_name": name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/GL_SetMode.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"GL_SetMode.{platform}.yaml": "required"},
        **({"instruction_rules": FBO_ADDRESS_RULES} if name in {"s_MSAAFBO", "s_BackBufferFBO"} else {}),
    }
    for name in TARGET_GLOBAL_NAMES
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
        gv_names=TARGET_GLOBAL_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(name, GV_FIELDS) for name in TARGET_GLOBAL_NAMES],
        debug=debug,
    )
