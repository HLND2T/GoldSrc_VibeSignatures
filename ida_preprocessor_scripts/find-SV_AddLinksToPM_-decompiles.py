#!/usr/bin/env python3
"""Recover the non-inlined server edict-to-physent conversion call.

The call takes (physent_t *, entity number, edict_t *) and initializes the
new visent before the area walker filters/copies it into collision lists.
SvEngine ELF inlines this body and deliberately has no output here.
"""

from ida_analyze_util import _output_for_symbol, preprocess_common_skill, write_func_yaml
from ida_preprocessor_scripts._server_physent_common import preserve_functions
from ida_preprocessor_scripts._engine_private_globals_common import inspect_func
from ida_preprocessor_scripts.renderer_elf_symbols import STT_FUNC, current_elf_symbols, select_symbol

LLM_DECOMPILE = [
    {
        "symbol_name": "SV_CopyEdictToPhysent",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/SV_AddLinksToPM_.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"SV_AddLinksToPM_.{platform}.yaml": "required"},
    },
]
FIELDS = ["func_name", "func_va", "func_rva", "func_size", "func_sig", "func_sig_allow_across_function_boundary:true"]


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
    if platform == "linux":
        # HL25 retains an uncalled out-of-line definition in the ELF symbol
        # table. It is catalogued for compatibility; the PM path is inlined.
        symbols = await current_elf_symbols(session, ["SV_CopyEdictToPhysent"])
        address = select_symbol(symbols, "SV_CopyEdictToPhysent", STT_FUNC)
        data = await inspect_func(session, int(image_base) + address, image_base, "SV_CopyEdictToPhysent")
        if not data:
            return False
        write_func_yaml(_output_for_symbol(expected_outputs, "SV_CopyEdictToPhysent"), data)
        return True
    found = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=["SV_CopyEdictToPhysent"],
        llm_decompile_specs=LLM_DECOMPILE if platform == "windows" else None,
        llm_config=llm_config,
        generate_yaml_desired_fields=[("SV_CopyEdictToPhysent", FIELDS)],
        debug=debug,
    )
    return found and await preserve_functions(
        session, expected_outputs, platform, image_base, ["SV_CopyEdictToPhysent"]
    )
