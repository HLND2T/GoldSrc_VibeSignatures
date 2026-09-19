#!/usr/bin/env python3
"""Recover the dynamic lightmap update entry, respecting HL25 Linux inlining.

Issue #156 approved the exact ELF STT_FUNC symbol for hl-10210/Linux: the
standalone entry is retained but all calls in R_DrawSequentialPoly are inlined.
Every other branch resolves a real call from the existing surface renderer.
"""

from pathlib import Path

import ida_analyze_util as u
from ida_preprocessor_scripts.renderer_elf_symbols import STT_FUNC, current_elf_symbols, select_symbol

TARGET = "R_RenderDynamicLightmaps"
FIELDS = ["func_name", "func_va", "func_rva", "func_size", "func_sig"]
LLM_DECOMPILE = [
    {
        "symbol_name": TARGET,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/R_DrawSequentialPoly.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"R_DrawSequentialPoly.{platform}.yaml": "required"},
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
    if (Path(new_binary_dir).resolve().parent.name, platform) == ("hl-10210", "linux"):
        symbols = await current_elf_symbols(session, [TARGET])
        address = image_base + select_symbol(symbols, TARGET, STT_FUNC)
        output = next((p for p in expected_outputs if Path(p).name == f"{TARGET}.{platform}.yaml"), None)
        if output is None:
            return False
        candidate = await u.preprocess_func_sig_via_mcp(
            session,
            output,
            None,
            image_base,
            new_binary_dir,
            platform,
            func_name=TARGET,
            direct_func_va=address,
            debug=debug,
        )
        if candidate is None:
            return False
        u.write_func_yaml(output, {field: candidate[field] for field in FIELDS})
        return True
    return await u.preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[TARGET],
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(TARGET, FIELDS)],
        debug=debug,
    )
