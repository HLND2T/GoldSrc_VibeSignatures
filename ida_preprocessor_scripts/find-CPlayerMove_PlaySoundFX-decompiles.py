#!/usr/bin/env python3
"""Recover the 5.15 Linux server callback from the actual forwarding wrapper.

PlaySoundFX passes eight arguments to PM_PlaySoundFX_SERVER and increments only
playerindex. Ignore the compiler's PIC thunk; require the annotated forwarding
call to belong to the current wrapper and resolve its PLT entry to a code body.
The wrapper and its reference are explicit dependencies, not a guessed second
call or a signature discovered in a neighboring function.
"""

from ida_analyze_util import preprocess_common_skill
from player_move_artifacts import publish_player_move_identities

TARGET = "PM_PlaySoundFX_SERVER"
LLM_DECOMPILE = [
    {
        "symbol_name": "PM_PlaySoundFX_SERVER",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/server/CPlayerMove_PlaySoundFX.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"CPlayerMove_PlaySoundFX.{platform}.yaml": "required"},
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
    if platform != "linux":
        return False
    success = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[TARGET],
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[
            (TARGET, ["func_name", "func_va", "func_rva", "func_size", "func_sig", "func_sig_resolve_jmp_thunk:true"])
        ],
        debug=debug,
    )
    if success:
        publish_player_move_identities(expected_outputs, platform)
    return success
