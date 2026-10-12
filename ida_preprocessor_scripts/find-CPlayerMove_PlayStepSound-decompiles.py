#!/usr/bin/env python3
"""Recover the footsteps' verified sound-emission callee, never by body bytes.

Both Windows versions and 5.16 Linux inline CPlayerMove::PlaySoundFX and call
PM_PlaySoundFX_SERVER directly with playerindex+1, the movement origin, channel,
sound, volume, attenuation 0.8, flags 0 and pitch 100. Linux 5.15 instead calls
the real PlaySoundFX wrapper (this first, raw playerindex). Its separate producer
and downstream finder preserve that extra DAG edge. Multiple sound branches
must agree on the same callee. References annotate calls, not literal addresses
or call ordinals. ELF PLT resolution must reach a real function body.
The 5.15 wrapper's output signature must cover argument forwarding and its
playerindex increment, since its short PIC/stack prefix is shared by wrappers.
"""

from pathlib import Path

from ida_analyze_util import preprocess_common_skill
from llm_spec import select_llm_specs
from player_move_artifacts import publish_player_move_identities

LLM_DECOMPILE = {
    "direct": [
        {
            "symbol_name": "PM_PlaySoundFX_SERVER",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/CPlayerMove_PlayStepSound.{platform}.yaml"],
            "expected_result_sections": ["found_call"],
            "dependency_policy": {"CPlayerMove_PlayStepSound.{platform}.yaml": "required"},
        }
    ],
    "wrapper": [
        {
            "symbol_name": "CPlayerMove_PlaySoundFX",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/CPlayerMove_PlayStepSound.{platform}.yaml"],
            "expected_result_sections": ["found_call"],
            "dependency_policy": {"CPlayerMove_PlayStepSound.{platform}.yaml": "required"},
        }
    ],
}


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
    targets = [Path(output).name.removesuffix(f".{platform}.yaml") for output in expected_outputs]
    branch = "wrapper" if targets == ["CPlayerMove_PlaySoundFX"] and platform == "linux" else "direct"
    specs = select_llm_specs(LLM_DECOMPILE, branch=branch)
    if targets != [spec["symbol_name"] for spec in specs]:
        return False
    success = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=targets,
        llm_decompile_specs=specs,
        llm_config=llm_config,
        generate_yaml_desired_fields=[
            (
                name,
                ["func_name", "func_va", "func_rva", "func_size", "func_sig", "func_sig_resolve_jmp_thunk:true"]
                + (["func_sig_allow_across_function_boundary:true"] if name == "CPlayerMove_PlaySoundFX" else []),
            )
            for name in targets
        ],
        debug=debug,
    )
    if success:
        publish_player_move_identities(expected_outputs, platform)
    return success
