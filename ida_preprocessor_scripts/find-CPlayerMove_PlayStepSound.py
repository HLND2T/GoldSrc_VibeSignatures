#!/usr/bin/env python3
"""Locate server footsteps by a target-owned sound and the speed gate.

On all four Sven 5.15/5.16 PE32/ELF32 inputs, player/pl_tile5.wav has three
owners: ClientPrecache, CBaseMonster::PlayStepSound and the player method.
Only the player method actually reads 220.0 for its horizontal-speed gate
(multiplayer, neither on a ladder nor jumping). Use the shared width-aware
SSE/x87/PIC reader. No code signature or old artifact participates in discovery.
The 5.16 Linux entry/zero-vector initialization collides with another function.
The output signature budget extends through the step-left toggle, runfuncs gate
and randomLong call inside this body. It remains output validation only.
"""

from ida_analyze_util import preprocess_common_skill
from player_move_artifacts import publish_player_move_identities

TARGET = "CPlayerMove_PlayStepSound"
FUNC_XREFS = [
    {
        "func_name": TARGET,
        "xref_strings": ["FULLMATCH:player/pl_tile5.wav"],
        "xref_floats": ["220.0"],
    }
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    success = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[TARGET],
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=[
            (
                TARGET,
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
    if success:
        publish_player_move_identities(expected_outputs, platform)
    return success
