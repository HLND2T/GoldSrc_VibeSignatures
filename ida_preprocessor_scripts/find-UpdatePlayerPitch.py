"""Locate the Sven Co-op client UpdatePlayerPitch below StudioDrawPlayer.

UpdatePlayerPitch(cl_entity_t* ent, float pitch) is a closed-source view.cpp
addition: it clamps the pitch through exactly two floating-point comparisons,
divides it by one float coefficient, and stores the result into the four
cl_entity_t pitch fields at +0xB54/+0x2CC/+0x178/+0xB28 (identical layout on
the 8948 and 10257 Windows/Linux clients). Every pitch-field write must itself
be an SSE scalar or x87 float store (movss/movsd/fst/fstp) and the single
division must be a float division; integer stores or an integer divide never
identify the function. CGameStudioRenderer (CStudioModelRenderer on
8948)::StudioDrawPlayer is the only cross-translation-unit caller, so exactly
one direct callee of the already-covered GameStudioRenderer_StudioDrawPlayer
vfunc exhibits the store quad; the same-TU V_CalcNormalRefdef reference is
compiler-inlined or PLT-routed and never reaches this walk. On 8948 Linux the
out-of-line function keeps the authoritative local symbol
_Z17UpdatePlayerPitchP11cl_entity_sf; the .plt.got thunk from StudioDrawPlayer
is resolved by the shared PLT resolver before the callee set is built.
"""

import inspect
from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    _parse_int,
    write_func_yaml,
)
import ida_preprocessor_scripts._pitch_store_predicate as _pitch_store_predicate
from ida_preprocessor_scripts._portal_layout_ida import run_layout_walk

NAME = "UpdatePlayerPitch"
PREDECESSOR = "GameStudioRenderer_StudioDrawPlayer"

WALK = (
    inspect.getsource(_pitch_store_predicate)
    + """

candidates = {}
for target in sorted(callees(values['studio_draw_player'])):
    try:
        insns = decode_function(target)
    except ValueError:
        continue
    if is_update_player_pitch_insns(insns):
        candidates[target] = len(insns)
if len(candidates) != 1:
    raise ValueError('UpdatePlayerPitch candidates: %r'
                     % sorted(hex(target) for target in candidates))
result = {'target': next(iter(candidates))}
"""
)


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    predecessor = _load_yaml_mapping(Path(new_binary_dir) / f"{PREDECESSOR}.{platform}.yaml")
    output = _output_for_symbol(expected_outputs, NAME)
    if not predecessor or predecessor.get("func_name") != PREDECESSOR or output is None:
        return False
    try:
        result = await run_layout_walk(
            session,
            {"studio_draw_player": _parse_int(predecessor["func_va"], "func_va"), "platform": platform},
            WALK,
        )
        if debug:
            print("UpdatePlayerPitch located:", result)
        function = await _inspect_function_via_mcp(session, result["target"], image_base, NAME)
        across = function is None
        if across:
            function = await _inspect_function_via_mcp(
                session, result["target"], image_base, NAME, allow_across_function_boundary=True
            )
        if not function:
            return False
        payload = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
        if across:
            payload["func_sig_allow_across_function_boundary"] = True
        write_func_yaml(output, payload)
        if debug:
            print("UpdatePlayerPitch verified:", result)
        return True
    except (ValueError, KeyError) as exc:
        if debug:
            print(exc)
        return False
