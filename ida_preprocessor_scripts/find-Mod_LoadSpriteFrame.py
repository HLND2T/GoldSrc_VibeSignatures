"""Locate sprite-frame loaders with approved per-platform integer anchors.

Approved for HL 3248/3266/3329/3647/4554/6153/8684 and CoF 5936 Windows:
the same function pushes 0x300 for the palette copy and 0x1C for frame
allocation/clearing (engine/gl_model.c, Mod_LoadSpriteFrame). Both values
must be immediate operands of PUSH; arithmetic, stack adjustment and memory
displacements do not qualify. Decode imm8 and imm32 alike, across all chunks.

Research over all functions in those eight binaries found exactly one such
entry in each. Its body loads dimensions/origin, fills a frame, uploads the
texture and advances past the pixels. No name, string, old artifact, address,
byte pattern, distance or call ordinal participates in legacy discovery.

HL25/Sven Windows intersect the exact "%s_%i" string's owners with decoded
0x300/0x1C immediates, then exclude the current Mod_LoadSpriteGroup entry from
its string-located dependency artifact. Group contains an inlined frame body
on those builds. Linux intersects the string and immediates without that
dependency; MOV-immediate argument stores are accepted there. No raw byte
patterns are used, and ambiguous or missing candidates always fail closed.
"""

import inspect
import json
from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    _parse_int,
    parse_mcp_result,
    write_func_yaml,
)
import ida_preprocessor_scripts._push_immediate_locator as _push_immediate_locator

NAME = "Mod_LoadSpriteFrame"
PALETTE_BYTES = 256 * 3
SPRITE_FRAME_BYTES = 28
GROUP_NAME = "Mod_LoadSpriteGroup"
LEGACY_WINDOWS = frozenset({"hl-3248", "hl-3266", "hl-3329", "hl-3647", "hl-4554", "hl-6153", "hl-8684", "cof-5936"})
HELPERS = inspect.getsource(_push_immediate_locator)
PUSH_LOCATOR = (
    HELPERS
    + "\nimport json\nresult = json.dumps({'candidates': find_push_immediate_functions("
    + repr((PALETTE_BYTES, SPRITE_FRAME_BYTES))
    + ")})\n"
)


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    del skill_name, old_yaml_map
    output = _output_for_symbol(expected_outputs, NAME)
    if platform not in {"windows", "linux"} or output is None or new_binary_dir is None:
        return False
    try:
        if platform == "windows" and Path(new_binary_dir).parent.name in LEGACY_WINDOWS:
            locator = PUSH_LOCATOR
        else:
            exclude_funcs = []
            if platform == "windows":
                group = _load_yaml_mapping(Path(new_binary_dir) / f"{GROUP_NAME}.{platform}.yaml")
                if not group or group.get("func_name") != GROUP_NAME:
                    return False
                exclude_funcs.append(_parse_int(group["func_va"], "func_va"))
            locator = (
                HELPERS
                + "\nimport json\nresult = json.dumps({'candidates': find_string_immediate_functions("
                + repr((PALETTE_BYTES, SPRITE_FRAME_BYTES))
                + ", '%s_%i', exclude_funcs="
                + repr(exclude_funcs)
                + ")})\n"
            )
        result = parse_mcp_result(
            await session.call_tool("py_eval", {"code": _push_immediate_locator.wrap_locator_source(locator)})
        )
        candidates = result.get("candidates") if isinstance(result, dict) else None
        if debug:
            print(f"{NAME} immediate candidates: {json.dumps(candidates)}")
        if not isinstance(candidates, list) or len(candidates) != 1 or type(candidates[0]) is not int:
            return False
        function = await _inspect_function_via_mcp(session, candidates[0], image_base, NAME)
        across = function is None
        if across:
            function = await _inspect_function_via_mcp(
                session, candidates[0], image_base, NAME, allow_across_function_boundary=True
            )
        if not function:
            return False
        payload = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
        if across:
            payload["func_sig_allow_across_function_boundary"] = True
        write_func_yaml(output, payload)
        return True
    except Exception as exc:  # noqa: BLE001 - worker/validation errors must fail closed.
        if debug:
            print(f"{NAME} discovery failed: {exc}")
        return False
