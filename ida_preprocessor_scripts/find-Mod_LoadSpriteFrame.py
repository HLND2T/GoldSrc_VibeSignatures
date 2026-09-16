"""Locate the legacy Windows sprite-frame loader by decoded push arguments.

Approved for HL 3248/3266/3329/3647/4554/6153/8684 and CoF 5936 Windows:
the same function pushes 0x300 for the palette copy and 0x1C for frame
allocation/clearing (engine/gl_model.c, Mod_LoadSpriteFrame). Both values
must be immediate operands of PUSH; arithmetic, stack adjustment and memory
displacements do not qualify. Decode imm8 and imm32 alike, across all chunks.

Research over all functions in those eight binaries found exactly one such
entry in each. Its body loads dimensions/origin, fills a frame, uploads the
texture and advances past the pixels. No name, string, old artifact, address,
byte pattern, distance or call ordinal participates in discovery. Modern
Windows inlines the loader into Mod_LoadSpriteGroup and is intentionally not
registered here; Linux argument stores require a separate approved locator.
"""

import inspect
import json

from ida_analyze_util import _inspect_function_via_mcp, _output_for_symbol, parse_mcp_result, write_func_yaml
import ida_preprocessor_scripts._push_immediate_locator as _push_immediate_locator

NAME = "Mod_LoadSpriteFrame"
PALETTE_BYTES = 256 * 3
SPRITE_FRAME_BYTES = 28
LOCATOR = (
    inspect.getsource(_push_immediate_locator)
    + "\nimport json\nresult = json.dumps({'candidates': find_push_immediate_functions("
    + repr((PALETTE_BYTES, SPRITE_FRAME_BYTES))
    + ")})\n"
)


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    del skill_name, old_yaml_map, new_binary_dir
    output = _output_for_symbol(expected_outputs, NAME)
    if platform != "windows" or output is None:
        return False
    try:
        result = parse_mcp_result(await session.call_tool("py_eval", {"code": LOCATOR}))
        candidates = result.get("candidates") if isinstance(result, dict) else None
        if debug:
            print(f"{NAME} push-immediate candidates: {json.dumps(candidates)}")
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
