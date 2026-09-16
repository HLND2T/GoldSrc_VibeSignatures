#!/usr/bin/env python3
"""Locate the HL 8684 Linux R_RenderFinalFog body by GL fog immediates.

This direct locator is intentionally registered only for hl-8684/linux. In
that binary, exactly one decoded x86 function body owns both GL_FOG_MODE
(0x0B65) and GL_EXP2 (0x0801), and the body implements the complete final-fog
state update. HL25 splits GL_FOG_MODE into R_SetFogMode, while SvEngine keeps
an inlined copy in its scene/view body, so those builds must not use this
locator. Raw byte occurrences, operand displacements, prior artifacts, and
symbol names do not participate in discovery.
"""

import inspect
import json

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)
import ida_preprocessor_scripts._push_immediate_locator as _immediate_locator


TARGET_FUNC_NAME = "R_RenderFinalFog"
GL_FOG_MODE = 0x0B65
GL_EXP2 = 0x0801
HELPERS = inspect.getsource(_immediate_locator)
LOCATOR = (
    HELPERS
    + "\nimport json\nresult = json.dumps({'candidates': find_immediate_functions("
    + repr((GL_FOG_MODE, GL_EXP2))
    + ")})\n"
)


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    debug=False,
):
    del skill_name, old_yaml_map, new_binary_dir
    output = _output_for_symbol(expected_outputs, TARGET_FUNC_NAME)
    if platform != "linux" or output is None:
        return False
    try:
        result = parse_mcp_result(
            await session.call_tool("py_eval", {"code": _immediate_locator.wrap_locator_source(LOCATOR)})
        )
        candidates = result.get("candidates") if isinstance(result, dict) else None
        if debug:
            print(f"{TARGET_FUNC_NAME} immediate candidates: {json.dumps(candidates)}")
        if not isinstance(candidates, list) or len(candidates) != 1 or type(candidates[0]) is not int:
            return False
        function = await _inspect_function_via_mcp(session, candidates[0], image_base, TARGET_FUNC_NAME)
        if not function:
            return False
        payload = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
        write_func_yaml(output, payload)
        return True
    except Exception as exc:  # noqa: BLE001 - worker/validation errors must fail closed.
        if debug:
            print(f"{TARGET_FUNC_NAME} discovery failed: {exc}")
        return False
