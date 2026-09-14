#!/usr/bin/env python3
"""Locate the Sven Co-op Linux engine detail-texture initializer.

engine/DetailTexture.cpp DT_Initialize is the only function that programs
GL_RGB_SCALE (0x8573); the SvEngine Linux build keeps it as a standalone
function, unlike the sprite-frame renderers that are inlined there. No byte
pattern participates in discovery.
"""

import json
from pathlib import Path

import ida_analyze_util as u

SYMBOL = "DT_Initialize"
MARKER = "__R120_DT_INIT_SVEN__"
GL_RGB_SCALE = 0x8573

WALK = r"""
import idautils, ida_funcs, ida_ua, idaapi, json

def has_imm(o, value):
    for pc in idautils.FuncItems(o):
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, pc) <= 0:
            continue
        for op in insn.ops:
            if int(op.type) == 0:
                break
            if int(op.type) == int(idaapi.o_imm) and int(op.value) == value:
                return True
    return False

dt = [int(f) for f in idautils.Functions() if has_imm(f, GL_RGB_SCALE)]
print(MARKER + json.dumps({
    "DT_Initialize" if len(dt) == 1 else "DT_Initialize_candidates":
        hex(dt[0]) if len(dt) == 1 else sorted(hex(x) for x in dt)
}))
"""


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
    _ = skill_name, old_yaml_map, new_binary_dir
    output = u._output_for_symbol(expected_outputs, SYMBOL)
    if output is None:
        return False
    raw = (
        await session.call_tool(
            "py_eval",
            {
                "code": "exec("
                + repr("GL_RGB_SCALE=" + repr(GL_RGB_SCALE) + "\nMARKER=" + repr(MARKER) + "\n" + WALK)
                + ", {})"
            },
        )
    ).model_dump(mode="json")
    structured = raw.get("structured_content") or {}
    if structured.get("stderr"):
        print("DT_Initialize walk stderr: " + structured["stderr"])
        return False
    located = None
    for line in (structured.get("stdout") or "").splitlines():
        if line.startswith(MARKER):
            located = json.loads(line[len(MARKER) :])
    if not located:
        return False
    address = located.get(SYMBOL)
    if address is None:
        if debug:
            print("DT_Initialize ambiguous: " + json.dumps(located))
        return False
    function = await u._inspect_function_via_mcp(session, int(address, 0), image_base, SYMBOL)
    if not function:
        function = await u._inspect_function_via_mcp(
            session, int(address, 0), image_base, SYMBOL, allow_across_function_boundary=True
        )
        if function:
            function["func_sig_allow_across_function_boundary"] = True
    if not function:
        return False
    payload = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    if function.get("func_sig_allow_across_function_boundary"):
        payload["func_sig_allow_across_function_boundary"] = True
    u.write_func_yaml(output, payload)
    return True
