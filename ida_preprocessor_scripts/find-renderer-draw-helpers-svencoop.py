#!/usr/bin/env python3
"""Locate the Sven Co-op engine 2D draw helpers that carry no usable literal.

SvEngine keeps engine/gl_draw.c Draw_Pic and engine/DetailTexture.cpp
DT_Initialize but drops the HL ``Draw_TransPic: bad coordinates`` diagnostic.
The public fill slots point to forwarding entries; find-svengine-fill-rgba
handles those separately from these screen-rendering anchors.

* ``Draw_Pic`` - the ``SCR_UpdateScreen_RenderBody`` callee with two callers that
  a single-call, single-caller wrapper delegates to (engine/gl_draw.c
  Draw_TransPic is that wrapper).
* ``DT_Initialize`` - the unique function pushing ``GL_RGB_SCALE`` (0x8573).

No byte pattern participates in discovery.
"""

import json
from pathlib import Path

import ida_analyze_util as u

SYMBOLS = ("Draw_Pic", "DT_Initialize")
MARKER = "__R120_DRAWHELPERS_SVEN__"

GL_RGB_SCALE = 0x8573
SCR = "SCR_UpdateScreen_RenderBody"

WALK = r"""
import idautils, ida_funcs, idc, idaapi, json

def fn(ea):
    f = ida_funcs.get_func(ea)
    return int(f.start_ea) if f else None

def calls(o):
    out = set()
    for pc in idautils.FuncItems(o):
        if (idc.print_insn_mnem(pc) or "").lower() != "call":
            continue
        t = idc.get_operand_value(pc, 0)
        if t and fn(t) == t:
            out.add(int(t))
    return out

def callers(o):
    return {fn(x) for x in idautils.CodeRefsTo(o, False) if fn(x)}

res = {}
sc = calls(SCR)

pic = set()
for c in sc:
    if len(callers(c)) != 2 or len(calls(c)) > 2:
        continue
    for wrapper in (callers(c) - {SCR}):
        if calls(wrapper) == {c} and len(callers(wrapper)) == 1:
            pic.add(c)
            break
res["Draw_Pic" if len(pic) == 1 else "Draw_Pic_candidates"] = (
    hex(next(iter(pic))) if len(pic) == 1 else sorted(hex(x) for x in pic)
)
res["_debug"] = {"scr_callees": sorted(hex(x) for x in sc)}
print(MARKER + json.dumps(res))
"""

DT_WALK = r"""
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


async def _eval(session, code):
    raw = (await session.call_tool("py_eval", {"code": "exec(" + repr(code) + ", {})"})).model_dump(mode="json")
    structured = raw.get("structured_content") or {}
    if structured.get("stderr"):
        print("Sven draw-helpers walk stderr: " + structured["stderr"])
        return None
    for line in (structured.get("stdout") or "").splitlines():
        if line.startswith(MARKER):
            return json.loads(line[len(MARKER) :])
    return None


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
    _ = skill_name, old_yaml_map
    new_binary_dir = Path(new_binary_dir)
    outputs = {name: u._output_for_symbol(expected_outputs, name) for name in SYMBOLS}
    if not any(outputs.values()):
        return False

    scr = u._load_yaml_mapping(new_binary_dir / f"{SCR}.{platform}.yaml")
    if not scr or scr.get("func_va") is None:
        return False
    scr_va = u._parse_int(scr["func_va"], "func_va")

    located = await _eval(session, "SCR=" + repr(scr_va) + "\nMARKER=" + repr(MARKER) + "\n" + WALK)
    if not located:
        return False
    dt_hits = await _eval(session, "GL_RGB_SCALE=" + repr(GL_RGB_SCALE) + "\nMARKER=" + repr(MARKER) + "\n" + DT_WALK)
    if not dt_hits:
        return False
    located.update(dt_hits)
    if debug and ("_debug" in located or any(k.endswith("_candidates") for k in located)):
        print("Sven draw-helpers notes: " + json.dumps(located))

    written = 0
    requested = 0
    for symbol in SYMBOLS:
        output = outputs[symbol]
        if output is None:
            continue
        requested += 1
        address = located.get(symbol)
        if address is None:
            continue
        function = await u._inspect_function_via_mcp(session, int(address, 0), image_base, symbol)
        if not function:
            function = await u._inspect_function_via_mcp(
                session, int(address, 0), image_base, symbol, allow_across_function_boundary=True
            )
            if function:
                function["func_sig_allow_across_function_boundary"] = True
        if not function:
            if debug:
                print(f"{symbol}: inspection failed at {address}")
            continue
        payload = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
        if function.get("func_sig_allow_across_function_boundary"):
            payload["func_sig_allow_across_function_boundary"] = True
        u.write_func_yaml(output, payload)
        written += 1
    return written == requested
