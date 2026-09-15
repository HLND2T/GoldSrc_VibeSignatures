#!/usr/bin/env python3
"""Locate Mod_UnloadSpriteTextures below ClientDLL_Shutdown.

engine/cl_draw.c SPR_Shutdown is the only ClientDLL_Shutdown callee that owns
a loop over the loaded HUD-sprite list, and engine/gl_model.c
Mod_UnloadSpriteTextures is the only function it calls besides the shared
free helper: it is the unique depth-two ClientDLL_Shutdown callee whose only
caller is that shutdown-loop function and whose own callee count matches the
sprite-texture-name plus GL_UnloadTexture pair. The ClientDLL_Shutdown
artifact is available on the Windows configs of the classic engine families;
HL25 and SvEngine inline ClientDLL_Shutdown into ClientDLL_Init and are not
covered by this anchor. No byte signature participates in discovery.
"""

import json
from pathlib import Path

import ida_analyze_util as u

TARGET = "Mod_UnloadSpriteTextures"
CDS = "ClientDLL_Shutdown"
MARKER = "__R124_SPRUNLOAD__"
MIN_SIZE = 60
MIN_CALLEES = 2

WALK = r"""
import idautils, ida_funcs, idc, json

MARKER = @@MARKER@@
CDS = @@CDS@@
MIN_SIZE = @@MIN_SIZE@@
MIN_CALLEES = @@MIN_CALLEES@@

def emit(d):
    print(MARKER + json.dumps(d))

def fn(ea):
    f = ida_funcs.get_func(ea)
    return int(f.start_ea) if f else None

def fsize(ea):
    f = ida_funcs.get_func(ea)
    return int(f.end_ea - f.start_ea) if f else 0

def internal_callees(o):
    out = set()
    for pc in idautils.FuncItems(o):
        if (idc.print_insn_mnem(pc) or "").lower() != "call":
            continue
        t = idc.get_operand_value(pc, 0)
        tf = fn(t) if t else None
        if tf is not None and tf == t and fsize(tf) > 16:
            out.add(tf)
    return out

def callers(o):
    return sorted({fn(x) for x in idautils.CodeRefsTo(o, False) if fn(x)})

res = {"candidates": []}
for x in sorted(internal_callees(CDS)):
    for y in sorted(internal_callees(x)):
        if callers(y) != [x]:
            continue
        if fsize(y) < MIN_SIZE or len(internal_callees(y)) < MIN_CALLEES:
            continue
        res["candidates"].append({
            "va": hex(y),
            "size": fsize(y),
            "parent": hex(x),
            "parent_size": fsize(x),
            "callees": [hex(c) for c in sorted(internal_callees(y))],
        })
if len(res["candidates"]) != 1:
    res["error"] = "Mod_UnloadSpriteTextures candidate is not unique"
emit(res)
"""


async def _eval(session, code):
    raw = (await session.call_tool("py_eval", {"code": "exec(" + repr(code) + ", {})"})).model_dump(mode="json")
    structured = raw.get("structured_content") or {}
    if structured.get("stderr"):
        print("sprunload walk stderr: " + structured["stderr"][:4000])
        return ""
    return structured.get("stdout") or ""


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
    output = u._output_for_symbol(expected_outputs, TARGET)
    if output is None:
        return False

    cds_data = u._load_yaml_mapping(new_binary_dir / f"{CDS}.{platform}.yaml")
    if not cds_data or cds_data.get("func_va") is None:
        if debug:
            print(f"{skill_name}: missing {CDS} artifact")
        return False
    cds_va = u._parse_int(cds_data["func_va"], "func_va")

    code = (
        WALK.replace("@@MARKER@@", repr(MARKER))
        .replace("@@CDS@@", repr(cds_va))
        .replace("@@MIN_SIZE@@", str(MIN_SIZE))
        .replace("@@MIN_CALLEES@@", str(MIN_CALLEES))
    )
    stdout = await _eval(session, code)
    located = None
    for line in stdout.splitlines():
        if line.startswith(MARKER):
            located = json.loads(line[len(MARKER) :])
            break
    if not located or "error" in located:
        if debug:
            print(f"{skill_name}: walk failed: {located}")
        return False
    info = located["candidates"][0]

    function = await u._inspect_function_via_mcp(session, int(info["va"], 0), image_base, TARGET)
    if not function:
        function = await u._inspect_function_via_mcp(
            session,
            int(info["va"], 0),
            image_base,
            TARGET,
            allow_across_function_boundary=True,
        )
        if function:
            function["func_sig_allow_across_function_boundary"] = True
    if not function:
        if debug:
            print(f"{skill_name}: no inspect result for {TARGET}")
        return False
    payload = {k: function[k] for k in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    if function.get("func_sig_allow_across_function_boundary"):
        payload["func_sig_allow_across_function_boundary"] = True
    u.write_func_yaml(output, payload)
    return True
