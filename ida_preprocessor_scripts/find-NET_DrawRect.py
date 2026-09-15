#!/usr/bin/env python3
"""Locate NET_DrawRect on SvEngine through its screen-clamp instruction shape.

SvEngine's NET_DrawRect (the netgraph filled rectangle helper, byte-identical
to D_FillRect because the linker folds the two bodies) begins by clamping
against the video mode: it loads the screen-width global into esi, compares
it against 0x400 and then 1 before issuing the vertex-array/blend GL calls.
Discovery is a disassembly walk, not a byte pattern: the unique function
whose first instructions contain that mov/cmp/cmp shape in order and whose
body has no non-thunk internal callee. MSVC /OPT:ICF merges NET_DrawRect
with D_FillRect on the validated Sven Co-op builds, so the emitted address
serves both names. No byte signature participates in discovery.
"""

import json
from pathlib import Path

import ida_analyze_util as u

TARGET = "NET_DrawRect"
MARKER = "__R124_NETDRAWRECT__"
CLAMP_IMM_A = 0x400
CLAMP_IMM_B = 1
HEAD_INSNS = 24
MIN_SIZE = 100
MAX_SIZE = 900

WALK = r"""
import idautils, ida_funcs, idc, json

MARKER = @@MARKER@@
IMM_A = @@IMM_A@@
IMM_B = @@IMM_B@@
HEAD = @@HEAD@@
MIN_SIZE = @@MIN_SIZE@@
MAX_SIZE = @@MAX_SIZE@@

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

res = {"hits": []}
for start in idautils.Functions():
    size = fsize(start)
    if not (MIN_SIZE <= size <= MAX_SIZE):
        continue
    if internal_callees(start):
        continue
    idx_mov = idx_a = idx_b = -1
    count = 0
    for pc in idautils.FuncItems(start):
        mnem = (idc.print_insn_mnem(pc) or "").lower()
        if mnem == "mov":
            if idx_mov < 0 and idc.get_operand_type(pc, 1) == 2:
                idx_mov = count
        elif mnem == "cmp":
            if idx_a < 0 and idc.get_operand_value(pc, 1) == IMM_A:
                idx_a = count
            if idx_b < 0 and idc.get_operand_value(pc, 1) == IMM_B and idx_a >= 0:
                idx_b = count
        count += 1
        if count > HEAD:
            break
    if 0 <= idx_mov < idx_a < idx_b <= HEAD:
        res["hits"].append({"va": hex(start), "size": size})
if len(res["hits"]) != 1:
    res["error"] = "NET_DrawRect candidate is not unique"
emit(res)
"""


async def _eval(session, code):
    raw = (await session.call_tool("py_eval", {"code": "exec(" + repr(code) + ", {})"})).model_dump(mode="json")
    structured = raw.get("structured_content") or {}
    if structured.get("stderr"):
        print("netdrawrect walk stderr: " + structured["stderr"][:4000])
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
    _ = skill_name, old_yaml_map, new_binary_dir
    output = u._output_for_symbol(expected_outputs, TARGET)
    if output is None:
        return False

    code = (
        WALK.replace("@@MARKER@@", repr(MARKER))
        .replace("@@IMM_A@@", str(CLAMP_IMM_A))
        .replace("@@IMM_B@@", str(CLAMP_IMM_B))
        .replace("@@HEAD@@", str(HEAD_INSNS))
        .replace("@@MIN_SIZE@@", str(MIN_SIZE))
        .replace("@@MAX_SIZE@@", str(MAX_SIZE))
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
    info = located["hits"][0]

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
