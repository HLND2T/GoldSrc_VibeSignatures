#!/usr/bin/env python3
"""Locate PVSNode (MetaHookSv field name, engine R_PVSNode) via triangleapi_t.

engine/pr_cmds.c PVSNode carries no literal and no cvar, but it is the only
self-recursive callee of tri_BoxinPVS, the BoxInPVS slot (index 16, counting
the leading TRI_API_VERSION dword) of the engine ``triangleapi_t`` table
registered from engine/r_triangle.c. The table is identified structurally in
data segments as a dword 1 followed by nineteen consecutive function
pointers; sibling version-1 tables (event/demo/net APIs) never expose a
self-recursive slot-16 callee, so exactly one table yields the candidate.
Validated on GoldSrc, HL25, SvEngine and CoF, Windows and Linux alike.
"""

import json
from pathlib import Path

import ida_analyze_util as u
from ida_elf import ELF_RESOLVER_PY

TARGETS = ("PVSNode",)
MARKER = "__R124_PVSNODE__"
TRI_SLOT_BOXINPVS = 16
TRI_FUNC_PTRS = 19
MIN_CALLERS = 4

WALK = (
    ELF_RESOLVER_PY
    + r"""
import idautils, ida_funcs, idc, ida_segment, ida_bytes, json

MARKER = @@MARKER@@
BOX_SLOT = @@BOX_SLOT@@
FUNC_PTRS = @@FUNC_PTRS@@
MIN_CALLERS = @@MIN_CALLERS@@

def emit(d):
    print(MARKER + json.dumps(d))

def fn(ea):
    f = ida_funcs.get_func(ea)
    return int(f.start_ea) if f else None

def callees(o):
    out = set()
    for pc in idautils.FuncItems(o):
        if (idc.print_insn_mnem(pc) or "").lower() != "call":
            continue
        t = resolve_elf_plt(idc.get_operand_value(pc, 0))
        tf = fn(t) if t else None
        if tf is not None and tf == t:
            out.add(tf)
    return out

def callers(o):
    return {fn(x) for x in elf_code_refs_to(o) if fn(x)}

def fsize(ea):
    f = ida_funcs.get_func(ea)
    return int(f.end_ea - f.start_ea) if f else 0

def is_func_start(v):
    if not v:
        return False
    f = ida_funcs.get_func(v)
    return f is not None and int(f.start_ea) == int(v)

res = {"tables": [], "hits": []}
for si in range(ida_segment.get_segm_qty()):
    seg = ida_segment.getnseg(si)
    if not seg:
        continue
    nm = ida_segment.get_segm_name(seg) or ""
    if not nm or nm.startswith(".text") or nm.startswith(".plt") or nm.startswith(".got"):
        continue
    data = ida_bytes.get_bytes(int(seg.start_ea), int(seg.end_ea) - int(seg.start_ea))
    if not data or len(data) < (FUNC_PTRS + 1) * 4:
        continue
    for off in range(0, len(data) - (FUNC_PTRS + 1) * 4, 4):
        if data[off] != 1 or data[off + 1] or data[off + 2] or data[off + 3]:
            continue
        base = int(seg.start_ea) + off
        if not all(is_func_start(ida_bytes.get_dword(base + i * 4)) for i in range(1, FUNC_PTRS + 1)):
            continue
        res["tables"].append(hex(base))
        box = ida_bytes.get_dword(base + BOX_SLOT * 4)
        if not is_func_start(box):
            continue
        for cand in sorted(callees(box)):
            if cand == box or cand not in callers(cand):
                continue
            cl = callers(cand)
            if len(cl) < MIN_CALLERS:
                continue
            res["hits"].append({
                "table": hex(base),
                "boxinpvs": hex(box),
                "boxinpvs_size": fsize(box),
                "PVSNode": hex(cand),
                "PVSNode_size": fsize(cand),
                "PVSNode_callers": [hex(x) for x in sorted(cl)],
            })
emit(res)
"""
)


async def _eval(session, code):
    raw = (await session.call_tool("py_eval", {"code": "exec(" + repr(code) + ", {})"})).model_dump(mode="json")
    structured = raw.get("structured_content") or {}
    if structured.get("stderr"):
        print("pvsnode walk stderr: " + structured["stderr"][:4000])
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
    outputs = {name: u._output_for_symbol(expected_outputs, name) for name in TARGETS}
    if not any(outputs.values()):
        return False

    code = (
        WALK.replace("@@MARKER@@", repr(MARKER))
        .replace("@@BOX_SLOT@@", str(TRI_SLOT_BOXINPVS))
        .replace("@@FUNC_PTRS@@", str(TRI_FUNC_PTRS))
        .replace("@@MIN_CALLERS@@", str(MIN_CALLERS))
    )
    stdout = await _eval(session, code)
    located = None
    for line in stdout.splitlines():
        if line.startswith(MARKER):
            located = json.loads(line[len(MARKER) :])
            break
    if not located:
        if debug:
            print(f"{skill_name}: walk produced no payload")
        return False
    hits = located.get("hits") or []
    if debug:
        print(f"{skill_name}: tables={located.get('tables')} hits={len(hits)}")
    if len(hits) != 1:
        return False
    info = hits[0]

    function = await u._inspect_function_via_mcp(session, int(info["PVSNode"], 0), image_base, "PVSNode")
    if not function:
        function = await u._inspect_function_via_mcp(
            session,
            int(info["PVSNode"], 0),
            image_base,
            "PVSNode",
            allow_across_function_boundary=True,
        )
        if function:
            function["func_sig_allow_across_function_boundary"] = True
    if not function:
        if debug:
            print(f"{skill_name}: no inspect result for PVSNode")
        return False
    payload = {k: function[k] for k in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    if function.get("func_sig_allow_across_function_boundary"):
        payload["func_sig_allow_across_function_boundary"] = True
    u.write_func_yaml(outputs["PVSNode"], payload)
    return True
