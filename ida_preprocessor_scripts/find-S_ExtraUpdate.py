#!/usr/bin/env python3
"""Locate S_ExtraUpdate through the render-view/render-scene caller overlap.

engine/snd_dma.c S_ExtraUpdate is called by both R_RenderView and
R_RenderScene (engine/gl_rmain.c), while no other R_RenderView callee is also
called by the scene stage. R_RenderScene itself is recovered without a stored
artifact: it is the R_RenderView callee that calls R_CheckVariables directly
(HL25/SvEngine inline R_SetupFrame into it) or through one intermediate
R_SetupFrame function (GoldSrc/CoF keep R_SetupFrame standalone). The unique
function in the callee intersection of R_RenderView and R_RenderScene is
S_ExtraUpdate. No byte signature participates in discovery.
"""

import json
from pathlib import Path

import ida_analyze_util as u
from ida_elf import ELF_RESOLVER_PY

TARGETS = ("S_ExtraUpdate",)
RRV = "R_RenderView"
RCV = "R_CheckVariables"
MARKER = "__R124_SEXTRA__"
MAX_SIZE = 700

WALK = (
    ELF_RESOLVER_PY
    + r"""
import idautils, ida_funcs, idc, json

MARKER = @@MARKER@@
RRV = @@RRV@@
RCV = @@RCV@@

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
        if tf is not None and tf == t and int(idc.get_func_attr(tf, idc.FUNCATTR_END)) - tf > 16:
            out.add(tf)
    return out

def callers(o):
    return {fn(x) for x in elf_code_refs_to(o) if fn(x)}

def fsize(ea):
    f = ida_funcs.get_func(ea)
    return int(f.end_ea - f.start_ea) if f else 0

res = {}
rv_callees = callees(RRV)
rcv_hosts = callers(RCV)
scene = sorted(rcv_hosts & rv_callees)
res["direct_scene"] = [hex(x) for x in scene]
if not scene:
    for host in rcv_hosts:
        scene.extend(sorted((callers(host) & rv_callees) - set(scene)))
if len(scene) != 1:
    res["error"] = "R_RenderScene candidate is not unique"
    emit(res)
else:
    rsc = scene[0]
    overlap = sorted(callees(rsc) & rv_callees - {rsc})
    res["R_RenderScene"] = {"va": hex(rsc), "size": fsize(rsc)}
    res["overlap"] = [(hex(x), fsize(x)) for x in overlap]
    # R_ForceCVars is legitimately called by both (the inlined R_Clear in
    # R_RenderView and the setup-frame triple in R_RenderScene); it is far
    # larger than the small pump-events helper this finder targets.
    overlap = [x for x in overlap if fsize(x) <= @@MAX_SIZE@@]
    if len(overlap) != 1:
        res["error"] = "render-view/scene callee overlap is not unique"
    else:
        cand = overlap[0]
        res["S_ExtraUpdate"] = {
            "va": hex(cand),
            "size": fsize(cand),
            "callers": [hex(c) for c in callers(cand)],
        }
    emit(res)
"""
)


async def _eval(session, code):
    raw = (await session.call_tool("py_eval", {"code": "exec(" + repr(code) + ", {})"})).model_dump(mode="json")
    structured = raw.get("structured_content") or {}
    if structured.get("stderr"):
        print("sextra walk stderr: " + structured["stderr"][:4000])
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
    outputs = {name: u._output_for_symbol(expected_outputs, name) for name in TARGETS}
    if not any(outputs.values()):
        return False

    anchors = {}
    for sym in (RRV, RCV):
        data = u._load_yaml_mapping(new_binary_dir / f"{sym}.{platform}.yaml")
        if not data or data.get("func_va") is None:
            if debug:
                print(f"{skill_name}: missing {sym} artifact")
            return False
        anchors[sym] = u._parse_int(data["func_va"], "func_va")

    code = (
        WALK.replace("@@MARKER@@", repr(MARKER))
        .replace("@@RRV@@", repr(anchors[RRV]))
        .replace("@@RCV@@", repr(anchors[RCV]))
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

    info = located.get("S_ExtraUpdate")
    if not info:
        return False
    function = await u._inspect_function_via_mcp(session, int(info["va"], 0), image_base, "S_ExtraUpdate")
    if not function:
        function = await u._inspect_function_via_mcp(
            session,
            int(info["va"], 0),
            image_base,
            "S_ExtraUpdate",
            allow_across_function_boundary=True,
        )
        if function:
            function["func_sig_allow_across_function_boundary"] = True
    if not function:
        if debug:
            print(f"{skill_name}: no inspect result for S_ExtraUpdate")
        return False
    payload = {k: function[k] for k in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    if function.get("func_sig_allow_across_function_boundary"):
        payload["func_sig_allow_across_function_boundary"] = True
    u.write_func_yaml(outputs["S_ExtraUpdate"], payload)
    return True
