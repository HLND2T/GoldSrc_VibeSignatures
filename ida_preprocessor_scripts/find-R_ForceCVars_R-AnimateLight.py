#!/usr/bin/env python3
"""Locate R_ForceCVars and R_AnimateLight around the R_CheckVariables call.

engine/gl_rmain.c R_SetupFrame (inlined into R_RenderScene on HL25 and
SvEngine) calls the triple

    R_ForceCVars( cl.maxclients > 1 );
    R_CheckVariables();
    R_AnimateLight ();

back to back, so inside the unique R_CheckVariables caller the direct internal
call immediately before the R_CheckVariables call site is R_ForceCVars and the
one immediately after it is R_AnimateLight. No byte signature participates in
discovery; the shared helper validates and writes both functions.
"""

from pathlib import Path

import json

import ida_analyze_util as u

TARGETS = ("R_ForceCVars", "R_AnimateLight")
RCV = "R_CheckVariables"
MARKER = "__R124_SETUP_TRIPLE__"
MAX_NEIGHBOR_GAP = 96

WALK = r"""
import idautils, ida_funcs, idc, ida_bytes, json

MARKER = @@MARKER@@
RCV = @@RCV@@
MAX_GAP = @@MAX_GAP@@

def emit(d):
    print(MARKER + json.dumps(d))

def fn(ea):
    f = ida_funcs.get_func(ea)
    return int(f.start_ea) if f else None

def name(ea):
    return idc.get_func_name(ea) if ea else ""

def fsize(ea):
    f = ida_funcs.get_func(ea)
    return int(f.end_ea - f.start_ea) if f else 0

def internal_calls(o):
    out = []
    for pc in idautils.FuncItems(o):
        if (idc.print_insn_mnem(pc) or "").lower() != "call":
            continue
        t = idc.get_operand_value(pc, 0)
        if not t:
            continue
        tf = fn(t)
        if tf is None or tf != t:
            continue
        # skip import/CRT thunks: tiny bodies that only forward elsewhere
        if fsize(tf) <= 16:
            continue
        out.append((int(pc), int(t)))
    return out

def callers(o):
    return sorted({fn(x) for x in idautils.CodeRefsTo(o, False) if fn(x)})

res = {}
seq_hosts = callers(RCV)
res["rcv_callers"] = [(hex(h), name(h), fsize(h)) for h in seq_hosts]
if len(seq_hosts) != 1:
    res["error"] = "R_CheckVariables caller is not unique"
    emit(res)
else:
    host = seq_hosts[0]
    seq = internal_calls(host)
    idx = [i for i, (_, t) in enumerate(seq) if t == RCV]
    res["host"] = hex(host)
    res["rcv_call_sites"] = [hex(seq[i][0]) for i in idx]
    if len(idx) != 1:
        res["error"] = "expected exactly one R_CheckVariables call site"
    elif idx[0] + 1 >= len(seq):
        res["error"] = "R_CheckVariables call site lacks the animate neighbour"
    else:
        i = idx[0]
        rcv_pc = seq[i][0]
        next_pc, next_t = seq[i + 1]
        if next_pc - rcv_pc > MAX_GAP:
            res["error"] = "animate call is not adjacent to the triple"
        else:
            # SvEngine's Linux layout opens the setup host straight with the
            # R_CheckVariables call, so R_ForceCVars has no in-host site; the
            # symbol is then simply absent for that platform.
            if i == 0:
                res["R_ForceCVars"] = None
                res["force_absent"] = True
            else:
                prev_pc, prev_t = seq[i - 1]
                if rcv_pc - prev_pc > MAX_GAP:
                    res["R_ForceCVars"] = None
                    res["force_absent"] = True
                else:
                    res["R_ForceCVars"] = {"va": hex(prev_t), "size": fsize(prev_t),
                                           "callers": [hex(c) for c in callers(prev_t)]}
                    res["force_callees"] = [hex(t) for _, t in internal_calls(prev_t)]
            res["R_AnimateLight"] = {"va": hex(next_t), "size": fsize(next_t),
                                     "callers": [hex(c) for c in callers(next_t)]}
            res["animate_callees"] = [hex(t) for _, t in internal_calls(next_t)]
    emit(res)
"""


async def _eval(session, code):
    raw = (await session.call_tool("py_eval", {"code": "exec(" + repr(code) + ", {})"})).model_dump(mode="json")
    structured = raw.get("structured_content") or {}
    if structured.get("stderr"):
        print("setup-triple walk stderr: " + structured["stderr"][:4000])
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

    rcv_data = u._load_yaml_mapping(new_binary_dir / f"{RCV}.{platform}.yaml")
    if not rcv_data or rcv_data.get("func_va") is None:
        if debug:
            print(f"{skill_name}: missing {RCV} artifact")
        return False
    rcv_va = u._parse_int(rcv_data["func_va"], "func_va")

    code = (
        WALK.replace("@@MARKER@@", repr(MARKER))
        .replace("@@RCV@@", repr(rcv_va))
        .replace("@@MAX_GAP@@", str(MAX_NEIGHBOR_GAP))
    )
    stdout = await _eval(session, code)
    located = None
    for line in stdout.splitlines():
        if line.startswith(MARKER):
            located = json.loads(line[len(MARKER) :])
            break
    if not located or "error" in located:
        if debug:
            print(f"{skill_name}: triple walk failed: {located}")
        return False

    written = 0
    for symbol in TARGETS:
        output = outputs[symbol]
        if output is None:
            continue
        info = located.get(symbol)
        if not info:
            if debug:
                print(f"{skill_name}: {symbol} absent on this layout")
            continue
        function = await u._inspect_function_via_mcp(session, int(info["va"], 0), image_base, symbol)
        if not function:
            function = await u._inspect_function_via_mcp(
                session,
                int(info["va"], 0),
                image_base,
                symbol,
                allow_across_function_boundary=True,
            )
            if function:
                function["func_sig_allow_across_function_boundary"] = True
        if not function:
            if debug:
                print(f"{skill_name}: no inspect result for {symbol}")
            continue
        payload = {k: function[k] for k in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
        if function.get("func_sig_allow_across_function_boundary"):
            payload["func_sig_allow_across_function_boundary"] = True
        u.write_func_yaml(output, payload)
        written += 1
    return written == sum(1 for name in TARGETS if outputs[name])
