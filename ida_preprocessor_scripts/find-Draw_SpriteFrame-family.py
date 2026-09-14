#!/usr/bin/env python3
"""Locate the HL/CoF sprite-frame draw family from the SPR_Draw* diagnostics.

engine/cl_draw.c SPR_DrawHoles/SPR_DrawAdditive/SPR_DrawGeneric are the only
owners of the three ``Client.dll SPR_Draw* error`` literals and each one calls
exactly one sprite-frame renderer (engine/gl_draw.c Draw_SpriteFrame*), which
in turn call the shared Draw_Frame. The literal owners are located by exact
string xref; the callee that is not shared with the sibling owners (i.e. not
R_GetSpriteFrame/Con_DPrintf) is the target, and Draw_Frame is the callee shared
by all three targets. No byte pattern participates in discovery.

On some builds the SPR_DrawHoles literal has two owners (the engine proxy and a
second copy); both call the same renderer, so the owner union is used.
"""

import json
from pathlib import Path

import ida_analyze_util as u

HOLES = "Client.dll SPR_DrawHoles error:  invalid frame\n"
ADDITIVE = "Client.dll SPR_DrawAdditive error:  invalid frame\n"
GENERIC = "Client.dll SPR_DrawGeneric error: invalid frame\n"

SYMBOLS = ("Draw_SpriteFrameHoles", "Draw_SpriteFrameAdditive", "Draw_SpriteFrameGeneric", "Draw_Frame")
MARKER = "__R120_SPRITEFRAME__"

WALK = r"""
import idautils, ida_funcs, idc, json

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

def owners(text):
    res = set()
    for st in idautils.Strings():
        if str(st) == text:
            for x in idautils.XrefsTo(int(st.ea), 0):
                o = fn(int(x.frm))
                if o:
                    res.add(o)
    return res

H, A, G = owners(HOLES), owners(ADDITIVE), owners(GENERIC)
if not H or not A or not G:
    print(MARKER + json.dumps({"error": "literal owners unresolved",
                               "counts": [len(H), len(A), len(G)]}))
else:
    # Helpers (R_GetSpriteFrame/Con_DPrintf) are called by every literal owner;
    # a build may also attach the literal to an unrelated function (e.g. the
    # crosshair body), so never trust a single owner's callee set.
    sets = [s for s in (calls(o) for o in (H | A | G)) if s]
    helper = set.intersection(*sets) if sets else set()
    families = {"holes": H, "additive": A, "generic": G}
    candidates = {
        key: set().union(*[calls(o) for o in own]) - helper
        for key, own in families.items()
    }
    all_candidates = set().union(*candidates.values())
    # Draw_Frame is the function reached from a candidate of every family and
    # is itself not a candidate.
    support = {}
    for key, cands in candidates.items():
        for callee in cands:
            for target in calls(callee):
                if target in all_candidates:
                    continue
                support.setdefault(target, set()).add(key)
    frames = [t for t, keys in support.items() if keys == set(families)]
    failed = {}
    for key, cands in candidates.items():
        hits = [c for c in cands if frames and frames[0] in calls(c)]
        if len(hits) != 1:
            failed[key] = sorted(hex(x) for x in cands)
    if len(frames) != 1 or failed:
        print(MARKER + json.dumps({"error": "renderer not unique",
                                   "frames": sorted(hex(x) for x in frames),
                                   "failed": failed}))
    else:
        frame = frames[0]
        resolved = {
            key: next(c for c in cands if frame in calls(c))
            for key, cands in candidates.items()
        }
        print(MARKER + json.dumps({"targets": {
            "holes": hex(resolved["holes"]),
            "additive": hex(resolved["additive"]),
            "generic": hex(resolved["generic"]),
            "frame": hex(frame),
        }}))
"""

ADDRESS_BY_SYMBOL = {
    "Draw_SpriteFrameHoles": "holes",
    "Draw_SpriteFrameAdditive": "additive",
    "Draw_SpriteFrameGeneric": "generic",
    "Draw_Frame": "frame",
}


async def _walk(session):
    code = (
        "HOLES="
        + repr(HOLES)
        + "\nADDITIVE="
        + repr(ADDITIVE)
        + "\nGENERIC="
        + repr(GENERIC)
        + "\nMARKER="
        + repr(MARKER)
        + "\n"
        + WALK
    )
    raw = (await session.call_tool("py_eval", {"code": "exec(" + repr(code) + ", {})"})).model_dump(mode="json")
    structured = raw.get("structured_content") or {}
    if structured.get("stderr"):
        print("Draw_SpriteFrame family walk stderr: " + structured["stderr"])
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
    _ = skill_name, old_yaml_map, new_binary_dir
    outputs = {name: u._output_for_symbol(expected_outputs, name) for name in SYMBOLS}
    if not any(outputs[name] for name in SYMBOLS):
        return False
    located = await _walk(session)
    if not located or located.get("error"):
        if debug:
            print("Draw_SpriteFrame family locate failed: " + json.dumps(located))
        return False
    addresses = {symbol: int(located["targets"][key], 0) for symbol, key in ADDRESS_BY_SYMBOL.items()}
    written = 0
    for symbol, output in outputs.items():
        if output is None:
            continue
        function = await u._inspect_function_via_mcp(session, addresses[symbol], image_base, symbol)
        if not function:
            function = await u._inspect_function_via_mcp(
                session, addresses[symbol], image_base, symbol, allow_across_function_boundary=True
            )
            if function:
                function["func_sig_allow_across_function_boundary"] = True
        if not function:
            if debug:
                print(f"{symbol}: inspection failed at {hex(addresses[symbol])}")
            return False
        payload = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
        if function.get("func_sig_allow_across_function_boundary"):
            payload["func_sig_allow_across_function_boundary"] = True
        u.write_func_yaml(output, payload)
        written += 1
    return written == sum(1 for name in SYMBOLS if outputs[name])
