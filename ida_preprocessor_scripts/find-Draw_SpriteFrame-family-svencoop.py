#!/usr/bin/env python3
"""Locate the Sven Co-op engine sprite-frame draw family.

SvEngine keeps engine/cl_draw.c SPR_DrawHoles/SPR_DrawAdditive/SPR_DrawGeneric
with the ``SPR_Draw*: Invalid frame %d`` diagnostics. Each one reaches exactly
one sprite-frame renderer (Draw_SpriteFrame*_SvEngine) and they share the Sven
Draw_Frame. Some of those diagnostics sit in code IDA never promoted to a
function, so the containing basic block is recovered from the xref.

The renderer is the callee that is not shared with the sibling families; the
shared Draw_Frame is the callee reached from one candidate of every family.
No byte pattern participates in discovery.
"""

import json
from pathlib import Path

import ida_analyze_util as u

HOLES = "SPR_DrawHoles: Invalid frame %d\n"
ADDITIVE = "SPR_DrawAdditive: Invalid frame %d\n"
GENERIC = "SPR_DrawGeneric: Invalid frame %d\n"

SYMBOLS = (
    "Draw_SpriteFrameHoles_SvEngine",
    "Draw_SpriteFrameAdditive_SvEngine",
    "Draw_SpriteFrameGeneric_SvEngine",
    "Draw_Frame",
)
MARKER = "__R120_SPRITEFRAME_SVEN__"

WALK = r"""
import idautils, ida_funcs, ida_bytes, idc, idaapi, json

def fn(ea):
    f = ida_funcs.get_func(ea)
    return int(f.start_ea) if f else None

def refs(text):
    out = set()
    for st in idautils.Strings():
        if str(st) == text:
            for x in idautils.XrefsTo(int(st.ea), 0):
                out.add(int(x.frm))
    return out

def region_items(frm):
    # SvEngine SPR_Draw* diagnostics may sit in functions IDA never promoted.
    # Those units are padding-separated, so the contiguous code run around the
    # reference is exactly one function.
    start = frm
    while True:
        candidate = idc.prev_head(start)
        if candidate is None or not ida_bytes.is_code(ida_bytes.get_flags(candidate)):
            break
        start = candidate
    items, pc = [], start
    while True:
        items.append(pc)
        following = idc.next_head(pc)
        if following is None or not ida_bytes.is_code(ida_bytes.get_flags(following)):
            break
        pc = following
    return items

def unit_items(frm):
    owner = fn(frm)
    return list(idautils.FuncItems(owner)) if owner else region_items(frm)

def targets(frm, mnems):
    out = set()
    for pc in unit_items(frm):
        if (idc.print_insn_mnem(pc) or "").lower() not in mnems:
            continue
        t = idc.get_operand_value(pc, 0)
        if t and fn(t) == t:
            out.add(int(t))
    return out

def family_union(text):
    # Prefer references inside IDA-defined functions; orphan references are the
    # fallback so a promoted sibling cannot pollute the family set.
    found = refs(text)
    chosen = [r for r in found if fn(r)] or found
    return set().union(*[targets(r, ("call", "jmp")) for r in chosen]) if chosen else set()

unions = {
    "holes": family_union(HOLES),
    "additive": family_union(ADDITIVE),
    "generic": family_union(GENERIC),
}
if not all(unions.values()):
    print(MARKER + json.dumps({"error": "literal refs unresolved",
                               "counts": {k: len(v) for k, v in unions.items()}}))
else:
    helper = set.intersection(*unions.values())
    candidates = {key: union - helper for key, union in unions.items()}
    all_candidates = set().union(*candidates.values())
    support = {}
    for key, cands in candidates.items():
        for callee in cands:
            for target in targets(callee, ("call",)):
                if target in all_candidates:
                    continue
                support.setdefault(target, set()).add(key)
    frames = [t for t, keys in support.items() if keys == set(candidates)]
    failed = {}
    for key, cands in candidates.items():
        hits = [c for c in cands if frames and frames[0] in targets(c, ("call",))]
        if len(hits) != 1:
            failed[key] = sorted(hex(x) for x in cands)
    if len(frames) != 1 or failed:
        print(MARKER + json.dumps({"error": "renderer not unique",
                                   "frames": sorted(hex(x) for x in frames),
                                   "failed": failed}))
    else:
        frame = frames[0]
        resolved = {key: next(c for c in cands if frame in targets(c, ("call",)))
                    for key, cands in candidates.items()}
        print(MARKER + json.dumps({"targets": {
            "holes": hex(resolved["holes"]),
            "additive": hex(resolved["additive"]),
            "generic": hex(resolved["generic"]),
            "frame": hex(frame),
        }}))
"""

ADDRESS_BY_SYMBOL = {
    "Draw_SpriteFrameHoles_SvEngine": "holes",
    "Draw_SpriteFrameAdditive_SvEngine": "additive",
    "Draw_SpriteFrameGeneric_SvEngine": "generic",
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
        print("Sven sprite-frame walk stderr: " + structured["stderr"])
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
            print("Sven sprite-frame locate failed: " + json.dumps(located))
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
