#!/usr/bin/env python3
"""Locate R_GLStudioDrawPoints through the engine_studio_api table.

engine/r_studio.c R_StudioDrawPoints is registered as the StudioDrawPoints
member of ``engine_studio_api_t`` (common/r_studioint.h, slot 25 counting
from zero), so its code body can never be inlined away by a table reference.
The table is anchored through four already-resolved studioapi members
(GetCurrentEntity slot 6, StudioSetHeader slot 35, SetRenderModel slot 36,
SetChromeOrigin slot 39). On CoF-era builds the slot holds the 9-line
IsATISmoothing wrapper and R_GLStudioDrawPoints is its two-call branch with
more direct callees; on GoldSrc/HL25/SvEngine LTCG merges the wrapper and the
GL body into one function which the slot references through a jmp thunk —
either way the final function is validated to call the table's StudioSetupSkin
(slot 29). No byte signature participates in discovery.
"""

import json
from pathlib import Path

import ida_analyze_util as u

TARGETS = ("R_GLStudioDrawPoints",)
TABLE_SLOTS = {
    "studioapi_GetCurrentEntity": 6,
    "studioapi_StudioSetHeader": 35,
    "studioapi_SetRenderModel": 36,
    "studioapi_SetChromeOrigin": 39,
}
SLOT_STUDIO_DRAW_POINTS = 25
SLOT_STUDIO_SETUP_SKIN = 29
MARKER = "__R124_GLDRAWPOINTS__"

WALK = r"""
import idautils, ida_funcs, idc, ida_bytes, ida_segment, json

MARKER = @@MARKER@@
ANCHORS = @@ANCHORS@@
DRAW_SLOT = @@DRAW_SLOT@@
SKIN_SLOT = @@SKIN_SLOT@@

def emit(d):
    print(MARKER + json.dumps(d))

def fn(ea):
    f = ida_funcs.get_func(ea)
    return int(f.start_ea) if f else None

def fsize(ea):
    f = ida_funcs.get_func(ea)
    return int(f.end_ea - f.start_ea) if f else 0

def callees(o):
    out = set()
    for pc in idautils.FuncItems(o):
        if (idc.print_insn_mnem(pc) or "").lower() != "call":
            continue
        t = idc.get_operand_value(pc, 0)
        tf = fn(t) if t else None
        if tf is not None and tf == t and fsize(tf) > 16:
            out.add(tf)
    return out

res = {"tables": []}
primary = ANCHORS.pop("primary")
# Scan data segments for the slot-6 value instead of DataRefsTo: ELF builds
# register the table through relocations and may not record a code xref, but
# the stored pointer itself is always present in the table image.
table_bases = set()
for si in range(ida_segment.get_segm_qty()):
    seg = ida_segment.getnseg(si)
    if not seg:
        continue
    nm = ida_segment.get_segm_name(seg) or ""
    if not nm or nm.startswith(".text") or nm.startswith(".plt") or nm.startswith(".got"):
        continue
    span = int(seg.end_ea) - int(seg.start_ea)
    if span < 46 * 4:
        continue
    try:
        data = ida_bytes.get_bytes(int(seg.start_ea), span)
    except Exception:
        continue
    if not data:
        continue
    needle = primary.to_bytes(4, "little")
    off = data.find(needle)
    while off != -1:
        table_bases.add(int(seg.start_ea) + off - 6 * 4)
        off = data.find(needle, off + 1)
for base in sorted(table_bases):
    if any(ida_bytes.get_dword(base + int(slot) * 4) != va for slot, va in ANCHORS.items()):
        continue
    res["tables"].append(hex(base))
    slot_va = ida_bytes.get_dword(base + DRAW_SLOT * 4)
    skin_va = ida_bytes.get_dword(base + SKIN_SLOT * 4)
    ent = {"table": hex(base), "slot25": hex(slot_va), "slot29_skin": hex(skin_va)}
    body = fn(slot_va)
    if body is None:
        ent["error"] = "slot 25 is not a function"
        res.setdefault("entries", []).append(ent)
        continue
    # Chase forwarding layers: an E9 jump thunk, or a small forwarder whose
    # only meaningful callee is the next layer (legacy MSVC builds ship
    # 35->37 byte call chains before the real body).
    cur = body
    hops = []
    for _ in range(4):
        if fsize(cur) >= 100:
            break
        nxt = None
        exits = set()
        for pc in idautils.FuncItems(cur):
            mn = (idc.print_insn_mnem(pc) or "").lower()
            if mn not in ("jmp", "call"):
                continue
            t = idc.get_operand_value(pc, 0)
            if not t or t == cur:
                continue
            tf = fn(t)
            exits.add(tf if tf is not None else t)
        if len(exits) == 1:
            nxt = next(iter(exits))
        if nxt is None:
            break
        hops.append((hex(cur), fsize(cur)))
        cur = nxt
    if hops:
        ent["thunk_chain"] = hops
    if fsize(cur) < 100:
        ent["cur_insns"] = [
            "%x %s %s|%s" % (pc, idc.print_insn_mnem(pc), idc.print_operand(pc, 0), idc.print_operand(pc, 1))
            for pc in idautils.FuncItems(cur)
        ]
    body = cur
    if body != fn(slot_va):
        ent["thunk_to"] = hex(body)
        ent["R_GLStudioDrawPoints"] = hex(body)
    else:
        jumps_out = set()
        for pc in idautils.FuncItems(body):
            if (idc.print_insn_mnem(pc) or "").lower() != "jmp":
                continue
            t = idc.get_operand_value(pc, 0)
            if t and t != body:
                tf = fn(t)
                jumps_out.add(tf if tf is not None else t)
        branch = sorted(
            {c for c in callees(body) | jumps_out if fsize(c) > 100}
        )
        if len(branch) == 2:
            scored = [(len(callees(c)), c) for c in branch]
            scored.sort()
            ent["branches"] = [(hex(c), fsize(c), len(callees(c))) for c in branch]
            ent["R_GLStudioDrawPoints"] = hex(scored[-1][1])
        elif len(branch) == 1:
            # Pre-ATI builds ship the wrapper without the ATINPatch branch;
            # the single large callee is R_GLStudioDrawPoints itself.
            ent["branches"] = [(hex(c), fsize(c), len(callees(c))) for c in branch]
            ent["R_GLStudioDrawPoints"] = hex(branch[0])
        elif not branch and fsize(body) >= 800:
            ent["R_GLStudioDrawPoints"] = hex(body)
        else:
            ent["error"] = "wrapper does not expose the studio-draw branch"
            ent["body_size"] = fsize(body)
            ent["body_callees"] = [(hex(c), fsize(c)) for c in sorted(callees(body))]
            res.setdefault("entries", []).append(ent)
            continue
    cand = int(ent["R_GLStudioDrawPoints"], 16)
    ent["cand_size"] = fsize(cand)
    # The StudioSetupSkin slot may hold a forced-face wrapper whose body jumps
    # to the shared inner skin routine; accept any direct jump target of the
    # slotted function as the skin implementation to compare against.
    skin_targets = {skin_va}
    skin_fn = fn(skin_va)
    if skin_fn is not None:
        for pc in idautils.FuncItems(skin_fn):
            if (idc.print_insn_mnem(pc) or "").lower() != "jmp":
                continue
            t = idc.get_operand_value(pc, 0)
            if t and fn(t) == t:
                skin_targets.add(int(t))
    ent["cand_calls_skin"] = bool(skin_targets & callees(cand))
    res.setdefault("entries", []).append(ent)
emit(res)
"""


async def _eval(session, code):
    raw = (await session.call_tool("py_eval", {"code": "exec(" + repr(code) + ", {})"})).model_dump(mode="json")
    structured = raw.get("structured_content") or {}
    if structured.get("stderr"):
        print("gldrawpoints walk stderr: " + structured["stderr"][:4000])
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
    for sym in TABLE_SLOTS:
        data = u._load_yaml_mapping(new_binary_dir / f"{sym}.{platform}.yaml")
        if not data or data.get("func_va") is None:
            if debug:
                print(f"{skill_name}: missing {sym} artifact")
            return False
        anchors[sym] = u._parse_int(data["func_va"], "func_va")

    slot_map = {slot: anchors[sym] for sym, slot in TABLE_SLOTS.items()}
    walk_anchors = dict(slot_map)
    walk_anchors["primary"] = anchors["studioapi_GetCurrentEntity"]
    code = (
        WALK.replace("@@MARKER@@", repr(MARKER))
        .replace("@@ANCHORS@@", repr(walk_anchors))
        .replace("@@DRAW_SLOT@@", str(SLOT_STUDIO_DRAW_POINTS))
        .replace("@@SKIN_SLOT@@", str(SLOT_STUDIO_SETUP_SKIN))
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
    entries = [e for e in located.get("entries", []) if "error" not in e and e.get("cand_calls_skin")]
    if debug:
        print(f"{skill_name}: tables={located.get('tables')} entries={located.get('entries')}")
    if len(entries) != 1:
        return False
    info = entries[0]

    function = await u._inspect_function_via_mcp(
        session, int(info["R_GLStudioDrawPoints"], 0), image_base, "R_GLStudioDrawPoints"
    )
    if not function:
        function = await u._inspect_function_via_mcp(
            session,
            int(info["R_GLStudioDrawPoints"], 0),
            image_base,
            "R_GLStudioDrawPoints",
            allow_across_function_boundary=True,
        )
        if function:
            function["func_sig_allow_across_function_boundary"] = True
    if not function:
        if debug:
            print(f"{skill_name}: no inspect result")
        return False
    payload = {k: function[k] for k in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    if function.get("func_sig_allow_across_function_boundary"):
        payload["func_sig_allow_across_function_boundary"] = True
    u.write_func_yaml(outputs["R_GLStudioDrawPoints"], payload)
    return True
