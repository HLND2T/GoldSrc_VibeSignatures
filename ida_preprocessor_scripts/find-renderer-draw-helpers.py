#!/usr/bin/env python3
"""Locate the Renderer 2D draw helpers that carry no usable in-body literal.

Anchors (approved issue #120 plan). Discovery never uses a byte pattern.

* ``Draw_Pic`` (engine/gl_draw.c Draw_Pic) - callee of the ``Draw_TransPic:
  bad coordinates`` literal owner, minus ``Sys_Error``. HL25 Windows dropped
  that literal, so there the unique ``SCR_UpdateScreen_RenderBody`` callee with
  two callers that a single-call single-caller wrapper delegates to is used.
* ``D_FillRect`` (engine/gl_screen.c D_FillRect) - the zero-call callee of the
  ``Downloading %s`` literal owner whose two callers are the owner and a
  ``SCR_UpdateScreen_RenderBody`` callee. HL25 Windows dropped that literal, so
  the depth-two zero-call callee of SCR's only-called-by-SCR intermediate is
  used instead.
* ``Draw_FillRGBA`` / ``Draw_FillRGBABlend`` - the ``cl_enginefuncs`` table
  slot 11 / 130 (engine/APIProxy.h ``cl_enginefunc_t`` order). The GL blend
  factor immediates (GL_SRC_ALPHA 0x302, GL_ONE_MINUS_SRC_ALPHA 0x303) are an
  output validator, not a discovery anchor.
* ``DT_Initialize`` - the unique function pushing ``GL_RGB_SCALE`` (0x8573).
  The BLOB builds (hl-3248/3266/3329/3647) inline it into
  ``CheckMultiTextureExtensions``, so the immediate there belongs to the host
  function; those configs do not declare the symbol and the walk is skipped.
"""

import json
from pathlib import Path

import ida_analyze_util as u
from ida_preprocessor_scripts.renderer_draw_signatures import CUSTOM_SIG

SYMBOLS = ("Draw_Pic", "D_FillRect", "Draw_FillRGBA", "Draw_FillRGBABlend", "DT_Initialize")
MARKER = "__R120_DRAWHELPERS__"

DOWNLOAD = "Downloading %s"
TRANSPIC = "Draw_TransPic: bad coordinates"
GL_SRC_ALPHA = 0x0302
GL_ONE_MINUS_SRC_ALPHA = 0x0303
GL_RGB_SCALE = 0x8573
SCR = "SCR_UpdateScreen_RenderBody"
SYS_ERROR = "Sys_Error"

WALK = r'''
import idautils, ida_funcs, ida_bytes, idc, idaapi, json

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

def flows(o):
    out = set()
    for pc in idautils.FuncItems(o):
        if (idc.print_insn_mnem(pc) or "").lower() not in ("call", "jmp"):
            continue
        t = idc.get_operand_value(pc, 0)
        if t and fn(t) == t:
            out.add(int(t))
    return out

def refs(text):
    out = set()
    for st in idautils.Strings():
        if text in str(st):
            for x in idautils.XrefsTo(int(st.ea), 0):
                out.add(int(x.frm))
    return out

BLOCK_TERMINATORS = ("retn", "ret", "jmp", "int3")

def region_items(frm):
    """Items of the orphan code block IDA never promoted to a function."""
    prev = idc.get_prev_func(frm)
    nxt = idc.get_next_func(frm)
    lo = int(ida_funcs.get_func(prev).end_ea) if prev not in (None, idaapi.BADADDR) else frm
    hi = int(nxt) if nxt not in (None, idaapi.BADADDR) else frm + 0x400
    start = frm
    while start > lo:
        candidate = idc.prev_head(start)
        if candidate is None or candidate < lo or not ida_bytes.is_code(ida_bytes.get_flags(candidate)):
            break
        if (idc.print_insn_mnem(candidate) or "").lower() in BLOCK_TERMINATORS:
            break
        start = candidate
    items, pc = [], start
    while pc < hi:
        items.append(pc)
        if (idc.print_insn_mnem(pc) or "").lower() in BLOCK_TERMINATORS:
            break
        following = idc.next_head(pc)
        if following is None or following <= pc:
            break
        pc = following
    return items

def unit_items(frm):
    owner = fn(frm)
    return list(idautils.FuncItems(owner)) if owner else region_items(frm)

def unit_targets(frm, mnems):
    out = set()
    for pc in unit_items(frm):
        if (idc.print_insn_mnem(pc) or "").lower() not in mnems:
            continue
        t = idc.get_operand_value(pc, 0)
        if t and fn(t) == t:
            out.add(int(t))
    return out

res = {}
sc = calls(SCR)
transpic_refs = refs(TRANSPIC)
download_refs = refs(DOWNLOAD)

# Draw_Pic
pic = set()
for ref in transpic_refs:
    pic |= (unit_targets(ref, ("call", "jmp")) - {SYS_ERROR})
if not transpic_refs:
    for c in sc:
        if len(callers(c)) != 2:
            continue
        for o in (callers(c) - {SCR}):
            if calls(o) == {c} and len(callers(o)) == 1:
                pic.add(c)
                break
res["Draw_Pic" if len(pic) == 1 else "Draw_Pic_candidates"] = (
    hex(next(iter(pic))) if len(pic) == 1 else sorted(hex(x) for x in pic)
)

# D_FillRect
cand = set()
for ref in download_refs:
    unit_fn = fn(ref)
    for f in unit_targets(ref, ("call",)):
        if calls(f):
            continue
        fcallers = callers(f)
        if not fcallers or len(fcallers) > 2:
            continue
        if all((unit_fn is not None and x == unit_fn) or x in sc for x in fcallers):
            cand.add(f)
if not cand:
    # HL25 Windows dropped the download literal; reach D_FillRect at depth two.
    for x in sc:
        if callers(x) != {SCR}:
            continue
        for f in calls(x):
            if callers(f) == {x} and not calls(f):
                cand.add(f)
res["D_FillRect" if len(cand) == 1 else "D_FillRect_candidates"] = (
    hex(next(iter(cand))) if len(cand) == 1 else sorted(hex(x) for x in cand)
)
res["_debug"] = {
    "sys_error": hex(SYS_ERROR),
    "transpic_refs": sorted(hex(x) for x in transpic_refs),
    "download_refs": sorted(hex(x) for x in download_refs),
}

print(MARKER + json.dumps(res))
'''

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

TABLE_WALK = r"""
import idautils, ida_funcs, ida_bytes, idc, idaapi, json

def fn(ea):
    f = ida_funcs.get_func(ea)
    return int(f.start_ea) if f else None

def has_imm(o, value):
    for pc in idautils.FuncItems(o):
        for index in range(8):
            if idc.get_operand_type(pc, index) == int(idaapi.o_imm) and idc.get_operand_value(pc, index) == value:
                return True
    return False

out = {}
for name, slot in SLOTS.items():
    ptr = ida_bytes.get_dword(slot)
    if fn(ptr) != ptr:
        out[name + "_error"] = "slot is not a function start"
        continue
    if name == "Draw_FillRGBA":
        ok = has_imm(ptr, GL_SRC_ALPHA) and not has_imm(ptr, GL_ONE_MINUS_SRC_ALPHA)
    else:
        ok = has_imm(ptr, GL_SRC_ALPHA) and has_imm(ptr, GL_ONE_MINUS_SRC_ALPHA)
    if not ok:
        out[name + "_error"] = "blend factor immediates do not match"
        continue
    out[name] = hex(ptr)
print(MARKER + json.dumps(out))
"""


async def _eval(session, code):
    raw = (await session.call_tool("py_eval", {"code": "exec(" + repr(code) + ", {})"})).model_dump(mode="json")
    structured = raw.get("structured_content") or {}
    if structured.get("stderr"):
        print("draw-helpers walk stderr: " + structured["stderr"])
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
    sys_error = u._load_yaml_mapping(new_binary_dir / f"{SYS_ERROR}.{platform}.yaml")
    helpers = u._load_yaml_mapping(new_binary_dir / f"cl_enginefuncs.{platform}.yaml")
    if not scr or not sys_error or not helpers:
        return False
    if scr.get("func_va") is None or sys_error.get("func_va") is None or helpers.get("gv_va") is None:
        return False
    scr_va = u._parse_int(scr["func_va"], "func_va")
    sys_error_va = u._parse_int(sys_error["func_va"], "func_va")
    table = u._parse_int(helpers["gv_va"], "gv_va")

    code = (
        "SCR=" + repr(scr_va) + "\n"
        "SYS_ERROR=" + repr(sys_error_va) + "\n"
        "TRANSPIC=" + repr(TRANSPIC) + "\n"
        "DOWNLOAD=" + repr(DOWNLOAD) + "\n"
        "GL_RGB_SCALE=" + repr(GL_RGB_SCALE) + "\n"
        "MARKER=" + repr(MARKER) + "\n"
    )
    located = await _eval(session, code + WALK)
    if not located:
        return False
    if outputs["DT_Initialize"] is not None:
        dt_hits = await _eval(
            session,
            "GL_RGB_SCALE=" + repr(GL_RGB_SCALE) + "\nMARKER=" + repr(MARKER) + "\n" + DT_WALK,
        )
        if not dt_hits:
            return False
        located.update(dt_hits)

    slots = {"Draw_FillRGBA": table + 11 * 4, "Draw_FillRGBABlend": table + 130 * 4}
    table_code = (
        "SLOTS=" + repr(slots) + "\n"
        "GL_SRC_ALPHA=" + repr(GL_SRC_ALPHA) + "\n"
        "GL_ONE_MINUS_SRC_ALPHA=" + repr(GL_ONE_MINUS_SRC_ALPHA) + "\n"
        "MARKER=" + repr(MARKER) + "\n"
    )
    table_hits = await _eval(session, table_code + TABLE_WALK)
    if not table_hits:
        return False
    located.update(table_hits)
    if debug and ("_debug" in located or any(k.endswith("_candidates") or k.endswith("_error") for k in located)):
        print("draw-helpers notes: " + json.dumps(located))

    written = 0
    requested = 0
    fallback = {}
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
            # Draw_FillRGBA and Draw_FillRGBABlend differ only by a GL blend
            # factor, which the default generator wildcards away; retry with the
            # immediates pinned.
            fallback[symbol] = (output, int(address, 0))
            continue
        payload = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
        if function.get("func_sig_allow_across_function_boundary"):
            payload["func_sig_allow_across_function_boundary"] = True
        u.write_func_yaml(output, payload)
        written += 1

    if fallback:
        custom = await _eval(
            session,
            "TARGETS="
            + repr({name: hex(va) for name, (_out, va) in fallback.items()})
            + "\nMARKER="
            + repr(MARKER)
            + "\n"
            + CUSTOM_SIG,
        )
        for symbol, (output, _va) in fallback.items():
            payload = (custom or {}).get(symbol)
            if not payload:
                if debug:
                    print(f"{symbol}: pinned signature failed ({json.dumps((custom or {}).get(symbol + '_error'))})")
                continue
            func_va = int(payload["func_va"], 0)
            u.write_func_yaml(
                output,
                {
                    "func_name": symbol,
                    "func_va": payload["func_va"],
                    "func_rva": hex(func_va - image_base),
                    "func_size": hex(int(payload["func_size"])),
                    "func_sig": payload["func_sig"],
                },
            )
            written += 1
    return written == requested
