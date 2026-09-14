#!/usr/bin/env python3
"""Recover CL_FxBlend from the verified studioapi_StudioSetRenderamt accessor.

engine/r_studio.c studioapi_StudioSetRenderamt(iRenderamt) stores the amount
into currententity->curstate.renderamt and then computes
r_blend = CL_FxBlend(currententity) / 255.0f, so the tiny accessor owns
exactly one direct call and its sole callee is CL_FxBlend. The callee's
source role is verified independently: engine/cl_tent.c CL_FxBlend de-syncs
the pulse effects with ``ent->curstate.number * 363.0`` and that constant
occurs exactly once inside the callee body on every validated build
(hl-4554/6153/8684/10210, cof-5936, svencoop-10257; both platforms where
shipped).
"""

from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    _parse_int,
    parse_mcp_result,
    write_func_yaml,
)

TARGET_FUNC_NAME = "CL_FxBlend"
PREDECESSOR = "studioapi_StudioSetRenderamt"
# offset = ent->curstate.number * 363.0 (pulse de-sync), engine/cl_tent.c.
FXBLEND_DESYNC_FLOAT = 363.0

WALK = r"""
def main(values):
    import ida_bytes, ida_funcs, ida_segment, ida_ua, idautils, idc, struct
    ea = int(values['predecessor'])
    fn = ida_funcs.get_func(ea)
    if fn is None or int(fn.start_ea) != ea:
        return {'error': 'predecessor is not a function start'}
    targets = []
    for cur in idautils.FuncItems(ea):
        if (idc.print_insn_mnem(cur) or '').lower() != 'call':
            continue
        target = idc.get_operand_value(cur, 0)
        if not target or target == cur:
            continue
        target_fn = ida_funcs.get_func(target)
        # SvEngine Linux compiles PIC: every accessor opens with
        # call __x86.get_pc_thunk.reg, a <=4-byte mov/ret stub that is not
        # part of the accessor's source-level calls.
        if target_fn is not None and int(target_fn.end_ea) - int(target_fn.start_ea) <= 4:
            continue
        targets.append(int(target))
    if len(targets) != 1:
        return {'error': 'sole-call contract violated', 'targets': [hex(t) for t in targets]}
    callee = targets[0]
    callee_fn = ida_funcs.get_func(callee)
    if callee_fn is None or int(callee_fn.start_ea) != callee:
        return {'error': 'callee is not a function start', 'callee': hex(callee)}

    def seg_ro(addr):
        seg = ida_segment.getseg(int(addr))
        name = ida_segment.get_segm_name(seg) if seg else ''
        return name == '.rdata' or name.startswith('.rodata')

    # SvEngine Linux compiles the callee PIC: its float pool is referenced
    # through [gotreg+disp32] once the prologue anchored a GOT base with
    # call __x86.get_pc_thunk.reg; add gotreg, imm32.
    got_base = None
    got_reg = None
    items = list(idautils.FuncItems(callee))
    for idx, cur in enumerate(items[:6]):
        if (idc.print_insn_mnem(cur) or '').lower() != 'call':
            continue
        nxt = items[idx + 1] if idx + 1 < len(items) else None
        if nxt is None or (idc.print_insn_mnem(nxt) or '').lower() != 'add':
            continue
        if idc.get_operand_type(nxt, 1) != 5:
            continue
        target = idc.get_operand_value(cur, 0)
        thunk = ida_funcs.get_func(target) if target else None
        if thunk is None or int(thunk.end_ea) - int(thunk.start_ea) > 4:
            continue
        imm = idc.get_operand_value(nxt, 1)
        got_base = (int(nxt) + int(imm)) & 0xFFFFFFFF
        got_reg = (idc.print_operand(nxt, 0) or '').strip().lower()
        break

    desync_hits = 0
    for cur in idautils.FuncItems(callee):
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, cur) <= 0:
            continue
        for operand_index, op in enumerate(insn.ops):
            if int(op.type) == 0:
                break
            values2 = []
            if int(op.type) == 5:
                raw = int(op.value) & 0xFFFFFFFF
                if raw:
                    values2 = [struct.unpack('<f', struct.pack('<I', raw))[0]]
            else:
                addr = int(op.addr) & 0xFFFFFFFF
                if got_base is not None and int(op.type) == 4:
                    offb = int(getattr(op, 'offb', 0) or 0)
                    if offb and int(insn.size) - offb >= 4:
                        addr = (got_base + addr) & 0xFFFFFFFF
                if addr and seg_ro(addr):
                    blob = ida_bytes.get_bytes(addr, 8)
                    if blob and len(blob) == 8:
                        values2 = [struct.unpack('<f', blob[:4])[0], struct.unpack('<d', blob)[0]]
            for value in values2:
                if abs(value - float(values['desync'])) < 1e-4:
                    desync_hits += 1
    if desync_hits < 1:
        return {'error': 'callee misses the 363.0 de-sync constant', 'callee': hex(callee)}
    return {'pointer_size': 4, 'callee': hex(callee), 'desync_hits': desync_hits}
import json
result = json.dumps(main(VALUES))
"""


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
    import json

    _ = skill_name, old_yaml_map, debug
    output = _output_for_symbol(expected_outputs, TARGET_FUNC_NAME)
    if output is None:
        return False
    predecessor = _load_yaml_mapping(Path(new_binary_dir) / f"{PREDECESSOR}.{platform}.yaml")
    if not predecessor or predecessor.get("func_name") != PREDECESSOR:
        return False
    try:
        predecessor_ea = _parse_int(predecessor.get("func_va"), "func_va")
    except Exception:  # noqa: BLE001 - malformed dependency fails closed.
        return False
    if predecessor_ea < int(image_base):
        return False
    values = json.dumps({"predecessor": predecessor_ea, "desync": FXBLEND_DESYNC_FLOAT})
    located = parse_mcp_result(await session.call_tool("py_eval", {"code": WALK.replace("VALUES", values)}))
    if not isinstance(located, dict) or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print("CL_FxBlend walk failed:", located)
        return False
    try:
        callee_ea = int(located["callee"], 0)
    except (KeyError, TypeError, ValueError):
        return False
    function = await _inspect_function_via_mcp(session, callee_ea, image_base, TARGET_FUNC_NAME)
    across = function is None
    if across:
        function = await _inspect_function_via_mcp(
            session, callee_ea, image_base, TARGET_FUNC_NAME, allow_across_function_boundary=True
        )
    if not function:
        return False
    payload = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    if across:
        payload["func_sig_allow_across_function_boundary"] = True
    write_func_yaml(output, payload)
    return True
