#!/usr/bin/env python3
"""Locate the Sven Co-op engine sprite-frame draw family.

SvEngine keeps engine/cl_draw.c SPR_DrawHoles/SPR_DrawAdditive/SPR_DrawGeneric
with the ``SPR_Draw*: Invalid frame %d`` diagnostics. Each one reaches exactly
one sprite-frame renderer (Draw_SpriteFrame*_SvEngine) and all of them share the
Sven Draw_Frame.

Draw_Frame is located first, from the only property that is stable on every
SvEngine build and both platforms: it is the function that reads the five
``gl_draw.c`` scissor statics for the ``qglScissor``/``qglEnable
(GL_SCISSOR_TEST)`` block (see ``_draw_frame_scissor_common``). The previous
"callee shared by all three families" derivation cannot do that on Linux:

* ``svencoop-8948/hw.so`` reaches each renderer through a local ``jmp``
  trampoline, so the literal owners' callees are the trampolines rather than the
  renderers, and no callee is shared by all three literal owners at all;
* ``svencoop-10257/hw.so`` shares four sibling helpers with the frame, so the
  support set has five members and the previous rule cannot pick one.

Each renderer is then the unique function reachable from its family's literal
sites that calls Draw_Frame. Resolving ``jmp`` trampolines makes the two
platforms agree, and a diagnostic that IDA attached to an unrelated neighbouring
function cannot pollute the result: only the reachable candidate that actually
calls Draw_Frame is accepted.
"""

import json
from pathlib import Path

import ida_analyze_util as u
from ida_preprocessor_scripts._draw_frame_scissor_common import DETECTOR
from ida_preprocessor_scripts._engine_private_globals_common import run_walk

HOLES = "SPR_DrawHoles: Invalid frame %d\n"
ADDITIVE = "SPR_DrawAdditive: Invalid frame %d\n"
GENERIC = "SPR_DrawGeneric: Invalid frame %d\n"

SYMBOLS = (
    "Draw_SpriteFrameHoles_SvEngine",
    "Draw_SpriteFrameAdditive_SvEngine",
    "Draw_SpriteFrameGeneric_SvEngine",
    "Draw_Frame",
)

WALK = (
    DETECTOR
    + r"""

def _owner(ea):
    owner = ida_funcs.get_func(int(ea))
    return int(owner.start_ea) if owner is not None else None


def _items(ea):
    # The diagnostic's unit: its function, or the contiguous code run when IDA
    # never promoted the owner.
    owner = ida_funcs.get_func(int(ea))
    if owner is not None:
        return [int(pc) for pc in idautils.FuncItems(int(owner.start_ea))]
    start = int(ea)
    if not ida_bytes.is_code(ida_bytes.get_flags(start)):
        return []
    while True:
        previous = idc.prev_head(start)
        if previous is None or previous == idc.BADADDR \
                or not ida_bytes.is_code(ida_bytes.get_flags(previous)):
            break
        start = previous
    items, pc = [], start
    while True:
        items.append(pc)
        following = idc.next_head(pc)
        if following is None or following == idc.BADADDR \
                or not ida_bytes.is_code(ida_bytes.get_flags(following)):
            break
        pc = following
    return items


def _direct_targets(items, mnemonics=('call', 'jmp')):
    found = set()
    for pc in items:
        if (idc.print_insn_mnem(pc) or '').lower() not in mnemonics:
            continue
        target = int(idc.get_operand_value(pc, 0))
        if target and _owner(target) == target:
            found.add(target)
    return found


def _resolve(ea):
    # Follow a local jmp trampoline. SvEngine emits two shapes: a direct
    # ``jmp Draw_Frame`` (Draw_SpriteFrame) and, on the Linux builds, a PIC
    # ``jmp ds:slot`` through a GOT entry that holds the renderer's address.
    for _ in range(4):
        owner = ida_funcs.get_func(int(ea))
        if owner is None:
            return ea
        items = [int(pc) for pc in idautils.FuncItems(int(owner.start_ea))]
        if not items or len(items) > 3:
            return ea
        last = items[-1]
        if (idc.print_insn_mnem(last) or '').lower() != 'jmp':
            return ea
        kind = idc.get_operand_type(last, 0)
        if kind == idaapi.o_near:
            target = int(idc.get_operand_value(last, 0))
        elif kind in (idaapi.o_mem, idaapi.o_displ):
            target = int(idc.get_wide_dword(int(idc.get_operand_value(last, 0))))
        else:
            return ea
        if _owner(target) != target:
            return ea
        ea = target
    return ea


def _literal_sites(text):
    sites = []
    for st in idautils.Strings():
        if str(st) == text:
            for xref in idautils.XrefsTo(int(st.ea), 0):
                sites.append(int(xref.frm))
    return sites


frames = locate_draw_frame()
if len(frames) != 1:
    result = {'error': 'Draw_Frame is not unique: %d' % len(frames),
              'frames': [hex(ea) for ea, _ in frames]}
else:
    frame = frames[0][0]
    resolved = {}
    problems = {}
    for label, text in (('holes', HOLES), ('additive', ADDITIVE), ('generic', GENERIC)):
        reachable = set()
        for site in _literal_sites(text):
            for target in _direct_targets(_items(site)):
                candidate = _resolve(target)
                if ida_funcs.get_func(candidate) is not None:
                    reachable.add(candidate)
        renderers = sorted(t for t in reachable if frame in _direct_targets(_items(t), ('call',)))
        if len(renderers) == 1:
            resolved[label] = renderers[0]
        else:
            problems[label] = [hex(t) for t in renderers]
    if problems or len(resolved) != 3:
        result = {'error': 'renderer not unique', 'frame': hex(frame), 'problems': problems}
    else:
        result = {'frame': hex(frame), 'holes': hex(resolved['holes']),
                  'additive': hex(resolved['additive']), 'generic': hex(resolved['generic'])}
"""
)

ADDRESS_BY_SYMBOL = {
    "Draw_SpriteFrameHoles_SvEngine": "holes",
    "Draw_SpriteFrameAdditive_SvEngine": "additive",
    "Draw_SpriteFrameGeneric_SvEngine": "generic",
    "Draw_Frame": "frame",
}


def _walk_values():
    """Literals are injected into the worker as a Python prelude."""
    return {
        "HOLES": repr(HOLES),
        "ADDITIVE": repr(ADDITIVE),
        "GENERIC": repr(GENERIC),
    }


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
    prelude = "".join(f"{name}={value}\n" for name, value in _walk_values().items())
    located = await run_walk(session, prelude + WALK, {})
    if not located or located.get("error") or "frame" not in located:
        if debug:
            print("Sven sprite-frame locate failed: " + json.dumps(located))
        return False
    addresses = {symbol: int(located[key], 0) for symbol, key in ADDRESS_BY_SYMBOL.items()}
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
