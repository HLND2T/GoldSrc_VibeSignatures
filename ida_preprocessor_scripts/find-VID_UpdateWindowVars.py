#!/usr/bin/env python3
"""Recover VID_UpdateWindowVars and the three window globals it writes.

CVideoMode_Common::UpdateWindowPosition builds a local RECT and calls
VID_UpdateWindowVars(&rect, cx, cy). That is the unique in-image direct callee
whose body copies a 16-byte RECT into a writable global (four consecutive
DWORD stores, or a 16-byte MOVUPS on HL25) and then writes two ints. Those
objects are window_rect, window_center_x, and window_center_y. GCC BSS order
is not stable, so the ints are identified by first-write order (x then y),
not by adjacency.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._direct_gv_common import write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import inspect_func, owner_context, run_walk

OWNER_NAME = "CVideoMode_Common_UpdateWindowPosition"
FUNC_NAME = "VID_UpdateWindowVars"
RECT_NAME = "window_rect"
CENTER_X_NAME = "window_center_x"
CENTER_Y_NAME = "window_center_y"
RECT_SIZE = 16

WALK = r"""
OWNER = int(values['owner'], 0)
RECT_SIZE = int(values['rect_size'])

def store_width(entry):
    insn = entry['insn']
    mnem = entry['mnem']
    if mnem in ('movups', 'movaps', 'movdqu', 'movdqa'):
        return 16
    for index, op in enumerate(insn.ops):
        if int(op.type) == int(idaapi.o_void):
            break
        if changed_operand(insn, index):
            try:
                size = int(ida_ua.get_dtype_size(op.dtype))
            except Exception:
                size = 0
            if size:
                return size
    if mnem == 'mov' and entry['written']:
        return 4
    return None

calls = direct_calls(OWNER)
if not calls:
    result = {'error': 'UpdateWindowPosition has no in-image direct call'}
else:
    matches = []
    debug_callees = []
    for callee in sorted(calls):
        entries = scan(callee)
        if entries is None:
            debug_callees.append({'callee': hex(int(callee)), 'scan': None})
            continue
        first_write = {}
        widths = {}
        for entry in entries:
            width = store_width(entry)
            for gv in entry['written']:
                first_write.setdefault(int(gv), int(entry['ea']))
                widths.setdefault(int(gv), width)
        dword_bases = sorted(gv for gv, width in widths.items() if width == 4)
        rects = set(gv for gv, width in widths.items() if width == RECT_SIZE)
        for gv in dword_bases:
            if gv + 4 in first_write and gv + 8 in first_write and gv + 12 in first_write:
                rects.add(gv)
        debug_callees.append({
            'callee': hex(int(callee)),
            'n': len(entries),
            'widths': {hex(k): v for k, v in widths.items()},
            'rects': [hex(v) for v in sorted(rects)],
        })
        if not rects:
            continue
        rect = min(rects)
        extra = []
        for gv, ea in first_write.items():
            if widths.get(gv) != 4:
                continue
            if rect <= gv < rect + RECT_SIZE:
                continue
            extra.append((ea, gv))
        extra.sort()
        unique_extra = []
        seen = set()
        for ea, gv in extra:
            if gv in seen:
                continue
            seen.add(gv)
            unique_extra.append((ea, gv))
        if len(unique_extra) != 2:
            continue

        def addressable(indexes):
            hit = first_addressable(entries, indexes)
            if hit is not None:
                return hit
            for index in indexes:
                item = entries[index]
                if int(item['len']) >= 5:
                    patched = dict(item)
                    patched['disp'] = int(item['len']) - 4
                    return patched
            return None

        rect_entry = addressable([i for i, item in enumerate(entries) if rect in item['written']])
        x_entry = addressable([i for i, item in enumerate(entries) if unique_extra[0][1] in item['written']])
        y_entry = addressable([i for i, item in enumerate(entries) if unique_extra[1][1] in item['written']])
        if rect_entry is None or x_entry is None or y_entry is None:
            continue
        matches.append({
            'callee': hex(int(callee)),
            'rect': access(rect_entry, rect),
            'center_x': access(x_entry, unique_extra[0][1]),
            'center_y': access(y_entry, unique_extra[1][1]),
        })
    if len(matches) != 1:
        result = {
            'error': 'VID_UpdateWindowVars callee is not unique: %d' % len(matches),
            'calls': [hex(int(value)) for value in sorted(calls)],
            'callees': debug_callees,
        }
    else:
        hit = matches[0]
        result = {
            'pointer_size': 4,
            'owner_ea': hex(int(hit['callee'], 16)),
            'rect': hit['rect'],
            'center_x': hit['center_x'],
            'center_y': hit['center_y'],
        }
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
    _ = old_yaml_map
    func_output = _output_for_symbol(expected_outputs, FUNC_NAME)
    if (
        func_output is None
        or _output_for_symbol(expected_outputs, RECT_NAME) is None
        or _output_for_symbol(expected_outputs, CENTER_X_NAME) is None
        or _output_for_symbol(expected_outputs, CENTER_Y_NAME) is None
    ):
        return False
    artifact = _load_yaml_mapping(Path(new_binary_dir) / f"{OWNER_NAME}.{platform}.yaml")
    if not artifact or artifact.get("func_name") != OWNER_NAME:
        if debug:
            print(f"{skill_name}: missing {OWNER_NAME} artifact")
        return False
    try:
        predecessor_ea = int(artifact["func_va"], 0)
    except (KeyError, TypeError, ValueError):
        return False
    if predecessor_ea < int(image_base):
        return False
    located = await run_walk(session, WALK, {"owner": hex(predecessor_ea), "rect_size": RECT_SIZE})
    if located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"{skill_name}: {located}")
        return False
    owner_ea = int(located["owner_ea"], 0)
    function = await inspect_func(session, owner_ea, image_base, FUNC_NAME)
    owner = await owner_context(session, owner_ea, image_base, FUNC_NAME)
    if not function or owner is None:
        if debug:
            print(f"{skill_name}: could not inspect {FUNC_NAME} at {owner_ea:#x}")
        return False
    if not await write_located_globals(
        session,
        expected_outputs,
        platform,
        image_base,
        owner,
        {
            RECT_NAME: located["rect"],
            CENTER_X_NAME: located["center_x"],
            CENTER_Y_NAME: located["center_y"],
        },
    ):
        return False
    write_func_yaml(func_output, function)
    if debug:
        print(
            f"{skill_name}: {FUNC_NAME}={owner_ea:#x} "
            f"{RECT_NAME}={located['rect']['gv_ea']} "
            f"{CENTER_X_NAME}={located['center_x']['gv_ea']} "
            f"{CENTER_Y_NAME}={located['center_y']['gv_ea']}"
        )
    return True
