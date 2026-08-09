"""Resolve secondary/ordinal vtables for 32-bit MSVC and Itanium ABIs."""

from __future__ import annotations

import json

from ida_analyze_util import parse_mcp_result


_ORDINAL_TEMPLATE = r"""
import ida_bytes, ida_funcs, ida_name, ida_segment, idaapi, idautils, json
class_name = CLASS_NAME_PLACEHOLDER
aliases = ALIASES_PLACEHOLDER
ordinal = ORDINAL_PLACEHOLDER
expected_offset = EXPECTED_OFFSET_PLACEHOLDER
pointer_size = 8 if idaapi.inf_is_64bit() else 4
candidates = []
if pointer_size == 4:
    names = list(aliases)
    if not names:
        names = [name for _ea, name in idautils.Names() if class_name in name and (name.startswith('??_7') or name.startswith('_ZTI'))]
    for name in names:
        ea = ida_name.get_name_ea(idaapi.BADADDR, name)
        if ea == idaapi.BADADDR:
            continue
        if name.startswith('_ZTI'):
            for ref in idautils.DataRefsTo(ea):
                header = int(ref) - pointer_size
                raw = int(ida_bytes.get_dword(header))
                offset_to_top = raw - 0x100000000 if raw & 0x80000000 else raw
                if expected_offset is not None and offset_to_top != expected_offset:
                    continue
                candidates.append((int(ref) + pointer_size, name, offset_to_top))
        else:
            candidates.append((int(ea), name, 0))
candidates = sorted(set(candidates))
selected = None
if 0 <= ordinal < len(candidates):
    start, symbol, offset_to_top = candidates[ordinal]
    entries = {}
    for index in range(512):
        target = int(ida_bytes.get_dword(start + index * pointer_size))
        segment = ida_segment.getseg(target)
        if target in (0, idaapi.BADADDR) or segment is None or not (segment.perm & ida_segment.SEGPERM_EXEC):
            break
        entries[index] = hex(target)
    if entries:
        selected = {
            'vtable_class': class_name,
            'vtable_symbol': symbol,
            'vtable_va': hex(start),
            'vtable_size': hex(len(entries) * pointer_size),
            'vtable_numvfunc': len(entries),
            'vtable_entries': entries,
            'offset_to_top': offset_to_top,
        }
result = json.dumps({'pointer_size': pointer_size, 'selected': selected})
"""


async def preprocess_ordinal_vtable_via_mcp(
    session,
    class_name,
    ordinal,
    image_base,
    platform,
    debug=False,
    symbol_aliases=None,
    expected_offset_to_top=None,
    canonical_vtable_symbol=None,
):
    """Resolve an ordinal vtable while preserving the CS2 helper signature."""

    del platform
    code = (
        _ORDINAL_TEMPLATE.replace("CLASS_NAME_PLACEHOLDER", json.dumps(class_name))
        .replace("ALIASES_PLACEHOLDER", json.dumps(list(symbol_aliases or ())))
        .replace("ORDINAL_PLACEHOLDER", str(int(ordinal)))
        .replace(
            "EXPECTED_OFFSET_PLACEHOLDER",
            "None" if expected_offset_to_top is None else str(int(expected_offset_to_top)),
        )
    )
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:
        return None
    selected = payload.get("selected") if isinstance(payload, dict) and payload.get("pointer_size") == 4 else None
    if not isinstance(selected, dict):
        return None
    try:
        va = int(selected["vtable_va"], 0)
        entries = {int(index): str(value) for index, value in selected["vtable_entries"].items()}
    except (KeyError, TypeError, ValueError):
        return None
    if debug:
        print(f"    Preprocess: resolved ordinal vtable {class_name}[{ordinal}] at {hex(va)}")
    return {
        "vtable_class": selected.get("vtable_class", class_name),
        "vtable_symbol": canonical_vtable_symbol or selected.get("vtable_symbol", class_name),
        "vtable_va": hex(va),
        "vtable_rva": hex(va - int(image_base)),
        "vtable_size": selected["vtable_size"],
        "vtable_numvfunc": selected["vtable_numvfunc"],
        "vtable_entries": entries,
    }
