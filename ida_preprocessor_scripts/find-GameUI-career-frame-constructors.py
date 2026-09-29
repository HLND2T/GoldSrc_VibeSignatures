#!/usr/bin/env python3
"""Locate GameUI's private career-frame constructors from their own literals.

Each constructor builds a dotted background label through the literal that
belongs to its own body and keeps the result in the matching ``m_p*`` member:
``CDottedBgLabel(this, "ProfileSelectionBackground", ...)`` stored into
``m_pProfileSelectionBackground``, and the Map/Bot equivalents. The literal is
therefore target-owned, not caller-owned.

The literal is discovered by scanning raw non-executable segment bytes instead
of IDA's string list: hl-8684 ``gameui.so`` carries DWARF, and IDA describes the
whole ``const CCareerProfileData save`` object around the literal as one data
item, so ``ProfileSelectionBackground`` is never surfaced as a string item and
is rendered as ``save.tutorData+56h``. Requiring a single literal owner and
requiring that owner to install its own RTTI vtable address point before the
reference keeps the anchor independent of MetaHookSv's Windows-only ``push
<literal>`` byte form, its two-push pattern and its ``ReverseSearchFunctionBegin``
window.
"""

from ida_analyze_util import _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._client_vgui_private_common import inspect_unique_function, run_walk

TARGETS = {
    "CCareerProfileFrame_ctor": {
        "class": "CCareerProfileFrame",
        "literal": "ProfileSelectionBackground",
        # Payload identity follows the demangled symbol in gameui.so.
        "func_name": "CCareerProfileFrame::CCareerProfileFrame(vgui2::Panel*)",
    },
    "CCareerMapFrame_ctor": {
        "class": "CCareerMapFrame",
        "literal": "MapSelectionBackground",
        "func_name": "CCareerMapFrame::CCareerMapFrame(vgui2::Panel*)",
    },
    "CCareerBotFrame_ctor": {
        "class": "CCareerBotFrame",
        "literal": "PoolBackground",
        "func_name": "CCareerBotFrame::CCareerBotFrame(vgui2::Panel*)",
    },
}

WALK = r"""
import ida_name

MAX_VTABLE_SLOTS = 128


def vtable_symbol(class_name):
    if values['platform'] == 'linux':
        # Itanium: the length prefix counts characters, and IDA names the
        # vtable header, not the address point the constructor stores.
        return '_ZTV' + str(len(class_name)) + class_name
    return '??_7' + class_name + '@@6B@'


def vtable_address_point(class_name):
    symbol = vtable_symbol(class_name)
    header = int(ida_name.get_name_ea(idaapi.BADADDR, symbol))
    if header == idaapi.BADADDR:
        raise ValueError('vtable symbol is missing: ' + symbol)
    return (header + 8) if values['platform'] == 'linux' else header


def literal_code_refs(literal):
    # A warmed database can omit an analyzed data region from IDA's string
    # list, so scan the raw bytes of every non-executable segment. GCC string
    # pooling may reference the literal as a suffix of a longer literal, so
    # the needle is the NUL-terminated literal itself, not a string item.
    needle = literal.encode('ascii') + b'\0'
    sites = set()
    for segment_ea in idautils.Segments():
        segment = ida_segment.getseg(segment_ea)
        if segment.perm & ida_segment.SEGPERM_EXEC:
            continue
        base = int(segment.start_ea)
        data = ida_bytes.get_bytes(base, int(segment.end_ea) - base) or b''
        start = 0
        while True:
            index = data.find(needle, start)
            if index < 0:
                break
            for ref in idautils.XrefsTo(base + index, 0):
                if ida_bytes.is_code(ida_bytes.get_flags(int(ref.frm))):
                    sites.add(int(ref.frm))
            start = index + 1
    return sites


def vptr_store_sites(function_ea, address_point):
    sites = []
    for ea in function_body(function_ea):
        insn = idautils.DecodeInstruction(ea)
        if insn is None or insn.get_canon_mnem() != 'mov':
            continue
        destination, source = insn.ops[0], insn.ops[1]
        # MSVC renders the store as `mov [ebp+0], offset ??_7<Class>@@6B@` and
        # GCC as `mov [reg], offset _ZTV<Class>+8`; both decode to a zero
        # displacement on the destination and an immediate address point.
        if (destination.type not in (ida_ua.o_phrase, ida_ua.o_displ)
                or int(destination.addr) != 0 or source.type != ida_ua.o_imm):
            continue
        if imm_value(source) == address_point:
            sites.append(int(ea))
    return sites


result = {}
for symbol, target in sorted(values['targets'].items()):
    try:
        literal = target['literal']
        class_name = target['class']
        sites = literal_code_refs(literal)
        if not sites:
            raise ValueError('literal has no code reference: ' + literal)
        owners = set()
        for site in sites:
            function = ida_funcs.get_func(site)
            if function is not None:
                owners.add(int(function.start_ea))
        if len(owners) != 1:
            raise ValueError('literal owner is not unique: ' + literal + ' ' + repr(sorted(owners)))
        entry = owners.pop()
        address_point = vtable_address_point(class_name)
        slots = valid_vtable_slots(address_point, maximum=MAX_VTABLE_SLOTS)
        if not slots:
            raise ValueError('class vtable is not a slot table: ' + vtable_symbol(class_name))
        stores = vptr_store_sites(entry, address_point)
        if len(stores) != 1:
            raise ValueError('class vptr store is not unique: ' + repr(sorted(stores)))
        if stores[0] >= min(sites):
            raise ValueError('class vptr store does not precede the literal reference')
        callers = sorted({int(ref.frm) for ref in idautils.XrefsTo(entry, 0)
                          if direct_call_target(int(ref.frm)) == entry})
        if not callers:
            raise ValueError('constructor has no direct caller')
        result[symbol] = {
            'func_va': entry,
            'vtable_va': address_point,
            'vptr_site': stores[0],
            'literal_sites': sorted(sites),
            'callers': callers,
        }
    except Exception as error:  # noqa: BLE001 - every target fails closed.
        result[symbol] = {'error': str(error)}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map, new_binary_dir
    if platform not in ("windows", "linux"):
        return False
    outputs = {symbol: _output_for_symbol(expected_outputs, symbol) for symbol in TARGETS}
    if not all(outputs.values()):
        return False
    found = await run_walk(session, WALK, {"platform": platform, "targets": TARGETS})
    if not isinstance(found, dict) or found.get("error"):
        return False
    located = {}
    for symbol, target in TARGETS.items():
        candidate = found.get(symbol)
        if not isinstance(candidate, dict) or "func_va" not in candidate:
            if debug:
                print(f"  {symbol}: locator failed: {candidate}")
            return False
        function = await inspect_unique_function(session, target["func_name"], candidate["func_va"], image_base, debug)
        if function is None:
            if debug:
                print(f"  {symbol}: no unique x86 signature at {hex(candidate['func_va'])}")
            return False
        located[symbol] = function
    for symbol, function in located.items():
        payload = {field: function[field] for field in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
        if function.get("func_sig_allow_across_function_boundary"):
            payload["func_sig_allow_across_function_boundary"] = True
        write_func_yaml(outputs[symbol], payload)
    return True
