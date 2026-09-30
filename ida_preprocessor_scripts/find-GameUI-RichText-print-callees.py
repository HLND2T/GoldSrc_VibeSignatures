#!/usr/bin/env python3
"""Locate RichText::InsertString / InsertColorChange from the console Print wrapper.

On old-generation Windows builds CGameConsoleDialog::Print is not inlined and
keeps the two direct calls of its source body::

    void CGameConsoleDialog::Print(const char *msg)
    {
        m_pHistory->InsertColorChange(m_PrintColor);
        m_pHistory->InsertString(msg);
    }

The already-anchored CGameConsoleDialog_Print artifact gives both callees
without an LLM premise. InsertString is identified positively by its RichText
markup scan (``cmp byte ptr [reg], 23h`` for the '#' hash introducer, the same
discriminator the newer-build print-target finder uses); InsertColorChange is
the remaining callee of the ordered pair on the same history object.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._client_vgui_private_common import inspect_unique_function
from ida_preprocessor_scripts._vgui_paint_common import walk


OWNER = "CGameConsoleDialog_Print"
INSERT = "GameUI_RichText_InsertStringA"
COLOR = "GameUI_RichText_InsertColorChange"
REAL_NAMES = {
    INSERT: "vgui2::RichText::InsertString(char const*)",
    COLOR: "vgui2::RichText::InsertColorChange(Color)",
}

# The '#' that opens a RichText markup tag (colors, links) inside the text.
MARKUP_IMMEDIATE = 0x23

LOCATE = r"""
print_va = int(values['print_va'])
function = ida_funcs.get_func(print_va)
if function is None or int(function.start_ea) != print_va:
    raise ValueError('CGameConsoleDialog_Print is not a function start')

def has_markup_compare(ea):
    for item in idautils.FuncItems(ea):
        insn = idautils.DecodeInstruction(item)
        if insn is None or insn.get_canon_mnem() != 'cmp':
            continue
        for operand in insn.ops:
            if operand.type == ida_ua.o_imm and (int(operand.value) & 0xFFFFFFFF) == values['markup']:
                return True
    return False

sites = {}
for item in idautils.FuncItems(print_va):
    if idc.print_insn_mnem(item) != 'call':
        continue
    target = local_call_target(item)
    callee = ida_funcs.get_func(target) if target is not None else None
    if callee is None or int(callee.start_ea) != target or not is_code_address(target):
        continue
    sites.setdefault(target, []).append(int(item))

if len(sites) != 2:
    raise ValueError('expected exactly two distinct callees, got ' + repr(sorted(hex(k) for k in sites)))

marked = [target for target in sites if has_markup_compare(target)]
if len(marked) != 1:
    raise ValueError('expected exactly one markup-scanning callee, got ' + repr(sorted(hex(k) for k in marked)))

insert = marked[0]
color = next(target for target in sites if target != insert)
insert_site = min(sites[insert])
color_site = min(sites[color])
if color_site >= insert_site:
    raise ValueError('InsertColorChange does not precede InsertString: ' + repr((hex(color_site), hex(insert_site))))

flow = flow_at(print_va, values['platform'])
receivers = {call['ea']:call['args'][0] for call in flow['calls'] if call['args']}
insert_this, color_this = receivers.get(insert_site), receivers.get(color_site)
# CoF loads the same m_pHistory member through different scratch registers.
# Require the member's provenance, not equality of physical register numbers.
if (not isinstance(insert_this, tuple) or len(insert_this) != 3
        or insert_this[:2] != ('load', ('arg', 0)) or insert_this[2] <= 0
        or insert_this != color_this):
    raise ValueError('callees do not share the history object: ' + repr((insert_this, color_this)))

result = {'insert': insert, 'color': color, 'insert_site': insert_site, 'color_site': color_site,
          'history_object': insert_this}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map, platform
    owner = _load_yaml_mapping(Path(new_binary_dir) / f"{OWNER}.{platform}.yaml")
    outputs = {
        INSERT: _output_for_symbol(expected_outputs, INSERT),
        COLOR: _output_for_symbol(expected_outputs, COLOR),
    }
    # Some consumers need only the ANSI predecessor. Keep the same two-callee
    # identity checks without publishing an unrelated color method for them.
    if owner is None or outputs[INSERT] is None:
        return False
    try:
        print_va = int(str(owner["func_va"]), 0)
    except (KeyError, TypeError, ValueError):
        return False
    found = await walk(
        session,
        LOCATE,
        {"print_va": print_va, "markup": MARKUP_IMMEDIATE, "platform": platform},
    )
    if found.get("error") or not isinstance(found.get("insert"), int) or not isinstance(found.get("color"), int):
        if debug:
            print(f"  condump print callees failed: {found}")
        return False
    written = True
    for symbol, va in ((INSERT, found["insert"]), (COLOR, found["color"])):
        if outputs[symbol] is None:
            continue
        inspected = await inspect_unique_function(session, REAL_NAMES[symbol], va, image_base, debug)
        if inspected is None:
            written = False
            continue
        write_func_yaml(outputs[symbol], inspected)
    return written
