#!/usr/bin/env python3
"""Recover a module's KeyValues vtable from MenuButton's hover tooltip.

``vgui2::MenuButton::OnCursorEntered`` constructs a ``KeyValues("CursorEnteredMenuButton")``
action message. Track the literal as the constructor's name argument to distinguish
message construction from menu message-map registration. The constructor's proven
primary vptr store yields the KeyValues vtable. Slot 2 of that table is
``KeyValues::LoadFromFile`` on every verified build (MSVC and Itanium ABI alike),
matching MetaHookSv's ``vftable[2]`` consumption.

The slot is read from the emitted table entries rather than assumed from source order;
the walk fails closed when the anchor literal, constructor, RTTI, or vptr store is
ambiguous.

GameUI and ServerBrowser use the module-local ``KeyValues_*`` output identities;
CS-family clients retain their ``ClientVGUI_KeyValues_*`` lookup identities.
"""

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _output_for_symbol,
    write_func_yaml,
    write_vtable_yaml,
)
from ida_preprocessor_scripts._client_vgui_private_common import (
    DECODER,
    LOADFROMFILE_SLOT_INDEX,
)
from ida_preprocessor_scripts._vgui_paint_common import walk

OUTPUT_SYMBOL_PAIRS = (
    ("KeyValues_vftable", "KeyValues_LoadFromFile"),
    ("ClientVGUI_KeyValues_vftable", "ClientVGUI_KeyValues_LoadFromFile"),
)
VTABLE_CLASS = "KeyValues"
ANCHOR_LITERAL = "CursorEnteredMenuButton"

# Reuse the shared ABI-aware tracer so debug MSVC push/pop and stack spills,
# ordinary GCC arguments, and PIC vptr values preserve the same this provenance.
WALK = (
    DECODER
    + r"""
def ctor_vptr_store(ctor_ea):
    matches = []
    for store in flow_at(ctor_ea, values['platform'])['stores']:
        if store['address'] != ('arg', 0) or store['width'] != 4:
            continue
        value = store['value']
        if value is None or value[0] != 'const':
            continue
        table = int(value[1]) & 0xFFFFFFFF
        slots = valid_vtable_slots(table)
        if slots:
            matches.append({'insn': store['ea'], 'vtable': table, 'slots': slots})
    if len(matches) != 1:
        raise ValueError('constructor primary vptr store is not unique: ' + repr(matches))
    return matches[0]


def table_identity(table):
    # Early GameUI builds embed vgui2::KeyValues. Read the current RTTI rather
    # than assigning the modern global class identity to that different class.
    pointer = int(ida_bytes.get_dword(table - 4))
    if values['platform'] == 'windows':
        descriptor = int(ida_bytes.get_dword(pointer + 12))
        name = idc.get_strlit_contents(descriptor + 8, -1, ida_nalt.STRTYPE_C)
        identities = {
            b'.?AVKeyValues@@': ('KeyValues', '??_7KeyValues@@6B@'),
            b'.?AVKeyValues@vgui2@@': ('vgui2::KeyValues', '??_7KeyValues@vgui2@@6B@'),
        }
    else:
        name_ea = int(ida_bytes.get_dword(pointer + 4))
        name = idc.get_strlit_contents(name_ea, -1, ida_nalt.STRTYPE_C)
        identities = {
            b'9KeyValues': ('KeyValues', '_ZTV9KeyValues + 0x8'),
            b'N5vgui29KeyValuesE': ('vgui2::KeyValues', '_ZTVN5vgui29KeyValuesE + 0x8'),
        }
    if name not in identities:
        raise ValueError('constructor table has unsupported KeyValues RTTI: ' + repr(name))
    return identities[name]


evidence = string_owner_evidence(values['literal'])
if evidence['count'] != 1 or not evidence['owners']:
    raise ValueError('anchor literal is not unique or has no code owner: ' + repr(evidence))
literal_ea = int(evidence['ea'][0], 0)
name_argument = 0 if values['platform'] == 'windows' else 1
callees = set()
for owner in evidence['owners']:
    for call in flow_at(owner, values['platform'])['calls']:
        if call['direct'] is not None and call['stack_args'][name_argument] == ('const', literal_ea):
            callees.add(call['direct'])
matches = []
diagnostics = []
for ctor in sorted(callees):
    try:
        store = ctor_vptr_store(ctor)
        class_name, table_symbol = table_identity(store['vtable'])
    except ValueError as exc:
        diagnostics.append((hex(ctor), str(exc)))
        continue
    matches.append((ctor, store, class_name, table_symbol))
if len(matches) != 1:
    raise ValueError('KeyValues constructor from anchor is not unique: ' + repr(diagnostics))
ctor, store, class_name, table_symbol = matches[0]
result = {
    'ctor': hex(ctor),
    'vtable': hex(store['vtable']),
    'vtable_insn': hex(store['insn']),
    'class_name': class_name,
    'table_symbol': table_symbol,
    'entries': {index: hex(target) for index, target in enumerate(store['slots'])},
}
"""
)


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
    output_pairs = [
        tuple(_output_for_symbol(expected_outputs, symbol) for symbol in symbols) for symbols in OUTPUT_SYMBOL_PAIRS
    ]
    output_pairs = [outputs for outputs in output_pairs if any(outputs)]
    if len(output_pairs) != 1 or not all(output_pairs[0]):
        if debug:
            print(f"  {VTABLE_CLASS}: expected exactly one complete KeyValues output pair, got {output_pairs}")
        return False
    vtable_output, vfunc_output = output_pairs[0]
    located = await walk(session, WALK, {"literal": ANCHOR_LITERAL, "platform": platform})
    if located.get("error") or "vtable" not in located:
        if debug:
            print(f"  {VTABLE_CLASS}: locator failed: {located.get('error', located)}")
        return False
    result = located
    entries = {int(index): str(value) for index, value in result["entries"].items()}
    raw_slot = entries.get(LOADFROMFILE_SLOT_INDEX)
    if raw_slot is None:
        if debug:
            print(f"  {VTABLE_CLASS}: no slot {LOADFROMFILE_SLOT_INDEX} entry")
        return False
    vtable_va = int(result["vtable"], 0)
    class_name = result["class_name"]
    function_name = f"{class_name}::LoadFromFile(IFileSystem*, char const*, char const*)"
    vtable = {
        "vtable_class": class_name,
        "vtable_symbol": result["table_symbol"],
        "vtable_va": hex(vtable_va),
        "vtable_rva": hex(vtable_va - int(image_base)),
        "vtable_size": hex(len(entries) * 4),
        "vtable_numvfunc": len(entries),
        "vtable_entries": entries,
    }
    load_target = int(raw_slot, 0)
    function = await _inspect_function_via_mcp(session, load_target, image_base, function_name)
    allow_across = function is None or not function.get("func_sig")
    if allow_across:
        function = await _inspect_function_via_mcp(
            session, load_target, image_base, function_name, allow_across_function_boundary=True
        )
    if not function or not function.get("func_sig"):
        if debug:
            print(f"  {function_name}: no unique signature at {hex(load_target)}")
        return False
    vfunc = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size")}
    vfunc.update(
        vtable_name=class_name,
        vfunc_index=LOADFROMFILE_SLOT_INDEX,
        vfunc_offset=hex(LOADFROMFILE_SLOT_INDEX * 4),
        vfunc_sig=function["func_sig"],
    )
    if allow_across:
        vfunc["vfunc_sig_allow_across_function_boundary"] = True
    write_vtable_yaml(vtable_output, vtable)
    write_func_yaml(vfunc_output, vfunc)
    return True
