#!/usr/bin/env python3
"""Recover GameUI's TextEntry, PropertySheet, and MessageBox private symbols.

The three UI literals identify callers, not the requested constructors or
methods. Current-binary RTTI supplies each class table. Constructor calls are
then checked against their arguments and vptr stores; PropertyDialog's member
comes from the constructed-pointer store. The MessageBox size patch is the
SetSize call whose receiver is the box itself, after its label's SetSize call.

TextEntry and PropertySheet methods are selected by their source behavior and
receiver/argument dataflow, then mapped back into their current class tables.
Inheritance is only an additional check. No virtual slot, VA, RVA, object size,
or member displacement is copied from a reference build.
"""

from pathlib import Path

from ida_analyze_util import (
    _find_unique_bytes,
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    preprocess_vtable_via_mcp,
    write_func_yaml,
    write_patch_yaml,
    write_struct_offset_yaml,
    write_vtable_yaml,
)
from ida_preprocessor_scripts._vgui_paint_common import walk
from ida_preprocessor_scripts import _vgui_private_method_identity as method_identity


CLASSES = {
    "tab": ("TabCatchingTextEntry", "??_7TabCatchingTextEntry@@6B@", "_ZTV20TabCatchingTextEntry"),
    "text": ("vgui2::TextEntry", "??_7TextEntry@vgui2@@6B@", "_ZTVN5vgui29TextEntryE"),
    "sheet": ("vgui2::PropertySheet", "??_7PropertySheet@vgui2@@6B@", "_ZTVN5vgui213PropertySheetE"),
    "msg": ("vgui2::MessageBox", "??_7MessageBox@vgui2@@6B@", "_ZTVN5vgui210MessageBoxE"),
    "frame": ("vgui2::Frame", "??_7Frame@vgui2@@6B@", "_ZTVN5vgui25FrameE"),
    "panel": ("vgui2::Panel", "??_7Panel@vgui2@@6B@", "_ZTVN5vgui25PanelE"),
}

TABLE_OUTPUTS = {
    "tab": "GameUI_TabCatchingTextEntry_vtable",
    "sheet": "GameUI_PropertySheet_vtable",
    "msg": "GameUI_MessageBox_vtable",
}

FUNCTIONS = {
    "GameUI_TabCatchingTextEntry_OnKeyCodeTyped": ("TabCatchingTextEntry::OnKeyCodeTyped(vgui2::KeyCode)", "tab"),
    "GameUI_TextEntry_InsertChar": ("vgui2::TextEntry::InsertChar(wchar_t)", "tab"),
    "GameUI_TextEntry_LayoutVerticalScrollBarSlider": ("vgui2::TextEntry::LayoutVerticalScrollBarSlider()", "tab"),
    "GameUI_TextEntry_GetStartDrawIndex": ("vgui2::TextEntry::GetStartDrawIndex(int&)", "tab"),
    "GameUI_PropertySheet_HasHotkey": ("vgui2::PropertySheet::HasHotkey(wchar_t)", "sheet"),
    "GameUI_PropertySheet_PerformLayout": ("vgui2::PropertySheet::PerformLayout()", "sheet"),
    "GameUI_MessageBox_ApplySchemeSettings": ("vgui2::MessageBox::ApplySchemeSettings(vgui2::IScheme*)", "msg"),
    "GameUI_PropertySheet_ctor": ("vgui2::PropertySheet::PropertySheet(vgui2::Panel*, char const*)", None),
    "GameUI_MessageBox_ctor": ("vgui2::MessageBox::MessageBox(char const*, char const*, vgui2::Panel*)", None),
    "GameUI_Panel_SetSize": ("vgui2::Panel::SetSize(int, int)", None),
}

MEMBER = "GameUI_PropertyDialog__propertySheet"
PATCH = "GameUI_MessageBox_ApplySchemeSettings_to_Panel_SetSize_callsite_0"

LOCATE = (
    Path(method_identity.__file__).read_text(encoding="utf-8")
    + r"""
import ida_gdl

def literal_reference(text):
    needle = text.encode() + bytes([0])
    references = set()
    for segment_ea in idautils.Segments():
        segment = ida_segment.getseg(segment_ea)
        if segment is None or segment.perm & ida_segment.SEGPERM_EXEC:
            continue
        data = ida_bytes.get_bytes(segment.start_ea, segment.end_ea - segment.start_ea)
        if not data:
            continue
        position = 0
        while True:
            offset = data.find(needle, position)
            if offset < 0:
                break
            address = int(segment.start_ea + offset)
            for xref in idautils.XrefsTo(address, 0):
                owner = ida_funcs.get_func(int(xref.frm))
                if owner is not None:
                    references.add((address, int(xref.frm), int(owner.start_ea)))
            position = offset + 1
    if len(references) != 1:
        raise ValueError('%s has %d code references, expected one' % (text, len(references)))
    return next(iter(references))

def has_vptr_store(function_ea, table_ea, platform):
    flow = flow_at(function_ea, platform)
    stores = []
    for store in flow['stores']:
        if store['address'] == ('arg', 0) and store['value'] == ('const', table_ea):
            stores.append(store)
    return bool(stores)

def contains(value, needle):
    if value == needle:
        return True
    if isinstance(value, tuple):
        for child in value[1:]:
            if contains(child, needle):
                return True
    return False

def constructor_from_caller(owner, ref_site, literal_ea, table_ea, platform):
    flow = flow_at(owner, platform)
    matches = []
    for call in flow['calls']:
        if call['ea'] <= ref_site or call['direct'] is None:
            continue
        if not any(contains(arg, ('const', literal_ea)) for arg in call['args'][:3]):
            continue
        try:
            installs = has_vptr_store(call['direct'], table_ea, platform)
        except ValueError:
            continue
        if installs:
            matches.append(call)
    if len(matches) != 1:
        raise ValueError('constructor from literal is ambiguous: %r' % [(c['ea'], c['direct']) for c in matches])
    return flow, matches[0]

def indirect_slot_calls(function_ea, offset):
    found = []
    for ea in idautils.FuncItems(function_ea):
        insn = idautils.DecodeInstruction(ea)
        if not insn or insn.get_canon_mnem() not in ('call', 'jmp'):
            continue
        operand = insn.ops[0]
        if operand.type == idaapi.o_displ and int(operand.addr) == offset:
            found.append(int(ea))
    return found

def direct_calls(function_ea, include_jumps=False):
    found = []
    for ea in idautils.FuncItems(function_ea):
        mnemonic = (idc.print_insn_mnem(ea) or '').lower()
        if mnemonic != 'call' and not (include_jumps and mnemonic == 'jmp'):
            continue
        target = local_call_target(ea)
        if target is not None:
            found.append((int(ea), int(target)))
    return found

def has_hundred_between(first, second):
    for ea in idautils.Heads(first + 1, second):
        insn = idautils.DecodeInstruction(ea)
        if insn is None:
            continue
        for operand in insn.ops:
            if operand.type == idaapi.o_imm and int(operand.value) == 100:
                return True
            if operand.type == idaapi.o_displ and int(operand.addr) == 100:
                return True
    return False

def message_size_method(table, count, frame_table, frame_count, platform):
    matches = []
    for index in range(count):
        method = int(ida_bytes.get_dword(table + index * 4))
        if not is_code_address(method):
            continue
        calls = direct_calls(method)
        targets = {}
        for site, target in calls:
            targets.setdefault(target, []).append(site)
        if not any(len(sites) == 2 for sites in targets.values()):
            continue
        try:
            flow = flow_at(method, platform)
        except ValueError:
            continue
        by_target = {}
        for call in flow['calls']:
            if call['direct'] is not None:
                by_target.setdefault(call['direct'], []).append(call)
        for target, pair in by_target.items():
            if len(pair) != 2:
                continue
            first, second = sorted(pair, key=lambda call: call['ea'])
            if index >= frame_count:
                continue
            base_method = int(ida_bytes.get_dword(frame_table + index * 4))
            # ApplySchemeSettings invokes Frame's method before sizing the
            # label; PerformLayout invokes Frame's method after sizing.
            if not any(site < first['ea'] and callee == base_method for site, callee in calls):
                continue
            before = first['args'][0] if first['args'] else None
            after = second['args'][0] if second['args'] else None
            if not (before and before[0] == 'load' and before[1] == ('arg', 0)
                    and isinstance(before[2], int) and before[2] > 0
                    and after == ('arg', 0) and has_hundred_between(first['ea'], second['ea'])):
                continue
            matches.append((index, method, target, second['ea']))
    if len(matches) != 1:
        raise ValueError('MessageBox size method is ambiguous: %r' % matches)
    return matches[0]

def warning_addresses():
    # InsertChar may reference the warning sound twice, and other controls
    # use it too. PIC references may have no IDA xref, so follow the pointer
    # into a call argument below instead of depending on IDA's string index.
    needle = b'Resource\\warning.wav\0'
    addresses = set()
    for segment_ea in idautils.Segments():
        segment = ida_segment.getseg(segment_ea)
        if segment is None or segment.perm & ida_segment.SEGPERM_EXEC:
            continue
        data = ida_bytes.get_bytes(segment.start_ea, segment.end_ea - segment.start_ea) or b''
        offset = data.find(needle)
        while offset >= 0:
            addresses.add(int(segment.start_ea + offset))
            offset = data.find(needle, offset + 1)
    return addresses

def method_candidates(table_key, base_key, warnings):
    candidates = []
    for index in range(min(values[table_key + '_count'], values[base_key + '_count'])):
        address = int(ida_bytes.get_dword(values[table_key + '_table'] + index * 4))
        base = int(ida_bytes.get_dword(values[base_key + '_table'] + index * 4))
        inherited = table_key == 'tab'
        if not is_code_address(address) or (address == base) != inherited:
            continue
        immediates, divides = set(), False
        for ea in idautils.FuncItems(address):
            instruction = idautils.DecodeInstruction(ea)
            if instruction is None:
                continue
            mnemonic = instruction.get_canon_mnem()
            divides |= mnemonic in ('idiv', 'div')
            for operand in instruction.ops:
                if operand.type == idaapi.o_imm:
                    immediates.add(int(operand.value))
        if inherited:
            if not CHARACTER_FILTER_CODES <= immediates and not divides:
                continue
        # Examine every override: a virtual dispatch can load its slot into
        # a register before CALL, as Sven 10257 does in HasHotkey.
        flow = flow_at(address, values['platform'])
        warning = any(arg == ('const', literal)
                      for call in flow['calls'] for arg in call['args'] for literal in warnings)
        candidates.append(dict(index=index, address=address, base=base,
                               warning=warning, comparisons=flow['comparisons'],
                               immediates=immediates, divides=divides,
                               calls=flow['calls'], stores=flow['stores']))
    return candidates

console_literal, console_site, console_owner = literal_reference('ConsoleEntry')
sheet_literal, sheet_site, sheet_owner = literal_reference('Sheet')
message_literal, message_site, message_owner = literal_reference('MessageBoxText')
if console_owner != values['console_owner']:
    raise ValueError('ConsoleEntry is not owned by the verified CGameConsoleDialog constructor')

# Most compilers inline the derived TextEntry constructor into the console
# owner. CoF emits it out of line; the literal-bearing direct callee installs
# the same derived vptr. Neither form depends on an instruction window.
console_flow = flow_at(console_owner, values['platform'])
inline_stores = []
for store in console_flow['stores']:
    if store['ea'] > console_site and store['value'] == ('const', values['tab_table']):
        inline_stores.append(store)
if not inline_stores:
    constructor_from_caller(console_owner, console_site, console_literal, values['tab_table'], values['platform'])

sheet_flow, sheet_call = constructor_from_caller(
    sheet_owner, sheet_site, sheet_literal, values['sheet_table'], values['platform']
)
constructed = sheet_call['args'][0]
member_stores = []
for store in sheet_flow['stores']:
    address = store['address']
    if (store['ea'] > sheet_call['ea'] and address and address[0] == 'address'
            and address[1] == ('arg', 0) and isinstance(address[2], int)
            and 0 < address[2] < 0x1000 and address[2] % 4 == 0
            and (contains(store['value'], constructed) or contains(store['value'], ('result', sheet_call['ea'])))):
        member_stores.append(store)
if len(member_stores) != 1:
    raise ValueError('PropertyDialog::_propertySheet store is ambiguous: %r' % member_stores)

_, message_call = constructor_from_caller(
    message_owner, message_site, message_literal, values['msg_table'], values['platform']
)

# OnKeyCodeTyped calls the base implementation for non-Tab keys, and forwards
# Tab to the parent's virtual method at that same vtable position.
key_matches = []
for index in range(min(values['tab_count'], values['text_count'])):
    derived = int(ida_bytes.get_dword(values['tab_table'] + index * 4))
    base = int(ida_bytes.get_dword(values['text_table'] + index * 4))
    if derived == base or not is_code_address(derived) or not is_code_address(base):
        continue
    if base in [target for _, target in direct_calls(derived, include_jumps=True)] and indirect_slot_calls(derived, index * 4):
        key_matches.append((index, derived, base))
if len(key_matches) != 1:
    raise ValueError('TabCatchingTextEntry::OnKeyCodeTyped is ambiguous: %r' % key_matches)

size_index, apply_ea, setsize_ea, patch_ea = message_size_method(
    values['msg_table'], values['msg_count'], values['frame_table'], values['frame_count'], values['platform']
)
methods = recover_private_methods(
    method_candidates('tab', 'text', warning_addresses()),
    method_candidates('sheet', 'panel', set()),
    setsize_ea,
)

result = {
    'sheet_ctor': sheet_call['direct'],
    'message_ctor': message_call['direct'],
    'sheet_owner': sheet_owner,
    'member_ea': member_stores[0]['ea'],
    'member_offset': member_stores[0]['address'][2],
    'key_index': key_matches[0][0],
    'key_ea': key_matches[0][1],
    'base_key_ea': key_matches[0][2],
    'apply_index': size_index,
    'apply_ea': apply_ea,
    'setsize_ea': setsize_ea,
    'patch_ea': patch_ea,
    'methods': {name: {'ea': method['address'], 'index': method['index']} for name, method in methods.items()},
}
"""
)


PATCH_SIGNATURE = r"""
def executable_ranges():
    found = []
    for segment_ea in idautils.Segments():
        segment = ida_segment.getseg(segment_ea)
        if segment is not None and segment.perm & ida_segment.SEGPERM_EXEC:
            found.append((int(segment.start_ea), int(segment.end_ea)))
    return found

def unique(tokens, expected):
    data = bytes(0 if token == '??' else int(token, 16) for token in tokens)
    mask = bytes(0 if token == '??' else 255 for token in tokens)
    flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK
    found = set()
    for start, end in executable_ranges():
        ea = ida_bytes.find_bytes(data, start, range_end=end, mask=mask, flags=flags)
        while ea != idaapi.BADADDR and len(found) < 2:
            found.add(int(ea))
            ea = ida_bytes.find_bytes(data, int(ea) + 1, range_end=end, mask=mask, flags=flags)
    return found == {expected}

def instruction_tokens(ea, insn):
    raw = ida_bytes.get_bytes(ea, insn.size)
    if not raw:
        raise ValueError('unreadable patch signature instruction')
    wildcard = set()
    for operand in insn.ops:
        if operand.type == idaapi.o_void:
            continue
        if operand.type in (idaapi.o_imm, idaapi.o_near, idaapi.o_far, idaapi.o_mem, idaapi.o_displ):
            offset = int(getattr(operand, 'offb', 0))
            if 0 < offset < insn.size:
                size = ida_ua.get_dtype_size(operand.dtype)
                for index in range(offset, min(insn.size, offset + max(size, 1))):
                    wildcard.add(index)
    if raw[0] in (0xE8, 0xE9, 0xEB):
        wildcard.update(range(1, insn.size))
    elif raw[0] == 0x0F and insn.size > 1 and raw[1] & 0xF0 == 0x80:
        wildcard.update(range(2, insn.size))
    elif 0x70 <= raw[0] <= 0x7F:
        wildcard.update(range(1, insn.size))
    return ['??' if index in wildcard else '%02X' % byte for index, byte in enumerate(raw)]

patch = values['patch']
instruction = idautils.DecodeInstruction(patch)
original = ida_bytes.get_bytes(patch, instruction.size) if instruction else None
if not instruction or not original or len(original) != 5 or original[0] != 0xE8:
    raise ValueError('patch is not a direct rel32 CALL')
tokens = ['%02X' % byte for byte in original]
cursor = patch + instruction.size
for _ in range(64):
    if len(tokens) >= 96:
        break
    current = idautils.DecodeInstruction(cursor)
    if not current or current.size <= 0:
        break
    tokens.extend(instruction_tokens(cursor, current))
    cursor += current.size
    if len(tokens) >= 6 and unique(tokens, patch):
        result = {'patch_sig': ' '.join(tokens)}
        break
else:
    raise ValueError('patch signature did not become unique')
if 'result' not in globals():
    raise ValueError('patch signature did not become unique')
"""


async def _function_payload(session, ea, image_base, name, *, table=None, index=None):
    candidate = None
    across = False
    for limit in (None, 128, 256, 512, 1024, 2048, 4096):
        candidate = await _inspect_function_via_mcp(
            session, ea, image_base, name, signature_byte_limit=limit, allow_relative_call_discriminator=True
        )
        if candidate:
            break
    if not candidate:
        candidate = await _inspect_function_via_mcp(session, ea, image_base, name, allow_across_function_boundary=True)
        across = bool(candidate)
    if not candidate:
        return None
    payload = {field: candidate[field] for field in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    if across or len(payload["func_sig"].split()) > int(payload["func_size"], 0):
        payload["func_sig_allow_across_function_boundary"] = True
    if table is not None:
        payload.update(vtable_name=table, vfunc_index=index, vfunc_offset=hex(index * 4))
    return payload


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    predecessor = _load_yaml_mapping(Path(new_binary_dir) / f"CGameConsoleDialog_ctor.{platform}.yaml")
    if predecessor is None or predecessor.get("func_name") != "CGameConsoleDialog::CGameConsoleDialog()":
        return False
    try:
        tables = {}
        for key, (class_name, windows_alias, linux_alias) in CLASSES.items():
            alias = windows_alias if platform == "windows" else linux_alias
            table = await preprocess_vtable_via_mcp(session, class_name, image_base, platform, symbol_aliases=[alias])
            if table is None or table.get("vtable_symbol") != alias:
                raise ValueError(f"{class_name} RTTI table is absent or mismatched")
            tables[key] = table

        found = await walk(
            session,
            LOCATE,
            {
                "platform": platform,
                "console_owner": int(predecessor["func_va"], 0),
                **{f"{key}_table": int(table["vtable_va"], 0) for key, table in tables.items()},
                **{f"{key}_count": table["vtable_numvfunc"] for key, table in tables.items()},
            },
        )
        if found.get("error"):
            raise ValueError(found["error"])

        methods = found["methods"]
        addresses = {
            "GameUI_TabCatchingTextEntry_OnKeyCodeTyped": (found["key_ea"], found["key_index"]),
            "GameUI_TextEntry_InsertChar": (methods["insert"]["ea"], methods["insert"]["index"]),
            "GameUI_TextEntry_LayoutVerticalScrollBarSlider": (methods["layout"]["ea"], methods["layout"]["index"]),
            "GameUI_TextEntry_GetStartDrawIndex": (methods["draw"]["ea"], methods["draw"]["index"]),
            "GameUI_PropertySheet_HasHotkey": (methods["hotkey"]["ea"], methods["hotkey"]["index"]),
            "GameUI_PropertySheet_PerformLayout": (methods["perform"]["ea"], methods["perform"]["index"]),
            "GameUI_MessageBox_ApplySchemeSettings": (found["apply_ea"], found["apply_index"]),
            "GameUI_PropertySheet_ctor": (found["sheet_ctor"], None),
            "GameUI_MessageBox_ctor": (found["message_ctor"], None),
            "GameUI_Panel_SetSize": (found["setsize_ea"], None),
        }
        payloads = {}
        for symbol, (display_name, table_key) in FUNCTIONS.items():
            address, index = addresses[symbol]
            table_name = CLASSES[table_key][0] if table_key else None
            payload = await _function_payload(session, address, image_base, display_name, table=table_name, index=index)
            if payload is None:
                raise ValueError(f"no unique function signature for {symbol} at {hex(address)}")
            payloads[symbol] = payload

        owner = await _function_payload(
            session,
            found["sheet_owner"],
            image_base,
            "vgui2::PropertyDialog::PropertyDialog(vgui2::Panel*, char const*)",
        )
        if owner is None:
            raise ValueError("no unique PropertyDialog constructor signature")
        member = dict(
            struct_name="vgui2::PropertyDialog",
            member_name="_propertySheet",
            offset=hex(found["member_offset"]),
            size=hex(4),
            offset_sig=owner["func_sig"],
            offset_sig_disp=hex(found["member_ea"] - found["sheet_owner"]),
        )
        if owner.get("func_sig_allow_across_function_boundary"):
            member["offset_sig_allow_across_function_boundary"] = True

        patch = None
        patch_output = _output_for_symbol(expected_outputs, PATCH)
        if patch_output is not None:
            signature = await walk(session, PATCH_SIGNATURE, {"patch": found["patch_ea"]})
            if signature.get("error") or not signature.get("patch_sig"):
                raise ValueError(f"patch signature failed: {signature}")
            if await _find_unique_bytes(session, signature["patch_sig"]) != found["patch_ea"]:
                raise ValueError("patch signature does not resolve to the selected CALL")
            patch = dict(
                patch_name="vgui2::MessageBox::ApplySchemeSettings to vgui2::Panel::SetSize callsite",
                patch_va=hex(found["patch_ea"]),
                patch_rva=hex(found["patch_ea"] - image_base),
                patch_sig=signature["patch_sig"],
                patch_sig_disp=hex(0),
            )

        # Emit only after every anchor and generated signature has been checked.
        for key, symbol in TABLE_OUTPUTS.items():
            write_vtable_yaml(_output_for_symbol(expected_outputs, symbol), tables[key])
        for symbol, payload in payloads.items():
            write_func_yaml(_output_for_symbol(expected_outputs, symbol), payload)
        write_struct_offset_yaml(_output_for_symbol(expected_outputs, MEMBER), member)
        if patch is not None:
            write_patch_yaml(patch_output, patch)
        if debug:
            print("GameUI private symbols:", found)
        return True
    except (KeyError, TypeError, ValueError) as exc:
        if debug:
            print("GameUI private symbols failed:", exc)
        return False
