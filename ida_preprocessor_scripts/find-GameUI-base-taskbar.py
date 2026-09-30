#!/usr/bin/env python3
"""Find GameUI's base panel and taskbar from their own exact literals.

``BasePanel`` belongs to CBasePanel's constructor and ``GameMenuButton`` to
CTaskbar's constructor (BasePanel.cpp:27, Taskbar.cpp:298). Require each
literal's unique owner to install the matching primary RTTI table through
ABI ``this``. Emit CTaskbar's table from that proven store.

OnCommand owns the Load/Save/Options command comparisons (Taskbar.cpp:662).
Intersect their exact string owners and reverse-map that unique entry in the
current taskbar table. The Windows/Linux destructor layout changes the slot;
no reference index is a locator. The quit-confirmation owner can be this same
body when its helper was inlined; reuse its current, independently checked
signature after discovery.

All 11 configured HL/Sven/CoF gameui versions have these entries (15 binaries).
CS/CZ configs declare no separate gameui module. Function signatures validate
outputs only. If the standard signature checks cannot distinguish CTaskbar's
constructor, retain its verified entry/size without func_sig, as requested:
HL25 Windows has a shared normalized prefix even at the standard 256-byte
limit. Do not extend that prefix further or use another build's address.
"""

from pathlib import Path

from ida_analyze_util import (
    _find_unique_bytes,
    _load_yaml_mapping,
    _output_for_symbol,
    write_func_yaml,
    write_vtable_yaml,
)
from ida_preprocessor_scripts._client_vgui_private_common import DECODER, inspect_unique_function
from ida_preprocessor_scripts._vgui_paint_common import walk

CONSTRUCTORS = {
    "CBasePanel_ctor": ("CBasePanel", "BasePanel", "CBasePanel::CBasePanel()"),
    "CTaskbar_ctor": ("CTaskbar", "GameMenuButton", "CTaskbar::CTaskbar(vgui2::Panel*, char const*)"),
}
COMMAND_LITERALS = ("OpenLoadGameDialog", "OpenSaveGameDialog", "OpenOptionsDialog")
COMMAND_SYMBOL = "CTaskbar_OnCommand"
COMMAND_NAME = "CTaskbar::OnCommand(char const*)"
TABLE_SYMBOL = "CTaskbar_vtable"
QUIT_OWNER = "CTaskbar_QuitConfirmationOwner"
FUNCTION_FIELDS = (
    "func_name",
    "func_va",
    "func_rva",
    "func_size",
    "func_sig",
    "func_sig_allow_across_function_boundary",
)

WALK = (
    DECODER
    + r"""
MAX_VTABLE_SLOTS = 256


def primary_table(point, class_name):
    segment = ida_segment.getseg(point)
    if segment is None or segment.perm & ida_segment.SEGPERM_EXEC:
        raise ValueError('vptr does not point to mapped data')
    info = int(ida_bytes.get_dword(point - 4))
    if not mapped(info):
        raise ValueError('vptr has no mapped RTTI')
    if values['platform'] == 'windows':
        if ida_bytes.get_dword(info) != 0 or ida_bytes.get_dword(info + 4) != 0:
            raise ValueError('not an x86 MSVC primary complete-object locator')
        descriptor = int(ida_bytes.get_dword(info + 12))
        name = idc.get_strlit_contents(descriptor + 8, -1, ida_nalt.STRTYPE_C)
        expected = ('.?AV' + class_name + '@@').encode('ascii')
        symbol = '??_7' + class_name + '@@6B@'
    else:
        if ida_bytes.get_dword(point - 8) != 0:
            raise ValueError('not an Itanium primary address point')
        name_ea = int(ida_bytes.get_dword(info + 4))
        name = idc.get_strlit_contents(name_ea, -1, ida_nalt.STRTYPE_C)
        expected = (str(len(class_name)) + class_name).encode('ascii')
        symbol = '_ZTV' + str(len(class_name)) + class_name + ' + 0x8'
    if name != expected:
        raise ValueError('vptr RTTI is not ' + class_name + ': ' + repr(name))
    entries = valid_vtable_slots(point, maximum=MAX_VTABLE_SLOTS)
    if not entries or len(entries) == MAX_VTABLE_SLOTS:
        raise ValueError('primary table is empty or exceeds the bounded slot scan')
    return {'point': point, 'symbol': symbol, 'entries': entries}


def constructor(literal, class_name):
    evidence = string_owner_evidence(literal)
    entry = require_single_owner(evidence, literal)
    matches = []
    for store in flow_at(entry, values['platform'])['stores']:
        if store['address'] != ('arg', 0) or store['width'] != 4:
            continue
        value = store['value']
        if value is None or value[0] != 'const':
            continue
        try:
            table = primary_table(int(value[1]) & 0xFFFFFFFF, class_name)
        except ValueError:
            continue
        matches.append({'store': store['ea'], **table})
    if len(matches) != 1:
        raise ValueError('constructor own primary this vptr store is not unique: ' + repr(matches))
    # Sven 8948 ELF calls the exported constructor through its local PLT/GOT.
    callers = {site for site in elf_code_refs_to(entry)
               if direct_call_target(site) == entry}
    if not callers:
        raise ValueError('constructor has no direct caller')
    function = ida_funcs.get_func(entry)
    return {'func_va': entry, 'func_size': int(function.end_ea) - entry,
            'literal': evidence, 'table': matches[0]}


result = {symbol: constructor(target[1], target[0])
          for symbol, target in values['constructors'].items()}
owners = None
for literal in values['commands']:
    evidence = string_owner_evidence(literal)
    if evidence['count'] != 1 or not evidence['owners']:
        raise ValueError('command exact string is not unique or has no owner: ' + repr(evidence))
    candidates = set(evidence['owners'])
    owners = candidates if owners is None else owners & candidates
if not owners or len(owners) != 1:
    raise ValueError('OnCommand string-owner intersection is not unique: ' + repr(owners))
command = next(iter(owners))
table = result['CTaskbar_ctor']['table']
indices = [index for index, target in enumerate(table['entries']) if target == command]
if len(indices) != 1:
    raise ValueError('OnCommand is not a unique current taskbar vtable entry: ' + repr(indices))
function = ida_funcs.get_func(command)
result['command'] = {'func_va': command, 'func_size': int(function.end_ea) - command,
                     'vfunc_index': indices[0]}
"""
)


def function_metadata(name, candidate, image_base):
    address = candidate["func_va"]
    return {
        "func_name": name,
        "func_va": hex(address),
        "func_rva": hex(address - int(image_base)),
        "func_size": hex(candidate["func_size"]),
    }


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    if platform not in ("windows", "linux"):
        return False
    outputs = {
        symbol: _output_for_symbol(expected_outputs, symbol) for symbol in (*CONSTRUCTORS, TABLE_SYMBOL, COMMAND_SYMBOL)
    }
    if not all(outputs.values()):
        return False
    located = await walk(
        session, WALK, {"platform": platform, "constructors": CONSTRUCTORS, "commands": COMMAND_LITERALS}
    )
    if located.get("error"):
        if debug:
            print(f"  GameUI base/taskbar locator failed: {located['error']}")
        return False
    functions = {}
    for symbol, (_, _, name) in CONSTRUCTORS.items():
        candidate = located[symbol]
        function = await inspect_unique_function(session, name, candidate["func_va"], image_base, debug)
        if function is None:
            if symbol != "CTaskbar_ctor":
                return False
            function = function_metadata(name, candidate, image_base)
            if debug:
                print(f"  {name}: emit verified entry/size without func_sig")
        functions[symbol] = {field: function[field] for field in FUNCTION_FIELDS if field in function}

    candidate = located["command"]
    # This dependency is produced from its own deterministic quit-title anchor.
    # Reuse its output only after the OnCommand strings and table entry agree.
    owner_path = Path(new_binary_dir) / f"{QUIT_OWNER}.{platform}.yaml"
    owner = _load_yaml_mapping(owner_path)
    if not owner:
        return False
    signature = owner.get("func_sig")
    if (
        int(owner["func_va"], 0) == candidate["func_va"]
        and int(owner["func_size"], 0) == candidate["func_size"]
        and signature
        and await _find_unique_bytes(session, signature) == candidate["func_va"]
    ):
        function = {**owner, "func_name": COMMAND_NAME}
    else:
        function = await inspect_unique_function(session, COMMAND_NAME, candidate["func_va"], image_base, debug)
    if function is None:
        return False
    command = {field: function[field] for field in ("func_name", "func_va", "func_rva", "func_size")}
    command.update(
        vtable_name="CTaskbar",
        vfunc_index=candidate["vfunc_index"],
        vfunc_offset=hex(candidate["vfunc_index"] * 4),
        vfunc_sig=function["func_sig"],
    )
    if function.get("func_sig_allow_across_function_boundary"):
        command["vfunc_sig_allow_across_function_boundary"] = True

    table = located["CTaskbar_ctor"]["table"]
    vtable = {
        "vtable_class": "CTaskbar",
        "vtable_symbol": table["symbol"],
        "vtable_va": hex(table["point"]),
        "vtable_rva": hex(table["point"] - int(image_base)),
        "vtable_size": hex(len(table["entries"]) * 4),
        "vtable_numvfunc": len(table["entries"]),
        "vtable_entries": {index: hex(target) for index, target in enumerate(table["entries"])},
    }
    for symbol, function in functions.items():
        write_func_yaml(outputs[symbol], function)
    write_vtable_yaml(outputs[TABLE_SYMBOL], vtable)
    write_func_yaml(outputs[COMMAND_SYMBOL], command)
    return True
