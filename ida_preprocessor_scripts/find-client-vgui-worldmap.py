#!/usr/bin/env python3
"""Recover the CZDS WorldMap objects from their constructors and vtables.

The resource names identify the two constructors. Their installed RTTI vptrs
distinguish the classes even in the 8684 IDB, where IDA merged adjacent code
into one function. The sole CWorldMap constructor caller is
``CZEROViewPort::Start``; its return-value store gives the viewport member.

Both derived vtables override the same Panel slot. The matching bodies get
screen dimensions through ISurface, then use ceil while painting map tiles.
Those semantics identify the slot without copying MetaHook's slot numbers.
The two 8684 bodies are byte-equivalent after normal relocation wildcards,
so a verified relative CALL displacement distinguishes their output signatures.

The vtable installs are resolved per compiler family: MSVC ``??_7`` symbols and
Itanium ``_ZTV`` symbols both name the vtable header, and the shared vtable
helper advances ``_ZTV`` by two pointer slots to the address point the
constructor actually stores. ``CZEROViewPort::Start`` is ``__thiscall`` on
Windows and cdecl on Linux, so the viewport member store is located from the
register that carried the constructor argument on each platform instead of
assuming the MSVC ``ecx``/``eax`` pairing.
"""

from ida_analyze_util import (
    _find_unique_bytes,
    _output_for_symbol,
    preprocess_vtable_via_mcp,
    write_func_yaml,
    write_struct_offset_yaml,
    write_vtable_yaml,
)
from ida_preprocessor_scripts._client_vgui_private_common import inspect_unique_function, run_walk

MEMBER_SYMBOL = "CClientVGUI_WorldMapPanel"
WORLD_TABLE_SYMBOL = "CWorldMap"
WORLD_PAINT_SYMBOL = "CWorldMap_PaintBackground"
MISSION_TABLE_SYMBOL = "CWorldMapMissionSelect"
MISSION_PAINT_SYMBOL = "CWorldMapMissionSelect_PaintBackground"
SCREEN_SYMBOL = "ISurface_GetScreenSize"
TARGETS = (
    MEMBER_SYMBOL,
    WORLD_TABLE_SYMBOL,
    WORLD_PAINT_SYMBOL,
    MISSION_TABLE_SYMBOL,
    MISSION_PAINT_SYMBOL,
    SCREEN_SYMBOL,
)
WORLD_RESOURCE = "resource/UI/WorldMap.res"
MISSION_RESOURCE = "resource/UI/WorldMapMissionSelect.res"
WORLD_CLASS = "CWorldMap"
MISSION_CLASS = "CWorldMapMissionSelect"
PANEL_CLASS = "vgui2::Panel"
VTABLE_ALIASES = {
    WORLD_CLASS: {
        "windows": ["??_7CWorldMap@@6B@"],
        "linux": ["_ZTV9CWorldMap"],
    },
    MISSION_CLASS: {
        "windows": ["??_7CWorldMapMissionSelect@@6B@"],
        "linux": ["_ZTV22CWorldMapMissionSelect"],
    },
    PANEL_CLASS: {
        "windows": ["??_7Panel@vgui2@@6B@"],
        "linux": ["_ZTVN5vgui25PanelE"],
    },
}

WALK = r"""
import ida_auto, ida_name

MAX_BODY_BYTES = 0x2000  # A failure bound, never a discovery window.
MAX_INSTRUCTIONS = 2048


def exact_code_ref(literal):
    # Scan raw non-executable bytes for every NUL-terminated occurrence instead
    # of relying on IDA's string list. GCC pools 'CWorldMap' / 'WorldMap' into
    # one literal and the constructors reference the suffix (IDA renders it
    # 'aCworldmap+1'), so no standalone string item exists for the short names,
    # and some warmed databases omit analyzed .rodata from the string list
    # entirely. The code reference itself stays unique.
    needle = literal.encode('ascii') + b'\0'
    sites = set()
    for seg_ea in idautils.Segments():
        segment = ida_segment.getseg(seg_ea)
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
    if len(sites) != 1:
        raise ValueError('literal code reference is not unique: ' + literal + ' ' + repr(sorted(sites)))
    return sites.pop()


def linear_body(entry):
    cursor = int(entry)
    items = []
    for _ in range(MAX_INSTRUCTIONS):
        if cursor - entry >= MAX_BODY_BYTES or not executable_address(cursor):
            break
        insn = idautils.DecodeInstruction(cursor)
        if insn is None or insn.size <= 0:
            break
        items.append(cursor)
        cursor += insn.size
        if insn.get_canon_mnem().startswith('ret'):
            break
    else:
        raise ValueError('linear method exceeds instruction bound at ' + hex(entry))
    if not items or not idautils.DecodeInstruction(items[-1]).get_canon_mnem().startswith('ret'):
        raise ValueError('method has no bounded return at ' + hex(entry))
    for ea in items:
        insn = idautils.DecodeInstruction(ea)
        mnemonic = insn.get_canon_mnem()
        if mnemonic.startswith('j') and insn.ops[0].type in (ida_ua.o_near, ida_ua.o_far):
            target = int(insn.ops[0].addr)
            if target < entry or target >= cursor:
                raise ValueError('method branch escapes body at ' + hex(ea)
                                 + ' entry=' + hex(entry) + ' end=' + hex(cursor)
                                 + ' target=' + hex(target))
    return items, cursor


def executable_address(ea):
    segment = ida_segment.getseg(int(ea))
    return bool(segment and segment.perm & ida_segment.SEGPERM_EXEC)


def callers(entry):
    found = []
    for ref in idautils.XrefsTo(int(entry), 0):
        site = int(ref.frm)
        if direct_call_target(site) == entry:
            found.append(site)
    return sorted(set(found))


def constructor_entry(vptr_site, resource_ref):
    # Walk to the preceding completed method, then require an actual direct
    # caller of the resulting entry. This works around the merged 8684 IDB.
    cursor = int(vptr_site)
    previous_return = None
    for _ in range(MAX_INSTRUCTIONS):
        previous = idc.prev_head(cursor, ida_segment.getseg(cursor).start_ea)
        if previous == idaapi.BADADDR or previous >= cursor or vptr_site - previous >= MAX_BODY_BYTES:
            break
        insn = idautils.DecodeInstruction(previous)
        if insn and insn.get_canon_mnem().startswith('ret'):
            previous_return = previous
            break
        cursor = previous
    if previous_return is None:
        raise ValueError('no preceding constructor boundary at ' + hex(vptr_site))
    cursor = previous_return + idautils.DecodeInstruction(previous_return).size
    candidates = []
    while cursor < vptr_site:
        if ida_bytes.is_code(ida_bytes.get_flags(cursor)) and callers(cursor):
            try:
                body, _ = linear_body(cursor)
            except ValueError:
                body = []
            if vptr_site in body and resource_ref in body:
                candidates.append(cursor)
        following = idc.next_head(cursor, vptr_site)
        if following <= cursor:
            break
        cursor = following
    if len(candidates) != 1:
        raise ValueError('constructor entry is not unique: ' + repr(candidates))
    return candidates[0]


def installed_vptr_site(table, resource_ref):
    candidates = []
    # IDA records the store against whichever address it named: the address
    # point itself, or the Itanium vtable header two pointer slots earlier when
    # the store renders as `_ZTV<Class>+8`. Accept both, then let the operand
    # value check below reject anything that does not store the address point.
    sources = [int(table)]
    if values.get('platform') == 'linux':
        sources.append(int(table) - 8)
    sites = set()
    for source in sources:
        for ref in idautils.XrefsTo(source, 0):
            sites.add(int(ref.frm))
    for site in sorted(sites):
        if site >= resource_ref:
            continue
        insn = idautils.DecodeInstruction(site)
        if insn is None or insn.get_canon_mnem() != 'mov':
            continue
        dest, source = insn.ops[0], insn.ops[1]
        if (dest.type not in (ida_ua.o_phrase, ida_ua.o_displ)
                or int(dest.addr) != 0 or source.type != ida_ua.o_imm
                or imm_value(source) != table):
            continue
        try:
            body, end = linear_body(site)
        except ValueError:
            # GCC emits destructor thunks that reinstall the same vtable and
            # tail-jump to the base destructor, so not every install site is a
            # constructible body. Only a body that owns the resource reference
            # can be the constructor.
            continue
        if resource_ref in body and resource_ref < end:
            candidates.append(site)
    if len(candidates) != 1:
        raise ValueError('resource constructor vptr is not unique: ' + repr(candidates))
    return candidates[0]


def inline_ceil_sites(items):
    # GCC inlines ceil in some builds as an x87 round-toward-+infinity: the
    # control word is OR'd with 0x800 before frndint rounds the scaled value.
    # The out-of-line form calls a symbol named ceil instead.
    sites = []
    for ea in items:
        insn = idautils.DecodeInstruction(ea)
        if insn is None or insn.get_canon_mnem() != 'frndint':
            continue
        cursor = ea
        for _ in range(6):
            cursor = idc.prev_head(cursor, items[0])
            prior = idautils.DecodeInstruction(cursor)
            if prior is None:
                break
            if (prior.get_canon_mnem() == 'or' and prior.ops[1].type == ida_ua.o_imm
                    and imm_value(prior.ops[1]) == 0x800):
                sites.append(ea)
                break
    return sites


def paint_features(entry):
    try:
        items, end = linear_body(entry)
    except ValueError:
        return None
    direct = [(ea, direct_call_target(ea)) for ea in items]
    direct = [(ea, target) for ea, target in direct if target is not None]
    ceil_calls = [ea for ea, target in direct if 'ceil' in ida_name.get_name(target).lower()]
    ceil_calls.extend(inline_ceil_sites(items))
    if len(ceil_calls) < 2:
        return None
    screen_calls = []
    for position, ea in enumerate(items):
        insn = idautils.DecodeInstruction(ea)
        if insn is None or insn.get_canon_mnem() != 'call':
            continue
        operand = insn.ops[0]
        if operand.type != ida_ua.o_displ or not 0 < int(operand.addr) < 0x10000:
            continue
        preceding = items[max(0, position - 10):position]
        pointer_args = sum(
            1 for prior in preceding
            if (idautils.DecodeInstruction(prior).get_canon_mnem() == 'lea'
                and idautils.DecodeInstruction(prior).ops[1].type == ida_ua.o_displ
                and int(idautils.DecodeInstruction(prior).ops[1].reg) in (4, 5))
        )
        if pointer_args < 2:
            continue
        prior_direct = [(site, target) for site, target in direct if site < ea]
        if prior_direct:
            screen_calls.append((ea, int(operand.addr), prior_direct[-1][1]))
    if len(screen_calls) != 1 or screen_calls[0][1] % 4:
        return None

    # Signature bytes are output validators only. Wildcard relocations and
    # ordinary relative branches/calls, retaining the direct-call operands
    # separately as an optional exact-binary discriminator.
    tokens = []
    relative_calls = []
    for ea in items:
        if len(tokens) >= 256:
            break
        insn = idautils.DecodeInstruction(ea)
        raw = list(ida_bytes.get_bytes(ea, insn.size) or b'')
        if len(raw) != insn.size:
            raise ValueError('unreadable paint instruction at ' + hex(ea))
        wildcard = insn.size
        if raw[0] in (0xE8, 0xE9) and insn.size >= 5:
            wildcard = 1
            if raw[0] == 0xE8:
                relative_calls.append((len(tokens) + 1, raw[1:5], direct_call_target(ea)))
        else:
            for operand in insn.ops:
                if operand.type == ida_ua.o_void:
                    break
                if operand.type in (ida_ua.o_near, ida_ua.o_far, ida_ua.o_mem, ida_ua.o_displ):
                    wildcard = min(wildcard, int(operand.offb or insn.size))
                elif operand.type == ida_ua.o_imm and ida_segment.getseg(int(operand.value)):
                    wildcard = min(wildcard, int(operand.offb or insn.size))
        tokens.extend('??' if index >= wildcard else '%02X' % byte
                      for index, byte in enumerate(raw))
    return {
        'entry': entry, 'end': end, 'screen_slot': screen_calls[0][1],
        'surface_getter': screen_calls[0][2], 'ceil_calls': len(ceil_calls),
        'tokens': tokens, 'relative_calls': relative_calls,
    }


world_ref = exact_code_ref(values['world_resource'])
mission_ref = exact_code_ref(values['mission_resource'])
mission_name = exact_code_ref('MissionSelect')
world_name = exact_code_ref('WorldMap')
world_vptr_site = installed_vptr_site(values['world_table'], world_ref)
mission_vptr_site = installed_vptr_site(values['mission_table'], mission_ref)
world_ctor = constructor_entry(world_vptr_site, world_ref)
mission_ctor = constructor_entry(mission_vptr_site, mission_ref)
world_body, world_end = linear_body(world_ctor)
mission_body, mission_end = linear_body(mission_ctor)
if (world_ref not in world_body or world_name not in world_body
        or mission_ref not in mission_body or mission_name not in mission_body):
    raise ValueError('constructor resource/name roles are inconsistent')
if sum(direct_call_target(ea) == mission_ctor for ea in world_body) != 1:
    raise ValueError('WorldMap constructor does not create one MissionSelect child')
world_callers = callers(world_ctor)
if len(world_callers) != 1:
    raise ValueError('WorldMap constructor caller is not unique: ' + repr(world_callers))
start_call = world_callers[0]
start_fn = ida_funcs.get_func(start_call)
if start_fn is None:
    raise ValueError('CZEROViewPort::Start has no IDA owner')
start = int(start_fn.start_ea)
start_items = function_body(start)
if start_call not in start_items:
    raise ValueError('constructor call lies outside Start')
call_position = start_items.index(start_call)
stores = []
if values.get('platform') == 'linux':
    # cdecl hands the constructed object to the constructor through the stack,
    # so no msvc `mov reg, ecx` chain exists. The caller keeps the object in
    # whichever register took the pre-call eax result (the allocation and the
    # constructor both return through eax) and stores that register into the
    # viewport member. Argument store order differs between GCC builds, so the
    # register is identified from its eax data flow, not from a stack slot.
    object_registers = set()
    for ea in start_items[:call_position]:
        insn = idautils.DecodeInstruction(ea)
        if (insn and insn.get_canon_mnem() == 'mov' and insn.ops[0].type == ida_ua.o_reg
                and insn.ops[1].type == ida_ua.o_reg and int(insn.ops[1].reg) == 0
                and int(insn.ops[0].reg) != 0):
            object_registers.add(int(insn.ops[0].reg))
    for ea in start_items[call_position + 1:]:
        insn = idautils.DecodeInstruction(ea)
        if insn is None:
            continue
        if insn.get_canon_mnem().startswith('ret'):
            break
        if direct_call_target(ea) is not None:
            break
        if insn.get_canon_mnem() != 'mov':
            continue
        dest, source = insn.ops[0], insn.ops[1]
        if (dest.type == ida_ua.o_displ and source.type == ida_ua.o_reg
                and int(source.reg) in object_registers
                and int(dest.reg) not in object_registers
                and 0 < int(dest.addr) < 0x10000):
            stores.append((ea, int(dest.addr)))
else:
    this_registers = set()
    for ea in start_items[:call_position]:
        insn = idautils.DecodeInstruction(ea)
        if (insn and insn.get_canon_mnem() == 'mov' and insn.ops[0].type == ida_ua.o_reg
                and insn.ops[1].type == ida_ua.o_reg and int(insn.ops[1].reg) == 1):
            this_registers.add(int(insn.ops[0].reg))
    for ea in start_items[call_position + 1:]:
        insn = idautils.DecodeInstruction(ea)
        if insn is None:
            continue
        if insn.get_canon_mnem().startswith('ret'):
            break
        if direct_call_target(ea) is not None:
            break
        if insn.get_canon_mnem() != 'mov':
            continue
        dest, source = insn.ops[0], insn.ops[1]
        if (dest.type == ida_ua.o_displ and int(dest.reg) in this_registers
                and source.type == ida_ua.o_reg and int(source.reg) == 0
                and 0 < int(dest.addr) < 0x10000):
            stores.append((ea, int(dest.addr)))
if len(stores) != 1:
    raise ValueError('WorldMap return-value member store is not unique: ' + repr(stores))

paint_candidates = []
for index in range(min(values['world_count'], values['mission_count'], values['panel_count'])):
    world = ida_bytes.get_dword(values['world_table'] + index * 4)
    mission = ida_bytes.get_dword(values['mission_table'] + index * 4)
    panel = ida_bytes.get_dword(values['panel_table'] + index * 4)
    if (not executable_address(world) or not executable_address(mission)
            or world in (mission, panel) or mission == panel):
        continue
    world_paint = paint_features(world)
    mission_paint = paint_features(mission)
    if (world_paint and mission_paint
            and world_paint['screen_slot'] == mission_paint['screen_slot']
            and world_paint['surface_getter'] == mission_paint['surface_getter']):
        paint_candidates.append((index, world_paint, mission_paint))
if len(paint_candidates) != 1:
    raise ValueError('WorldMap PaintBackground slot is not unique: '
                     + repr([item[0] for item in paint_candidates]))
paint_index, world_paint, mission_paint = paint_candidates[0]

# The 8684 IDB merges the virtual-only CWorldMap body into an earlier method.
# Restore just the validated vtable entry/end in this owned, no-save worker so
# the ordinary runtime artifact validator can inspect a real function start.
for paint in (world_paint, mission_paint):
    entry, end = paint['entry'], paint['end']
    owner = ida_funcs.get_func(entry)
    if owner is not None and int(owner.start_ea) != entry:
        if not (int(owner.start_ea) < entry and int(owner.end_ea) >= end):
            raise ValueError('paint entry overlaps an incompatible IDA function')
        if not ida_funcs.del_func(int(owner.start_ea)):
            raise ValueError('could not remove merged IDA function at ' + hex(owner.start_ea))
        if not ida_funcs.add_func(entry, end):
            raise ValueError('could not define validated paint function at ' + hex(entry))
        ida_auto.auto_wait()
    owner = ida_funcs.get_func(entry)
    if owner is None or int(owner.start_ea) != entry or int(owner.end_ea) != end:
        raise ValueError('paint function boundary was not restored at ' + hex(entry))
result = {
    'start': start,
    'start_call': start_call,
    'member_offset': stores[0][1],
    'world_ctor': world_ctor,
    'mission_ctor': mission_ctor,
    'world_resource_ref': world_ref,
    'mission_resource_ref': mission_ref,
    'paint_index': paint_index,
    'world_paint': world_paint,
    'mission_paint': mission_paint,
}
"""


async def _unique_paint_signature(session, paint):
    tokens = paint["tokens"]
    for length in (64, 96, 128, 192, 256):
        if length > len(tokens):
            continue
        signature = " ".join(tokens[:length])
        if await _find_unique_bytes(session, signature) == paint["entry"]:
            return signature
    for offset, raw, target in paint["relative_calls"]:
        if target is None:
            continue
        for length in (64, 96, 128, 192, 256):
            if length > len(tokens) or offset + 4 > length:
                continue
            discriminated = tokens[:length].copy()
            discriminated[offset : offset + 4] = [f"{byte:02X}" for byte in raw]
            signature = " ".join(discriminated)
            if await _find_unique_bytes(session, signature) == paint["entry"]:
                return signature
    return None


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map, new_binary_dir
    if platform not in VTABLE_ALIASES[WORLD_CLASS]:
        return False
    outputs = {name: _output_for_symbol(expected_outputs, name) for name in TARGETS}
    if not all(outputs.values()):
        return False
    tables = {}
    for cls in (WORLD_CLASS, MISSION_CLASS, PANEL_CLASS):
        tables[cls] = await preprocess_vtable_via_mcp(
            session, cls, image_base, platform, symbol_aliases=VTABLE_ALIASES[cls][platform]
        )
    if not all(tables.values()):
        return False
    found = await run_walk(
        session,
        WALK,
        {
            "world_resource": WORLD_RESOURCE,
            "mission_resource": MISSION_RESOURCE,
            "platform": platform,
            "world_table": int(tables[WORLD_CLASS]["vtable_va"], 0),
            "mission_table": int(tables[MISSION_CLASS]["vtable_va"], 0),
            "panel_table": int(tables[PANEL_CLASS]["vtable_va"], 0),
            "world_count": tables[WORLD_CLASS]["vtable_numvfunc"],
            "mission_count": tables[MISSION_CLASS]["vtable_numvfunc"],
            "panel_count": tables[PANEL_CLASS]["vtable_numvfunc"],
        },
    )
    if found.get("error") or not all(k in found for k in ("member_offset", "world_paint", "mission_paint")):
        if debug:
            print(f"  {WORLD_CLASS}: locator failed: {found.get('error', found)}")
        return False
    start = await inspect_unique_function(session, "CZEROViewPort::Start()", found["start"], image_base, debug)
    if start is None:
        return False
    signatures = {}
    for symbol, key in ((WORLD_PAINT_SYMBOL, "world_paint"), (MISSION_PAINT_SYMBOL, "mission_paint")):
        signatures[symbol] = await _unique_paint_signature(session, found[key])
        if signatures[symbol] is None:
            if debug:
                print(f"  {symbol}: no unique x86 signature")
            return False

    member = {
        "struct_name": "CZEROViewPort",
        "member_name": "m_pWorldMapPanel",
        "offset": hex(found["member_offset"]),
        "size": 4,
    }
    write_struct_offset_yaml(outputs[MEMBER_SYMBOL], member)
    for symbol, cls in ((WORLD_TABLE_SYMBOL, WORLD_CLASS), (MISSION_TABLE_SYMBOL, MISSION_CLASS)):
        write_vtable_yaml(
            outputs[symbol], {key: value for key, value in tables[cls].items() if not key.startswith("_")}
        )
    for symbol, cls, key in (
        (WORLD_PAINT_SYMBOL, WORLD_CLASS, "world_paint"),
        (MISSION_PAINT_SYMBOL, MISSION_CLASS, "mission_paint"),
    ):
        paint = found[key]
        payload = {
            "func_name": f"{cls}::PaintBackground()",
            "func_va": hex(paint["entry"]),
            "func_rva": hex(paint["entry"] - image_base),
            "func_size": hex(paint["end"] - paint["entry"]),
            "vtable_name": cls,
            "vfunc_index": found["paint_index"],
            "vfunc_offset": hex(found["paint_index"] * 4),
            "vfunc_sig": signatures[symbol],
        }
        write_func_yaml(outputs[symbol], payload)
    screen_slot = found["world_paint"]["screen_slot"]
    write_func_yaml(
        outputs[SCREEN_SYMBOL],
        {
            "func_name": "vgui2::ISurface::GetScreenSize",
            "vtable_name": "vgui2::ISurface",
            "vfunc_index": screen_slot // 4,
            "vfunc_offset": hex(screen_slot),
        },
    )
    return True
