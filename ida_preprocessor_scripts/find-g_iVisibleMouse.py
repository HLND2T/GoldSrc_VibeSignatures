#!/usr/bin/env python3
"""Recover Sven's cursor-visibility global from two exported mouse callbacks.

IN_MouseEvent and IN_Accumulate both guard mouse processing with the global.
Their writable-data intersection also includes mouse-use/camera flags, so each
candidate is followed through its write xrefs. The viewport-owned candidate
has a single writer that stores both false and true while calling
vgui::App::getInstance. The 8948 ELF names that writer
TeamFortressViewport::UpdateCursorState and the object g_iVisibleMouse.

Windows uses absolute operands, 8948 ELF a GOT slot with a GLOB_DAT relocation,
and 10257 ELF GOTOFF. No code signature, field offset, address, or xref order
participates in discovery. The emitted runtime signature is generated only
after the current binary's xrefs and writer dataflow select one object.
"""

from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact, write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import run_walk

TARGET_GV_NAMES = ["g_iVisibleMouse"]
MOUSE_EVENT = "IN_MouseEvent"
ACCUMULATE = "IN_Accumulate"

WALK = r"""
import ida_name

readers = {int(values['mouse_event']), int(values['accumulate'])}
if len(readers) != 2:
    result = {'error': 'mouse callback artifacts overlap'}
else:
    # Validate that the predecessor artifacts still identify the exact exports.
    for name, address in (("IN_MouseEvent", values['mouse_event']),
                          ("IN_Accumulate", values['accumulate'])):
        exports = {int(ea) for _, _, ea, export in idautils.Entries() if export == name}
        if exports != {int(address)}:
            raise ValueError('export identity changed for ' + name)

    event_entries = scan(int(values['mouse_event']))
    accumulate_entries = scan(int(values['accumulate']))
    if event_entries is None or accumulate_entries is None:
        raise ValueError('a mouse callback has no decoded function body')

    def read_globals(entries):
        return {gv for entry in entries for gv in entry['targets'] - entry['written']
                if entry['mnem'] in ('mov', 'lea', 'cmp', 'test') and is_writable_data(gv)}

    candidates = read_globals(event_entries) & read_globals(accumulate_entries)

    def code_owners(gv):
        owners = set()
        for ref in idautils.XrefsTo(gv, 0):
            sites = [int(ref.frm)]
            if is_got(ref.frm):
                if int(ida_bytes.get_dword(ref.frm)) != gv:
                    continue
                sites = [int(site.frm) for site in idautils.XrefsTo(ref.frm, 0)]
            for site in sites:
                function = ida_funcs.get_func(site)
                if function is not None and is_code_address(site):
                    owners.add(int(function.start_ea))
        return owners

    def calls_vgui_app(entries):
        names = {'?getInstance@App@vgui@@SAPAV12@XZ',
                 '_ZN4vgui3App11getInstanceEv'}
        for entry in entries:
            if entry['mnem'] != 'call':
                continue
            operand = entry['insn'].ops[0]
            if int(operand.type) not in (int(idaapi.o_near), int(idaapi.o_far)):
                continue
            if ida_name.get_name(int(operand.addr)).removeprefix('.') in names:
                return True
        return False

    verified = []
    for gv in sorted(candidates):
        for owner in sorted(code_owners(gv) - readers):
            entries = scan(owner)
            if entries is None or not calls_vgui_app(entries):
                continue
            constants = set()
            for entry in entries:
                if gv not in entry['written'] or entry['mnem'] != 'mov':
                    continue
                source = entry['insn'].ops[1]
                if int(source.type) == int(idaapi.o_imm):
                    constants.add(int(source.value) & 0xffffffff)
            if {0, 1} <= constants:
                verified.append((gv, owner))

    if len(verified) != 1:
        result = {'error': 'viewport writer is absent or ambiguous',
                  'candidates': [hex(gv) for gv in sorted(candidates)],
                  'writers': [(hex(gv), hex(owner)) for gv, owner in verified]}
    else:
        gv, owner = verified[0]
        reads = [entry for entry in event_entries if gv in entry['targets'] - entry['written']
                 and entry['disp']]
        if len(reads) != 1:
            result = {'error': 'IN_MouseEvent global operand is ambiguous',
                      'reads': [hex(entry['ea']) for entry in reads]}
        else:
            result = {'global': access(reads[0], gv), 'writer': hex(owner),
                      'candidates': [hex(item) for item in sorted(candidates)]}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map
    if platform not in {"windows", "linux"}:
        return False
    event = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, MOUSE_EVENT)
    accumulate = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, ACCUMULATE)
    if event is None or accumulate is None:
        return False
    located = await run_walk(
        session,
        WALK,
        {"mouse_event": event["owner_ea"], "accumulate": accumulate["owner_ea"]},
    )
    if located.get("error") or not located.get("global"):
        if debug:
            print(f"{skill_name}: {located}")
        return False
    if debug:
        print(f"{skill_name}: {located}")
    return await write_located_globals(
        session, expected_outputs, platform, image_base, event, {TARGET_GV_NAMES[0]: located["global"]}
    )
