#!/usr/bin/env python3
"""Locate the shared track-number MP3 initializer and its native volume setter.

Issue #403 anchors were confirmed by the requester, including a separate legacy
integer setter. InitStream owns its success diagnostic (GoldSrc/BLOB/COF/Sven)
or the track-range assertion (HL25 Windows). HL25 Linux has neither: the unique
AIL_open_stream owner must also save playback rate in stream userdata and set
the cached volume, without starting playback. Filename initialization delegates
to this entry; Play/Prime/Start are not substitutes.

The setter has no literal and GCC inlines all its callers. Walk the imported
Miles volume API's owners, including IAT/PLT thunks, and require a standalone
body with only the volume API pair (or the legacy stream-volume API). Verify
clamping, a read/write member cache, native return/argument shape, and the same
stream global used by InitStream. Other owners (Init/Frame/CDUpdate) have extra
calls. No fixed RVA, member displacement, call ordinal, or discovery signature.

Windows this=ECX: InitStream returns bool in AL, ret 8; the setter ret 4.
Linux this/arguments use cdecl stack slots. Float volume is [0,1], returns ST0;
legacy Windows volume is int [0,127], returns EAX (-1 when unchanged).
The _int identity is intentionally separate; no float artifact is emitted for
that backend. Linux canonical identities are MP3_InitStreamEib/MP3_SetVolumeEf
in CCDAudio's Itanium names. Emitted signatures are output validation only.
"""

from pathlib import Path

from ida_analyze_util import _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._engine_private_globals_common import inspect_func, run_walk

INIT = "CCDAudio__MP3_InitStream"
FLOAT_VOLUME = "CCDAudio__MP3_SetVolume"
INT_VOLUME = "CCDAudio__MP3_SetVolume_int"
TARGET_FUNCTION_NAMES = [INIT, FLOAT_VOLUME, INT_VOLUME]

WALK = r"""
import re
import struct
import ida_ida

APIS = {
    'AIL_open_stream', 'AIL_stream_sample_handle', 'AIL_sample_playback_rate',
    'AIL_stream_playback_rate', 'AIL_set_stream_user_data',
    'AIL_set_sample_volume_pan', 'AIL_set_stream_volume',
    'AIL_start_stream', 'AIL_set_stream_loop_count',
}
MAX_POINTER_FLOW_STATES = 256


def api_name(name):
    match = re.search(r'(AIL_[A-Za-z_]+)(?:@[0-9]+)?$', name or '')
    return match.group(1) if match and match.group(1) in APIS else None


# Import identities survive stripped ELF; include their named IAT/PLT aliases.
api_addresses = {}
for ea, name in idautils.Names():
    api = api_name(name)
    if api:
        api_addresses[int(ea)] = api


def api_owners(api):
    frontier = {ea for ea, name in api_addresses.items() if name == api}
    seen, owners = set(), set()
    while frontier - seen:
        following = set()
        for target in frontier - seen:
            seen.add(target)
            for ref in idautils.XrefsTo(target, 0):
                function = ida_funcs.get_func(int(ref.frm))
                if function is None:
                    continue
                start = int(function.start_ea)
                if int(function.flags) & int(ida_funcs.FUNC_THUNK) or is_plt(start):
                    following.add(start)
                elif (idc.print_insn_mnem(int(ref.frm)) or '').lower() == 'call':
                    owners.add(start)
        frontier = following
    return owners


def pic_setup(entry, target):
    # Stripped IDBs may not name GCC's get_pc_thunk. Verify its return-address
    # load and the caller's matching GOT-base addition instead of trusting a name.
    if values['platform'] != 'linux' or not is_code_address(target):
        return False
    load, ret, addition = ida_ua.insn_t(), ida_ua.insn_t(), ida_ua.insn_t()
    if not ida_ua.decode_insn(load, target) or load.get_canon_mnem().lower() != 'mov':
        return False
    dst, src = load.ops[0], load.ops[1]
    if (int(dst.type) != int(idaapi.o_reg) or int(dst.dtype) != int(ida_ua.dt_dword)
            or int(src.type) not in (int(idaapi.o_phrase), int(idaapi.o_displ))
            or reg4(src) != 'esp' or int(src.addr) != 0):
        return False
    if (not ida_ua.decode_insn(ret, target + int(load.size))
            or ret.get_canon_mnem().lower() not in ('ret', 'retn')
            or int(ret.ops[0].type) != int(idaapi.o_void)):
        return False
    following = entry['ea'] + int(entry['insn'].size)
    return bool(ida_ua.decode_insn(addition, following)
                and addition.get_canon_mnem().lower() == 'add'
                and int(addition.ops[0].type) == int(idaapi.o_reg)
                and reg4(addition.ops[0]) == reg4(dst)
                and int(addition.ops[1].type) == int(idaapi.o_imm))


def calls(entries):
    registers = {}
    found = []
    for entry in entries:
        insn, mnemonic, ea = entry['insn'], entry['mnem'], entry['ea']
        if mnemonic == 'call':
            op = insn.ops[0]
            target = int(idc.get_operand_value(ea, 0))
            api = api_addresses.get(target)
            if int(op.type) == int(idaapi.o_reg):
                api = registers.get(reg4(op))
            # GCC's PIC base thunk is the only permitted non-Miles setter call.
            pic = int(op.type) != int(idaapi.o_reg) and pic_setup(entry, target)
            found.append((ea, api, pic))
            for reg in ('eax', 'ecx', 'edx'):
                registers.pop(reg, None)
        elif int(insn.ops[0].type) == int(idaapi.o_reg) and changed_operand(insn, 0):
            reg = reg4(insn.ops[0])
            source = insn.ops[1]
            value = None
            if mnemonic == 'mov':
                if int(source.type) == int(idaapi.o_reg):
                    value = registers.get(reg4(source))
                else:
                    value = api_addresses.get(int(idc.get_operand_value(ea, 1)))
            registers.pop(reg, None)
            if value:
                registers[reg] = value
    return found


def native_return(entries, argument_bytes):
    returns = [e for e in entries if e['mnem'] in ('ret', 'retn')]
    if not returns:
        return False
    expected = argument_bytes if values['platform'] == 'windows' else 0
    return all(int(e['insn'].ops[0].value) == expected
               if int(e['insn'].ops[0].type) == int(idaapi.o_imm)
               else expected == 0 for e in returns)


def cache_members(entries):
    # Follow native this through registers and stack spills. COF's unoptimized
    # body reloads the same object into different registers for reads/writes.
    # Traverse the CFG: an early-return epilogue must not clobber the state of
    # the alternate branch that updates the volume.
    owner = ida_funcs.get_func(entries[0]['ea'])
    blocks = {int(b.start_ea): b for b in idaapi.FlowChart(owner)}
    pending = [(int(owner.start_ea), frozenset({'ecx'} if values['platform'] == 'windows' else ()), frozenset(), 0, None)]
    seen = set()
    reads, writes = set(), set()
    while pending:
        state = pending.pop()
        if state in seen:
            continue
        seen.add(state)
        if len(seen) > MAX_POINTER_FLOW_STATES:
            return set()
        start, aliases, spills, stack_depth, frame_depth = state
        aliases, spills = set(aliases), set(spills)
        block = blocks[start]
        for entry in entries:
            if not int(block.start_ea) <= entry['ea'] < int(block.end_ea):
                continue
            insn, mnemonic = entry['insn'], entry['mnem']
            dst, src = insn.ops[0], insn.ops[1]

            def stack_slot(op):
                if int(op.type) != int(idaapi.o_displ):
                    return None
                depth = stack_depth if reg4(op) == 'esp' else frame_depth if reg4(op) == 'ebp' else None
                return signed32(op.addr) - depth if depth is not None else None

            for index, op in enumerate(insn.ops):
                if int(op.type) == int(idaapi.o_void):
                    break
                if int(op.type) != int(idaapi.o_displ) or int(op.dtype) not in (int(ida_ua.dt_dword), int(ida_ua.dt_float)):
                    continue
                if reg4(op) not in aliases:
                    continue
                key = ('this', signed32(op.addr))
                (writes if changed_operand(insn, index) else reads).add(key)
            origin = False
            if mnemonic == 'mov':
                if int(src.type) == int(idaapi.o_reg):
                    origin = reg4(src) in aliases
                elif int(src.type) == int(idaapi.o_displ):
                    slot = stack_slot(src)
                    origin = slot in spills or (values['platform'] == 'linux' and slot == 4)
                slot = stack_slot(dst)
                if slot is not None:
                    spills.discard(slot)
                    if origin:
                        spills.add(slot)
            if mnemonic == 'mov' and reg4(dst) == 'ebp' and reg4(src) == 'esp':
                frame_depth = stack_depth
            if mnemonic == 'push':
                stack_depth += 4
            elif mnemonic == 'pop':
                stack_depth -= 4
            elif mnemonic in ('sub', 'add') and reg4(dst) == 'esp' and int(src.type) == int(idaapi.o_imm):
                stack_depth += int(src.value) * (1 if mnemonic == 'sub' else -1)
            elif mnemonic == 'mov' and reg4(dst) == 'esp' and reg4(src) == 'ebp' and frame_depth is not None:
                stack_depth = frame_depth
            if int(dst.type) == int(idaapi.o_reg) and changed_operand(insn, 0):
                register = reg4(dst)
                aliases.discard(register)
                if origin:
                    aliases.add(register)
            if mnemonic == 'call':
                aliases.difference_update(('eax', 'ecx', 'edx'))
                name = idc.get_name(idc.get_operand_value(entry['ea'], 0)) or ''
                cleanup = re.search(r'@([0-9]+)$', name)
                if values['platform'] == 'windows' and cleanup:
                    stack_depth -= int(cleanup.group(1))
        for successor in block.succs():
            pending.append((int(successor.start_ea), frozenset(aliases), frozenset(spills), stack_depth, frame_depth))
    return reads & writes


def writable_globals(entries):
    # Arithmetic in a PIC prologue can have a spurious writable-data xref
    # (e.g. _DYNAMIC). Only actual loads/stores are evidence of stream storage.
    accesses = [e['targets'] for e in entries if e['mnem'] in ('mov', 'movss', 'movsd', 'fld', 'fst', 'fstp')]
    return set().union(*accesses) if accesses else set()


def float_constants(entries):
    constants = set()
    for entry in entries:
        scalar_sse = entry['mnem'] in ('movss', 'minss', 'comiss', 'ucomiss')
        if not (entry['mnem'].startswith('f') or scalar_sse):
            continue
        widths = {int(op.dtype) for op in entry['insn'].ops
                  if int(op.type) in (int(idaapi.o_mem), int(idaapi.o_displ))}
        for ref in idautils.DataRefsFrom(entry['ea']):
            if not is_readable_data(ref):
                continue
            for dtype, width, fmt in ((ida_ua.dt_float, 4, '<f'), (ida_ua.dt_double, 8, '<d')):
                # Scalar SSE determines f32 width even when IDA labels the
                # memory operand dt_dword rather than dt_float.
                if (scalar_sse and width == 4) or (not scalar_sse and int(dtype) in widths):
                    raw = ida_bytes.get_bytes(ref, width)
                    if raw and len(raw) == width:
                        constants.add(struct.unpack(fmt, raw)[0])
    return constants


def setter(start, floating):
    entries = scan(start)
    if not entries or not native_return(entries, 4):
        return None
    transfers = calls(entries)
    wanted = {'AIL_stream_sample_handle', 'AIL_set_sample_volume_pan'} if floating else {'AIL_set_stream_volume'}
    actual = {api for _, api, _ in transfers if api}
    if actual != wanted or any(api is None and not pic for _, api, pic in transfers):
        return None
    cache = cache_members(entries)
    if len(cache) != 1:
        return None
    mnemonics = {e['mnem'] for e in entries}
    if floating:
        constants = float_constants(entries)
        zero, one = 'fldz' in mnemonics or 0.0 in constants, 'fld1' in mnemonics or 1.0 in constants
        x87 = zero and one and any(m.startswith('fcom') or m.startswith('fucom') for m in mnemonics)
        sse = 'minss' in mnemonics and bool({'comiss', 'ucomiss'} & mnemonics) and 'xorps' in mnemonics and one
        if not (x87 or sse) or 'fld' not in mnemonics:
            return None
    else:
        # Legacy clamp has an integer upper bound, and the unchanged sentinel.
        upper = any(e['mnem'] == 'cmp' and int(e['insn'].ops[1].type) == int(idaapi.o_imm)
                    and int(e['insn'].ops[1].value) == 127 for e in entries)
        sentinel = any(e['mnem'] in ('or', 'mov') and reg4(e['insn'].ops[0]) == 'eax'
                       and int(e['insn'].ops[1].type) == int(idaapi.o_imm)
                       and int(e['insn'].ops[1].value) & 0xffffffff == 0xffffffff for e in entries)
        if not upper or not sentinel or 'fld' in mnemonics:
            return None
    return {'entry': hex(start), 'cache': [list(k) for k in sorted(cache)],
            'globals': sorted(writable_globals(entries))}


def string_owners():
    literals = {
        'MP3_InitStream(%d, %s) successful\n',
        '1 < trackNum && trackNum < g_iMP3NumTracks',
    }
    strings = idautils.Strings(default_setup=False)
    strings.setup(strtypes=[ida_nalt.STRTYPE_C, ida_nalt.STRTYPE_C_16], minlen=8)
    matches = [(int(s.ea), str(s)) for s in strings if str(s) in literals]
    owners = set()
    for ea, _ in matches:
        current = {int(ida_funcs.get_func(x.frm).start_ea) for x in idautils.XrefsTo(ea, 0)
                   if ida_funcs.get_func(x.frm) is not None}
        if len(current) != 1:
            return None, matches
        owners.update(current)
    if any(sum(text == literal for _, text in matches) > 1 for literal in literals):
        return None, matches
    return owners, matches


def initializer(start, floating, volume):
    entries = scan(start)
    if not entries or not native_return(entries, 8):
        return None
    apis = {api for _, api, _ in calls(entries) if api}
    required = {'AIL_open_stream', 'AIL_set_stream_user_data'}
    required |= {'AIL_sample_playback_rate', 'AIL_stream_sample_handle', 'AIL_set_sample_volume_pan'} if floating else {
        'AIL_stream_playback_rate', 'AIL_set_stream_volume'}
    if not required <= apis or 'AIL_start_stream' in apis:
        return None
    shared = writable_globals(entries) & set(volume['globals'])
    if len(shared) != 1:
        return None
    # AL=true is the native success return, not the integer Play/Prime wrapper.
    success = any(e['mnem'] == 'mov' and reg1(e['insn'].ops[0]) == 'al'
                  and int(e['insn'].ops[1].type) == int(idaapi.o_imm)
                  and int(e['insn'].ops[1].value) == 1 for e in entries)
    if not success:
        return None
    return {'entry': hex(start), 'stream': hex(next(iter(shared))), 'apis': sorted(apis)}


floating = bool(api_owners('AIL_set_sample_volume_pan'))
legacy = bool(api_owners('AIL_set_stream_volume'))
if not ida_ida.inf_is_32bit_exactly():
    result = {'error': 'only native x86-32 is supported'}
elif floating == legacy:
    result = {'error': 'exactly one verified Miles volume backend is required'}
else:
    api = 'AIL_set_sample_volume_pan' if floating else 'AIL_set_stream_volume'
    candidates = [row for start in sorted(api_owners(api)) if (row := setter(start, floating))]
    if len(candidates) != 1:
        result = {'error': 'standalone volume setter is absent or ambiguous', 'candidates': candidates}
    else:
        volume = candidates[0]
        owners, literals = string_owners()
        if owners is None:
            result = {'error': 'initializer literal is ambiguous', 'literals': literals}
        else:
            mode = 'own_literal' if owners else 'Miles_open_stream'
            owners = owners if owners else api_owners('AIL_open_stream')
            initializers = [row for start in sorted(owners) if (row := initializer(start, floating, volume))]
            if len(initializers) != 1:
                result = {'error': 'shared initializer is absent or ambiguous', 'candidates': initializers}
            else:
                result = {'pointer_size': 4, 'floating': floating, 'volume': volume,
                          'init': initializers[0], 'mode': mode, 'literals': literals}
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
    _ = old_yaml_map, new_binary_dir
    located = await run_walk(session, WALK, {"platform": platform})
    if debug:
        print(f"{skill_name}: {located}")
    if located.get("error") or located.get("pointer_size") != 4:
        return False
    volume = FLOAT_VOLUME if located["floating"] else INT_VOLUME
    requested = {Path(path).name for path in expected_outputs}
    if requested != {f"{INIT}.{platform}.yaml", f"{volume}.{platform}.yaml"}:
        return False
    records = []
    for name, key in ((INIT, "init"), (volume, "volume")):
        output = _output_for_symbol(expected_outputs, name)
        function = await inspect_func(session, int(located[key]["entry"], 0), image_base, name)
        if output is None or function is None:
            return False
        records.append((output, function))
    for output, function in records:
        write_func_yaml(output, function)
    return True
