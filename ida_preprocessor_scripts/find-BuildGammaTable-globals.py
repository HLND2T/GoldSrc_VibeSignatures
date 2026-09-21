#!/usr/bin/env python3
"""Recover the four gamma tables from BuildGammaTable / V_BuildGammaTable.

engine/view.c BuildGammaTable fills the tables in a fixed statement order:

    texgammatable[i] = inf;                 // 256 byte stores
    lightgammatable[i] = inf;               // 1024 dwords, 0.075/0.875 shift
    lineargammatable[i] = 1023 * pow(..., g);
    screengammatable[i] = 1023 * pow(..., 1/g);

Identity is that first-write order inside the already-located builder, not BSS
layout. Indexed stores whose only address register is the PIC GOT base are
scalar spills and are ignored. A GOT-relative byte store whose decoded
displacement is the GOTOFF (IDA may name it as a fake absolute) is folded by
adding the GOT base. Two byte bases one apart collapse to the true 256-byte
table start.

The owner artifact is V_BuildGammaTable on SvEngine and BuildGammaTable on
GoldSrc/HL25/CoF.
"""

from ida_analyze_util import _output_for_symbol
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact, write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import owner_context, run_walk

OWNER_CANDIDATES = ("V_BuildGammaTable", "BuildGammaTable")
TABLE_NAMES = (
    "texgammatable",
    "lightgammatable",
    "lineargammatable",
    "screengammatable",
)

WALK = r"""
OWNER = int(values['owner'], 0)
INDEX_REGS = ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp')
DWORD_TABLE_SPAN = 0x1000

entries = scan(OWNER)
if entries is None:
    result = {'error': 'gamma builder is not a function start'}
else:
    got_base, got_register = got_anchor(OWNER)

    def uses_array_index(entry):
        insn = entry['insn']
        for index, op in enumerate(insn.ops):
            if int(op.type) == int(idaapi.o_void):
                break
            if not changed_operand(insn, index):
                continue
            text = (idc.print_operand(entry['ea'], index) or '').lower()
            if '*' in text:
                return True
            regs = [name for name in INDEX_REGS if name in text]
            if got_register:
                regs = [name for name in regs if name != got_register]
            if regs:
                return True
            if '[' in text and (got_register is None or got_register not in text):
                return True
        return False

    def store_width(entry):
        insn = entry['insn']
        for index, op in enumerate(insn.ops):
            if int(op.type) == int(idaapi.o_void):
                break
            if changed_operand(insn, index):
                return int(ida_ua.get_dtype_size(op.dtype))
        return None

    def folded(gv, entry):
        if got_base is None or got_register is None:
            return int(gv)
        insn = entry['insn']
        disp = None
        uses_got = False
        for index, op in enumerate(insn.ops):
            if int(op.type) == int(idaapi.o_void):
                break
            if not changed_operand(insn, index):
                continue
            if int(op.type) not in (int(idaapi.o_mem), int(idaapi.o_displ), int(idaapi.o_phrase)):
                continue
            text = (idc.print_operand(entry['ea'], index) or '').lower()
            if got_register in text or reg4(op) == got_register:
                uses_got = True
            offb = int(getattr(op, 'offb', 0) or 0)
            if offb and int(insn.size) - offb >= 4:
                disp = signed32(op.addr)
        if uses_got and disp is not None:
            candidate = (int(got_base) + disp) & 0xFFFFFFFF
            if is_writable_data(candidate) and not is_got(candidate):
                return candidate
        return int(gv)

    def operand_data(entry, op_index):
        op = entry['insn'].ops[op_index]
        kind = int(op.type)
        if kind == int(idaapi.o_imm) and is_writable_data(int(op.value)):
            return int(op.value)
        if kind == int(idaapi.o_mem) and is_writable_data(int(op.addr)):
            return int(op.addr)
        return None

    byte_first = {}
    dword_first = {}
    pointer_starts = []
    pointer_ends = []
    for entry in entries:
        insn = entry['insn']
        dest = insn.ops[0]
        if entry['mnem'] in ('mov', 'lea') and int(dest.type) == int(idaapi.o_reg):
            absolute = operand_data(entry, 1)
            if absolute is None and len(entry['targets']) == 1 and not entry['written']:
                absolute = next(iter(entry['targets']))
            if absolute is not None and is_writable_data(absolute) and not is_got(absolute):
                pointer_starts.append((int(absolute), entry))
        if entry['mnem'] == 'cmp':
            end = operand_data(entry, 1)
            if end is not None:
                pointer_ends.append(int(end))
    for start, defined in pointer_starts:
        if any(((end - start) & 0xFFFFFFFF) == DWORD_TABLE_SPAN for end in pointer_ends):
            dword_first.setdefault(start, defined)
    for entry in entries:
        if not entry['written'] or not uses_array_index(entry):
            continue
        width = store_width(entry)
        for gv in entry['written']:
            gv = folded(gv, entry)
            if not is_writable_data(gv) or is_got(gv):
                continue
            if width == 1:
                byte_first.setdefault(gv, entry)
            elif width == 4:
                dword_first.setdefault(gv, entry)

    bytes_ = sorted(byte_first)
    collapsed = []
    skip = set()
    for gv in bytes_:
        if gv in skip:
            continue
        if (gv + 1) in byte_first:
            collapsed.append(gv + 1)
            skip.update((gv, gv + 1))
        elif (gv - 1) in byte_first:
            skip.add(gv)
        else:
            collapsed.append(gv)
    dwords = sorted(dword_first, key=lambda gv: dword_first[gv]['ea'])
    if len(collapsed) != 1:
        result = {'error': 'texgammatable is not unique: %s' % [hex(x) for x in collapsed]}
    elif len(dwords) != 3:
        result = {'error': 'expected 3 dword gamma tables: %s' % [hex(x) for x in dwords]}
    else:
        ordered = [collapsed[0], *dwords]
        names = ['texgammatable', 'lightgammatable', 'lineargammatable', 'screengammatable']
        def locate(gv):
            indexes = []
            for index, entry in enumerate(entries):
                folded_written = {folded(item, entry) for item in entry['written']}
                if gv in folded_written and uses_array_index(entry):
                    indexes.append(index)
                elif dword_first.get(gv) is entry:
                    indexes.append(index)
            item = access(first_addressable(entries, indexes), gv)
            if item is not None:
                return item
            needle = int(gv).to_bytes(4, 'little')
            for index in indexes:
                entry = entries[index]
                raw = ida_bytes.get_bytes(entry['ea'], entry['len']) or b''
                off = raw.find(needle)
                if off >= 0 and off + 4 <= len(raw):
                    patched = dict(entry)
                    patched['disp'] = off
                    return access(patched, gv)
            return None

        located = {}
        failed = None
        for name, gv in zip(names, ordered):
            item = locate(gv)
            if item is None:
                failed = name
                break
            located[name] = item
        if failed is not None:
            result = {'error': 'no addressable operand for %s' % failed}
        else:
            located['pointer_size'] = 4
            result = located
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
    if any(_output_for_symbol(expected_outputs, name) is None for name in TABLE_NAMES):
        return False
    owner_name = None
    owner = None
    for candidate in OWNER_CANDIDATES:
        owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, candidate)
        if owner is not None:
            owner_name = candidate
            break
    if owner is None or owner_name is None:
        if debug:
            print(f"{skill_name}: missing BuildGammaTable/V_BuildGammaTable artifact")
        return False
    located = await run_walk(session, WALK, {"owner": hex(owner["owner_ea"])})
    if located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"{skill_name}: {located.get('error')}")
        return False
    context = await owner_context(session, owner["owner_ea"], image_base, owner_name)
    if context is None:
        return False
    tables = {name: located[name] for name in TABLE_NAMES}
    if debug:
        summary = " ".join(f"{name}={tables[name]['gv_ea']}" for name in TABLE_NAMES)
        print(f"{skill_name}: owner={owner_name} {summary}")
    return await write_located_globals(session, expected_outputs, platform, image_base, context, tables)
