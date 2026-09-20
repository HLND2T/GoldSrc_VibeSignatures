#!/usr/bin/env python3
"""Recover gl_filter_min / gl_filter_max from the gl_texturemode handler.

``gl_filter_min`` and ``gl_filter_max`` are the two engine globals the texture
mode handler writes from its ``modes`` table:

    gl_filter_min = modes[i].minimize;   // table entry + 4
    gl_filter_max = modes[i].maximize;   // table entry + 8

Their addresses are laid out differently on every family (adjacent in either
order, or 0x10 apart), so neither may be derived from the other and both are
returned by one walk. A direct locator is used instead of an LLM predecessor
because the classic, HL25 and SvEngine handler bodies differ substantially while
``{gamever}`` reference resolution only falls back to hl-10210, which would
require a separate reference file for every legacy family.

Discovery is a structural property of the current binary: exactly one adjacent
store pair whose source registers were loaded from one shared table base with a
four-byte displacement delta. Store order follows table offset, so the
lower-offset load feeds ``gl_filter_min``.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, _parse_int
from ida_preprocessor_scripts._direct_gv_common import write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import owner_context, run_walk
from ida_preprocessor_scripts._engine_texture_mode_common import ensure_function_defined, texture_mode_name

OWNER_FUNC_NAME = "Draw_TextureMode_f"
TARGET_GLOBAL_NAMES = ["gl_filter_min", "gl_filter_max"]
# The two loads sit at most this far from their store in every validated build.
LOAD_WINDOW = 6

WALK = r"""
import idaapi
import ida_gdl
import struct

OWNER_EA = int(values['owner'], 0)
LOAD_WINDOW = int(values['window'])
entries = scan(OWNER_EA)
if entries is None:
    result = {'error': 'Draw_TextureMode_f is not a function start'}
else:
    blocks = list(ida_gdl.FlowChart(ida_funcs.get_func(OWNER_EA)))
    def block_start(entry):
        return next((int(block.start_ea) for block in blocks
                     if block.start_ea <= entry['ea'] < block.end_ea), None)

    def clobbers(entry, registers):
        if entry['mnem'] == 'call':
            return True
        for index, operand in enumerate(entry['insn'].ops):
            if int(operand.type) == int(idaapi.o_reg) and changed_operand(entry['insn'], index):
                if reg4(operand) in registers:
                    return True
        # These instructions also write implicit registers.
        implicit_imul = entry['mnem'] == 'imul' and sum(
            int(op.type) != int(idaapi.o_void) for op in entry['insn'].ops) == 1
        return implicit_imul or entry['mnem'] in ('mul', 'div', 'idiv', 'cdq', 'popa', 'popad')

    def memory_address(entry):
        # Decode only unprefixed x86-32 MOV loads. Comparing the complete
        # ModRM/SIB address avoids treating unrelated [base+4]/[other+8]
        # accesses as one table. Unknown encodings fail closed.
        raw = ida_bytes.get_bytes(entry['ea'], entry['len']) or b''
        if len(raw) == 5 and raw[0] == 0xA1:
            return (None, None, 1), struct.unpack_from('<I', raw, 1)[0]
        if len(raw) < 2 or raw[0] != 0x8B:
            return None
        mod, rm = raw[1] >> 6, raw[1] & 7
        if mod == 3:
            return None
        cursor, base, index, scale = 2, rm, None, 1
        if rm == 4:
            if cursor >= len(raw):
                return None
            sib = raw[cursor]
            cursor += 1
            base, index, scale = sib & 7, (sib >> 3) & 7, 1 << (sib >> 6)
            if index == 4:
                index, scale = None, 1
        displacement_size = 1 if mod == 1 else 4 if mod == 2 or (mod == 0 and base == 5) else 0
        if mod == 0 and base == 5:
            base = None
        if cursor + displacement_size != len(raw):
            return None
        displacement = int.from_bytes(raw[cursor:], 'little', signed=True) if displacement_size else 0
        base = None if base is None else ida_idp.get_reg_name(base, 4)
        index = None if index is None else ida_idp.get_reg_name(index, 4)
        return (base, index, scale), displacement

    def register_value(register, before):
        # CoF reloads the same stack index into different registers and scales
        # each by sizeof(modes[0]). Prove that equivalence instead of requiring
        # equal register numbers or accepting equal displacements alone.
        block = block_start(entries[before])
        for index in range(before - 1, -1, -1):
            entry = entries[index]
            if block_start(entry) != block:
                break
            if not clobbers(entry, {register}):
                continue
            raw = ida_bytes.get_bytes(entry['ea'], entry['len']) or b''
            if entry['mnem'] == 'mov':
                insn = entry['insn']
                if int(insn.ops[0].type) == int(idaapi.o_reg) and reg4(insn.ops[0]) == register:
                    if int(insn.ops[1].type) == int(idaapi.o_reg):
                        return register_value(reg4(insn.ops[1]), index)
                    address = memory_address(entry)
                    if address is not None and address[0] == ('ebp', None, 1):
                        # Only a frame-local read is reused across instructions.
                        # Potential stack/indirect writes invalidate it; stores
                        # to absolute globals cannot alias this frame slot.
                        epoch = -1
                        for prior in range(index):
                            previous = entries[prior]
                            if block_start(previous) != block:
                                continue
                            for n, op in enumerate(previous['insn'].ops):
                                if changed_operand(previous['insn'], n) and int(op.type) in (
                                        int(idaapi.o_displ), int(idaapi.o_phrase)):
                                    epoch = prior
                            if previous['mnem'] in ('call', 'push', 'pop'):
                                epoch = prior
                        return ('frame', register_value('ebp', index), address[1], epoch)
            if len(raw) in (3, 6) and raw[0] in (0x6B, 0x69) and raw[1] >> 6 == 3:
                source = ida_idp.get_reg_name(raw[1] & 7, 4)
                multiplier = int.from_bytes(raw[2:], 'little', signed=True)
                return ('multiply', register_value(source, index), multiplier)
            return ('unknown', register, index)
        return ('incoming', register, block)

    def table_address(load):
        index, (base, subscript, scale), displacement = load
        return (None if base is None else register_value(base, index),
                None if subscript is None else register_value(subscript, index), scale)

    stores = []
    for index, entry in enumerate(entries):
        if entry['mnem'] != 'mov' or len(entry['written']) != 1:
            continue
        insn = entry['insn']
        destination = insn.ops[0]
        if int(destination.type) not in (int(idaapi.o_mem), int(idaapi.o_displ)):
            continue
        source = reg4(insn.ops[1]) if int(insn.ops[1].type) == int(idaapi.o_reg) else None
        if source is None:
            continue
        stores.append((index, entry, sorted(entry['written'])[0], source))

    def load_definition(register, before):
        for index in range(before - 1, max(-1, before - 1 - LOAD_WINDOW), -1):
            entry = entries[index]
            if block_start(entry) is None or block_start(entry) != block_start(entries[before]):
                return None
            insn = entry['insn']
            if not clobbers(entry, {register}):
                continue
            if entry['mnem'] != 'mov' or int(insn.ops[0].type) != int(idaapi.o_reg) or reg4(insn.ops[0]) != register:
                return None
            address = memory_address(entry)
            return None if address is None else (index, *address)
        return None

    pairs = []
    for position in range(len(stores) - 1):
        first, second = stores[position], stores[position + 1]
        first_load = load_definition(first[3], first[0])
        second_load = load_definition(second[3], second[0])
        if first_load is None or second_load is None:
            continue
        if table_address(first_load) != table_address(second_load) or second_load[2] - first_load[2] != 4:
            continue
        if block_start(first[1]) != block_start(second[1]):
            continue
        pairs.append((first, second))

    if len(pairs) != 1:
        result = {'error': 'filter store pair is not unique: %d' % len(pairs),
                  'pairs': [[entry[1]['disasm'], second[1]['disasm']] for entry, second in pairs],
                  'stores': [[entry['disasm'], hex(gv)] for _, entry, gv, _ in stores],
                  'load_context': [[entry['disasm'],
                                    (ida_bytes.get_bytes(entry['ea'], entry['len']) or b'').hex(),
                                    block_start(entry)]
                                   for index, _, _, _ in stores
                                   for entry in entries[max(0, index - LOAD_WINDOW):index + 1]]}
    else:
        first, second = pairs[0]
        result = {
            'pointer_size': 4,
            'gl_filter_min': access(first[1], first[2]),
            'gl_filter_max': access(second[1], second[2]),
            'store_summary': [first[1]['disasm'], second[1]['disasm']],
        }
"""


def _owner_artifact(new_binary_dir, platform, image_base):
    artifact = _load_yaml_mapping(Path(new_binary_dir) / f"{OWNER_FUNC_NAME}.{platform}.yaml")
    if not artifact or artifact.get("func_name") != texture_mode_name(new_binary_dir):
        return None
    try:
        func_ea = _parse_int(artifact["func_va"], "func_va")
        func_size = _parse_int(artifact["func_size"], "func_size")
    except Exception:  # noqa: BLE001 - malformed artifact fails closed.
        return None
    if func_ea < int(image_base):
        return None
    return func_ea, func_size


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
    _ = skill_name, old_yaml_map
    if any(_output_for_symbol(expected_outputs, name) is None for name in TARGET_GLOBAL_NAMES):
        return False
    owner_artifact = _owner_artifact(new_binary_dir, platform, image_base)
    if owner_artifact is None:
        if debug:
            print(f"{skill_name}: missing {OWNER_FUNC_NAME} artifact")
        return False
    owner_ea, owner_size = owner_artifact
    if not await ensure_function_defined(session, owner_ea, owner_size, debug):
        if debug:
            print(f"{skill_name}: could not revalidate the handler at {owner_ea:#x}")
        return False
    located = await run_walk(session, WALK, {"owner": hex(owner_ea), "window": LOAD_WINDOW})
    if located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"{skill_name}: {located}")
        return False
    owner = await owner_context(session, owner_ea, image_base, OWNER_FUNC_NAME)
    if owner is None:
        if debug:
            print(f"{skill_name}: could not revalidate {OWNER_FUNC_NAME} at {owner_ea:#x}")
        return False
    if not await write_located_globals(
        session,
        expected_outputs,
        platform,
        image_base,
        owner,
        {name: located[name] for name in TARGET_GLOBAL_NAMES},
    ):
        return False
    if debug:
        print(
            f"{skill_name}: owner={owner_ea:#x} "
            f"min={located['gl_filter_min']['gv_ea']} max={located['gl_filter_max']['gv_ea']}"
        )
    return True
