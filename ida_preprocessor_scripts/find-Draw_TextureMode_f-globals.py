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
from ida_preprocessor_scripts._engine_texture_mode_common import ensure_function_defined

OWNER_FUNC_NAME = "Draw_TextureMode_f"
TARGET_GLOBAL_NAMES = ["gl_filter_min", "gl_filter_max"]
# The two loads sit at most this far from their store in every validated build.
LOAD_WINDOW = 6

WALK = r"""
import idaapi

OWNER_EA = int(values['owner'], 0)
LOAD_WINDOW = int(values['window'])
entries = scan(OWNER_EA)
if entries is None:
    result = {'error': 'Draw_TextureMode_f is not a function start'}
else:
    stores = []
    for index, entry in enumerate(entries):
        if entry['mnem'] != 'mov' or len(entry['written']) != 1:
            continue
        insn = entry['insn']
        destination = insn.ops[0]
        if int(destination.type) not in (int(idaapi.o_mem), int(idaapi.o_displ)):
            continue
        source = reg4(insn.ops[1])
        if source is None:
            continue
        stores.append((index, entry, sorted(entry['written'])[0], source))

    def load_definition(register, before):
        for index in range(before - 1, max(-1, before - 1 - LOAD_WINDOW), -1):
            entry = entries[index]
            if entry['mnem'] != 'mov':
                continue
            insn = entry['insn']
            if int(insn.ops[0].type) != int(idaapi.o_reg) or reg4(insn.ops[0]) != register:
                continue
            operand = insn.ops[1]
            if int(operand.type) not in (int(idaapi.o_mem), int(idaapi.o_displ), int(idaapi.o_phrase)):
                return None
            return (index, int(operand.type), signed32(operand.addr))
        return None

    pairs = []
    for position in range(len(stores) - 1):
        first, second = stores[position], stores[position + 1]
        first_load = load_definition(first[3], first[0])
        second_load = load_definition(second[3], second[0])
        if first_load is None or second_load is None:
            continue
        if second_load[2] - first_load[2] != 4:
            continue
        pairs.append((first, second))

    if len(pairs) != 1:
        result = {'error': 'filter store pair is not unique: %d' % len(pairs),
                  'pairs': [[entry[1]['disasm'], second[1]['disasm']] for entry, second in pairs],
                  'stores': [[entry['disasm'], hex(gv)] for _, entry, gv, _ in stores]}
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
    if not artifact or artifact.get("func_name") != OWNER_FUNC_NAME:
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
