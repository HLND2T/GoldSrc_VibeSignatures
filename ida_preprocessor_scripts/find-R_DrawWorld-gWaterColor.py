#!/usr/bin/env python3
"""Locate gWaterColor from the water tint R_DrawWorld copies into its entity.

``engine/gl_rsurf.c`` opens ``R_DrawWorld`` with

    ent.curstate.rendercolor.r = gWaterColor.r;
    ent.curstate.rendercolor.g = gWaterColor.g;
    ent.curstate.rendercolor.b = gWaterColor.b;

so ``gWaterColor`` is the only writable global whose ``+0``/``+4``/``+8`` dwords
are each read and whose low bytes land in three *consecutive* bytes of one
``cl_entity_t``. Both halves of that shape are needed: three adjacent dwords
alone also match ``r_refdef.vieworg`` and ``modelorg``, which the same prologue
copies as full floats.

The destination object is tracked by provenance because the builds disagree on
where ``ent`` lives: most keep it as a stack local (``mov [ebp+var_8B8], al``)
while CoF-5936 stores through the ``currententity`` pointer, reloading it into a
different register for each of the three bytes.

MetaHookSv instead keeps two hardcoded byte patterns (``GWATERCOLOR_SIG`` and an
HL25 variant) and derives ``cshift_water`` as ``gWaterColor + 12``; that offset
does not hold here (it is ``+0x10`` on Windows and ``+0x44`` on Linux), and
``cshift_water`` already has its own semantic locator.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol
from ida_preprocessor_scripts._direct_gv_common import write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import owner_context, run_walk

GV_NAME = "gWaterColor"
OWNER_FUNC_NAME = "R_DrawWorld"
# colorVec r/g/b are three dwords; the copy lands in consecutive entity bytes.
COLOR_MEMBER_OFFSETS = (0, 4, 8)
# The three reads and their byte stores interleave with the qglColor3f setup.
STORE_WINDOW = 16

WALK = r"""
OWNER = int(values['owner'], 0)
OFFSETS = tuple(values['offsets'])
WINDOW = int(values['window'])

entries = scan(OWNER)
if entries is None:
    result = {'error': 'R_DrawWorld artifact is not a function start'}
else:
    mapping = single_globals(entries)

    def store_key(index):
        # (object identity, byte displacement) of a stack or pointer byte store.
        operand = entries[index]['insn'].ops[0]
        if int(operand.type) not in (int(idaapi.o_displ), int(idaapi.o_phrase)):
            return None
        base = reg4(operand)
        displacement = signed32(operand.addr)
        if base in ('esp', 'ebp'):
            return ('stack', displacement)
        origin = entries[index]['provenance'].get(base)
        if origin is None:
            return None
        kind, anchor = origin
        return ((kind, anchor), displacement + (anchor if kind == 'stack' else 0))

    def byte_stores(index):
        # Every byte store of the value read at index, keyed by target object.
        low = reg1(entries[index]['insn'].ops[0])
        if not low:
            return set()
        found = set()
        for offset in range(index + 1, min(index + 1 + WINDOW, len(entries))):
            entry = entries[offset]
            destination = entry['insn'].ops[0]
            source = entry['insn'].ops[1]
            if int(destination.type) == int(idaapi.o_reg) and reg1(destination) == low:
                if entry['mnem'] != 'mov' or reg1(source) != low:
                    break
            if entry['mnem'] != 'mov' or reg1(source) != low:
                continue
            key = store_key(offset)
            if key is not None:
                found.add(key)
        return found

    candidates = []
    for gv in sorted(mapping):
        if not all(gv + offset in mapping for offset in OFFSETS):
            continue
        per_member = []
        for offset in OFFSETS:
            stores = set()
            for index in mapping[gv + offset]:
                stores |= byte_stores(index)
            per_member.append(stores)
        if any((obj, disp + 1) in per_member[1] and (obj, disp + 2) in per_member[2]
               for obj, disp in per_member[0]):
            candidates.append(gv)
    if len(candidates) != 1:
        result = {'error': 'gWaterColor candidate is not unique: %s' % [hex(x) for x in candidates]}
    else:
        located = access(first_addressable(entries, mapping[candidates[0]]), candidates[0])
        if located is None:
            result = {'error': 'no addressable gWaterColor reference'}
        else:
            result = {'pointer_size': 4, 'gv': located}
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
    if _output_for_symbol(expected_outputs, GV_NAME) is None:
        return False
    artifact = _load_yaml_mapping(Path(new_binary_dir) / f"{OWNER_FUNC_NAME}.{platform}.yaml")
    if not artifact or artifact.get("func_name") != OWNER_FUNC_NAME:
        if debug:
            print(f"{skill_name}: missing {OWNER_FUNC_NAME} artifact")
        return False
    try:
        owner_ea = int(artifact["func_va"], 0)
    except (KeyError, TypeError, ValueError):
        return False
    if owner_ea < int(image_base):
        return False

    located = await run_walk(
        session,
        WALK,
        {"owner": hex(owner_ea), "offsets": list(COLOR_MEMBER_OFFSETS), "window": STORE_WINDOW},
    )
    if located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"{skill_name}: {located.get('error')}")
        return False

    owner = await owner_context(session, owner_ea, image_base, OWNER_FUNC_NAME)
    if owner is None:
        return False
    if debug:
        print(f"{skill_name}: {GV_NAME}={located['gv']['gv_ea']} via {located['gv']['insn_disasm']}")
    return await write_located_globals(session, expected_outputs, platform, image_base, owner, {GV_NAME: located["gv"]})
