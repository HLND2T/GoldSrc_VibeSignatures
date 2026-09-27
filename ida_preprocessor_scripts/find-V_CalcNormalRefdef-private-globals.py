"""Recover Sven view globals from the already located normal-view function.

The 8948 ELF symbol table names all three objects.  Across both Sven builds,
the normal-view body tests the same spectator word with bits 2 and 4, copies
``ref_params.vieworg`` to ``v_origin``, and writes the final three view-angle
components to ``g_vVecViewangles`` just before its GL fog setup.  The walk
checks those dataflows inside the current function; no MetaHookSv first-match
pattern, fixed window, or cross-build address is used for discovery.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact, write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import run_walk

OWNER = "V_CalcNormalRefdef"
GLOBALS = ("v_origin", "iIsSpectator", "g_vVecViewangles")

WALK = r"""
GL_FOG_MODE = 0x0B65
MAX_FOG_WATERLEVEL = 2
SPECTATOR_MODE_BITS = (2, 4)
VECTOR_COMPONENT_BYTES = 4
VECTOR_LAST_COMPONENT = 2 * VECTOR_COMPONENT_BYTES
MAX_VECTOR_COPY_INSTRUCTIONS = 12
VECTOR_COMPONENTS = 3
REP_MOVSD = b'\xf3\xa5'
entries = scan(int(values['owner'], 0))
if entries is None:
    raise ValueError('V_CalcNormalRefdef is not an exact function start')

def immediates(entry):
    return {int(op.value) for op in entry['insn'].ops if int(op.type) == int(idaapi.o_imm)}

def one_global(entry):
    return next(iter(entry['targets'])) if len(entry['targets']) == 1 else None

def addressable(gv, before):
    candidates = [entry for entry in entries[:before] if one_global(entry) == gv and entry['disp']]
    return candidates[-1] if candidates else None

def load_base(entry, destination, offset):
    insn = entry['insn']
    if (entry['mnem'] != 'mov' or int(insn.ops[0].type) != int(idaapi.o_reg)
            or reg4(insn.ops[0]) != destination
            or int(insn.ops[1].type) not in (int(idaapi.o_phrase), int(idaapi.o_displ))
            or signed32(insn.ops[1].addr) != offset):
        return None
    base = reg4(insn.ops[1])
    return base if base not in (None, 'esp', 'ebx') else None

def register_source(entry):
    op = entry['insn'].ops[1]
    return reg4(op) if int(op.type) == int(idaapi.o_reg) else None

fog = [index for index, entry in enumerate(entries) if GL_FOG_MODE in immediates(entry)]
if len(fog) != 1:
    raise ValueError('GL_FOG_MODE marker is absent or ambiguous')
fog_index = fog[0]
waterlevel = int(values['waterlevel'], 0)
water_checks = [entry['ea'] for entry in entries[:fog_index]
                if entry['mnem'] == 'cmp' and waterlevel in entry['targets']
                and MAX_FOG_WATERLEVEL in immediates(entry)]

# The last three contiguous float stores before glFogi(GL_FOG_MODE, GL_LINEAR)
# write the final viewangles, including any viewentity override.  Require all
# three components rather than merely taking the closest writable operand.
angle_groups = []
for index, first in enumerate(entries[:fog_index]):
    if first['mnem'] not in ('movss', 'fstp') or len(first['written']) != 1:
        continue
    gv = next(iter(first['written']))
    if not is_writable_data(gv + VECTOR_LAST_COMPONENT):
        continue
    component_indexes = []
    for component in (VECTOR_COMPONENT_BYTES, VECTOR_LAST_COMPONENT):
        matches = [next_index for next_index in range(index + 1, min(index + MAX_VECTOR_COPY_INSTRUCTIONS, fog_index))
                   if entries[next_index]['mnem'] == first['mnem']
                   and gv + component in entries[next_index]['written']]
        if len(matches) != 1:
            break
        component_indexes.append(matches[0])
    if len(component_indexes) != 2 or component_indexes[0] >= component_indexes[1]:
        continue
    angle_groups.append((index, gv, component_indexes))
if not angle_groups:
    raise ValueError('final view-angle vector copy is absent')
angle_index, angle_gv, angle_components = max(angle_groups, key=lambda item: item[0])
if len([item for item in angle_groups if item[0] == angle_index]) != 1:
    raise ValueError('final view-angle vector copy is ambiguous')
angle_ref = entries[angle_index] if entries[angle_index]['disp'] else addressable(angle_gv, angle_index)
if angle_ref is None:
    raise ValueError('view-angle vector has no addressable instruction')

# Spectator state is one integer whose two mode bits are both read by this
# function.  g_iUser1 and the distinct g_IsSpectator array fail this test.
bits = {}
for index, entry in enumerate(entries):
    if entry['mnem'] != 'test':
        continue
    gv = one_global(entry)
    if gv is None:
        continue
    for bit in SPECTATOR_MODE_BITS:
        if bit in immediates(entry):
            bits.setdefault(gv, set()).add(bit)
spectators = [gv for gv, found in bits.items() if found == set(SPECTATOR_MODE_BITS)]
if len(spectators) != 1:
    raise ValueError('spectator bit tests are ambiguous: %r' % spectators)
spectator_gv = spectators[0]
spectator_ref = addressable(spectator_gv, len(entries))
if spectator_ref is None:
    raise ValueError('spectator state has no addressable instruction')

# Recover the source-level ``v_origin = pparams->vieworg`` copy.  MSVC stores
# two components with MOVQ plus the third with MOV; newer GCC uses three MOVs;
# older GCC uses REP MOVSD from the unoffset ref_params argument.  These are
# instruction forms for one source operation, not build-specific addresses.
qword_copies = []
scalar_copies = []
rep_copies = []
for index, entry in enumerate(entries[:angle_index]):
    gv = one_global(entry)
    if gv is None or not is_writable_data(gv + VECTOR_LAST_COMPONENT):
        continue
    insn = entry['insn']
    if entry['mnem'] == 'movq' and gv in entry['written'] and index:
        previous = entries[index - 1]
        source = previous['insn'].ops[1]
        if (previous['mnem'] != 'movq' or int(source.type) not in (int(idaapi.o_phrase), int(idaapi.o_displ))
                or signed32(source.addr) != 0
                or idc.print_operand(previous['ea'], 0) != idc.print_operand(entry['ea'], 1)):
            continue
        base = reg4(source)
        if base in (None, 'esp', 'ebx'):
            continue
        tail = [next_index for next_index in range(index + 1, min(index + 6, angle_index))
                if gv + VECTOR_LAST_COMPONENT in entries[next_index]['written']
                and entries[next_index]['mnem'] == 'mov']
        if len(tail) == 1 and tail[0] > index + 1:
            load = entries[tail[0] - 1]
            if load_base(load, register_source(entries[tail[0]]), VECTOR_LAST_COMPONENT) == base:
                qword_copies.append((gv, entry))
    if entry['mnem'] == 'mov' and gv in entry['written'] and index:
        base = load_base(entries[index - 1], register_source(entry), 0)
        if base is None:
            continue
        components = []
        for offset in (VECTOR_COMPONENT_BYTES, VECTOR_LAST_COMPONENT):
            matches = [next_index for next_index in range(index + 1, min(index + 7, angle_index))
                       if gv + offset in entries[next_index]['written']
                       and next_index and load_base(entries[next_index - 1],
                                                    register_source(entries[next_index]), offset) == base]
            if len(matches) != 1:
                break
            components.append(matches[0])
        if len(components) == 2 and components[0] < components[1]:
            scalar_copies.append((gv, entry))
    if ida_bytes.get_bytes(entry['ea'], entry['len']) == REP_MOVSD:
        before = entries[max(0, index - 5):index]
        if not any(item['mnem'] == 'mov' and
                   idc.print_operand(item['ea'], 0).lower() == 'esi' and
                   idc.print_operand(item['ea'], 1).lower() == 'ebp' for item in before):
            continue
        if not any(VECTOR_COMPONENTS in immediates(item) for item in before):
            continue
        destination = [item for item in before if item['mnem'] == 'mov'
                       and int(item['insn'].ops[0].type) == int(idaapi.o_reg)
                       and reg4(item['insn'].ops[0]) == 'edi'
                       and one_global(item) is not None and item['disp']]
        if len(destination) == 1 and one_global(entry) == one_global(destination[0]):
            rep_copies.append((one_global(destination[0]), destination[0]))

if qword_copies:
    # On MSVC the preceding v_angles copy may also start from an unoffset
    # temporary pointer.  The later vieworg snapshot follows the verified
    # g_iWaterLevel fog guard in both Sven Windows builds.
    qword_copies = [(gv, entry) for gv, entry in qword_copies
                    if any(check < entry['ea'] for check in water_checks)]
origin_copies = qword_copies or scalar_copies or rep_copies
origin_addresses = {gv for gv, _ in origin_copies}
if len(origin_addresses) != 1 or angle_gv in origin_addresses or spectator_gv in origin_addresses:
    raise ValueError('view origin copies are absent or ambiguous: %r' % [hex(gv) for gv in origin_addresses])
origin_gv, origin_ref = origin_copies[0]
result = {'v_origin': access(origin_ref, origin_gv),
          'iIsSpectator': access(spectator_ref, spectator_gv),
          'g_vVecViewangles': access(angle_ref, angle_gv),
          'fog_marker': hex(entries[fog_index]['ea']),
          'angle_stores': [hex(entries[index]['ea']) for index in (angle_index, *angle_components)]}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map
    if platform not in {"windows", "linux"}:
        return False
    owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, OWNER)
    if owner is None:
        return False
    waterlevel = _load_yaml_mapping(Path(new_binary_dir) / f"g_iWaterLevel.{platform}.yaml")
    if not waterlevel or waterlevel.get("gv_name") != "g_iWaterLevel":
        return False
    try:
        waterlevel_ea = int(waterlevel["gv_va"], 0)
    except (KeyError, TypeError, ValueError):
        return False
    located = await run_walk(session, WALK, {"owner": hex(owner["owner_ea"]), "waterlevel": hex(waterlevel_ea)})
    if located.get("error") or any(name not in located for name in GLOBALS):
        if debug:
            print(f"{skill_name}: {located}")
        return False
    if debug:
        print(f"{skill_name}: {located}")
    return await write_located_globals(
        session, expected_outputs, platform, image_base, owner, {name: located[name] for name in GLOBALS}
    )
