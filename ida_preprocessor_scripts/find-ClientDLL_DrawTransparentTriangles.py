#!/usr/bin/env python3
"""Locate ClientDLL_DrawTransparentTriangles and its cl_funcs member slot.

``engine/cdll_int.c``:

    void ClientDLL_DrawTransparentTriangles( void )
    {
        if ( cl_funcs.pDrawTransparentTriangles )
            cl_funcs.pDrawTransparentTriangles();
    }

The transparent-entity loader is its only caller, so the owner is the unique
direct callee of ``R_DrawTEntitiesOnList`` that

1. is tiny (a single guarded tail dispatch), and
2. references exactly one ``cl_funcs`` member, ``pDrawTransparentTriangles``.

``cl_funcs_pDrawTransparentTriangles`` is that member's own address, recovered
from the same walk; it is never derived as ``cl_funcs`` plus a hardcoded offset
because ``cldll_func_t`` is not guaranteed to keep its layout across builds.
Discovery never consumes an old artifact signature.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, _parse_int, write_func_yaml
from ida_preprocessor_scripts._direct_gv_common import write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import owner_context, run_walk

OWNER_FUNC_NAME = "R_DrawTEntitiesOnList"
FUNC_NAME = "ClientDLL_DrawTransparentTriangles"
GV_NAME = "cl_funcs_pDrawTransparentTriangles"
CL_FUNCS_NAME = "cl_funcs"
# cldll_func_t is 0x110 bytes through pClientFactory on the widest build.
CL_FUNCS_SPAN = 0x120
# The forwarder is a load, a test, a branch and one indirect call.
MAX_FORWARDER_SIZE = 0x40

WALK = r"""
OWNER_EA = int(values['owner'], 0)
CL_FUNCS = int(values['cl_funcs'], 0)
SPAN = int(values['span'])
LIMIT = int(values['limit'])

if scan(OWNER_EA) is None:
    result = {'error': 'R_DrawTEntitiesOnList is not a function start'}
else:
    found = []
    rejected = []
    for callee, sites in sorted(direct_calls(OWNER_EA).items()):
        entries = scan(callee)
        if entries is None:
            continue
        owner = ida_funcs.get_func(callee)
        size = int(owner.end_ea) - int(owner.start_ea)
        if size > LIMIT:
            rejected.append([hex(callee), 'too large'])
            continue
        mapping = single_globals(entries)
        members = sorted(
            gv for gv in mapping
            if CL_FUNCS <= gv < CL_FUNCS + SPAN and (gv - CL_FUNCS) % 4 == 0
        )
        if len(members) != 1:
            rejected.append([hex(callee), 'cl_funcs members: %d' % len(members)])
            continue
        entry = entries[mapping[members[0]][0]]
        found.append({
            'func_ea': callee,
            'member_ea': members[0],
            'member_offset': members[0] - CL_FUNCS,
            'site': hex(int(sites[0])),
            'insn': access(entry, members[0]),
        })
    if len(found) != 1:
        result = {'error': 'DrawTransparentTriangles candidate is not unique: %d' % len(found),
                  'found': [[hex(item['func_ea']), hex(item['member_offset'])] for item in found],
                  'rejected': rejected[:20]}
    else:
        result = {'pointer_size': 4, **found[0]}
"""


def _artifact_func_ea(new_binary_dir, platform, name, image_base):
    artifact = _load_yaml_mapping(Path(new_binary_dir) / f"{name}.{platform}.yaml")
    if not artifact or artifact.get("func_name") != name:
        return None
    try:
        value = artifact["func_va"]
    except KeyError:
        return None
    try:
        func_ea = _parse_int(value, "func_va")
    except Exception:  # noqa: BLE001 - malformed artifact fails closed.
        return None
    return func_ea if func_ea >= int(image_base) else None


def _cl_funcs_ea(new_binary_dir, platform, image_base):
    artifact = _load_yaml_mapping(Path(new_binary_dir) / f"{CL_FUNCS_NAME}.{platform}.yaml")
    if not artifact or artifact.get("gv_name") != CL_FUNCS_NAME:
        return None
    try:
        gv_ea = _parse_int(artifact["gv_va"], "gv_va")
    except Exception:  # noqa: BLE001 - malformed artifact fails closed.
        return None
    return gv_ea if gv_ea >= int(image_base) else None


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
    func_output = _output_for_symbol(expected_outputs, FUNC_NAME)
    if func_output is None or _output_for_symbol(expected_outputs, GV_NAME) is None:
        return False
    owner_ea = _artifact_func_ea(new_binary_dir, platform, OWNER_FUNC_NAME, image_base)
    cl_funcs_ea = _cl_funcs_ea(new_binary_dir, platform, image_base)
    if owner_ea is None or cl_funcs_ea is None:
        if debug:
            print(f"{skill_name}: missing {OWNER_FUNC_NAME} or {CL_FUNCS_NAME} artifact")
        return False
    located = await run_walk(
        session,
        WALK,
        {
            "owner": hex(owner_ea),
            "cl_funcs": hex(cl_funcs_ea),
            "span": CL_FUNCS_SPAN,
            "limit": MAX_FORWARDER_SIZE,
        },
    )
    if located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"{skill_name}: {located.get('error')}")
        return False
    func_ea = int(located["func_ea"])
    # The member slot lives inside the forwarder, so the forwarder owns the
    # global's signature rather than the transparent-entity loader.
    forwarder = await owner_context(session, func_ea, image_base, FUNC_NAME)
    if forwarder is None:
        if debug:
            print(f"{skill_name}: could not revalidate {FUNC_NAME} at {func_ea:#x}")
        return False
    if not await write_located_globals(
        session,
        expected_outputs,
        platform,
        image_base,
        forwarder,
        {GV_NAME: located["insn"]},
    ):
        if debug:
            print(f"{skill_name}: could not write {GV_NAME} from {located['insn']}")
        return False
    write_func_yaml(func_output, forwarder["function"])
    if debug:
        print(
            f"{skill_name}: {FUNC_NAME}={func_ea:#x} {GV_NAME}={located['member_ea']:#x} "
            f"(cl_funcs+{located['member_offset']:#x})"
        )
    return True
