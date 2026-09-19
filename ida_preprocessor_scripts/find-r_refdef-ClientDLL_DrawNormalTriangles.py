#!/usr/bin/env python3
"""Locate r_refdef and ClientDLL_DrawNormalTriangles from the scene renderer.

``engine/gl_rmain.c`` opens ``R_RenderScene`` with

    if ( CL_IsDevOverviewMode() )
        CL_SetDevOverView( &r_refdef );
    ...
    ClientDLL_DrawNormalTriangles();

so the scene renderer is the unique caller of ``CL_SetDevOverView`` and passes
``&r_refdef`` as its only argument. The caller is derived rather than read from
a config artifact because SvEngine 10257 Windows inlines ``R_RenderScene`` into
``R_RenderView``; keying on ``R_RenderScene`` by name would fail there.

``ClientDLL_DrawNormalTriangles`` (``engine/cdll_int.c``) is the unique direct
callee of that renderer which references exactly one ``cl_funcs`` member —
``pDrawNormalTriangles`` — and additionally dispatches through a non-member
function pointer, which is ``tri.RenderMode(kRenderNormal)``. The second
condition is required: ``ClientDLL_IsThirdPerson`` also touches exactly one
member on SvEngine Windows, but has no trailing dispatch.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._direct_gv_common import write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import (
    inspect_func,
    owner_context,
    run_walk,
)

GV_NAME = "r_refdef"
FUNC_NAME = "ClientDLL_DrawNormalTriangles"
SETDEV_FUNC_NAME = "CL_SetDevOverView"
CL_FUNCS_NAME = "cl_funcs"
# cldll_func_t is 0x110 bytes through pClientFactory on the widest build.
CL_FUNCS_SPAN = 0x120
# CL_SetDevOverView takes one pointer, so its argument setup is close by.
ARGUMENT_WINDOW = 12

WALK = r"""
SETDEV = int(values['setdev'], 0)
CL_FUNCS = int(values['cl_funcs'], 0)
SPAN = int(values['span'])
WINDOW = int(values['window'])

calling = sorted({start for start, _ in callers(SETDEV)})
if len(calling) != 1:
    result = {'error': 'CL_SetDevOverView caller is not unique: %s' % [hex(x) for x in calling]}
else:
    renderer = calling[0]
    entries = scan(renderer)
    if entries is None:
        result = {'error': 'scene renderer is not a function start'}
    else:
        sites = sorted(site for start, site in callers(SETDEV) if start == renderer)
        chosen = []
        for site in sites:
            window = [entry for entry in entries if entry['ea'] < site][-WINDOW:]
            for entry in reversed(window):
                if entry['mnem'] not in ('mov', 'push', 'lea'):
                    continue
                if len(entry['targets']) != 1 or not entry['disp']:
                    continue
                chosen.append(access(entry, next(iter(entry['targets']))))
                break
        values_seen = {item['gv_ea'] for item in chosen}
        if len(chosen) != len(sites) or len(values_seen) != 1:
            result = {'error': 'r_refdef argument is not unique: %s' % sorted(values_seen)}
        else:
            found = []
            for callee in sorted(direct_calls(renderer)):
                callee_entries = scan(callee)
                if callee_entries is None:
                    continue
                mapping = single_globals(callee_entries)
                members = sorted(
                    gv for gv in mapping
                    if CL_FUNCS <= gv < CL_FUNCS + SPAN and (gv - CL_FUNCS) % 4 == 0
                )
                dispatches_other = False
                for entry in callee_entries:
                    if entry['mnem'] != 'call':
                        continue
                    if int(entry['insn'].ops[0].type) == int(idaapi.o_near):
                        continue
                    for gv in entry['targets']:
                        if not (CL_FUNCS <= gv < CL_FUNCS + SPAN):
                            dispatches_other = True
                if len(members) == 1 and dispatches_other:
                    found.append((callee, members[0] - CL_FUNCS))
            if len(found) != 1:
                result = {'error': 'DrawNormalTriangles candidate is not unique: %s'
                                   % [(hex(a), hex(b)) for a, b in found]}
            else:
                result = {
                    'pointer_size': 4,
                    'renderer_ea': hex(renderer),
                    'gv': chosen[0],
                    'func_ea': hex(found[0][0]),
                    'member_offset': hex(found[0][1]),
                }
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
    func_output = _output_for_symbol(expected_outputs, FUNC_NAME)
    if func_output is None or _output_for_symbol(expected_outputs, GV_NAME) is None:
        return False

    new_binary_dir = Path(new_binary_dir)
    anchors = {}
    for name, key in ((SETDEV_FUNC_NAME, "func_va"), (CL_FUNCS_NAME, "gv_va")):
        artifact = _load_yaml_mapping(new_binary_dir / f"{name}.{platform}.yaml")
        identity = "func_name" if key == "func_va" else "gv_name"
        if not artifact or artifact.get(identity) != name:
            if debug:
                print(f"{skill_name}: missing {name} artifact")
            return False
        try:
            anchors[name] = int(artifact[key], 0)
        except (KeyError, TypeError, ValueError):
            return False
        if anchors[name] < int(image_base):
            return False

    located = await run_walk(
        session,
        WALK,
        {
            "setdev": hex(anchors[SETDEV_FUNC_NAME]),
            "cl_funcs": hex(anchors[CL_FUNCS_NAME]),
            "span": CL_FUNCS_SPAN,
            "window": ARGUMENT_WINDOW,
        },
    )
    if located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"{skill_name}: {located.get('error')}")
        return False

    renderer_ea = int(located["renderer_ea"], 0)
    owner = await owner_context(session, renderer_ea, image_base, "R_RenderScene")
    if owner is None:
        if debug:
            print(f"{skill_name}: could not revalidate the scene renderer at {renderer_ea:#x}")
        return False
    function = await inspect_func(session, int(located["func_ea"], 0), image_base, FUNC_NAME)
    if not function:
        if debug:
            print(f"{skill_name}: could not inspect {FUNC_NAME} at {located['func_ea']}")
        return False
    if not await write_located_globals(
        session, expected_outputs, platform, image_base, owner, {GV_NAME: located["gv"]}
    ):
        return False
    write_func_yaml(func_output, function)
    if debug:
        print(
            f"{skill_name}: renderer={renderer_ea:#x} {GV_NAME}={located['gv']['gv_ea']} "
            f"{FUNC_NAME}={located['func_ea']} (cl_funcs+{located['member_offset']})"
        )
    return True
