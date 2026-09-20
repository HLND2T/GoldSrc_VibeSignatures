#!/usr/bin/env python3
"""Locate the client-data update pair and the two globals they exchange.

``engine/cdll_int.c`` defines two functions around the same
``cl_funcs.pHudUpdateClientDataFunc`` member:

    void ClientDLL_UpdateClientData( void ) {
        ...
        VectorCopy( cl.viewangles, cdat.viewangles );
        cdat.fov = scr_fov.value;
        if ( cl_funcs.pHudUpdateClientDataFunc( &cdat, cl.time ) ) {
            VectorCopy( cdat.viewangles, cl.viewangles );
            scr_fov.value = cdat.fov;
        }
    }
    void ClientDLL_DemoUpdateClientData( client_data_t *cdat ) {
        if ( cl_funcs.pHudUpdateClientDataFunc( cdat, cl.time ) ) { ...same writes... }
    }

They are the only two functions sharing that member, which identifies the pair
without a byte pattern. Their common globals are exactly ``cl.viewangles`` (a
vec3, i.e. ``x``/``x+4``/``x+8``) and ``scr_fov.value``.

The roles are then separated by data flow, not by an immediate: the non-demo
entry point *reads* the view angles before the call (``VectorCopy( cl.viewangles,
cdat.viewangles )``) whereas the demo entry point only writes them back. That is
stable across MSVC SSE, GCC SSE and GCC x87 bodies, unlike MetaHookSv's
suggestion of keying on the literals ``5`` (``ca_active``) and ``0x20``.

``scr_fov_value`` is the ``value`` member of ``cvar_t scr_fov``; the artifact
deliberately carries that member address, matching how the symbol is consumed.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._direct_gv_common import write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import (
    inspect_func,
    owner_context,
    run_walk,
)

UPDATE_FUNC_NAME = "ClientDLL_UpdateClientData"
DEMO_FUNC_NAME = "ClientDLL_DemoUpdateClientData"
VIEWANGLES_GV_NAME = "cl_viewangles"
FOV_GV_NAME = "scr_fov_value"
CL_FUNCS_NAME = "cl_funcs"

CL_FUNCS_SPAN = 0x120
# The table registrar assigns nearly every member; the two update entry points
# touch a single one. Anything above this is structural setup, not a consumer.
MAX_CONSUMER_MEMBERS = 4

WALK = r"""
CL_FUNCS = int(values['cl_funcs'], 0)
SPAN = int(values['span'])
MAX_MEMBERS = int(values['max_members'])

consumers = set()
for offset in range(0, SPAN, 4):
    for ref in idautils.XrefsTo(CL_FUNCS + offset, 0):
        function = ida_funcs.get_func(int(ref.frm))
        if function is not None:
            consumers.add(int(function.start_ea))

analysed = {}
for start in sorted(consumers):
    entries = scan(start)
    if entries is None:
        continue
    mapping = single_globals(entries)
    members, reads, writes = set(), set(), set()
    for gv, indexes in mapping.items():
        if CL_FUNCS <= gv < CL_FUNCS + SPAN:
            members.add(gv - CL_FUNCS)
            continue
        for index in indexes:
            if gv in entries[index]['written']:
                writes.add(gv)
            else:
                reads.add(gv)
    analysed[start] = {
        'entries': entries, 'mapping': mapping,
        'members': members, 'reads': reads, 'writes': writes,
    }

by_member = {}
for start, data in analysed.items():
    if len(data['members']) > MAX_MEMBERS:
        continue
    for offset in data['members']:
        by_member.setdefault(offset, []).append(start)

pairs = []
for offset, functions in sorted(by_member.items()):
    if len(functions) != 2:
        continue
    first, second = functions
    shared = (analysed[first]['writes'] | analysed[first]['reads']) & analysed[second]['writes']
    vectors = [gv for gv in sorted(shared) if gv + 4 in shared and gv + 8 in shared]
    if len(vectors) != 1:
        continue
    viewangles = vectors[0]
    scalars = sorted(shared - {viewangles, viewangles + 4, viewangles + 8})
    if len(scalars) != 1:
        continue
    reads_first = viewangles in analysed[first]['reads']
    reads_second = viewangles in analysed[second]['reads']
    if reads_first == reads_second:
        continue
    update, demo = (first, second) if reads_first else (second, first)
    pairs.append((offset, update, demo, viewangles, scalars[0]))

if len(pairs) != 1:
    result = {'error': 'client-data update pair is not unique: %s'
                       % [(hex(a), hex(b), hex(c)) for a, b, c, _, _ in pairs]}
else:
    offset, update, demo, viewangles, fov = pairs[0]
    demo_data = analysed[demo]
    viewangles_access = access(first_addressable(demo_data['entries'], demo_data['mapping'][viewangles]),
                               viewangles)
    fov_access = access(first_addressable(demo_data['entries'], demo_data['mapping'][fov]), fov)
    if viewangles_access is None or fov_access is None:
        result = {'error': 'no addressable reference for the exchanged globals'}
    else:
        result = {
            'pointer_size': 4,
            'member_offset': hex(offset),
            'update_ea': hex(update),
            'demo_ea': hex(demo),
            'viewangles': viewangles_access,
            'fov': fov_access,
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
    outputs = {name: _output_for_symbol(expected_outputs, name) for name in (UPDATE_FUNC_NAME, DEMO_FUNC_NAME)}
    if any(output is None for output in outputs.values()):
        return False
    if any(_output_for_symbol(expected_outputs, name) is None for name in (VIEWANGLES_GV_NAME, FOV_GV_NAME)):
        return False

    artifact = _load_yaml_mapping(Path(new_binary_dir) / f"{CL_FUNCS_NAME}.{platform}.yaml")
    if not artifact or artifact.get("gv_name") != CL_FUNCS_NAME:
        if debug:
            print(f"{skill_name}: missing {CL_FUNCS_NAME} artifact")
        return False
    try:
        cl_funcs_va = int(artifact["gv_va"], 0)
    except (KeyError, TypeError, ValueError):
        return False
    if cl_funcs_va < int(image_base):
        return False

    located = await run_walk(
        session,
        WALK,
        {"cl_funcs": hex(cl_funcs_va), "span": CL_FUNCS_SPAN, "max_members": MAX_CONSUMER_MEMBERS},
    )
    if located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"{skill_name}: {located.get('error')}")
        return False

    demo_ea = int(located["demo_ea"], 0)
    owner = await owner_context(session, demo_ea, image_base, DEMO_FUNC_NAME)
    if owner is None:
        return False
    functions = {}
    for name, key in ((UPDATE_FUNC_NAME, "update_ea"), (DEMO_FUNC_NAME, "demo_ea")):
        function = await inspect_func(session, int(located[key], 0), image_base, name)
        if not function:
            if debug:
                print(f"{skill_name}: could not inspect {name} at {located[key]}")
            return False
        functions[name] = function

    if not await write_located_globals(
        session,
        expected_outputs,
        platform,
        image_base,
        owner,
        {VIEWANGLES_GV_NAME: located["viewangles"], FOV_GV_NAME: located["fov"]},
    ):
        return False
    for name, function in functions.items():
        write_func_yaml(outputs[name], function)
    if debug:
        print(
            f"{skill_name}: member=cl_funcs+{located['member_offset']} "
            f"{UPDATE_FUNC_NAME}={located['update_ea']} {DEMO_FUNC_NAME}={located['demo_ea']} "
            f"{VIEWANGLES_GV_NAME}={located['viewangles']['gv_ea']} {FOV_GV_NAME}={located['fov']['gv_ea']}"
        )
    return True
