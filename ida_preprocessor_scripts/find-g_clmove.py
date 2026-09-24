#!/usr/bin/env python3
"""Recover g_clmove from the two source-level client movement initializers.

``ClientDLL_Init`` passes the object to ClientDLL_ClientMoveInit (inlined on
some builds); ``Host_Init`` passes the same object to PM_Init. Requiring one
writable data object referenced by both bodies after ScreenShake distinguishes
the true playermove_t from cl_funcs, cl_enginefuncs, and other globals. The
selected ClientDLL_Init instruction supplies the version-specific operand.
"""

from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact, write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import run_walk

NAME = "g_clmove"
CLIENT = "ClientDLL_Init"
HOST = "Host_Init"

WALK = r"""
client = int(values['client'], 0)
host = int(values['host'], 0)
client_entries = scan(client)
host_entries = scan(host)
if client_entries is None or host_entries is None:
    result = {'error': 'predecessor is not a function start'}
else:
    screen_sources = []
    for item in idautils.Strings():
        if str(item) != 'ScreenShake':
            continue
        for ref in idautils.DataRefsTo(int(item.ea)):
            function = ida_funcs.get_func(int(ref))
            if function is not None and int(function.start_ea) == client:
                screen_sources.append(int(ref))
    client_globals = single_globals(client_entries)
    host_globals = single_globals(host_entries)
    shared = sorted(set(client_globals) & set(host_globals))
    matches = []
    if len(screen_sources) == 1:
        screen_source = screen_sources[0]
        for gv in shared:
            indexes = [index for index in client_globals[gv] if int(client_entries[index]['ea']) > screen_source]
            entry = first_addressable(client_entries, indexes)
            if entry is not None:
                matches.append(access(entry, gv))
    if len(matches) != 1:
        result = {'error': 'expected one shared post-ScreenShake object', 'shared': [hex(x) for x in shared], 'matches': matches, 'screen_sources': [hex(x) for x in screen_sources]}
    else:
        result = {'gv': matches[0], 'shared': [hex(x) for x in shared]}
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
    client = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, CLIENT)
    host = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, HOST)
    if client is None or host is None:
        if debug:
            print(f"{skill_name}: missing or invalid {CLIENT}/{HOST} artifact")
        return False
    located = await run_walk(session, WALK, {"client": hex(client["owner_ea"]), "host": hex(host["owner_ea"])})
    if located.get("error") or not located.get("gv"):
        if debug:
            print(f"{skill_name}: {located}")
        return False
    if debug:
        print(f"{skill_name}: {located['gv']['gv_ea']} via {located['gv']['insn_disasm']}")
    return await write_located_globals(session, expected_outputs, platform, image_base, client, {NAME: located["gv"]})
