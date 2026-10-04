#!/usr/bin/env python3
"""Locate the inner host frame and inactive-server RCON poller by current calls.

CEngine::Frame calls the outer Host_Frame, which executes Cbuf on state changes
and calls the inner _Host_Frame. The inner body also calls Cbuf once. This pair
of edges uniquely separates the main frame from initialization/exec reentry.
The poller is the inner frame's unique direct callee reaching both challenge
and Rcon within the source's optional HandleRconPacket layer. SV_Frame's active
server path traverses ReadPackets/ConnectionlessPacket instead. PLT edges are
resolved before comparison; no call ordinal, address, or old signature is used.
"""

from pathlib import Path

from ida_analyze_util import _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._engine_private_globals_common import inspect_func, run_walk
from ida_preprocessor_scripts._native_rcon_common import CALL_GRAPH_PY, preserve_function_identities, verify_function

WALK = r"""
engine, cbuf = (int(values[key]) for key in ('engine', 'cbuf'))
rcon = {int(ea) for ea in values['rcon']}
challenge = {int(ea) for ea in values['challenge']}
outer = [ea for ea in native_rcon_edges(engine) if cbuf in native_rcon_edges(ea)]
if len(outer) != 1:
    raise ValueError('expected one outer state/command frame')
inner = [ea for ea in native_rcon_edges(outer[0]) if cbuf in native_rcon_edges(ea)]
if len(inner) != 1:
    raise ValueError('expected one inner main frame')
pollers = []
for candidate in native_rcon_edges(inner[0]):
    edges = native_rcon_edges(candidate)
    # Only the source's direct dispatch or one HandleRconPacket layer.
    reachable = edges | {target for child in edges for target in native_rcon_edges(child)}
    if reachable & rcon and reachable & challenge:
        pollers.append(candidate)
if len(pollers) != 1:
    raise ValueError('expected one inactive-server RCON poller')
result = {'_Host_Frame': hex(inner[0]), 'SV_CheckForRcon': hex(pollers[0]), 'outer': hex(outer[0])}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map
    inputs = ["CEngine_Frame", "Cbuf_Execute", "SVC_ServiceChallenge", "SV_Rcon"]
    special = (Path(new_binary_dir).parent.name, platform) == ("hl-8684", "linux")
    if special:
        inputs += ["SVC_ServiceChallenge.part.6", "SV_Rcon.constprop.20"]
    owners = {}
    for name in inputs:
        owner = await verify_function(session, new_binary_dir, platform, image_base, name)
        if owner is None:
            return False
        owners[name] = owner["owner_ea"]
    values = {
        "engine": owners["CEngine_Frame"],
        "cbuf": owners["Cbuf_Execute"],
        "challenge": [owners["SVC_ServiceChallenge"]],
        "rcon": [owners["SV_Rcon"]],
    }
    if special:
        values["challenge"].append(owners["SVC_ServiceChallenge.part.6"])
        values["rcon"].append(owners["SV_Rcon.constprop.20"])
    located = await run_walk(session, CALL_GRAPH_PY + WALK, values)
    if located.get("error"):
        if debug:
            print(f"{skill_name}: {located}")
        return False
    names = ["_Host_Frame", "SV_CheckForRcon"]
    for name in names:
        output = _output_for_symbol(expected_outputs, name)
        function = await inspect_func(session, int(located[name], 0), image_base, name)
        if output is None or function is None:
            return False
        write_func_yaml(output, function)
    return await preserve_function_identities(session, expected_outputs, new_binary_dir, platform, image_base, names)
