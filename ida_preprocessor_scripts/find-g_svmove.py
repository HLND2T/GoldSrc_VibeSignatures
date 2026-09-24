#!/usr/bin/env python3
"""Recover g_svmove from SV_Init's PM_Init argument.

Host_Init passes g_clmove to PM_Init. The same callee is reached once from
SV_Init, where the corresponding argument is g_svmove. Require the recovered
object to also be used by Host_InitializeGameDLL's game-DLL movement setup;
GCC may move that setup into a directly called split helper.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact, write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import run_walk

NAME = "g_svmove"
CLIENT_MOVE = "g_clmove"
SV_INIT = "SV_Init"
HOST_INIT = "Host_Init"
GAME_INIT = "Host_InitializeGameDLL"

WALK = r"""
import ida_gdl

host = int(values['host'], 0)
server = int(values['server'], 0)
game = int(values['game'], 0)
clmove = int(values['clmove'], 0)
host_entries = scan(host)
server_entries = scan(server)
game_entries = scan(game)
if host_entries is None or server_entries is None or game_entries is None:
    result = {'error': 'predecessor is not a function start'}
else:
    host_refs = single_globals(host_entries)
    host_calls = direct_calls(host)
    server_calls = direct_calls(server)
    common_callees = set(host_calls) & set(server_calls)
    host_sites = {ea: target for target, sites in host_calls.items() for ea in sites}
    pm_candidates = set()
    for index in host_refs.get(clmove, []):
        for entry in host_entries[index + 1:]:
            if entry['mnem'] == 'call':
                target = host_sites.get(entry['ea'])
                if target in common_callees:
                    pm_candidates.add(target)
                break
            if entry['mnem'].startswith('j') or entry['mnem'] in ('ret', 'retn'):
                break
    if len(pm_candidates) != 1:
        result = {'error': 'PM_Init callee is not unique', 'candidates': [hex(x) for x in sorted(pm_candidates)], 'clmove_host_refs': len(host_refs.get(clmove, []))}
    else:
        pm_init = next(iter(pm_candidates))
        calls = server_calls[pm_init]
        if len(calls) != 1:
            result = {'error': 'SV_Init does not call PM_Init exactly once', 'calls': [hex(x) for x in calls]}
        else:
            call_ea = calls[0]
            owner = ida_funcs.get_func(server)
            block = next((block for block in ida_gdl.FlowChart(owner) if int(block.start_ea) <= call_ea < int(block.end_ea)), None)
            if block is None:
                result = {'error': 'PM_Init call has no basic block'}
            else:
                before = [entry for entry in server_entries if int(block.start_ea) <= entry['ea'] < call_ea]
                last_call = max((i for i, entry in enumerate(before) if entry['mnem'] == 'call'), default=-1)
                argument_setup = before[last_call + 1:]
                addressable = [entry for entry in argument_setup if len(entry['targets']) == 1 and entry['disp']]
                if not addressable:
                    result = {'error': 'PM_Init argument has no decoded data reference', 'call': hex(call_ea)}
                else:
                    carrier = addressable[-1]
                    gv = next(iter(carrier['targets']))
                    if gv == clmove:
                        result = {'error': 'server PM_Init reuses client movement object'}
                    else:
                        corroborated = gv in single_globals(game_entries)
                        if not corroborated:
                            callees = set(direct_calls(game))
                            for entry in game_entries:
                                if entry['mnem'] == 'jmp':
                                    target = local_call_target(entry['ea'])
                                    if target is not None:
                                        callees.add(target)
                            for callee in callees:
                                callee_entries = scan(callee)
                                if callee_entries is not None and gv in single_globals(callee_entries):
                                    corroborated = True
                                    break
                        if not corroborated:
                            result = {'error': 'game-DLL initializer does not corroborate PM_Init object', 'gv': hex(gv), 'pm_init': hex(pm_init)}
                        else:
                            result = {'gv': access(carrier, gv), 'pm_init': hex(pm_init), 'call': hex(call_ea)}
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
    host = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, HOST_INIT)
    server = await inspect_owner_artifact(
        session, new_binary_dir, platform, image_base, SV_INIT, allow_relative_call_discriminator=True
    )
    game = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, GAME_INIT)
    clmove_artifact = _load_yaml_mapping(Path(new_binary_dir) / f"{CLIENT_MOVE}.{platform}.yaml")
    if host is None or server is None or game is None or not clmove_artifact:
        if debug:
            print(f"{skill_name}: missing or invalid predecessor artifact")
        return False
    if clmove_artifact.get("gv_name") != CLIENT_MOVE:
        return False
    try:
        clmove_ea = int(clmove_artifact["gv_va"], 0)
    except (KeyError, TypeError, ValueError):
        return False
    located = await run_walk(
        session,
        WALK,
        {
            "host": hex(host["owner_ea"]),
            "server": hex(server["owner_ea"]),
            "game": hex(game["owner_ea"]),
            "clmove": hex(clmove_ea),
        },
    )
    if located.get("error") or not located.get("gv"):
        if debug:
            print(f"{skill_name}: {located}")
        return False
    if debug:
        print(f"{skill_name}: {located['gv']['gv_ea']} via SV_Init {located['gv']['insn_disasm']}")
    return await write_located_globals(session, expected_outputs, platform, image_base, server, {NAME: located["gv"]})
