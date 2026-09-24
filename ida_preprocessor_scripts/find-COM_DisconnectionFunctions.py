#!/usr/bin/env python3
"""Recover both explanation callees from CL_Parse_Disconnect's message branches.

The svc_disconnect table already identifies CL_Parse_Disconnect. Its nonempty
message branch passes the Extended GameUI token to COM_ExplainDisconnection,
then passes the server message to COM_ExtendedExplainDisconnection. The empty
branch calls the same basic explanation function with the shorter GameUI token.
Calls are resolved through ELF PLT thunks before either callee is emitted.
"""

from ida_analyze_util import _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact
from ida_preprocessor_scripts._engine_private_globals_common import inspect_func, run_walk

OWNER_NAME = "CL_Parse_Disconnect"
FUNCTION_NAMES = ("COM_ExplainDisconnection", "COM_ExtendedExplainDisconnection")

WALK = r"""
import ida_gdl

OWNER = int(values['owner'], 0)
LITERALS = {
    'extended': b'#GameUI_DisconnectedFromServerExtended\0',
    'basic': b'#GameUI_DisconnectedFromServer\0',
}


def call_after_literal(function, needle):
    sites = []
    for block in ida_gdl.FlowChart(function):
        items = list(idautils.Heads(int(block.start_ea), int(block.end_ea)))
        for index, ea in enumerate(items):
            if not any(ida_bytes.get_bytes(int(ref), len(needle)) == needle
                       for ref in idautils.DataRefsFrom(int(ea))):
                continue
            calls = []
            for following in items[index + 1:]:
                if (idc.print_insn_mnem(int(following)) or '').lower() != 'call':
                    continue
                target = local_call_target(following)
                if target is None:
                    return None
                calls.append((int(following), target))
                if len(calls) == 2:
                    break
            sites.append(calls)
    return sites[0] if len(sites) == 1 else None


function = ida_funcs.get_func(OWNER)
if function is None or int(function.start_ea) != OWNER:
    result = {'error': 'CL_Parse_Disconnect artifact is not a function start'}
else:
    extended = call_after_literal(function, LITERALS['extended'])
    basic = call_after_literal(function, LITERALS['basic'])
    if extended is None or len(extended) != 2 or basic is None or not basic:
        result = {'error': 'disconnect explanation callsites are missing or ambiguous'}
    elif extended[0][1] != basic[0][1] or extended[0][1] == extended[1][1]:
        result = {'error': 'disconnect branches do not agree on explanation callees'}
    else:
        result = {
            'pointer_size': 4,
            'basic': hex(extended[0][1]),
            'extended': hex(extended[1][1]),
            'basic_call': hex(extended[0][0]),
            'extended_call': hex(extended[1][0]),
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
    outputs = {name: _output_for_symbol(expected_outputs, name) for name in FUNCTION_NAMES}
    if any(output is None for output in outputs.values()):
        return False
    owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, OWNER_NAME)
    if owner is None:
        return False
    located = await run_walk(session, WALK, {"owner": hex(owner["owner_ea"])})
    if located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"{skill_name}: {located.get('error')}")
        return False
    payloads = {}
    for name, key in zip(FUNCTION_NAMES, ("basic", "extended")):
        payloads[name] = await inspect_func(session, int(located[key], 0), image_base, name)
        if payloads[name] is None:
            return False
    for name, payload in payloads.items():
        write_func_yaml(outputs[name], payload)
    if debug:
        print(f"{skill_name}: {located}")
    return True
