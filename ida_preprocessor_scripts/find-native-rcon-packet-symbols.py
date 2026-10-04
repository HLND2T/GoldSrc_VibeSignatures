#!/usr/bin/env python3
"""Locate the native ban reply and the three-command inactive-server parser.

Own literals exclude active connectionless dispatch (connect) and inline packet
readers (NET_GetPacket). Constant-array string copies are handled by exact bytes
and recorded data xrefs, without depending on IDA's string-item boundaries.
Sven Windows retains uncalled parser code whose original IDB lacks a function;
only a proven padding boundary and the current dispatch body can restore it.
"""

from pathlib import Path

from ida_analyze_util import _output_for_symbol
from ida_preprocessor_scripts._native_rcon_common import verify_function
from ida_preprocessor_scripts._native_rcon_path_common import locate_path_functions, write_path_functions

WALK = r"""
receive, send = (int(values[key]) for key in ('receive','send'))
ban = literal_owners('You have been banned from this server.\n')
ban = {ea for ea in ban if receive not in native_rcon_edges(ea) and send in native_rcon_edges(ea)}
def ban_body(ea):
    entries=scan(ea) or []
    constants={int(op.value)&0xFFFFFFFF for entry in entries for op in entry['insn'].ops
               if int(op.type)==int(idaapi.o_imm)}
    calls=[local_call_target(entry['ea']) for entry in entries if entry['mnem']=='call']
    # OOB -1 header, A2A_PRINT (108), NS_SERVER (1), and the same clear routine
    # before building and after sending. These are protocol semantics, not RVAs.
    return {0xFFFFFFFF,108,1}<=constants and any(calls.count(target)>=2 for target in set(calls)-{None,send})
ban={ea for ea in ban if ban_body(ea)}
if len(ban)!=1:
    raise ValueError('ambiguous native ban reply literal/body')
functions={'SV_SendBan':hex(next(iter(ban)))}
if values['handle']:
    protocol=('getchallenge','challenge','rcon')
    locations={text:literal_addresses(text) for text in protocol}
    if not all(locations.values()):
        raise ValueError('missing current RCON protocol literals')
    recovered=set()
    for address in locations['getchallenge']:
        for ref in elf_data_refs_to(address):
            if ida_funcs.get_func(ref) is not None or not is_code_address(ref):
                continue
            start=orphan_entry(ref)
            if start is None:
                continue
            # Check every protocol reference in the decoded orphan span before
            # creating metadata; a previous return/padding proves the boundary.
            seen=set()
            cursor=start
            for _ in range(ORPHAN_BACKTRACK_LIMIT):
                insn=ida_ua.insn_t()
                size=ida_ua.decode_insn(insn,cursor)
                if not size or cursor-start>=ORPHAN_BACKTRACK_LIMIT:
                    break
                for target in idautils.DataRefsFrom(cursor):
                    seen.update(text for text,items in locations.items() if int(target) in items)
                cursor+=int(size)
                if (idc.print_insn_mnem(cursor-int(size)) or '').lower() in ('ret','retn'):
                    span=scan(start,cursor) or []
                    edges={local_call_target(entry['ea']) for entry in span
                           if entry['mnem'] in ('call','jmp')}
                    if (seen==set(protocol) and edges&set(values['rcon'])
                            and edges&set(values['challenge']) and ida_funcs.add_func(start,cursor)):
                        recovered.add(start)
                    break
    owners=set.intersection(*(literal_owners(text) for text in protocol))
    owners-=literal_owners('connect')
    owners={ea for ea in owners if receive not in native_rcon_edges(ea)}
    owners={ea for ea in owners if native_rcon_edges(ea)&set(values['rcon'])
            and native_rcon_edges(ea)&set(values['challenge'])}
    if len(owners)!=1:
        raise ValueError('ambiguous independent three-command RCON parser')
    functions['SV_HandleRconPacket']=hex(next(iter(owners)))
result={'functions':functions}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map
    names = ["NET_GetPacket", "NET_SendPacket", "SV_Rcon", "SVC_ServiceChallenge"]
    special = (Path(new_binary_dir).parent.name, platform) == ("hl-8684", "linux")
    if special:
        names += ["SV_Rcon.constprop.20", "SVC_ServiceChallenge.part.6"]
    inputs = {}
    for name in names:
        owner = await verify_function(session, new_binary_dir, platform, image_base, name)
        if owner is None:
            return False
        inputs[name] = owner["owner_ea"]
    values = {
        "receive": inputs["NET_GetPacket"],
        "send": inputs["NET_SendPacket"],
        "handle": bool(_output_for_symbol(expected_outputs, "SV_HandleRconPacket")),
        "rcon": [inputs["SV_Rcon"]],
        "challenge": [inputs["SVC_ServiceChallenge"]],
    }
    if special:
        values["rcon"].append(inputs["SV_Rcon.constprop.20"])
        values["challenge"].append(inputs["SVC_ServiceChallenge.part.6"])
    located = await locate_path_functions(session, WALK, values)
    if debug:
        print(f"{skill_name}: {located}")
    return await write_path_functions(session, expected_outputs, new_binary_dir, platform, image_base, located)
