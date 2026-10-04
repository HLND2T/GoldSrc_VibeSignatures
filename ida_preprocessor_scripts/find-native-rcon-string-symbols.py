#!/usr/bin/env python3
"""Locate native RCON entries through their own exact diagnostic/protocol strings.

HL25 Windows inlines Validate into Rcon and declares no Validate func output.
SvEngine Windows retains both bodies; exclude Rcon's own Empty-rcon literal to
select the standalone validator. HL 8684 Linux splits ServiceChallenge and clones
Rcon. Publish both real ELF entries there, with independent string ownership and
wrapper-call validation; do not substitute the no-argument clone's ABI for Rcon.
"""

from pathlib import Path

from ida_analyze_util import _output_for_symbol, preprocess_common_skill, write_func_yaml
from ida_preprocessor_scripts._engine_private_globals_common import inspect_func, run_walk
from ida_preprocessor_scripts._native_rcon_common import CALL_GRAPH_PY, preserve_function_identities
from ida_preprocessor_scripts.renderer_elf_symbols import STT_FUNC, current_elf_symbols, select_symbol

SVC = "SVC_ServiceChallenge"
PART = "SVC_ServiceChallenge.part.6"
RCON = "SV_Rcon"
CLONE = "SV_Rcon.constprop.20"
DIRECT_XREFS = [
    {"func_name": "SV_CheckChallenge", "xref_strings": ["FULLMATCH:SV_CheckChallenge:  Null address\n"]},
    {"func_name": "SV_FlushRedirect", "xref_strings": ["FULLMATCH:Redirected Text"]},
    {
        "func_name": "SV_Rcon_Validate",
        "xref_strings": ["FULLMATCH:Banning %s for rcon hacking attempts\n"],
        "exclude_strings": ["FULLMATCH:Empty rcon\n"],
    },
]
FIELDS = ["func_name", "func_va", "func_rva", "func_size", "func_sig"]
WALK = r"""
svc_owners = set()
rcon_owners = set()
for literal, owners in ((values['svc_literal'], svc_owners), (values['rcon_literal'], rcon_owners)):
    matches = [int(item.ea) for item in idautils.Strings() if str(item) == literal]
    if len(matches) != 1:
        raise ValueError('expected one exact RCON literal: %r' % literal)
    for ref in idautils.DataRefsTo(matches[0]):
        f = ida_funcs.get_func(int(ref))
        if f is not None:
            owners.add(int(f.start_ea))
if values['special']:
    svc, part, rcon, clone = (int(values[key]) for key in ('svc', 'part', 'rcon', 'clone'))
    if svc_owners != {part} or rcon_owners != {rcon, clone}:
        raise ValueError('ELF entries disagree with current literal owners')
    calls = native_rcon_edges(svc)
    argc = {ea for ea in calls if ida_funcs.get_func_name(ea) == 'Cmd_Argc'}
    compares = [entry for entry in scan(svc) or [] if entry['mnem'] == 'cmp'
                and any(int(op.type) == int(idaapi.o_imm) and int(op.value) == 2
                        for op in entry['insn'].ops)]
    if len(argc) != 1 or calls != argc | {part} or len(compares) != 1:
        raise ValueError('ServiceChallenge wrapper lacks the verified argc==2/core path')
    result = {'functions': {'SVC_ServiceChallenge': hex(svc),
                           'SVC_ServiceChallenge.part.6': hex(part),
                           'SV_Rcon': hex(rcon), 'SV_Rcon.constprop.20': hex(clone)}}
elif len(svc_owners) == len(rcon_owners) == 1:
    result = {'functions': {'SVC_ServiceChallenge': hex(next(iter(svc_owners))),
                           'SV_Rcon': hex(next(iter(rcon_owners)))}}
else:
    raise ValueError('RCON string owners are absent or ambiguous')
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map
    direct = [xref for xref in DIRECT_XREFS if _output_for_symbol(expected_outputs, xref["func_name"])]
    names = [xref["func_name"] for xref in direct]
    if not await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=names,
        func_xrefs=direct,
        generate_yaml_desired_fields=[(name, FIELDS) for name in names],
        debug=debug,
    ):
        return False
    special = (Path(new_binary_dir).parent.name, platform) == ("hl-8684", "linux")
    if special != bool(_output_for_symbol(expected_outputs, PART)) or special != bool(
        _output_for_symbol(expected_outputs, CLONE)
    ):
        return False
    values = {"special": special, "svc_literal": "%c%c%c%cchallenge %s %u\n", "rcon_literal": "Empty rcon\n"}
    if special:
        symbols = await current_elf_symbols(session, [SVC, PART, RCON, CLONE])
        values.update(
            {
                key: int(image_base) + select_symbol(symbols, name, STT_FUNC)
                for key, name in (("svc", SVC), ("part", PART), ("rcon", RCON), ("clone", CLONE))
            }
        )
    located = await run_walk(session, CALL_GRAPH_PY + WALK, values)
    if located.get("error") or not located.get("functions"):
        if debug:
            print(f"{skill_name}: {located}")
        return False
    for name, address in located["functions"].items():
        output = _output_for_symbol(expected_outputs, name)
        function = await inspect_func(session, int(address, 0), image_base, name)
        if output is None or function is None:
            return False
        write_func_yaml(output, function)
        names.append(name)
    return await preserve_function_identities(session, expected_outputs, new_binary_dir, platform, image_base, names)
