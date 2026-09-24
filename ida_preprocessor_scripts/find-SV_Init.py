#!/usr/bin/env python3
"""Locate the engine server initializer through its dropclient registration.

``SV_Init`` registers ``dropclient`` and ``fullupdate`` in every supported
engine family. The former has one code-owning function on all configured
Windows and Linux binaries; the latter also occurs in packet parsing and is
checked as behavioral evidence rather than used alone for discovery.
"""

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _output_for_symbol,
    preprocess_func_xrefs_via_mcp,
    write_func_yaml,
)
from ida_preprocessor_scripts._engine_private_globals_common import run_walk

NAME = "SV_Init"

CHECK_FULLUPDATE = r"""
owner = int(values['owner'], 0)
found = False
for item in idautils.Strings():
    if str(item) != 'fullupdate':
        continue
    for ref in idautils.DataRefsTo(int(item.ea)):
        function = ida_funcs.get_func(int(ref))
        if function is not None and int(function.start_ea) == owner:
            found = True
result = {'fullupdate_registration': found}
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
    output = _output_for_symbol(expected_outputs, NAME)
    if output is None:
        return False
    candidate = await preprocess_func_xrefs_via_mcp(
        session=session,
        func_name=NAME,
        xref_strings=["FULLMATCH:dropclient"],
        xref_gvs=[],
        xref_signatures=[],
        xref_funcs=[],
        exclude_funcs=[],
        exclude_strings=[],
        exclude_gvs=[],
        exclude_signatures=[],
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
    )
    if not candidate:
        return False
    owner_ea = int(candidate["func_va"], 0)
    evidence = await run_walk(session, CHECK_FULLUPDATE, {"owner": hex(owner_ea)})
    if evidence.get("fullupdate_registration") is not True:
        if debug:
            print(f"{skill_name}: missing fullupdate registration in {owner_ea:#x}")
        return False
    for across_boundary in (False, True):
        function = await _inspect_function_via_mcp(
            session,
            owner_ea,
            image_base,
            NAME,
            allow_across_function_boundary=across_boundary,
            allow_relative_call_discriminator=True,
        )
        if function:
            payload = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
            if across_boundary:
                payload["func_sig_allow_across_function_boundary"] = True
            write_func_yaml(output, payload)
            if debug:
                print(f"{skill_name}: {payload['func_va']} via dropclient/fullupdate registrations")
            return True
    return False
