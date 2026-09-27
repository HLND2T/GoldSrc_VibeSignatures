#!/usr/bin/env python3
"""Materialize the approved Sven client global/color predecessors.

HUD_Init is the exact public client export, following the repository's
existing client-private ABI-root policy. PrintText owns 'Server Console'.
Print is the intersection of 'misc/talk.wav' references with callers of the
already validated AllowedToPrintText body: the sound literal alone has
several owners. Both intersections were checked on Sven 8948/10257, PE/ELF.
No address, call ordinal, layout offset or prior artifact locates these roots.
"""

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _output_for_symbol,
    parse_mcp_result,
    preprocess_common_skill,
    write_func_yaml,
)

TARGET_FUNCTION_NAMES = ["HUD_Init", "CHudBaseTextBlock_Print", "CHudSayText_PrintText"]
FIELDS = ["func_name", "func_va", "func_rva", "func_size", "func_sig"]
FUNC_XREFS = [
    {
        "func_name": "CHudBaseTextBlock_Print",
        "xref_strings": ["FULLMATCH:misc/talk.wav"],
        "xref_funcs": ["TeamFortressViewport_AllowedToPrintText"],
    },
    {"func_name": "CHudSayText_PrintText", "xref_strings": ["FULLMATCH:Server Console"]},
]
LOCATE_EXPORT = r"""
def locate():
    import ida_funcs, idaapi, idautils
    if idaapi.inf_is_64bit():
        return []
    entries = set()
    for _, _, ea, name in idautils.Entries():
        if name == 'HUD_Init':
            function = ida_funcs.get_func(ea)
            if function is not None and int(function.start_ea) == ea:
                entries.add(int(ea))
    return sorted(entries)
import json
result = json.dumps({'entries': locate()})
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    located = parse_mcp_result(await session.call_tool("py_eval", {"code": LOCATE_EXPORT}))
    entries = located.get("entries", []) if isinstance(located, dict) else []
    if len(entries) != 1:
        return False
    candidate = await _inspect_function_via_mcp(session, entries[0], image_base, "HUD_Init")
    output = _output_for_symbol(expected_outputs, "HUD_Init")
    if candidate is None or output is None:
        return False
    if not await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES[1:],
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=[(name, FIELDS) for name in TARGET_FUNCTION_NAMES[1:]],
        debug=debug,
    ):
        return False
    write_func_yaml(output, {field: candidate[field] for field in FIELDS})
    return True
