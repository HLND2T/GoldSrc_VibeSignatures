#!/usr/bin/env python3
"""Locate dictionary iterator members through approved, budgeted body patterns.

These tiny bodies have no strings or floating-point anchors. begin/end create
an eight-byte {node, dictionary} iterator; GetKey returns the node's CString;
operator!= compares node pointers; GetValue forwards the dictionary engine,
output buffer and integer typeId to CScriptDictValue::Get. Windows ++ follows
the next node. Each pattern encodes those complete statements, not a prologue.
The 5.15 Linux begin/end/GetValue patterns start after their PIC headers.
Call displacements are wildcarded. The budgets are three patterns for each
begin/end, two for GetKey/!= and four for GetValue across all four inputs.

Selection tries patterns in order, advancing only on zero hits. Malformed or
ambiguous matches fail closed. Old artifacts never participate in discovery.
Current body/ABI evidence is recorded in the iterator locator memory note.
Linux prefix/postfix ++ have identical bodies; the separate Linux decompile
finder distinguishes the prefix call inside InitializeEntity. Output-only
signatures may cross tiny function boundaries to establish uniqueness.
"""

from ida_analyze_util import (
    _find_byte_matches,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)
from script_dictionary_artifacts import inspect_dictionary_function

BODY_SIGNATURES = {
    "windows": {
        "CScriptDictionary_begin": ["8B 41 14 8B 10 8B 44 24 04 89 10 89 48 04 C2 04 00"],
        "CScriptDictionary_end": ["8B 44 24 04 8B 51 14 89 10 89 48 04 C2 04 00"],
        "CScriptDictionary_CIterator_GetKey": ["8B 01 83 C0 08 C3"],
        "CScriptDictionary_CIterator_operator_NE": ["8B 44 24 04 8B 09 3B 08 0F 95 C0 C2 04 00"],
        "CScriptDictionary_CIterator_GetValue": [
            "FF 74 24 08 8B 41 04 FF 74 24 08 8B 09 83 C1 30 FF 70 04 E8 ?? ?? ?? ?? C2 08 00",
            "FF 74 24 08 8B 41 04 8B 11 FF 74 24 08 FF 70 04 8D 4A 30 E8 ?? ?? ?? ?? C2 08 00",
        ],
        "CScriptDictionary_CIterator_operator_PP": ["8B 01 8B 00 89 01 C3"],
    },
    "linux": {
        "CScriptDictionary_begin": [
            "8B 50 18 52 50 56 E8 ?? ?? ?? ?? 89 F0 83 C4 14 5B 5E C2 04 00",
            "8B 44 24 04 8B 54 24 08 8B 4A 18 89 08 89 50 04 C2 04 00",
        ],
        "CScriptDictionary_end": [
            "8B 74 24 14 6A 00 8B 44 24 1C 50 56 E8 ?? ?? ?? ?? 89 F0 83 C4 14 5B 5E C2 04 00",
            "8B 44 24 04 C7 00 00 00 00 00 8B 54 24 08 89 50 04 C2 04 00",
        ],
        "CScriptDictionary_CIterator_GetKey": ["8B 44 24 04 8B 00 83 C0 04 C3"],
        "CScriptDictionary_CIterator_operator_NE": ["8B 44 24 08 8B 54 24 04 8B 08 39 0A 0F 95 C0 C3"],
        "CScriptDictionary_CIterator_GetValue": [
            (
                "8B 44 24 10 8B 54 24 18 52 8B 4C 24 18 51 8B 50 04 8B 4A 04 51 8B 00 83 C0 28 50 "
                "E8 ?? ?? ?? ?? 83 C4 18 5B C3"
            ),
            (
                "8B 44 24 20 8B 54 24 28 89 54 24 0C 8B 4C 24 24 89 4C 24 08 8B 50 04 8B 4A 04 "
                "89 4C 24 04 8B 00 83 C0 28 89 04 24 E8 ?? ?? ?? ?? 83 C4 1C C3"
            ),
        ],
    },
}


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    patterns = BODY_SIGNATURES.get(platform)
    if patterns is None:
        return False
    located = []
    for symbol, alternatives in patterns.items():
        for signature in alternatives:
            matches = await _find_byte_matches(session, signature, limit=2)
            if matches is None or len(matches) > 1:
                return False
            if matches:
                # A short member can begin at the match. Generic owner
                # backtracking sees adjacent callable entries and is ambiguous;
                # require the entire approved statement inside this IDA body.
                code = (
                    "import ida_funcs, ida_segment, idaapi, json\n"
                    f"hit = {matches[0]}\n"
                    f"length = {len(signature.split())}\n"
                    "fn = ida_funcs.get_func(hit)\n"
                    "seg = ida_segment.getseg(hit)\n"
                    "valid = (not idaapi.inf_is_64bit() and fn is not None and seg is not None "
                    "and seg.perm & ida_segment.SEGPERM_EXEC and fn.start_ea <= hit "
                    "and hit + length <= fn.end_ea)\n"
                    "result = json.dumps({'entry': int(fn.start_ea) if valid else None})\n"
                )
                owner = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
                if not isinstance(owner, dict) or owner.get("entry") is None:
                    return False
                located.append((symbol, int(owner["entry"])))
                break
        else:
            return False
    for symbol, entry in located:
        output = _output_for_symbol(expected_outputs, symbol)
        if output is None:
            return False
        payload = await inspect_dictionary_function(session, entry, image_base, symbol)
        if payload is None:
            return False
        write_func_yaml(output, payload)
    return True
