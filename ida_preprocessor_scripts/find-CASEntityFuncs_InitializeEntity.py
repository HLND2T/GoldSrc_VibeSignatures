#!/usr/bin/env python3
"""Anchor InitializeEntity with its two exact CreateCustomEntity diagnostics.

The diagnostic text names CreateCustomEntity, but the retained 5.15 ELF symbol
and the verified key/value dispatch loop identify InitializeEntity. Both exact
literals must independently identify the same unique owner. The shared PIC
string-owner helper recovers 5.15 ELF GOTOFF operands without inventing xrefs.
This supporting function is an ordinary func, not a callsite or iterator method.
"""

from ida_analyze_util import _inspect_function_via_mcp, _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._sven_client_pic_common import unique_string_owner_ea

SYMBOL = "CASEntityFuncs_InitializeEntity"
IDENTITY = "CASEntityFuncs::InitializeEntity(const CString&, CBaseEntity*, CScriptDictionary*)"
LITERALS = [
    "CASEntityFuncs::CreateCustomEntity: failed to retrieve value for key '%s' from dictionary!\n",
    "CASEntityFuncs::CreateCustomEntity: failed to get string type!\n",
]
BODY_SIGNATURE_BYTE_LIMIT = 256


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map, new_binary_dir
    if platform not in {"windows", "linux"}:
        return False
    owners = [await unique_string_owner_ea(session, literal, label=SYMBOL, debug=debug) for literal in LITERALS]
    if None in owners or len(set(owners)) != 1:
        return False
    output = _output_for_symbol(expected_outputs, SYMBOL)
    if output is None:
        return False
    payload = await _inspect_function_via_mcp(
        session, owners[0], image_base, IDENTITY, signature_byte_limit=BODY_SIGNATURE_BYTE_LIMIT
    )
    if payload is None:
        return False
    payload.pop("_pointer_size", None)
    write_func_yaml(output, payload)
    return True
