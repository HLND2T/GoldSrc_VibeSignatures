#!/usr/bin/env python3
"""Locate the standalone Sven sentence-index lookup (8948/10257, PE/ELF).

The diagnostic is also inlined into PlayFMODSound, so it cannot select an
owner alone. Two body patterns encode index <= 4095, two null checks, and
returning the sample string. Member displacements and branches are wildcarded.
Windows starts at the callable entry; Linux matches inside the existing owner.
The explicit-entry inspector recovers the Windows function missing from the
warm IDB. Verify the diagnostic owner and exclude the independently anchored
PlayFMODSound before emitting a fresh unique signature. No old YAML discovery.
"""

import json
from pathlib import Path

import yaml

from ida_analyze_util import (
    _find_byte_matches,
    _inspect_function_via_mcp,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)
from ida_preprocessor_scripts._sven_client_pic_common import PIC_STRING_OWNERS_PY, exact_string_ea

TARGET_FUNCTION_NAMES = ["CClient_SoundEngine_LookupSoundBySentenceIndex"]
SIGNATURES = [
    "8B 54 24 04 81 FA FF 0F 00 00 77 ?? 83 3C 91 00 74 ?? 0F AE E8 8B 04 91 83 78 ?? 00 74 ?? 0F AE E8 8B 04 91 8B 40 ?? 83 C0 ?? C2 04 00",
    "8B 44 24 ?? 3D FF 0F 00 00 77 ?? 8B 54 24 ?? 8B 0C 82 85 C9 74 ?? 8B 41 ?? 85 C0 74 ?? 83 C0 ?? 83 C4 ?? 5B C3",
]
LITERAL = "Tried to look up sound by sentence index out of bounds.\n"
OWNER_CODE = r"""
import ida_funcs, json
function = ida_funcs.get_func(HIT)
result = json.dumps({'owner': int(function.start_ea) if function else None})
"""
DIRECT_REFERENCE_CODE = r"""
import idautils, ida_funcs, json
owners = set()
for xref in idautils.XrefsTo(STRING_EA, 0):
    function = ida_funcs.get_func(xref.frm)
    if function:
        owners.add(hex(int(function.start_ea)))
result = json.dumps({'owners': sorted(owners)})
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    for index, signature in enumerate(SIGNATURES):
        matches = await _find_byte_matches(session, signature, limit=2)
        if matches is None or len(matches) > 1:
            return False
        if matches:
            break
    else:
        return False
    hit = matches[0]
    if index == 0:
        owner = hit
    else:
        located = parse_mcp_result(await session.call_tool("py_eval", {"code": OWNER_CODE.replace("HIT", str(hit))}))
        owner = located.get("owner") if isinstance(located, dict) else None
    if not isinstance(owner, int):
        return False
    name = TARGET_FUNCTION_NAMES[0]
    candidate = await _inspect_function_via_mcp(session, owner, image_base, name)
    if candidate is None:
        return False
    sibling_path = Path(new_binary_dir) / f"CClient_SoundEngine_PlayFMODSound.{platform}.yaml"
    sibling = yaml.safe_load(sibling_path.read_text(encoding="utf-8"))
    if int(str(sibling["func_va"]), 0) == owner:
        return False
    string_ea = await exact_string_ea(session, LITERAL)
    if string_ea is None:
        return False
    references = parse_mcp_result(
        await session.call_tool(
            "py_eval",
            {"code": DIRECT_REFERENCE_CODE.replace("STRING_EA", str(string_ea))},
        )
    )
    if platform == "linux" and isinstance(references, dict) and hex(owner) not in references.get("owners", []):
        references = parse_mcp_result(
            await session.call_tool(
                "py_eval",
                {"code": PIC_STRING_OWNERS_PY.replace("VALUES", json.dumps({"string_ea": string_ea}))},
            )
        )
    if not isinstance(references, dict) or owner not in {int(value, 0) for value in references.get("owners", [])}:
        if debug:
            print(f"  {name}: recovered body does not own the diagnostic: {references}")
        return False
    output = _output_for_symbol(expected_outputs, name)
    if output is None:
        return False
    write_func_yaml(
        output,
        {key: candidate[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")},
    )
    return True
