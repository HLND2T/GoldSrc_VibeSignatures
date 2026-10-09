#!/usr/bin/env python3
"""Locate three callable lifetime methods through verified body statements.

The first matching pattern must identify exactly one owner; ambiguity fails
without trying a weaker pattern. Each target uses three patterns for the four
Sven 5.15/5.16 PE32/ELF32 inputs. No entry/prologue pattern or prior YAML is used.

InternalRelease: decrement the pointed-to count and return whether it is zero.
Its entire Windows body is seven bytes; Linux starts after the this load (+4).
Any Release: clear gcFlag, atomically decrement refCount and read the remaining
count on the nonzero path. Windows starts at +4 and has count/flag at +8/+12;
Linux starts at +20 and has them at +4/+8. The Windows asext Any caller pattern
actually calls Array Release and is deliberately not reused.
Function Create: conditionally release the incoming asIScriptFunction when the
bool ownership argument is true, then return the new CASFunction. Patterns start
at +0x98 (Windows), +0x59 (5.15 Linux) and +0x55 (5.16 Linux).
The located factories also reject a null function, allocate/construct the
callable and acquire its function/module references; they have no this argument.
"""

from pathlib import Path

from as_callable_artifacts import publish_callable_identities
from ida_analyze_util import (
    _find_byte_matches,
    _inspect_function_via_mcp,
    parse_mcp_result,
    preprocess_common_skill,
    write_func_yaml,
)

BODY_SIGNATURES = {
    "CASRefCountedBaseClass_InternalRelease": {
        "windows": ["83 01 FF 0F 94 C0 C3"],
        "linux": ["FF 0A 0F 94 C0 C3", "83 2A 01 0F 94 C0 C3"],
    },
    "CScriptAny_Release": {
        "windows": ["8D 7E 08 C6 46 0C 00 57 E8 ?? ?? ?? ?? 83 C4 04 85 C0 75 ??"],
        "linux": [
            "C6 46 08 00 8D 46 04 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 ?? 8B 46 04",
            "C6 46 08 00 8D 46 04 89 04 24 E8 ?? ?? ?? ?? 85 C0 74 ?? 8B 46 04",
        ],
    },
    "CASFunction_Create": {
        "windows": ["80 7D 10 00 C7 45 FC FF FF FF FF 74 ?? 8B 17 8B CF FF 52 08 8B C6"],
        "linux": [
            "8B 1F 57 FF 53 08 83 C4 10 89 F0",
            "8B 5D 00 89 2C 24 FF 53 08 89 F0",
        ],
    },
}
GENERATE_YAML_DESIRED_FIELDS = [
    (
        name,
        ["func_name", "func_va", "func_rva", "func_size", "func_sig", "func_sig_allow_across_function_boundary:true"],
    )
    for name in BODY_SIGNATURES
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    for name, patterns in BODY_SIGNATURES.items():
        selected = None
        for pattern in patterns[platform]:
            matches = await _find_byte_matches(session, pattern)
            if matches is None:
                return False
            if matches:
                selected = pattern
                break
        if selected is None:
            return False
        outputs = [path for path in expected_outputs if Path(path).name == f"{name}.{platform}.yaml"]
        if name == "CASRefCountedBaseClass_InternalRelease" and platform == "windows":
            # This anchor is the complete seven-byte body. The generic owner
            # backtracker sees nearby CALL entries at a tiny function's start;
            # require exact current-IDB boundaries instead of guessing an owner.
            if len(matches) != 1 or len(outputs) != 1:
                return False
            entry = matches[0]
            proof = parse_mcp_result(
                await session.call_tool(
                    "py_eval",
                    {
                        "code": f"""
import ida_funcs, json
fn = ida_funcs.get_func({entry})
result = json.dumps({{'exact_body': bool(fn is not None and fn.start_ea == {entry} and fn.end_ea == {entry + 7})}})
"""
                    },
                )
            )
            if not isinstance(proof, dict) or not proof.get("exact_body"):
                return False
            payload = await _inspect_function_via_mcp(
                session,
                entry,
                image_base,
                name,
                allow_across_function_boundary=True,
            )
            if payload is None:
                return False
            payload.pop("_pointer_size", None)
            payload["func_sig_allow_across_function_boundary"] = True
            write_func_yaml(outputs[0], payload)
            publish_callable_identities(outputs, platform)
            continue
        if not await preprocess_common_skill(
            session=session,
            expected_outputs=outputs,
            old_yaml_map=None,
            new_binary_dir=new_binary_dir,
            platform=platform,
            image_base=image_base,
            func_names=[name],
            func_xrefs=[{"func_name": name, "xref_signatures": [selected]}],
            generate_yaml_desired_fields=[fields for fields in GENERATE_YAML_DESIRED_FIELDS if fields[0] == name],
            debug=debug,
        ):
            return False
        publish_callable_identities(outputs, platform)
    return True
