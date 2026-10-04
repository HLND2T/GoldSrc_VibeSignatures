#!/usr/bin/env python3
"""Publish the single main-frame Cbuf call as a patch, retaining ELF identities.

The address is a five-byte E8 instruction, not a function. Consumers can compare
its return address (callsite + 5) to distinguish initialization, state changes
and nested command execution. This locator never modifies binary bytes.
"""

from ida_analyze_util import _find_unique_bytes, _output_for_symbol, write_patch_yaml
from ida_preprocessor_scripts._func_to_func_callsites_common import locate_callsites
from ida_preprocessor_scripts._native_rcon_common import verify_function

NAME = "_Host_Frame_to_Cbuf_Execute_callsite_0"
CALL_LENGTH = 5


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map
    output = _output_for_symbol(expected_outputs, NAME)
    owner = await verify_function(session, new_binary_dir, platform, image_base, "_Host_Frame")
    callee = await verify_function(session, new_binary_dir, platform, image_base, "Cbuf_Execute")
    if output is None or owner is None or callee is None:
        return False
    found = await locate_callsites(session, owner["owner_ea"], callee["owner_ea"])
    if not found or found.get("error") or found.get("pointer_size") != 4 or len(found.get("sites", [])) != 1:
        return False
    site = found["sites"][0]
    if (
        int(site["insn_len"]) != CALL_LENGTH
        or not site["disasm"].lstrip().startswith("call")
        or site["patch_sig"].split()[0].upper() != "E8"
    ):
        return False
    address = int(site["ea"], 0)
    if int(site["patch_sig_disp"]) != 0 or await _find_unique_bytes(session, site["patch_sig"]) != address:
        return False
    write_patch_yaml(
        output,
        {
            "patch_name": NAME,
            "patch_va": hex(address),
            "patch_rva": hex(address - image_base),
            "patch_sig": site["patch_sig"],
            "patch_sig_disp": 0,
        },
    )
    if debug:
        print(f"{skill_name}: main-frame call={address:#x}, return={address + CALL_LENGTH:#x}")
    return True
