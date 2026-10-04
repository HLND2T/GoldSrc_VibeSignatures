#!/usr/bin/env python3
"""Locate SvEngine's IP transport configuration, separately from P2P_Config."""

from ida_analyze_util import preprocess_common_skill
from ida_preprocessor_scripts._native_rcon_common import preserve_function_identities, verify_function
from ida_preprocessor_scripts._native_rcon_path_common import locate_path_functions

FIELDS = ["func_name", "func_va", "func_rva", "func_size", "func_sig"]
FUNC_XREFS = [
    {"func_name": "Sock_Config", "xref_strings": ["FULLMATCH:Local IP address: %s, SV port: %d, CL port: %d\n"]}
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    config = await verify_function(session, new_binary_dir, platform, image_base, "NET_Config")
    if config is None:
        return False
    found = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=["Sock_Config"],
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=[("Sock_Config", FIELDS)],
        debug=debug,
    )
    if not found or not await preserve_function_identities(
        session, expected_outputs, new_binary_dir, platform, image_base, ["Sock_Config"]
    ):
        return False
    sock = await verify_function(session, new_binary_dir, platform, image_base, "Sock_Config")
    if sock is None:
        return False
    check = await locate_path_functions(
        session,
        "result={'valid': values['sock'] in native_rcon_edges(values['config'])}",
        {"sock": sock["owner_ea"], "config": config["owner_ea"]},
    )
    return check.get("valid") is True
