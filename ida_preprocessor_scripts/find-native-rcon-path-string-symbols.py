#!/usr/bin/env python3
"""Locate native send and failed-RCON accounting by exact target-owned strings.

The failure log also belongs to an inlined HL8684 Linux Validate copy; exclude
its own Banning diagnostic. NET_SendPacket remains the native entry, including
SvEngine's downstream transport wrapper and by-value 36-byte netadr ABI.
"""

from ida_analyze_util import preprocess_common_skill
from ida_preprocessor_scripts._native_rcon_common import preserve_function_identities

NAMES = ["NET_SendPacket", "SV_AddFailedRcon"]
FUNC_XREFS = [
    {"func_name": "NET_SendPacket", "xref_strings": ["FULLMATCH:NET_SendPacket: bad address type"]},
    {
        "func_name": "SV_AddFailedRcon",
        "xref_strings": ["FULLMATCH:User %s will be banned for rcon hacking\n"],
        "exclude_strings": ["FULLMATCH:Banning %s for rcon hacking attempts\n"],
    },
]
FIELDS = ["func_name", "func_va", "func_rva", "func_size", "func_sig"]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    found = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=NAMES,
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=[(name, FIELDS) for name in NAMES],
        debug=debug,
    )
    return found and await preserve_function_identities(
        session, expected_outputs, new_binary_dir, platform, image_base, NAMES
    )
