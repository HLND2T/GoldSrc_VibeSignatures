#!/usr/bin/env python3
"""Recover Linux's retained filter using the poller's actual filterban operand.

The poller contains mask/expiry filtering inline or retains its direct helper.
The filtering body's writable float32 scalar is filterban; record times are
pointer members and realtime is float64. Require a
separate owner reading that exact scalar, AND/mask comparison and float-to-int
return, whose only semantic call is optional memmove. Never reuse a peer offset.
"""

from ida_preprocessor_scripts._native_rcon_common import verify_function
from ida_preprocessor_scripts._native_rcon_path_common import locate_path_functions, write_path_functions

WALK = r"""
poll,receive=(int(values[key]) for key in ('poll','receive'))
scalars=float_globals(poll)
if not scalars:
    # HL8684 Linux retains the filtering call. Use current direct callees only
    # to seed the same operand/xref search; the body checks below still identify
    # the filter. This does not assume which callee or call ordinal owns it.
    scalars={scalar for target in native_rcon_edges(poll) for scalar in float_globals(target)}
if not scalars:
    raise ValueError('missing current filterban operand')
found=[]
for candidate in {ea for scalar in scalars for ea in functions_referencing(scalar)}:
    if candidate==poll or not float_globals(candidate)&scalars:
        continue
    edges=semantic_calls(candidate)
    if receive in edges or any('memmove' not in ida_funcs.get_func_name(ea).lower() for ea in edges):
        continue
    entries=scan(candidate) or []
    mnemonics={entry['mnem'] for entry in entries}
    if ('and' not in mnemonics or 'cmp' not in mnemonics
            or not mnemonics&{'cvttss2si','cvtss2si','fistp','fisttp'}):
        continue
    found.append(candidate)
if len(found)!=1:
    raise ValueError('ambiguous retained native IP filter: %r' % found)
result={'functions':{'SV_FilterPacket':hex(found[0])}}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map
    if platform != "linux":
        return False
    values = {}
    for key, name in (("poll", "SV_CheckForRcon"), ("receive", "NET_GetPacket")):
        owner = await verify_function(session, new_binary_dir, platform, image_base, name)
        if owner is None:
            return False
        values[key] = owner["owner_ea"]
    located = await locate_path_functions(session, WALK, values)
    if debug:
        print(f"{skill_name}: {located}")
    return await write_path_functions(session, expected_outputs, new_binary_dir, platform, image_base, located)
