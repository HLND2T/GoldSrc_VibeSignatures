#!/usr/bin/env python3
"""Recover listener_origin from the verified S_Update body.

``engine/snd_dma.c`` S_Update opens with four ``VectorCopy`` stores,
``VectorCopy(origin, listener_origin)`` first, before any channel update.
Every listener global is a ``vec3_t`` whose ``+0 +4 +8`` members are each
written by a separate store, across the MSVC integer-register stores, the
SvEngine x87 ``fld/fstp`` pairs, and the HL25/GCC SSE ``movss`` triples, with
PIC members resolved through the shared GOT decoder. The origin copy is the
group that comes first in function instruction order, so ``listener_origin``
is the lowest-ordered writable base with all three members written.

MetaHookSv instead arms on a hand-written byte pattern per engine family; the
store-group shape is the reproducible invariant here. The finder revalidates
the produced ``S_Update`` artifact, scans its body, and fails closed unless
exactly one earliest candidate exists. No LLM step and no byte signature
participate.
"""

from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact, write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import run_walk

OWNER_NAME = "S_Update"
GV_NAME = "listener_origin"
MEMBER_OFFSETS = (0, 4, 8)

WALK = r"""
owner = int(values['owner'], 0)
entries = scan(owner)
if entries is None:
    result = {'error': 'S_Update artifact is not a function start'}
else:
    # {written address: first entry index writing it, in function order}.
    first_write = {}
    for index, entry in enumerate(entries):
        for gv in entry['written']:
            first_write.setdefault(int(gv), index)
    offsets = values['offsets']
    bases = [gv for gv in sorted(first_write)
             if all(gv + off in first_write for off in offsets)]
    if not bases:
        result = {'error': 'no vec3_t store group found in S_Update'}
    else:
        order = min(first_write[gv] for gv in bases)
        earliest = [gv for gv in bases if first_write[gv] == order]
        if len(earliest) != 1:
            result = {'error': 'earliest vec3_t store group is not unique',
                      'bases': [hex(gv) for gv in bases]}
        else:
            gv = earliest[0]
            carrier = first_addressable(entries, [index for index, entry in enumerate(entries)
                                                  if gv in entry['targets']])
            located = access(carrier, gv) if carrier is not None else None
            if located is None:
                result = {'error': 'no addressable listener_origin reference'}
            else:
                result = {'pointer_size': 4, 'owner_ea': hex(owner), 'gv': located,
                          'groups': [hex(b) for b in bases]}
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
    owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, OWNER_NAME)
    if owner is None:
        if debug:
            print(f"{skill_name}: missing or invalid {OWNER_NAME} artifact")
        return False
    located = await run_walk(session, WALK, {"owner": hex(owner["owner_ea"]), "offsets": list(MEMBER_OFFSETS)})
    if debug:
        print(f"{skill_name}: {located}")
    if located.get("error") or located.get("pointer_size") != 4:
        return False
    return await write_located_globals(session, expected_outputs, platform, image_base, owner, {GV_NAME: located["gv"]})
