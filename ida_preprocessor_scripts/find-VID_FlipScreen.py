#!/usr/bin/env python3
"""Recover the VID_FlipScreen function-pointer global from GL_EndRendering.

engine/gl_vidnt.c calls VID_FlipScreen() at the end of GL_EndRendering.
BLOB/CoF keep only a 6-11 byte forwarding wrapper through that pointer; GoldSrc
and HL25 keep the full FBO body, which also calls a packed table of qgl
function pointers. The requested object is the unique writable 4-byte pointer
used as a call/jmp operand that does not sit in that packed table (address gap
> 0x400 from the other call-pointer globals in the same function).

SvEngine inlines the swap and exports VID_FlipScreen as a function, so this
finder is not registered on svencoop-*.
"""

from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact, write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import run_walk

OWNER_NAME = "GL_EndRendering"
GV_NAME = "VID_FlipScreen"
CLUSTER_GAP = 0x400

WALK = r"""
OWNER = int(values['owner'], 0)
CLUSTER_GAP = int(values['cluster_gap'])

entries = scan(OWNER)
if entries is None:
    result = {'error': 'GL_EndRendering is not a function start'}
else:
    hits = []
    for entry in entries:
        if entry['mnem'] not in ('call', 'jmp'):
            continue
        for gv in entry['targets']:
            hits.append((int(entry['ea']), int(gv), entry))
    gvs = sorted({gv for _ea, gv, _entry in hits})
    if not gvs:
        result = {'error': 'GL_EndRendering has no writable call/jmp pointer'}
    else:
        clusters = []
        current = [gvs[0]]
        for gv in gvs[1:]:
            if gv - current[-1] <= CLUSTER_GAP:
                current.append(gv)
            else:
                clusters.append(current)
                current = [gv]
        clusters.append(current)
        singletons = [group[0] for group in clusters if len(group) == 1]
        if len(singletons) != 1:
            result = {
                'error': 'VID_FlipScreen pointer cluster is not unique: %s'
                % [hex(value) for value in singletons]
            }
        else:
            gv = singletons[0]
            chosen = None
            for _ea, target, entry in hits:
                if target == gv and entry['disp']:
                    chosen = entry
                    break
            located = access(chosen, gv)
            if located is None:
                result = {'error': 'VID_FlipScreen reference has no addressable displacement'}
            else:
                result = {'pointer_size': 4, 'gv': located}
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
            print(f"{skill_name}: missing {OWNER_NAME} artifact")
        return False
    located = await run_walk(session, WALK, {"owner": hex(owner["owner_ea"]), "cluster_gap": CLUSTER_GAP})
    if located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"{skill_name}: {located.get('error')}")
        return False
    if not await write_located_globals(
        session, expected_outputs, platform, image_base, owner, {GV_NAME: located["gv"]}
    ):
        return False
    if debug:
        print(f"{skill_name}: {GV_NAME}={located['gv']['gv_ea']}")
    return True
