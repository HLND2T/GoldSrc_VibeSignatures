#!/usr/bin/env python3
"""Recover ISurface slots from modal control flow, never from fixed indices.

The same interface getter supplies GetScreenSize, GetModalPanel and the guarded
PaintTraverse. The paint parameter is the static panel's VPANEL getter result
or its compiler-guarded inline member load. A negative modal result cannot reach
the paint call. Interface artifacts intentionally contain only slot metadata.
"""

from ida_preprocessor_scripts._vgui_paint_common import function_address, walk, write_slot


LOCATE = r"""
flow = flow_at(values['owner'],values['platform'])
calls = call_map(flow)
candidates = []
for branch in flow['branches']:
    condition = branch['condition']
    if condition is None or condition[0]!='result':
        continue
    modal = calls.get(condition[1])
    if modal is None:
        continue
    targets = virtual_targets(modal['target'])
    if len(targets)!=1:
        continue
    receiver, modal_offset = targets[0]
    getter = direct_receiver(receiver,calls)
    if getter is None or modal['args'][0]!=receiver:
        continue
    positive = reachable(flow['blocks'],branch['nonzero'])-reachable(flow['blocks'],branch['zero'])
    screen = [call for call in calls.values() if len(call['args'])>=3
              and all(a is not None and a[0]=='stack' for a in call['args'][1:3])
              and any(direct_receiver(r,calls)==getter for r,_ in virtual_targets(call['target']))]
    if len(screen)!=1:
        continue
    paints = []
    for call in calls.values():
        target = virtual_targets(call['target'])
        if call['block'] not in positive or len(target)!=1 or len(call['args'])<2:
            continue
        paint_receiver, paint_offset = target[0]
        if direct_receiver(paint_receiver,calls)!=getter or call['args'][0]!=paint_receiver or paint_offset==modal_offset:
            continue
        roots = set()
        for argument in alternatives(call['args'][1]):
            root = None
            if argument is not None and argument[0]=='result':
                producer = calls.get(argument[1])
                origins = virtual_targets(producer['target']) if producer else []
                if len(origins)==1 and producer['args'][0]==origins[0][0]:
                    root = origins[0][0]
            elif argument is not None and argument[0]=='load':
                root = argument[1]
            if root is None or root[0]!='load' or root[1] is None or root[1][0]!='const' or root[2]!=0:
                roots.add(None)
            else:
                roots.add(root)
        if None not in roots and len(roots)==1:
            paints.append(paint_offset)
    if len(paints)==1 and one_slot(screen[0]) not in (modal_offset,paints[0]):
        candidates.append((modal_offset,paints[0]))
if len(candidates)!=1:
    raise ValueError('modal surface dataflow is not unique: '+repr(candidates))
result={'modal':candidates[0][0],'paint':candidates[0][1]}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map, image_base
    owner = function_address(new_binary_dir, "CGameUI_RunFrame", platform)
    if owner is None:
        return False
    found = await walk(session, LOCATE, dict(owner=owner, platform=platform))
    if found.get("error") or set(found) != {"modal", "paint"}:
        if debug:
            print(found)
        return False
    return all(
        write_slot(expected_outputs, name, "vgui2::ISurface", method, found[key])
        for name, method, key in (
            ("ISurface_GetModalPanel", "GetModalPanel", "modal"),
            ("ISurface_PaintTraverse", "PaintTraverse", "paint"),
        )
    )
