#!/usr/bin/env python3
"""Identify IPanel visibility, popup-state and paint slots by their source roles."""

from ida_preprocessor_scripts._vgui_paint_common import function_address, walk, write_slot


LOCATE = r"""
flow=flow_at(values['owner'],values['platform'])
calls=call_map(flow)
guarded={b['condition'][1] for b in flow['branches'] if b['condition'] and b['condition'][0]=='result'}
candidates=[]
for guard in flow['branches']:
    condition=guard['condition']
    visible=calls.get(condition[1]) if condition and condition[0]=='result' else None
    if not visible or len(visible['args'])<2 or visible['args'][1]!=('arg',1):
        continue
    targets=virtual_targets(visible['target'])
    if len(targets)!=1:
        continue
    receiver,visible_offset=targets[0]
    getter=direct_receiver(receiver,calls)
    if getter is None or visible['args'][0]!=receiver:
        continue
    group=[]
    for call in calls.values():
        targets=virtual_targets(call['target'])
        if targets and all(direct_receiver(r,calls)==getter for r,_ in targets):
            if choice(*(r for r,_ in targets))==call['args'][0]:
                group.append(call)
    positive=reachable(flow['blocks'],guard['nonzero'])-reachable(flow['blocks'],guard['zero'])
    paint=[c for c in group if c['ea'] not in guarded and len(c['args'])>=4
           and c['args'][2:4]==[('const',1),('const',1)] and c['block'] in positive]
    paint_slots={one_slot(c) for c in paint}
    if len(paint)<2 or len(paint_slots)!=1 or None in paint_slots or not any(c['args'][1]==('arg',1) for c in paint):
        continue
    popup=[]
    for call in group:
        if call['ea'] in guarded or len(call['args'])<3 or call['args'][2]!=('const',0) or call['block'] not in positive:
            continue
        if any(call['block'] in reachable(flow['blocks'],s) for s in flow['blocks'].get(call['block'],[])):
            popup.append(call)
    if len(popup)!=1 or one_slot(popup[0]) is None:
        continue
    selected=(visible_offset,one_slot(popup[0]),next(iter(paint_slots)))
    if len(set(selected))==3:
        candidates.append(selected)
if len(candidates)!=1:
    raise ValueError('IPanel paint roles disagree: '+repr(candidates))
result=dict(zip(('visible','popup','paint'),candidates[0]))
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map, image_base
    owner = function_address(new_binary_dir, "BaseUISurface_PaintTraverse", platform)
    if owner is None:
        return False
    found = await walk(session, LOCATE, dict(owner=owner, platform=platform))
    if found.get("error") or set(found) != {"visible", "popup", "paint"}:
        if debug:
            print(found)
        return False
    return all(
        write_slot(expected_outputs, name, "vgui2::IPanel", method, found[key])
        for name, method, key in (
            ("vgui2_IPanel_IsVisible", "IsVisible", "visible"),
            ("vgui2_IPanel_Render_SetPopupVisible", "Render_SetPopupVisible", "popup"),
            ("vgui2_IPanel_PaintTraverse", "PaintTraverse", "paint"),
        )
    )
