#!/usr/bin/env python3
"""Find Panel(Panel*, const char*) in the control factory's Panel branch.

The equality branch must call a constructor with two null arguments on a newly
returned allocation. Its body must install the current engine Panel primary
vptr. No constructor order, allocation size, or reference-build address is used.
"""

from ida_preprocessor_scripts._vgui_paint_common import artifact, function_address, walk, write_function


LOCATE = r"""
flow=flow_at(values['owner'],values['platform'])
calls=call_map(flow)
matches=set()
for comparison in calls.values():
    args=comparison['stack_args']
    if len(args)<2 or args[0]!=('arg',1) or args[1] is None or args[1][0]!='const':
        continue
    literal=idc.get_strlit_contents(args[1][1],-1,ida_nalt.STRTYPE_C)
    if literal!=b'Panel':
        continue
    guards=[b for b in flow['branches'] if b['condition']==('result',comparison['ea'])]
    for guard in guards:
        region=reachable(flow['blocks'],guard['zero'])-reachable(flow['blocks'],guard['nonzero'])
        for call in calls.values():
            if call['block'] not in region or call['direct'] is None:
                continue
            actual=[call['this'],*call['stack_args'][:2]] if values['platform']=='windows' else call['stack_args'][:3]
            if len(actual)!=3 or actual[1:]!=[('const',0),('const',0)] or actual[0] is None or actual[0][0]!='result':
                continue
            allocation=calls.get(actual[0][1])
            # operator new can be an imported ELF PLT call; it has a static
            # call operand but deliberately no local function body to resolve.
            if allocation is None or not allocation['target'] or allocation['target'][0]!='const' or allocation['block'] not in region:
                continue
            candidate=flow_at(call['direct'],values['platform'])
            installs=[s for s in candidate['stores'] if s['address']==('arg',0) and s['value']==('const',values['vtable'])]
            if installs:
                matches.add(call['direct'])
if len(matches)!=1:
    raise ValueError('Panel two-argument constructor is not unique: '+repr(sorted(matches)))
result={'ea':next(iter(matches))}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    owner = function_address(new_binary_dir, "vgui2_EditablePanel_CreateControlByName", platform)
    table = artifact(new_binary_dir, "vgui2_Panel_vtable", platform)
    if owner is None or not table:
        return False
    found = await walk(session, LOCATE, dict(owner=owner, vtable=int(table["vtable_va"], 0), platform=platform))
    if found.get("error") or set(found) != {"ea"}:
        if debug:
            print(found)
        return False
    return await write_function(
        session,
        expected_outputs,
        "vgui2_Panel_ctor",
        "vgui2::Panel::Panel(vgui2::Panel*, char const*)",
        found["ea"],
        image_base,
    )
