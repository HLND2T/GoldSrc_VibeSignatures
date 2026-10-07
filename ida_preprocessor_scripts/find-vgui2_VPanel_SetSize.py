#!/usr/bin/env python3
"""Follow IPanel::SetSize -> VPanelWrapper::SetSize -> VPanel::SetSize -> IClientPanel.

GameUI's Panel::Init proves the IPanel SetSize slot. The wrapper entry at that
slot must forward its own (VPANEL, wide, tall) to exactly one VPANEL receiver
slot, which selects VPanel::SetSize in the current internal table. Windows and
Linux use different IPanel and VPanel slots, so neither slot is inherited.

VPanel::SetSize notifies its client after clamping. Linux can inline Client()
behind a function-pointer comparison; accept only receivers proven to be the
current VPanel::Client result or its returned member, never a counted call.
"""

from ida_preprocessor_scripts._vgui_paint_common import artifact, walk, write_function, write_slot


LOCATE = r"""
platform=values['platform']
wrapper={int(k):int(v,0) for k,v in values['wrapper'].items()}
panel={int(k):int(v,0) for k,v in values['panel'].items()}
offset=values['size_offset']
if offset%4 or offset//4 not in wrapper:
    raise ValueError('invalid IPanel SetSize slot')

def args(c):
    return [c['this'],*c['stack_args']] if platform=='windows' else c['stack_args']

owner=wrapper[offset//4]
forwards=[]
for c in flow_at(owner,platform)['calls']:
    a=args(c)
    targets=virtual_targets(c['target'])
    if len(targets)==1 and targets[0][0]==('arg',1) and a[:3]==[('arg',1),('arg',2),('arg',3)]:
        forwards.append(targets[0][1])
if len(forwards)!=1:
    raise ValueError('VPanelWrapper::SetSize forwarding is not unique: '+repr(forwards))
setsize=panel.get(forwards[0]//4)
if setsize is None or setsize==owner:
    raise ValueError('VPanel SetSize slot absent from current table')
client=values['client_ea']
client_offset=values['client_offset']
if panel.get(client_offset//4)!=client:
    raise ValueError('VPanel::Client artifact disagrees with current table')
getter=flow_at(client,platform)
returns={r['value'] for r in getter['returns']}
returned=next(iter(returns)) if len(returns)==1 else None
if getter['calls'] or returned is None or returned[0]!='load' or returned[1]!=('arg',0) or returned[2]<=0:
    raise ValueError('VPanel::Client is not a member getter')
member=returned[2]
flow=flow_at(setsize,platform)
calls=call_map(flow)

def client_receiver(receiver):
    if receiver==('load',('arg',0),member):
        return True
    if receiver is None or receiver[0]!='result' or receiver[1] not in calls:
        return False
    producer=calls[receiver[1]]
    return producer['direct']==client or virtual_targets(producer['target'])==[(('arg',0),client_offset)]

notify=[]
for c in flow['calls']:
    targets=virtual_targets(c['target'])
    a=args(c)
    # Clamped sizes come from CMOVcc and may be unknown; the receiver proves the role.
    if targets and all(client_receiver(r) for r,_ in targets) and choice(*(r for r,_ in targets))==a[0]:
        notify.append(c)
if len(notify)!=1 or one_slot(notify[0]) is None:
    raise ValueError('IClientPanel size notification is not unique')
result={'setsize_ea':setsize,'setsize_offset':forwards[0],'notify_offset':one_slot(notify[0])}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    inherited = artifact(new_binary_dir, "../gameui/vgui2_IPanel_SetSize", platform)
    wrapper = artifact(new_binary_dir, "vgui2_VPanelWrapper_vtable", platform)
    panel = artifact(new_binary_dir, "vgui2_VPanel_vtable", platform)
    client = artifact(new_binary_dir, "vgui2_VPanel_Client", platform)
    if not inherited or not wrapper or not panel or not client:
        return False
    offset = int(inherited["vfunc_offset"], 0)
    if offset != inherited["vfunc_index"] * 4:
        return False
    found = await walk(
        session,
        LOCATE,
        dict(
            wrapper=wrapper["vtable_entries"],
            panel=panel["vtable_entries"],
            size_offset=offset,
            client_ea=int(client["func_va"], 0),
            client_offset=int(client["vfunc_offset"], 0),
            platform=platform,
        ),
    )
    if found.get("error") or set(found) != {"setsize_ea", "setsize_offset", "notify_offset"}:
        if debug:
            print(found)
        return False
    if not write_slot(
        expected_outputs,
        "vgui2_IClientPanel_OnSizeChanged",
        "vgui2::IClientPanel",
        "OnSizeChanged",
        found["notify_offset"],
    ):
        return False
    return await write_function(
        session,
        expected_outputs,
        "vgui2_VPanel_SetSize",
        "vgui2::VPanel::SetSize(int, int)",
        found["setsize_ea"],
        image_base,
        table="vgui2::VPanel",
        index=found["setsize_offset"] // 4,
    )
