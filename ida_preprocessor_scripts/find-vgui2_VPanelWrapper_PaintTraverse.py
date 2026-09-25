#!/usr/bin/env python3
"""Follow IPanel -> VPanelWrapper::Client -> VPanel::Client -> IClientPanel.

The wrapper itself belongs to the global namespace. HL25/SvEngine Linux can
inline both Client getters behind function-pointer comparisons and tail-jump
to IClientPanel::PaintTraverse. Validate every merged receiver against the
current tables and the real getter body, rather than counting indirect calls.
"""

from ida_preprocessor_scripts._vgui_paint_common import artifact, walk, write_function, write_slot


LOCATE = r"""
wrapper={int(k):int(v,0) for k,v in values['wrapper'].items()}
panel={int(k):int(v,0) for k,v in values['panel'].items()}
offset=values['paint_offset']
if offset%4 or offset//4 not in wrapper:
    raise ValueError('invalid inherited IPanel paint slot')
owner=wrapper[offset//4]
flow=flow_at(owner,values['platform'])
calls=call_map(flow)
outer=[c for c in calls.values() if len(c['args'])>=2 and c['args'][0:2]==[('arg',0),('arg',1)]
       and len(virtual_targets(c['target']))==1 and virtual_targets(c['target'])[0][0]==('arg',0)]
outer_slots={one_slot(c) for c in outer}
if len(outer_slots)!=1 or None in outer_slots:
    raise ValueError('VPanelWrapper::Client receiver/slot is ambiguous')
outer_offset=next(iter(outer_slots))
client=wrapper.get(outer_offset//4)
if client is None or client==owner:
    raise ValueError('invalid wrapper Client entry')
if values['platform']=='windows':
    # Debug-style builds can pre-push paint arguments before calling Client.
    # IDA sometimes attributes all pushes to Client; use its actual RET amount.
    purge=callee_stack_purge(client)
    flow=flow_at(owner,values['platform'],{c['ea']:purge for c in outer})
    calls=call_map(flow)
client_flow=flow_at(client,values['platform'])
inner=[c for c in client_flow['calls'] if len(virtual_targets(c['target']))==1
       and virtual_targets(c['target'])[0][0]==('arg',1) and c['args'][0]==('arg',1)]
inner_slots={one_slot(c) for c in inner}
if len(inner_slots)!=1 or None in inner_slots:
    raise ValueError('VPanel::Client forwarding slot is ambiguous')
inner_offset=next(iter(inner_slots))
getter=panel.get(inner_offset//4)
if getter is None:
    raise ValueError('VPanel Client slot absent from current table')
getter_flow=flow_at(getter,values['platform'])
returns={r['value'] for r in getter_flow['returns']}
if getter_flow['calls'] or len(returns)!=1:
    raise ValueError('VPanel Client is not a member getter')
returned=next(iter(returns))
if returned is None or returned[0]!='load' or returned[1]!=('arg',0) or returned[2]<=0:
    raise ValueError('VPanel Client does not return its client-panel member')
member=returned[2]

def compared_target(receiver,slot,address):
    for comparison in flow['comparisons']:
        left,right=comparison['values']
        if right==('const',address) and virtual_targets(left)==[(receiver,slot)]:
            return True
        if left==('const',address) and virtual_targets(right)==[(receiver,slot)]:
            return True
    return False

def client_receiver(receiver):
    if receiver==('load',('arg',1),member):
        return compared_target(('arg',0),outer_offset,client) and compared_target(('arg',1),inner_offset,getter)
    if receiver is not None and receiver[0]=='result':
        producer=calls.get(receiver[1])
        if not producer:
            return False
        targets=virtual_targets(producer['target'])
        return (targets==[(('arg',0),outer_offset)] and producer['args'][:2]==[('arg',0),('arg',1)]) or (
            targets==[(('arg',1),inner_offset)] and producer['args'][0]==('arg',1))
    return False

paint=[]
for call in calls.values():
    targets=virtual_targets(call['target'])
    args=[call['this'],*call['stack_args']] if values['platform']=='windows' else call['args']
    if not targets or len(args)<3 or args[1:3]!=[('arg',2),('arg',3)]:
        continue
    if all(client_receiver(r) for r,_ in targets) and choice(*(r for r,_ in targets))==args[0]:
        paint.append(call)
if len(paint)!=1 or one_slot(paint[0]) is None:
    raise ValueError('IClientPanel paint forwarding is not unique')
result={'client_ea':getter,'client_offset':inner_offset,'paint_offset':one_slot(paint[0])}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    inherited = artifact(new_binary_dir, "../engine/vgui2_IPanel_PaintTraverse", platform)
    wrapper = artifact(new_binary_dir, "vgui2_VPanelWrapper_vtable", platform)
    panel = artifact(new_binary_dir, "vgui2_VPanel_vtable", platform)
    if not inherited or not wrapper or not panel:
        return False
    offset = int(inherited["vfunc_offset"], 0)
    if offset != inherited["vfunc_index"] * 4:
        return False
    found = await walk(
        session,
        LOCATE,
        dict(wrapper=wrapper["vtable_entries"], panel=panel["vtable_entries"], paint_offset=offset, platform=platform),
    )
    if found.get("error") or set(found) != {"client_ea", "client_offset", "paint_offset"}:
        if debug:
            print(found)
        return False
    if not write_slot(expected_outputs, "vgui2_VPanelWrapper_PaintTraverse", "VPanelWrapper", "PaintTraverse", offset):
        return False
    if not write_slot(
        expected_outputs,
        "vgui2_IClientPanel_PaintTraverse",
        "vgui2::IClientPanel",
        "PaintTraverse",
        found["paint_offset"],
    ):
        return False
    return await write_function(
        session,
        expected_outputs,
        "vgui2_VPanel_Client",
        "vgui2::VPanel::Client()",
        found["client_ea"],
        image_base,
        table="vgui2::VPanel",
        index=found["client_offset"] // 4,
        signature=False,
    )
