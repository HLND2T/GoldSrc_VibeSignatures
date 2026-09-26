#!/usr/bin/env python3
"""Recover paint context slots and the BuildGroup receiver from current value flow.

The existing deterministic PaintTraverse/vtable chain is the only entry anchor.
Background/foreground pushes must use the same VPANEL and false/true insets;
their paired pops use that same surface getter and panel. The BuildGroup getter
must feed an overlay loop, followed by a no-argument call on the same member.
No reference slot, member offset, call ordinal or byte window is a locator.
"""

from ida_preprocessor_scripts._vgui_paint_common import artifact, walk, write_slot
from ida_preprocessor_scripts._vgui_context_common import write_member


LOCATE = r"""
platform=values['platform']
table=values['table']
owner=values['owner']
entry=flow_at(owner,platform)
bodies=[(owner,entry,None)]
for call in entry['calls']:
    # Compiler-created hot parts are reached by a direct tail edge with the
    # original receiver still proven in the register/stack calling convention.
    if call['tail'] and call['direct'] and call['direct']!=owner:
        state=entry_state_from_call(call)
        if ('arg',0) in state.values():
            bodies.append((call['direct'],flow_at(call['direct'],platform,entry_state=state),state))
candidates=[]
diagnostics=[]
for body,flow,state in bodies:
    calls=call_map(flow)
    getters={}
    for call in calls.values():
        targets=virtual_targets(call['target'])
        if len(targets)!=1 or targets[0][0]!=('arg',0):
            continue
        slot=targets[0][1]//4
        target=int(ida_bytes.get_dword(values['table_va']+4*slot))
        if str(slot) not in table or target!=int(table[str(slot)],0):
            raise ValueError('Panel current vtable disagrees with predecessor artifact')
        getter=flow_at(target,platform)
        returns={r['value'] for r in getter['returns']}
        if getter['calls'] or len(returns)!=1:
            continue
        returned=next(iter(returns))
        if returned and returned[0]=='load' and returned[1]==('arg',0) and returned[2]>0:
            getters[targets[0][1]]=(target,returned)
    for getter_offset,(getter_ea,member) in getters.items():
        if platform=='windows':
            purge=callee_stack_purge(getter_ea)
            corrected={c['ea']:purge for c in calls.values()
                       if virtual_targets(c['target']) and one_slot(c)==getter_offset
                       and choice(*(r for r,o in virtual_targets(c['target'])))==c['this']}
            function=ida_funcs.get_func(body)
            for ea in list(corrected):
                insn=idautils.DecodeInstruction(ea)
                stolen=int(ida_frame.get_spd(function,ea+insn.size))-int(ida_frame.get_spd(function,ea))-purge
                consumers=[c for c in calls.values() if c['ea']>ea and not c['direct'] and ('result',ea) in c['stack_args']]
                if stolen and consumers:
                    consumer=min(consumers,key=lambda c:c['ea'])['ea']
                    decoded=idautils.DecodeInstruction(consumer)
                    cleanup=int(ida_frame.get_spd(function,consumer+decoded.size))-int(ida_frame.get_spd(function,consumer))
                    corrected[consumer]=cleanup+stolen
            flow=flow_at(body,platform,corrected,entry_state=state)
            calls=call_map(flow)
        def is_panel(value):
            for part in alternatives(value):
                if part==member:
                    if not any((left==('const',getter_ea) and virtual_targets(right)==[(('arg',0),getter_offset)]) or
                               (right==('const',getter_ea) and virtual_targets(left)==[(('arg',0),getter_offset)])
                               for left,right in (c['values'] for c in flow['comparisons'])):
                        return False
                elif part and part[0]=='result':
                    producer=calls.get(part[1])
                    if not producer or virtual_targets(producer['target'])!=[(('arg',0),getter_offset)]:
                        return False
                else:
                    return False
            return True
        surface=[]
        for call in calls.values():
            targets=virtual_targets(call['target'])
            args=call['args'] if platform=='linux' else [call['this'],*call['stack_args']]
            if len(targets)!=1 or len(args)<2 or args[0]!=targets[0][0] or not is_panel(args[1]):
                continue
            getter=direct_receiver(targets[0][0],calls)
            if getter is not None:
                surface.append((call,args,getter,targets[0][1]))
        push_keys={(getter,offset) for call,args,getter,offset in surface if len(args)>2 and args[2]==('const',1)}
        diag=dict(body=hex(body),getter=getter_offset,surface=[(hex(c['ea']),o,a[1:3]) for c,a,g,o in surface],push_keys=list(push_keys))
        diagnostics.append(diag)
        for surface_getter,push_offset in push_keys:
            pushes=[(c,a) for c,a,g,o in surface if (g,o)==(surface_getter,push_offset) and a[2] in (('const',0),('const',1))]
            if not {a[2] for c,a in pushes}>={('const',0),('const',1)}:
                continue
            # Pair around an actual Panel paint call. Order alone is insufficient:
            # all three calls must retain receiver/VPANEL identity and CFG reachability.
            pop_offsets=set()
            paired_flags={}
            for push,args in pushes:
                by_block={b:sorted((c for c in calls.values() if c['block']==b),key=lambda c:c['ea']) for b in flow['blocks']}
                boundaries={c['ea']:o for c,a,g,o in surface if g==surface_getter}
                pending=[(push['block'],push['ea'],False)]
                visited=set()
                next_calls=[]
                while pending:
                    block,after,paint=pending.pop()
                    if (block,after,paint) in visited:
                        continue
                    visited.add((block,after,paint))
                    stopped=False
                    for c in by_block[block]:
                        if c['ea']<=after:
                            continue
                        if c['ea'] in boundaries:
                            next_calls.append((boundaries[c['ea']],paint))
                            stopped=True
                            break
                        targets=virtual_targets(c['target'])
                        if targets and all(r==('arg',0) for r,o in targets) and one_slot(c)!=getter_offset:
                            paint=True
                    if not stopped:
                        pending.extend((successor,-1,paint) for successor in flow['blocks'][block])
                offsets={o for o,paint in next_calls}
                if len(offsets)!=1 or not any(paint for o,paint in next_calls):
                    continue
                offset=next(iter(offsets))
                if offset!=push_offset:
                    pop_offsets.add(offset)
                    paired_flags.setdefault(offset,set()).add(args[2])
            pop_offsets={offset for offset in pop_offsets if paired_flags[offset]>={('const',0),('const',1)}}
            if len(pop_offsets)!=1:
                continue
            diag['pop_offsets']=list(pop_offsets)
            group_calls=[]
            for call in calls.values():
                targets=virtual_targets(call['target'])
                if len(targets)!=1:
                    continue
                receiver,offset=targets[0]
                if receiver and receiver[0]=='load' and receiver[1]==('arg',0) and receiver[2]>0 and call['args'][0]==receiver:
                    group_calls.append((call,receiver,offset))
            groups=[]
            for get_group,receiver,group_slot in group_calls:
                # The returned control-group object is read in the overlay loop.
                token=('result',get_group['ea'])
                def contains(value,needle):
                    return value==needle or (isinstance(value,(tuple,list)) and any(contains(v,needle) for v in (value[1:] if isinstance(value,tuple) else value)))
                loops={b for b,succs in flow['blocks'].items() if any(b in reachable(flow['blocks'],s) for s in succs)}
                used_loops={c['block'] for c in calls.values() if c['block'] in loops and
                            (contains(c['target'],token) or any(contains(a,token) for a in c['args']))}
                used_loops.update(c['block'] for c in flow['comparisons'] if c['block'] in loops and contains(c['values'],token))
                if not used_loops:
                    continue
                for rulers,r,slot in group_calls:
                    if r!=receiver or slot==group_slot or rulers['block'] in loops:
                        continue
                    if not any(rulers['block'] in reachable(flow['blocks'],loop) for loop in used_loops):
                        continue
                    loads=[l for l in flow['loads'] if l['value']==receiver and l['width']==4]
                    if loads:
                        groups.append((receiver[2],slot,min(l['ea'] for l in loads)))
            if len(set(groups))==1:
                offset,rulers,insn=groups[0]
                candidates.append(dict(push=push_offset,pop=next(iter(pop_offsets)),rulers=rulers,member=offset,insn=insn))
            diag['groups']=groups
unique={tuple(sorted(c.items())) for c in candidates}
if len(unique)!=1:
    raise ValueError('Panel paint context roles are ambiguous: '+repr(candidates)+'; '+repr(diagnostics))
result=dict(next(iter(unique)))
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    owner = artifact(new_binary_dir, "vgui2_Panel_PaintTraverse", platform)
    table = artifact(new_binary_dir, "vgui2_Panel_vtable", platform)
    if not owner or not table:
        return False
    found = await walk(
        session,
        LOCATE,
        dict(
            owner=int(owner["func_va"], 0),
            table_va=int(table["vtable_va"], 0),
            table={str(k): v for k, v in table["vtable_entries"].items()},
            platform=platform,
        ),
    )
    if found.get("error"):
        if debug:
            print(found)
        return False
    if not await write_member(
        session,
        expected_outputs,
        "vgui2_Panel__buildGroup",
        "vgui2::Panel",
        "_buildGroup",
        found["insn"],
        found["member"],
        image_base,
    ):
        return False
    return all(
        write_slot(expected_outputs, name, cls, method, found[key])
        for name, cls, method, key in (
            ("ISurface_PushMakeCurrent", "vgui2::ISurface", "PushMakeCurrent", "push"),
            ("ISurface_PopMakeCurrent", "vgui2::ISurface", "PopMakeCurrent", "pop"),
            ("vgui2_BuildGroup_DrawRulers", "vgui2::BuildGroup", "DrawRulers", "rulers"),
        )
    )
