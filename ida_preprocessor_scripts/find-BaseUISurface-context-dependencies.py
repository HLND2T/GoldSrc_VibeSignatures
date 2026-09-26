#!/usr/bin/env python3
"""Follow panel geometry into IEngineSurface and recover the reset texture cache."""

from ida_preprocessor_scripts._vgui_paint_common import function_address, walk, write_slot
from ida_preprocessor_scripts._vgui_context_common import write_member

LOCATE = r"""
push=flow_at(values['push'],values['platform'])
pop=flow_at(values['pop'],values['platform'])
candidates=[]
for call in push['calls']:
    targets=virtual_targets(call['target'])
    args=call['args'] if values['platform']=='linux' else [call['this'],*call['stack_args']]
    if len(targets)!=1 or len(args)<5 or args[4]!=('const',0):
        continue
    receiver,offset=targets[0]
    if not receiver or receiver[0]!='load' or receiver[1]!=('arg',0) or args[0]!=receiver:
        continue
    arrays=args[1:4]
    if len(set(arrays))!=3 or any(a is None or a[0]!='stack' for a in arrays):
        continue
    # GetInset is guarded by the current useInsets argument. The other IPanel
    # queries write into stack locals before the engine call consumes them.
    guards=[b for b in push['branches'] if b['condition']==('arg',2)]
    if not guards:
        continue
    producers=[c for c in push['calls'] if c['ea']!=call['ea'] and virtual_targets(c['target'])
               and any(a in c['stack_args'] or a in c['args'] for a in arrays)]
    if not all(any(array in c['stack_args'] or array in c['args'] for c in producers) for array in arrays):
        continue
    if not any(c['block'] in (reachable(push['blocks'],g['nonzero'])-reachable(push['blocks'],g['zero']))
               and (arrays[0] in c['stack_args'] or arrays[0] in c['args']) for g in guards for c in producers):
        continue
    forwarded=[c for c in pop['calls'] if virtual_targets(c['target']) and
               all(r==receiver for r,o in virtual_targets(c['target'])) and c['args'][0]==receiver]
    if len(forwarded)!=1 or one_slot(forwarded[0]) in (None,offset):
        continue
    stores=[s for s in push['stores'] if s['width']==4 and s['value']==('const',0) and s['address'] and
            s['address'][0]=='address' and s['address'][1]==('arg',0) and s['address'][2]>0]
    if len(stores)!=1:
        continue
    candidates.append(dict(push=offset,pop=one_slot(forwarded[0]),insn=stores[0]['ea'],member=stores[0]['address'][2]))
if len(candidates)!=1:
    raise ValueError('BaseUISurface context dataflow is ambiguous: '+repr(candidates))
result=candidates[0]
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    push = function_address(new_binary_dir, "BaseUISurface_PushMakeCurrent", platform)
    pop = function_address(new_binary_dir, "BaseUISurface_PopMakeCurrent", platform)
    if push is None or pop is None:
        return False
    found = await walk(session, LOCATE, dict(push=push, pop=pop, platform=platform))
    if found.get("error"):
        if debug:
            print(found)
        return False
    if not await write_member(
        session,
        expected_outputs,
        "BaseUISurface_m_iCurrentTexture",
        "BaseUISurface",
        "m_iCurrentTexture",
        found["insn"],
        found["member"],
        image_base,
    ):
        return False
    return all(
        write_slot(expected_outputs, "IEngineSurface_" + method, "IEngineSurface", method, found[key])
        for method, key in [("pushMakeCurrent", "push"), ("popMakeCurrent", "pop")]
    )
