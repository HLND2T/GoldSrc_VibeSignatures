#!/usr/bin/env python3
"""Recover the client Career popup owners from the weapon-box constructor.

The exact BuyBoxSelectWeapon literal anchors its constructor. Its same-this
base call installs current CCareerBaseBox RTTI and stores this in s_currentBox.
Global read xrefs then identify the guarded IsVisible/MoveToFront/DoModal
sequence; ShowWindow and the modal interface dataflow independently prove it.
BringToFront callers are intersected with current primary viewport RTTI and
the Tick/spectator/client-UI/UndoModal branches. Slots and offsets are derived.

This direct global locator is verified on czero-10210/8684 PE32 and ELF32:
construction, replacement, OnClose and destructor paths agree on the storage.
It avoids an LLM selecting another UI global. GCC guarded devirtualization and
MSVC conditional tail branches are decoded rather than treated as CALLs.
Old signatures, reference addresses, member layouts and slot numbers never
participate in discovery. Only the three requested symbols are exported.
"""

from ida_analyze_util import (
    _output_for_symbol,
    gv_resolution_fields_via_mcp,
    write_func_yaml,
    write_gv_yaml,
)
from ida_preprocessor_scripts._career_bot_cost_common import COMMON, IDENTITY_SOURCE
from ida_preprocessor_scripts._career_player_name_common import COLLECT_COMMON, collect
from ida_preprocessor_scripts._patch_signature_common import run_signature
from ida_preprocessor_scripts._vgui_paint_common import walk
from ida_preprocessor_scripts._vgui_private_symbols_common import function_payload

WALK = r"""
def method(ea):
    if ea not in cache:cache[ea]=traced(ea)
    return cache[ea]

def check_name(ea,name):
    identity(ea,[name])

def explicit(call,index):
    return call['stack_args'][index+(values['platform']=='linux')]

def dispatches(flow,receiver):
    return [(c,d[1]) for c in flow['calls'] if (d:=virtual_dispatch(c))
            and d[0]==receiver and c['args'][0]==receiver]

def guarded(flow,condition,site):
    return any(b['condition']==condition and site in reachable(flow['blocks'],b['nonzero'])
               and site not in reachable(flow['blocks'],b['zero']) for b in flow['branches'])

def incoming(target):
    return {owner for owner,site in callers(target)}

def panel_value(value,receiver,index,call):
    # GCC may replace GetVPanel with its verified leaf load on one branch.
    allowed={('result',call['ea'])}
    leaf=method(career[index])
    returns={r['value'] for r in leaf['returns']}
    if not leaf['calls'] and len(returns)==1:
        returned=next(iter(returns))
        if returned and returned[:2]==('load',THIS):
            allowed.add(('load',receiver,returned[2]))
    return all(part in allowed for part in alternatives(value))

def modal_behavior(ea):
    # DoModal: this->ShowWindow(); input()->SetAppModalSurface(this->GetVPanel()).
    flow=method(ea)
    own=dispatches(flow,THIS)
    found=[]
    for show,show_index in own:
        if show_index not in career:continue
        shown=method(career[show_index])
        calls=dispatches(shown,THIS)
        if len(calls)!=3 or any(explicit(c,0)!=('const',1) for c,i in calls[:2]):continue
        move_index=calls[-1][1]
        for getpanel,panel_index in own:
            if getpanel['ea']==show['ea']:continue
            for setter in flow['calls']:
                dispatch=virtual_dispatch(setter)
                if not dispatch or not panel_value(explicit(setter,0),THIS,panel_index,getpanel):continue
                receiver=dispatch[0]
                if not receiver or receiver[0]!='result':continue
                getter=next((c for c in flow['calls'] if c['ea']==receiver[1] and c['direct']),None)
                if not getter or not show['ea']<getter['ea']<setter['ea']:continue
                found.append(dict(show=career[show_index],show_index=show_index,move_index=move_index,
                                  panel_index=panel_index,input_getter=getter['direct'],input_modal_index=dispatch[1]))
    return sole(found,'DoModal/ShowWindow/modal-interface behavior')

def visible_behavior(ea,panel_index):
    flow=method(ea)
    # Panel::IsVisible delegates the same VPanel to the panel interface.
    own=[c for c,i in dispatches(flow,THIS) if i==panel_index]
    if len(own)!=1:return False
    return any(virtual_dispatch(c) and panel_value(explicit(c,0),THIS,panel_index,own[0])
               and virtual_dispatch(c)[0] and virtual_dispatch(c)[0][0]=='result'
               for c in flow['calls'])

def bring_behavior(ea):
    flow=method(ea)
    if any(s['address'] and s['address'][0]!='stack' for s in flow['stores']):return None
    if any(contains_value(load['address'],THIS) for load in flow['loads']):return None
    calls=dispatches(flow,current)
    if len(calls)<3:return None
    for visible,visible_index in calls:
        if not guarded(flow,current,visible['block']):continue
        following=[(c,i) for c,i in calls if guarded(flow,('result',visible['ea']),c['block'])]
        # 10210 GCC retains the virtual fallback alongside its inlined DoModal.
        for move,move_index in following:
            for modal,modal_index in following:
                if not visible['ea']<move['ea']<modal['ea'] or modal_index not in career:continue
                try:proof=modal_behavior(career[modal_index])
                except ValueError:continue
                if proof['move_index']!=move_index or not visible_behavior(career[visible_index],proof['panel_index']):continue
                check_name(career[visible_index],'_ZN5vgui25Panel9IsVisibleEv')
                check_name(career[move_index],'_ZN5vgui25Panel11MoveToFrontEv')
                check_name(career[modal_index],'_ZN14CCareerBaseBox7DoModalEv')
                check_name(proof['show'],'_ZN14CCareerBaseBox10ShowWindowEv')
                if not stack_abi(ea,0):raise ValueError('static BringToFront stack ABI disagrees')
                return dict(ea=ea,visible_index=visible_index,modal_index=modal_index,**proof)
    return None

def primary_base(table,base):
    if values['platform']=='windows':return base_identity(table,base)
    address=int(table['vtable_va'],0)
    ti=ida_bytes.get_dword(address-4)
    expected=ida_name.get_name_ea(idaapi.BADADDR,'_ZTI'+str(len(base))+base)
    if expected==idaapi.BADADDR:raise ValueError('base RTTI absent: '+base)
    if ida_bytes.get_dword(ti+8)==expected:return 0
    count=ida_bytes.get_dword(ti+12)
    if not 1<=count<=64:raise ValueError('invalid Itanium base count')
    offsets=[]
    for i in range(count):
        if ida_bytes.get_dword(ti+16+i*8)!=expected:continue
        flags=ida_bytes.get_dword(ti+20+i*8)
        if flags&1:raise ValueError('virtual primary base unsupported')
        offsets.append(signed32(flags)>>8)
    return sole(offsets,'primary base '+base)

def undo_behavior(flow,proof):
    # UndoModal may be inlined in Tick. It compares this same current box's
    # VPanel with input()->GetAppModalSurface, then resets that interface to 0.
    calls=flow['calls']
    getters={c['ea'] for c in calls if c['direct']==proof['input_getter']}
    panels={c['ea'] for c,i in dispatches(flow,current) if i==proof['panel_index']}
    gets=[c for c in calls if (d:=virtual_dispatch(c)) and d[0] in {('result',p) for p in getters}
          and d[1]!=proof['input_modal_index']]
    clears=[c for c in calls if (d:=virtual_dispatch(c)) and d[0] in {('result',p) for p in getters}
            and d[1]==proof['input_modal_index'] and explicit(c,0)==('const',0)]
    comparisons=flow['comparisons']
    pairs=[(p,g) for p in panels for g in gets if any(
        contains_value(c['values'],('result',p)) and contains_value(c['values'],('result',g['ea']))
        for c in comparisons)]
    return [c['block'] for c in clears] if pairs else []

cache={}
tables=values['tables']
career=entries(tables['CCareerBaseBox'])
frame=entries(tables['vgui2::Frame'])
viewport=entries(tables['CounterStrikeViewport'])
base_viewport=entries(tables['TeamFortressViewport'])
if primary_base(tables['CounterStrikeViewport'],'TeamFortressViewport')!=0:
    raise ValueError('viewport this is not the primary complete-object base')
if primary_base(tables['TeamFortressViewport'],'IViewPort')!=0:
    raise ValueError('viewport primary interface is not IViewPort')
if base_identity(tables['CWeaponSelectBox'],'CCareerBaseBox')!=0:
    raise ValueError('weapon box Career receiver adjustment disagrees')
literal=literal_evidence('BuyBoxSelectWeapon')
if len(literal['addresses'])!=1:raise ValueError('weapon-box literal is not unique')
weapon=sole(literal['owners'],'weapon constructor literal owner')
ctor_store(method(weapon),tables['CWeaponSelectBox'])
base_calls=[c for c in method(weapon)['calls'] if c['direct'] and c['args'][0]==THIS
            and explicit(c,1)==('const',literal['addresses'][0]) and explicit(c,2)==('const',0)]
base_call=sole(base_calls,'same-this named Career base construction')
base=base_call['direct']
ctor_store(method(base),tables['CCareerBaseBox'])
check_name(base,'_ZN14CCareerBaseBoxC2EPN5vgui25PanelEPKcb')
stores=[s for s in method(base)['stores'] if s['width']==4 and s['value']==THIS
        and s['address'] and s['address'][0]=='const' and is_writable_data(s['address'][1])]
storage=sole(stores,'current-box constructor pointer assignment')
gv=storage['address'][1]
current=('load',('const',gv),0)
# Replacement must close the previous object only on the non-null branch.
if not any(guarded(method(base),current,c['block']) for c,i in dispatches(method(base),current)):
    raise ValueError('constructor does not close the previous current box')
owners=set()
for site in elf_data_refs_to(gv):
    f=ida_funcs.get_func(site)
    if f and not is_plt(f.start_ea):owners.add(int(f.start_ea))
proofs=[proof for ea in sorted(owners) if (proof:=bring_behavior(ea))]
proof=sole(proofs,'guarded current-box BringToFront')
bring=proof['ea']
check_name(bring,'_ZN14CCareerBaseBox12BringToFrontEv')
if values['platform']=='linux' and ida_name.get_name(gv)!='_ZN14CCareerBaseBox12s_currentBoxE':
    raise ValueError('current-box ELF global identity disagrees')
# Independently prove the pointer is conditionally cleared by this object's
# OnClose and destructor, rather than being an active menu or surface handle.
clears=[]
for ea in owners:
    flow=method(ea)
    if not any(c['direct'] and c['args'][0]==THIS for c in flow['calls']):continue
    if not any(contains_value(c['values'],THIS) and contains_value(c['values'],current)
               for c in flow['comparisons']):continue
    if any(s['address']==('const',gv) and s['width']==4 and contains_value(s['value'],('const',0))
           for s in flow['stores']):clears.append(ea)
destructors=[]
closes=[]
for ea in set(clears):
    flow=method(ea)
    try:
        ctor_store(flow,tables['CCareerBaseBox'])
        destructors.append(ea)
    except ValueError:pass
    if ea in destructors:continue
    for index,target in career.items():
        if target!=ea or index not in frame:continue
        if any(c['direct']==frame[index] and c['args'][0]==THIS for c in flow['calls']):
            check_name(ea,'_ZN14CCareerBaseBox7OnCloseEv')
            closes.append(ea)
if not destructors or len(set(closes))!=1:
    raise ValueError('OnClose/destructor current-box clearing proof absent')

ticks=[]
for index,ea in viewport.items():
    if ea not in incoming(bring):continue
    flow=method(ea)
    # The override calls the actual same-slot base implementation with this.
    if index not in base_viewport or not any(c['direct']==base_viewport[index] and c['args'][0]==THIS
                                            for c in flow['calls']):continue
    # Spectator visibility check and conditional update share a this-member receiver.
    spectator=[(c,d) for c in flow['calls'] if (d:=virtual_dispatch(c)) and d[0]
               and d[0][:2]==('load',THIS) and c['args'][0]==d[0]]
    if not any(a[1][0]==b[1][0] and a[1][1]!=b[1][1]
               and guarded(flow,('result',a[0]['ea']),b[0]['block']) for a in spectator for b in spectator):continue
    undo_blocks=undo_behavior(flow,proof)
    for c in flow['calls']:
        if (c['direct'] and c['direct']!=base_viewport[index] and c['direct']!=bring
                and c['direct'] in owners and undo_behavior(method(c['direct']),proof)):
            check_name(c['direct'],'_ZN14CCareerBaseBox9UndoModalEv')
            undo_blocks.append(c['block'])
    if not undo_blocks:continue
    gates=[]
    for branch in flow['branches']:
        condition=branch['condition']
        if not condition or condition[0]!='narrow' or condition[2]!=1:continue
        member=condition[1]
        if not member or member[:2]!=('load',THIS):continue
        # A conditional tail branch may lead directly out of IDA's CFG.
        positive=reachable(flow['blocks'],branch['nonzero'])
        negative=reachable(flow['blocks'],branch['zero'])
        sites=[c['block'] for c in flow['calls'] if c['direct']==bring]
        if ((branch['nonzero']==bring or any(s in positive and s not in negative for s in sites))
                and any(s in negative and s not in positive for s in undo_blocks)):
            gates.append(branch['ea'])
    if len(gates)!=1:continue
    if ea==base_viewport[index] or idc.print_insn_mnem(ea)=='jmp':continue
    check_name(ea,'_ZN21CounterStrikeViewport6OnTickEv')
    ticks.append((index,ea,gates[0]))
index,tick,gate=sole(ticks,'primary viewport Tick implementation')
accesses=[]
for ea in idautils.FuncItems(bring):
    insn=idautils.DecodeInstruction(ea)
    for op in insn.ops:
        if op.type==idaapi.o_mem and int(op.addr)==gv and op.offb and insn.size-op.offb>=4:
            accesses.append(dict(ea=int(ea),length=int(insn.size),displacement=int(op.offb)))
access=sole(accesses[:1],'decoded current-box access')
result=dict(weapon=weapon,base=base,gv=gv,bring=bring,tick=tick,index=index,gate=gate,
            access=access,destructors=sorted(set(destructors)),onclose=closes[0],literal=literal,proof=proof,
            this_base='IViewPort / TeamFortressViewport / complete CounterStrikeViewport',this_adjustment=0)
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    try:
        tables = await collect(
            session,
            platform,
            ["CCareerBaseBox", "CWeaponSelectBox", "CounterStrikeViewport", "TeamFortressViewport", "vgui2::Frame"],
        )
        found = await walk(
            session, IDENTITY_SOURCE + COMMON + COLLECT_COMMON + WALK, {"platform": platform, "tables": tables}
        )
        if debug:
            print(f"  {skill_name} evidence: {found}")
        if found.get("error"):
            return False
        tick = await function_payload(
            session,
            found["tick"],
            image_base,
            "CounterStrikeViewport::OnTick()",
            table="CounterStrikeViewport",
            index=found["index"],
        )
        bring = await function_payload(session, found["bring"], image_base, "CCareerBaseBox::BringToFront()")
        access = found["access"]
        signature = await run_signature(session, access["ea"])
        resolution = await gv_resolution_fields_via_mcp(
            session, access["ea"], access["displacement"], found["gv"], image_base, platform
        )
        if not tick or not bring or not signature or resolution is None:
            return False
        global_payload = dict(
            gv_name="CCareerBaseBox::s_currentBox",
            gv_va=hex(found["gv"]),
            gv_rva=hex(found["gv"] - image_base),
            gv_sig=signature["patch_sig"],
            gv_sig_va=hex(access["ea"]),
            gv_inst_offset="0x0",
            gv_inst_length=hex(access["length"]),
            gv_inst_disp=hex(access["displacement"]),
            **resolution,
        )
        write_func_yaml(_output_for_symbol(expected_outputs, "CounterStrikeViewport_OnTick"), tick)
        write_func_yaml(_output_for_symbol(expected_outputs, "CCareerBaseBox_BringToFront"), bring)
        write_gv_yaml(_output_for_symbol(expected_outputs, "CCareerBaseBox_s_currentBox"), global_payload)
        return True
    except (ValueError, KeyError, TypeError) as exc:
        if debug:
            print(f"  {skill_name} rejected: {exc}")
        return False
