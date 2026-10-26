#!/usr/bin/env python3
"""Recover Frame KeyCode slots and the requested Career end-menu primary tables.

RTTI plus the RoundEnd resource-owning constructor identifies its primary vptr.
Cancel message construction/posting under ESC and SupportsFeature identifies
Pressed; modifier/F4 and Enter/default-button messages identify Typed, including
early CS where Typed has no ESC branch. Current table membership supplies slots.
When Typed has ESC, validate the app-modal equality and current CloseModal body.
No previous artifact, fixed slot, RVA, SDK order or byte pattern locates a target.
MatchEnd export additionally requires its own resource constructor and vptr store.
"""

from pathlib import Path

from ida_analyze_util import _output_for_symbol, write_func_yaml, write_vtable_yaml
from ida_preprocessor_scripts._career_bot_cost_common import COMMON, IDENTITY_SOURCE
from ida_preprocessor_scripts._career_player_name_common import COLLECT_COMMON, collect
from ida_preprocessor_scripts._vgui_paint_common import walk
from ida_preprocessor_scripts._vgui_private_symbols_common import function_payload
import ida_preprocessor_scripts._frame_key_identity as key_identity


KEY_SOURCE = Path(key_identity.__file__).read_text(encoding="utf-8")
FRAME = "vgui2::Frame"
ROUND = "CCSCareerRoundEndMenu"
MATCH = "CCSCareerMatchEndMenu"
WALK = r"""
def method(ea,excluded_edges=()):
    if ea in cache:return cache[ea]
    m=traced(ea,excluded_edges=excluded_edges)
    m['equalities']=[]
    for c in m['comparisons']:
        branch=idc.next_head(c['ea'])
        # GCC saves callee-saved registers between CMP and Jcc. These decoded
        # instructions preserve flags; never search past a flag-writing one.
        while idc.print_insn_mnem(branch) in ('mov','push','pop','lea','nop'):
            branch=idc.next_head(branch)
        op=idc.print_insn_mnem(branch)
        if op not in ('je','jz','jne','jnz'):continue
        target=int(idautils.DecodeInstruction(branch).ops[0].addr)
        others=[s for s in m['blocks'].get(c['block'],[]) if s!=target]
        if target not in m['blocks'].get(c['block'],[]) or len(others)!=1:continue
        equal,unequal=(target,others[0]) if op in ('je','jz') else (others[0],target)
        m['equalities'].append(dict(c,equal=equal,unequal=unequal))
    if not excluded_edges:
        fallback_edges=[]
        for c in m['equalities']:
            for target,address in (c['values'],list(reversed(c['values']))):
                if (target and len(target)==3 and target[:2]==('load',('load',THIS,0))
                        and target[2]%4==0 and address and address[0]=='const'
                        and frame.get(target[2]//4)==address[1]):
                    fallback_edges.append((c['block'],c['equal']))
        if fallback_edges:return method(ea,fallback_edges)
    cache[ea]=m
    return m

def select(candidates,identify):
    matches=[]
    rejected=[]
    for ea in sorted(candidates & set(frame.values())):
        try:proof=identify(method(ea),literals)
        except ValueError as exc:
            rejected.append((hex(ea),str(exc)))
            continue
        if not stack_abi(ea,4 if values['platform']=='windows' else 0):continue
        matches.append((ea,proof))
    return key_sole(matches,identify.__name__+' '+repr(rejected))

def primary(table):
    ap=int(table['vtable_va'],0)
    offset=ida_bytes.get_dword(ap-8) if values['platform']=='linux' else ida_bytes.get_dword(ida_bytes.get_dword(ap-4)+4)
    if offset!=0:raise ValueError('not a primary complete-object vptr')

def direct_base(table,base,encoding):
    primary(table)
    if values['platform']=='windows':
        if base_identity(table,base)!=0:raise ValueError('nonzero base adjustment')
    else:
        ti=ida_bytes.get_dword(int(table['vtable_va'],0)-4)
        parent=ida_bytes.get_dword(ti+8)
        expected=ida_name.get_name_ea(idaapi.BADADDR,'_ZTI'+encoding)
        if expected==idaapi.BADADDR or parent!=expected:raise ValueError('single primary base disagrees')

cache={}
tables=values['tables'];frame=entries(tables['vgui2::Frame'])
primary(tables['vgui2::Frame'])
names=('Command','command','Cancel','CloseFrameButtonPressed','Hotkey','Close')
evidence={s:literal_evidence(s) for s in names}
literals={s:set(v['addresses']) for s,v in evidence.items()}
pressed,pressed_proof=select(set(evidence['Cancel']['owners']) & set(evidence['Command']['owners']),identify_pressed)
typed,typed_proof=select(set(evidence['CloseFrameButtonPressed']['owners']) & set(evidence['Hotkey']['owners']),identify_typed)
if pressed==typed:raise ValueError('key event identities overlap')
identity(pressed,['_ZN5vgui25Frame16OnKeyCodePressedENS_7KeyCodeE'])
identity(typed,['_ZN5vgui25Frame14OnKeyCodeTypedENS_7KeyCodeE'])
pressed_index=unique_slot(frame,pressed);typed_index=unique_slot(frame,typed)
surface,support_index,post_index=pressed_proof
input_getter,_=typed_proof
if surface==input_getter:raise ValueError('surface and input providers alias')

# Do not infer the presence of ESC from a version tag. Early Typed bodies have
# no such comparison; they are still identified by the full key-message flow.
body=method(typed)
esc=[c for c in body['equalities'] if set(c['values'])=={FRAME_KEY,('const',KEY_ESCAPE)}]
modal_proof=None
if esc:
    supports=[c for c in body['calls'] if interface_getter(body,c)==surface
              and key_dispatch(c)[1]==support_index and c['args'][1:2]==[('const',ESCAPE_FEATURE)]
              and key_equals(body,KEY_ESCAPE,c['block'])]
    support=key_sole(supports,'Typed Escape capability')
    queries=[c for c in body['calls'] if interface_getter(body,c)==input_getter
             and key_truth(body,('result',support['ea']),c['block'])]
    panel_values=set()
    for call in body['calls']:
        d=key_dispatch(call)
        if not d or d[0]!=THIS or d[1] not in frame:continue
        leaf=method(frame[d[1]])
        returned={r['value'] for r in leaf['returns']}
        if leaf['calls'] or len(returned)!=1:continue
        value=next(iter(returned))
        if value and value[:2]==('load',THIS):
            panel_values.update((('result',call['ea']),value))
    modal=[]
    for query in queries:
        for c in body['equalities']:
            if ('result',query['ea']) not in c['values']:continue
            other=c['values'][1] if c['values'][0]==('result',query['ea']) else c['values'][0]
            if all(v in panel_values for v in key_alternatives(other)):modal.append((query,c))
    query,guard=key_sole(modal,'app-modal equals this VPanel')
    # A GCC guarded-devirtualized call can join an earlier key branch. Recover
    # its current slot load on the modal-equal arm, then verify the selected body.
    closes=[]
    slot_uses=body['loads']+[dict(ea=c['ea'],value=c['target']) for c in body['calls']]
    for load in slot_uses:
        v=load['value']
        if not v or len(v)!=3 or v[:2]!=('load',('load',THIS,0)) or v[2]%4:continue
        block=next((int(b.start_ea) for b in ida_gdl.FlowChart(ida_funcs.get_func(typed))
                    if b.start_ea<=load['ea']<b.end_ea),None)
        if not key_guard(body,guard['equal'],guard['unequal'],block):continue
        if not any(c['args'][:1]==[THIS] and contains_value(c['target'],v) for c in body['calls']):continue
        index=v[2]//4
        if index not in frame:continue
        close=method(frame[index])
        posts=[c for c in message_posts(close,literals,('Close',))
               if c['args'][1]==THIS and key_dispatch(c)[1]==post_index]
        if len(posts)!=1:continue
        input_calls=[c for c in close['calls'] if interface_getter(close,c)==input_getter]
        restores=[c for c in input_calls if len(c['args'])>1 and c['args'][1]
                  and c['args'][1][:2]==('load',THIS)]
        if len(restores)!=1 or len(input_calls)!=2:continue
        field=restores[0]['args'][1][2]
        if not any(s['address']==('address',THIS,field) and s['value']==('const',0) for s in close['stores']):continue
        if not stack_abi(frame[index],0):continue
        identity(frame[index],['_ZN5vgui25Frame10CloseModalEv'])
        closes.append((index,frame[index]))
    close_index,close_ea=key_sole(set(closes),'modal Close implementation')
    modal_proof=dict(query=query['ea'],guard=guard['ea'],index=close_index,ea=close_ea)

constructor=None
if 'CCSCareerRoundEndMenu' in tables:
    direct_base(tables['CCSCareerBaseMenu'],'Frame@vgui2','N5vgui25FrameE')
    for cls in ('CCSCareerRoundEndMenu','CCSCareerMatchEndMenu'):
        direct_base(tables[cls],'CCSCareerBaseMenu','17CCSCareerBaseMenu')
        derived=entries(tables[cls])
        if derived.get(pressed_index)!=pressed or derived.get(typed_index)!=typed:
            raise ValueError(cls+' overrides or adjusts a key event')
    resource=literal_evidence('Resource/UI/CSCareerRoundEnd.res')
    label=literal_evidence('CSCareerRoundEnd')
    constructor=key_sole(set(resource['owners']) & set(label['owners']),'RoundEnd resource constructor')
    ctor_store(method(constructor),tables['CCSCareerRoundEndMenu'])
    identity(constructor,['_ZN21CCSCareerRoundEndMenuC1EPN5vgui25PanelE','_ZN21CCSCareerRoundEndMenuC2EPN5vgui25PanelE'])
match_constructor=None
if values['export_match']:
    if int(tables['CCSCareerMatchEndMenu']['vtable_va'],0)==int(tables['CCSCareerRoundEndMenu']['vtable_va'],0):
        raise ValueError('MatchEnd and RoundEnd primary tables alias')
    resource=literal_evidence('Resource/UI/CSCareerMatchEnd.res')
    label=literal_evidence('CSCareerMatchEnd')
    match_constructor=key_sole(set(resource['owners']) & set(label['owners']),'MatchEnd resource constructor')
    ctor_store(method(match_constructor),tables['CCSCareerMatchEndMenu'])
    identity(match_constructor,['_ZN21CCSCareerMatchEndMenuC1EPN5vgui25PanelE','_ZN21CCSCareerMatchEndMenuC2EPN5vgui25PanelE'])
result=dict(pressed=pressed,typed=typed,pressed_index=pressed_index,typed_index=typed_index,
            pressed_proof=pressed_proof,typed_proof=typed_proof,modal=modal_proof,constructor=constructor,
            match_constructor=match_constructor)
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map, new_binary_dir
    try:
        round_output = _output_for_symbol(expected_outputs, ROUND + "_vtable")
        match_output = _output_for_symbol(expected_outputs, MATCH + "_vtable")
        classes = [FRAME]
        if round_output or match_output:
            classes += ["CCSCareerBaseMenu", ROUND, MATCH]
        tables = await collect(session, platform, classes)
        found = await walk(
            session,
            IDENTITY_SOURCE + COMMON + COLLECT_COMMON + KEY_SOURCE + WALK,
            {"platform": platform, "tables": tables, "export_match": bool(match_output)},
        )
        if debug:
            print(f"  {skill_name} evidence: {found}")
        if found.get("error"):
            return False
        payloads = []
        for role, method_name in (("pressed", "OnKeyCodePressed"), ("typed", "OnKeyCodeTyped")):
            output = _output_for_symbol(expected_outputs, "vgui2_Frame_" + method_name)
            payload = await function_payload(
                session,
                found[role],
                image_base,
                f"vgui2::Frame::{method_name}(vgui2::KeyCode)",
                table=FRAME,
                index=found[role + "_index"],
            )
            if not output or not payload:
                return False
            payloads.append((output, payload))
        for output, payload in payloads:
            write_func_yaml(output, payload)
        for cls, output in ((ROUND, round_output), (MATCH, match_output)):
            if output:
                table = dict(tables[cls], vtable_rva=hex(int(tables[cls]["vtable_va"], 0) - image_base))
                write_vtable_yaml(output, table)
        return True
    except (ValueError, KeyError, TypeError) as exc:
        if debug:
            print(f"  {skill_name} rejected: {exc}")
        return False
