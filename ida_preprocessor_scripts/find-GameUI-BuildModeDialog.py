#!/usr/bin/env python3
"""Native build editor DPI dependencies, recovered from the current GameUI.

The GoldSrc list predates GetItemIDFromRow/SetVerticalBufferPixels. Publish the
actual sorted-int-vector pointer/count and spacing field, NOT an SDK container
layout. Consumers bounds-check the row, read its int ID, and use native getters.
SetFirstColumnWidth is retained on ELF; Windows uses the verified width field.
BuildModeDialog inherits Frame::ApplySchemeSettings: its artifact identifies the
real shared body, so downstream detours must discriminate the receiver.
"""

from pathlib import Path
import inspect

from ida_analyze_util import (
    _load_yaml_mapping,
    _output_for_symbol,
    preprocess_vtable_via_mcp,
    write_func_yaml,
    write_struct_offset_yaml,
    write_vtable_yaml,
)
from ida_preprocessor_scripts._vgui_paint_common import walk
from ida_preprocessor_scripts._vgui_private_symbols_common import function_payload
import ida_preprocessor_scripts._buildmode_identity as identity
from ida_preprocessor_scripts._vgui_private_method_identity import stack_check_preserves_registers


COLLECT = r"""
import ida_name
from functools import lru_cache
platform=values['platform']
tables=values['tables']
READ_HELPER_DEPTH=6
preserved=stack_check_helpers({int(ea,0) for t in tables.values() for ea in t['vtable_entries'].values()}
    | {int(values['setsize']['func_va'],0)},stack_check_preserves_registers)
def entries(cls):return {int(i):int(a,0) for i,a in tables[cls]['vtable_entries'].items()}
def target(cls,index):
    ea=entries(cls)[index]
    f=ida_funcs.get_func(ea)
    if not f or f.start_ea!=ea:raise ValueError('not a complete current function')
    return dict(ea=ea,index=index)
@lru_cache(maxsize=None)
def flow(ea,**kwargs):
    return flow_at(ea,platform,first_pass=True,symbolic_indices=True,symbolic_sums=True,preserved_calls=preserved,**kwargs)
def expanded_flow(ea,entry=None,depth=0):
    # Unoptimized releases keep CUtl accessors out of line. Project only
    # read-only helper results through their actual calling registers/stack;
    # no container field or helper call position is assumed.
    f=flow(ea) if entry is None else flow_at(ea,platform,first_pass=True,symbolic_indices=True,
        symbolic_sums=True,preserved_calls=preserved,entry_state=entry)
    calls={c['ea']:c for c in f['calls']}
    projected={};children=[]
    def expand(v):
        if not isinstance(v,tuple):return v
        if v[0]=='result' and v[1] in calls and depth<READ_HELPER_DEPTH:
            site=v[1]
            if site not in projected:
                projected[site]=v
                c=calls[site]
                if c['direct'] and is_code_address(c['direct']):
                    child=expanded_flow(c['direct'],entry_state_from_call(c),depth+1)
                    if child['pure'] and child['returns']:
                        vals=[r['value'] for r in child['returns']]
                        if all(x is not None and not any(n[0]=='stack' for n in nodes(x)) for x in vals):
                            projected[site]=choice(*vals)
                            children.append(child)
            return expand(projected[site]) if projected[site]!=v else v
        values=tuple(expand(x) for x in v)
        if values[0]=='load' and isinstance(values[1],tuple) and values[1][0]=='address':
            return ('load',values[1][1],values[1][2]+values[2])
        return values
    out=dict(f)
    for field in ('returns','loads','stores','comparisons'):
        out[field]=[]
        for item in f[field]:
            current=dict(item)
            for key in ('value','address'):
                if key in current:current[key]=expand(current[key])
            if 'values' in current:current['values']=[expand(v) for v in current['values']]
            out[field].append(current)
    out['pure']=not any(s['address'] and s['address'][0]!='stack' for s in out['stores']) and all(c['direct'] for c in f['calls'])
    for child in children:
        for field in ('loads','comparisons'):out[field].extend(child[field])
    return out
def methods(cls):
    result=[]
    for index,ea in entries(cls).items():
        if entries('vgui2::Panel').get(index)==ea:continue
        try:result.append(dict(target(cls,index),flow=expanded_flow(ea) if cls=='vgui2::PanelListPanel' else flow(ea)))
        except ValueError:continue
    return result
def literal(text):
    found=set();needle=text.encode()+b'\0'
    for se in idautils.Segments():
        seg=ida_segment.getseg(se)
        if seg.perm & ida_segment.SEGPERM_EXEC:continue
        raw=ida_bytes.get_bytes(seg.start_ea,seg.end_ea-seg.start_ea) or b''
        pos=raw.find(needle)
        while pos>=0:
            found.add(int(seg.start_ea+pos));pos=raw.find(needle,pos+1)
    return found
def owners(text):
    return {int(f.start_ea) for ea in literal(text) for ref in idautils.DataRefsTo(ea)
            if (f:=ida_funcs.get_func(ref)) is not None}
def has_literal(call,text):return any(('const',ea) in call['args'] for ea in literal(text))
def reference(ea,value):
    f=expanded_flow(ea)
    loads=[s for s in f['loads'] if s['value']==value and s['width']==4]
    loads += [c for c in f['comparisons'] if value in c['values']]
    loads += [a for a in f['addresses'] if value in set(nodes(a['value']))]
    matches=[]
    for load in loads:
        insn=idautils.DecodeInstruction(load['ea'])
        if ida_funcs.func_contains(ida_funcs.get_func(ea),load['ea']) and any(
                op.type==idaapi.o_displ and signed32(op.addr)==value[2] for op in insn.ops):matches.append(load['ea'])
    if not matches:
        if not loads:raise ValueError(f'no current composed access to {value}')
        return dict(offset=value[2])
    return dict(owner=ea,ea=min(matches),offset=value[2])
def slot_input(key,cls):
    data=values[key];i=int(data['vfunc_index'])
    # Inheritance takes only the current validated slot; never an old address.
    if int(data['vfunc_offset'],0)!=i*4:raise ValueError('unaligned inherited slot')
    return target(cls,i)

result={}
ctor=sole(owners('VGUI Build Mode Editor'),'complete BuildModeDialog constructor')
ctorflow=flow(ctor,track_memory=True)
table=('const',int(tables['vgui2::BuildModeDialog']['vtable_va'],0))
if not any(s['address']==THIS and s['value']==table for s in ctorflow['stores']):
    raise ValueError('constructor does not install current BuildModeDialog RTTI table')
result['ctor']=dict(ea=ctor)
create=sole(owners('BuildModeControls') & owners('FileSelectionCombo'),'controls creation owner')
createflow=flow(create,track_memory=True)
if create!=ctor and not any(c['direct']==create and c['args'][0]==THIS for c in ctorflow['calls']):
    raise ValueError('controls creation is not on complete constructor chain')
named_combo=sole([c for c in createflow['calls'] if c['direct'] and len(c['args'])>=3 and c['args'][1]==THIS
                 and c['args'][0] and c['args'][0][0]=='result'
                 and c['args'][2] in {('const',ea) for ea in literal('FileSelectionCombo')}],'file combo constructor')
if named_combo['args'][1]!=THIS:raise ValueError('file combo has wrong parent')
combo_ctor=named_combo['direct']
combo_table=('const',int(tables['vgui2::ComboBox']['vtable_va'],0))
if not any(s['address']==THIS and s['value']==combo_table for s in flow(combo_ctor)['stores']):
    raise ValueError('named ComboBox constructor lacks current RTTI assignment')
anonymous=[c for c in createflow['calls'] if c['direct']==combo_ctor and c['args'][1:3]==[THIS,('const',0)]]
additions=[c for c in createflow['calls'] if len(c['args'])>=3
           and c['args'][1] in {('const',ea) for ea in literal('None')} and c['args'][2]==('const',0)]
add_combo=sole([c for c in anonymous if any({('result',c['ea']),c['args'][0]} & set(nodes(a['args'][0])) for a in additions)],'anonymous add control combo')
store=sole([s for s in createflow['stores'] if s['address'] and s['address'][:2]==('address',THIS)
            and {('result',add_combo['ea']),add_combo['args'][0]} & set(nodes(s['value']))],'add control combo assignment')
result['add_combo']=dict(owner=create,ea=store['ea'],offset=store['address'][2])
# Every configured native version currently has just this one anonymous ComboBox.
# Fail if a new implementation introduces navigation so its fields are explicitly
# identified and declared rather than silently ignored or guessed by child index.
if len(anonymous)!=1:raise ValueError('additional anonymous navigation requires explicit identification')
result['control_names']=sorted({text for text in ('BuildModeControls','FileSelectionCombo','StatusLabel','Divider',
 'SaveButton','ExitButton','ApplyButton','VarsButton','DeletePanelButton','Localization','NextChild','PrevChild') if create in owners(text)})
result['layout']=slot_input('layout','vgui2::BuildModeDialog')
result['scheme']=slot_input('scheme','vgui2::BuildModeDialog')
if result['scheme']['ea']!=entries('vgui2::Frame')[result['scheme']['index']]:
    raise ValueError('new BuildModeDialog scheme override requires verification')
result['list_layout']=slot_input('layout','vgui2::PanelListPanel')

# GetClientArea writes four caller-owned references, gets dimensions through
# the same two references, and is overridden by Frame relative to Panel.
clients=[]
for m in methods('vgui2::Frame'):
    stores={s['address'] for s in m['flow']['stores']}
    if not {('arg',j) for j in (1,3,4)}<=stores:continue
    if not any(c['args'][:3]==[THIS,('arg',3),('arg',4)] for c in m['flow']['calls']):continue
    clients.append(m)
result['client_area']=sole(clients,'Frame client area output references')

# Panel::SetSize dispatches GetVPanel on this before forwarding its result to
# IPanel. Prove the candidate is a pure getter in the current Panel table.
sizeflow=flow(int(values['setsize']['func_va'],0))
getters=[]
for c in sizeflow['calls']:
    t=c['target']
    if not t or len(t)!=3 or t[:2]!=('load',('load',THIS,0)) or t[2]%4:continue
    m=target('vgui2::Panel',t[2]//4);f=flow(m['ea'])
    if f['calls'] or any(s['address'] and s['address'][0]!='stack' for s in f['stores']):continue
    if len({r['value'] for r in f['returns']})!=1 or not member(f['returns'][0]['value']):continue
    if not any(('result',c['ea']) in d['args'][1:] for d in sizeflow['calls']):continue
    getters.append(m)
if not getters:
    # GCC may inline the ordinary getter behind a devirtualization guard.
    handles={v for c in sizeflow['calls'] if c['args'][2:4]==[('arg',1),('arg',2)]
             for v in nodes(c['args'][1]) if member(v)}
    for i,ea in entries('vgui2::Panel').items():
        f=ida_funcs.get_func(ea)
        if not f or f.start_ea!=ea:continue
        f=flow(ea)
        returns={r['value'] for r in f['returns']}
        if not f['calls'] and len(returns)==1 and next(iter(returns)) in handles:
            getters.append(target('vgui2::Panel',i))
result['vpanel']=sole(getters,'Panel GetVPanel forwarding')

listmethods=methods('vgui2::PanelListPanel')
access=sparse_accessors(listmethods)
for key in ('renderer','panel','label'):result[key]=access[key]
renderer=access['renderer']
def returns_null_without_calls(start,method):
    zeros={r['ea'] for r in method['flow']['returns'] if r['value']==('const',0)}
    visited=set()
    while start not in visited:
        visited.add(start)
        if start in zeros:return True
        if not ida_funcs.func_contains(ida_funcs.get_func(method['ea']),start):return False
        mnemonic=idc.print_insn_mnem(start)
        if mnemonic in ('call','ret','retn') or mnemonic.startswith('j') and mnemonic!='jmp':return False
        if mnemonic=='jmp':
            insn=idautils.DecodeInstruction(start)
            if insn.ops[0].type!=idaapi.o_near:return False
            start=int(insn.ops[0].addr)
        else:start=idc.next_head(start)
    return False
counts=set()
for c in renderer['flow']['comparisons']:
    if ROW not in c['values']:continue
    fields={v for v in c['values'] if v in access['counts']}
    branch=idc.next_head(c['ea'])
    if not fields or idc.print_insn_mnem(branch) not in ('jge','jl','jle','jg'):continue
    insn=idautils.DecodeInstruction(branch)
    rejects=returns_null_without_calls(int(insn.ops[0].addr),renderer) or returns_null_without_calls(idc.next_head(branch),renderer)
    if not rejects and ida_funcs.func_contains(ida_funcs.get_func(renderer['ea']),c['ea']):
        # Optimized GCC merges the null and valid return into one RET. Trace
        # the signed out-of-range edge separately to prove its return value.
        successors=flow(renderer['ea'])['blocks'].get(c['block'],[])
        target_ea=int(insn.ops[0].addr)
        other=[s for s in successors if s!=target_ea]
        if len(other)==1:
            rejected=flow(renderer['ea'],excluded_edges=((c['block'],other[0]),))
            rejects={r['value'] for r in rejected['returns']}=={('const',0)}
    if rejects:
        counts.update(fields)
if not counts:
    # Debug IsValidIndex is out of line. Restrict the actual guard to its zero
    # successor and require a null return before using that helper's bound.
    raw=flow(renderer['ea'])
    for branch in raw['branches']:
        if not branch['condition'] or branch['condition'][0]!='result':continue
        c=next((c for c in raw['calls'] if c['ea']==branch['condition'][1] and c['direct']),None)
        if not c:continue
        rejected=flow(renderer['ea'],excluded_edges=((branch['block'],branch['nonzero']),))
        if {r['value'] for r in rejected['returns']}!={('const',0)}:continue
        helper=expanded_flow(c['direct'],entry_state_from_call(c),1)
        fields={v for cmp in helper['comparisons'] if ROW in cmp['values'] for v in cmp['values'] if v in access['counts']}
        if len(fields)==1:counts.update(fields)
access['count']=sole(counts,'signed row bound returning null')
result['row_memory']=reference(renderer['ea'],access['row_id'][1][1])
result['row_count']=reference(renderer['ea'],access['count'])
count_methods=[]
for m in listmethods:
    f=m['flow'];returns={r['value'] for r in f['returns']}
    if f.get('pure') and len(returns)==1 and member(next(iter(returns))):count_methods.append(m)
result['item_count']=sole(count_methods,'native list item count getter')

# Native computeVPixelsNeeded returns buffer + accumulated panel heights. The
# return's first addend is a member, and the body walks the same sorted rows.
computes=[]
for m in listmethods:
    returns={r['value'] for r in m['flow']['returns']}
    if len(returns)!=1:continue
    v=next(iter(returns))
    if not v or v[0]!='indexed' or v[-1]!=1:continue
    buffers={v[j] for j in (1,2) if member(v[j])}
    if len(buffers)!=1:continue
    loads={s['value'] for s in m['flow']['loads']}
    loads.update(v for c in m['flow']['comparisons'] for v in c['values'])
    if access['count'] not in loads or access['row_id'][1][1] not in loads:continue
    if not m['flow']['calls']:continue
    computes.append((m,next(iter(buffers))))
compute,buffer=sole(computes,'native vertical pixel calculation')
result['compute']=compute
result['buffer']=reference(compute['ea'],buffer)

layoutflow=flow(result['list_layout']['ea'])
widths=[]
label_field=returned_pointer(access['label']['flow'])[2]
panel_field=returned_pointer(access['panel']['flow'])[2]
for c in layoutflow['calls']:
    args=c['args']
    if len(args)<5 or not member(args[3]):continue
    # The row label's member offset is recovered from the paired native getter.
    receiver=args[0]
    if not receiver or receiver[0]!='load' or receiver[2]!=label_field:continue
    for other in layoutflow['calls']:
        a=other['args']
        if len(a)<5 or a[0]!=('load',receiver[1],panel_field):continue
        if c['direct']!=other['direct'] or not c['direct']:continue
        if args[2] is None or args[4] is None or args[2]!=a[2] or args[4]!=a[4]:continue
        if args[3] in set(nodes(a[1])) and buffer in set(nodes(a[1])):
            widths.append(args[3])
width=sole(set(widths),'list label first column geometry')
result['column']=reference(result['list_layout']['ea'],width)
if platform=='linux':
    ea=ida_name.get_name_ea(-1,'_ZN5vgui214PanelListPanel19SetFirstColumnWidthEi')
    if ea!=idaapi.BADADDR:
        setter=flow(ea)
        if not any(s['address']==('address',THIS,width[2]) and s['value']==('arg',1) for s in setter['stores']):
            raise ValueError('ELF column setter disagrees with native layout')
        result['set_column']=dict(ea=int(ea))

# Keep transport small; function traces are research evidence, not artifacts.
for key,value in result.items():
    if isinstance(value,dict):
        value.pop('flow',None)
        if 'ea' in value and platform=='linux' and 'offset' not in value:
            value['demangled']=ida_name.demangle_name(ida_name.get_name(value['ea']),ida_name.MNG_SHORT_FORM)
"""

FUNCTIONS = [
    ("vgui2_BuildModeDialog_ctor", "vgui2::BuildModeDialog::BuildModeDialog(vgui2::BuildGroup*)", None, "ctor"),
    (
        "vgui2_BuildModeDialog_PerformLayout",
        "vgui2::BuildModeDialog::PerformLayout()",
        "vgui2::BuildModeDialog",
        "layout",
    ),
    (
        "vgui2_BuildModeDialog_ApplySchemeSettings",
        "vgui2::Frame::ApplySchemeSettings(vgui2::IScheme*)",
        "vgui2::BuildModeDialog",
        "scheme",
    ),
    ("vgui2_Frame_GetClientArea", "vgui2::Frame::GetClientArea(int&, int&, int&, int&)", "vgui2::Frame", "client_area"),
    ("vgui2_Panel_GetVPanel", "vgui2::Panel::GetVPanel()", "vgui2::Panel", "vpanel"),
    (
        "vgui2_PanelListPanel_PerformLayout",
        "vgui2::PanelListPanel::PerformLayout()",
        "vgui2::PanelListPanel",
        "list_layout",
    ),
    (
        "vgui2_PanelListPanel_GetItemCount",
        "vgui2::PanelListPanel::GetItemCount()",
        "vgui2::PanelListPanel",
        "item_count",
    ),
    ("vgui2_PanelListPanel_GetItemLabel", "vgui2::PanelListPanel::GetItemLabel(int)", "vgui2::PanelListPanel", "label"),
    ("vgui2_PanelListPanel_GetItemPanel", "vgui2::PanelListPanel::GetItemPanel(int)", "vgui2::PanelListPanel", "panel"),
    (
        "vgui2_PanelListPanel_GetCellRenderer",
        "vgui2::PanelListPanel::GetCellRenderer(int)",
        "vgui2::PanelListPanel",
        "renderer",
    ),
    (
        "vgui2_PanelListPanel_computeVPixelsNeeded",
        "vgui2::PanelListPanel::computeVPixelsNeeded()",
        "vgui2::PanelListPanel",
        "compute",
    ),
    ("vgui2_PanelListPanel_SetFirstColumnWidth", "vgui2::PanelListPanel::SetFirstColumnWidth(int)", None, "set_column"),
]
MEMBERS = [
    ("vgui2_BuildModeDialog", "m_pAddNewControlCombo", "add_combo"),
    ("vgui2_PanelListPanel", "m_SortedItems_m_pMemory", "row_memory"),
    ("vgui2_PanelListPanel", "m_SortedItems_m_Size", "row_count"),
    ("vgui2_PanelListPanel", "m_iPanelBuffer", "buffer"),
    ("vgui2_PanelListPanel", "m_iFirstColumnWidth", "column"),
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    try:
        tables = {}
        for short in ("Panel", "Frame", "BuildModeDialog", "PanelListPanel", "ComboBox"):
            alias = f"??_7{short}@vgui2@@6B@" if platform == "windows" else f"_ZTVN5vgui2{len(short)}{short}E"
            table = await preprocess_vtable_via_mcp(
                session, f"vgui2::{short}", image_base, platform, symbol_aliases=[alias]
            )
            if not table or table.get("vtable_symbol") != alias:
                raise ValueError(f"{short}: missing current RTTI")
            tables[f"vgui2::{short}"] = dict(
                table, vtable_entries={str(i): a for i, a in table["vtable_entries"].items()}
            )
        inputs = {}
        for key, stem in (
            ("layout", "GameUI_PropertySheet_PerformLayout"),
            ("scheme", "GameUI_MessageBox_ApplySchemeSettings"),
            ("setsize", "GameUI_Panel_SetSize"),
        ):
            data = _load_yaml_mapping(Path(new_binary_dir) / f"{stem}.{platform}.yaml")
            if not data:
                raise ValueError(f"missing current {stem}")
            inputs[key] = data
        found = await walk(
            session,
            Path(identity.__file__).read_text(encoding="utf-8")
            + inspect.getsource(stack_check_preserves_registers)
            + COLLECT,
            dict(inputs, platform=platform, tables=tables),
        )
        if found.get("error"):
            raise ValueError(found["error"])
        payloads = {}
        for symbol, name, cls, key in FUNCTIONS:
            if key not in found:
                continue
            target = found[key]
            demangled = target.get("demangled")
            if demangled:
                if demangled.replace(" ", "").replace("(void)", "()") != name.replace(" ", ""):
                    raise ValueError(f"{symbol}: ELF ABI disagrees: {demangled}")
                name = demangled
            payload = await function_payload(
                session, target["ea"], image_base, name, table=cls, index=target.get("index")
            )
            if not payload:
                raise ValueError(f"{symbol}: no unique signature")
            payloads[symbol] = payload
        for struct, member, key in MEMBERS:
            ref = found[key]
            owner = (
                await function_payload(session, ref["owner"], image_base, "member reference")
                if "owner" in ref
                else None
            )
            if "owner" in ref and not owner:
                raise ValueError(f"{member}: no unique owner signature")
            payload = dict(
                struct_name=struct.replace("_", "::", 1),
                member_name=member,
                offset=hex(ref["offset"]),
                size="0x4",
            )
            if owner:
                payload.update(offset_sig=owner["func_sig"], offset_sig_disp=hex(ref["ea"] - ref["owner"]))
            if owner and owner.get("func_sig_allow_across_function_boundary"):
                payload["offset_sig_allow_across_function_boundary"] = True
            write_struct_offset_yaml(_output_for_symbol(expected_outputs, f"{struct}_{member}"), payload)
        table = tables["vgui2::PanelListPanel"]
        table.pop("_pointer_size", None)
        write_vtable_yaml(_output_for_symbol(expected_outputs, "vgui2_PanelListPanel_vtable"), table)
        for symbol, payload in payloads.items():
            write_func_yaml(_output_for_symbol(expected_outputs, symbol), payload)
        if debug:
            print(f"[BuildModeDialog] Native control names: {found['control_names']}")
        return True
    except Exception as exc:
        if debug:
            print(f"[BuildModeDialog] {exc}")
        return False
