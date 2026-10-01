"""Shared current-binary collection and emission for the private VGUI chains."""

from pathlib import Path
from uuid import uuid4

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    preprocess_vtable_via_mcp,
    write_func_yaml,
    write_struct_offset_yaml,
)
from ida_preprocessor_scripts._vgui_paint_common import walk
import ida_preprocessor_scripts._vgui_private_method_identity as identity


COMMON_CLASSES = ("vgui2::Panel", "vgui2::Frame", "vgui2::EditablePanel", "vgui2::FocusNavGroup")
GAMEUI_CLASSES = (
    "vgui2::PropertySheet",
    "COptionsSubVideo",
    "COptionsSubAudio",
    "COptionsSubMultiplayer",
    "CBasePanel",
    "CCvarSlider",
)
INTERFACES = {
    "ISurface_SupportsFeature": (
        "vgui2::ISurface",
        "vgui2::ISurface::SupportsFeature(vgui2::ISurface::SurfaceFeature_e)",
    ),
    "IInput_GetAppModalSurface": ("vgui2::IInput", "vgui2::IInput::GetAppModalSurface()"),
    "ISchemeManager_ReloadSchemes": ("vgui2::ISchemeManager", "vgui2::ISchemeManager::ReloadSchemes()"),
}
SHEET_ARGUMENTS = {
    "AddPage": "vgui2::Panel*, char const*",
    "SetActivePage": "vgui2::Panel*",
    "SetTabWidth": "int",
    "GetActivePage": "",
    "ResetAllData": "",
    "ApplyChanges": "",
    "GetPage": "int",
    "DeletePage": "vgui2::Panel*",
    "GetActiveTab": "",
    "GetActiveTabTitle": "char*, int",
    "GetTabTitle": "int, char*, int",
    "GetActivePageNum": "",
    "GetNumPages": "",
    "DisablePage": "char const*",
    "EnablePage": "char const*",
    "ChangeActiveTab": "int",
}


async def walk_stages(session, stages, values):
    """Keep one owned-worker namespace while bounding each IDA tool request."""
    key = "_vgui_private_" + uuid4().hex
    try:
        for index, stage in enumerate(stages):
            if index == 0:
                body = f"import builtins\nsetattr(builtins, {key!r}, globals())\n" + stage
            else:
                body = f"import builtins\nns = getattr(builtins, {key!r})\nexec({stage!r}, ns)\nresult = ns['result']"
            if index != len(stages) - 1:
                body += "\nresult = {'ready': True}"
            found = await walk(session, body, values)
            if found.get("error"):
                raise ValueError(found["error"])
        return found
    finally:
        await walk(session, f"import builtins\nbuiltins.__dict__.pop({key!r}, None)\nresult = {{}}", {})


async def function_payload(session, ea, image_base, name, *, table=None, index=None):
    candidate = None
    across = False
    for limit in (None, 128, 256, 512, 1024, 2048, 4096):
        candidate = await _inspect_function_via_mcp(
            session, ea, image_base, name, signature_byte_limit=limit, allow_relative_call_discriminator=True
        )
        if candidate:
            break
    if not candidate:
        candidate = await _inspect_function_via_mcp(session, ea, image_base, name, allow_across_function_boundary=True)
        across = bool(candidate)
    if not candidate:
        return None
    payload = {field: candidate[field] for field in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    if across or len(payload["func_sig"].split()) > int(payload["func_size"], 0):
        payload["func_sig_allow_across_function_boundary"] = True
    if table is not None:
        payload.update(vtable_name=table, vfunc_index=index, vfunc_offset=hex(index * 4))
    return payload


REGISTRATION_COLLECT = r"""
# These are traversal budgets, not instruction windows or message-field offsets.
MAP_WRAPPER_DEPTH=2
REGISTRATION_CALL_DEPTH=4
RETURN_PROJECTION_DEPTH=3
# Collect only the class-name/map wrappers reachable from anchored registration owners.
frontier={c['direct'] for ea in roots['setfocus_all'] for c in method_calls(functions[str(ea)])
          if c['direct'] and is_code_address(c['direct'])}
for _ in range(MAP_WRAPPER_DEPTH):
    following=set()
    for ea in frontier:
        if str(ea) not in functions:
            functions[str(ea)]=safe_describe(ea)
        following.update(c['direct'] for c in method_calls(functions[str(ea)])
                         if c['direct'] and is_code_address(c['direct']))
    frontier=following
dispatchers = []
for method in table_methods(data, 'vgui2::Panel'):
    if "Message '%s', sent to '%s', has invalid parameter types\n" not in owned_labels(method):
        continue
    flow = flow_at(method['ea'],values['platform'],first_pass=True,
                   symbolic_indices=True,preserved_calls=preserved,arithmetic_conditions=True,symbolic_sums=True)
    excluded=[]
    for comparison in flow['comparisons']:
        target,address=comparison['values']
        dispatch=virtual_dispatch(dict(target=target))
        if not dispatch or dispatch[0]!=THIS or not address or address[0]!='const':continue
        entry=values['tables']['vgui2::Panel']['vtable_entries'].get(str(dispatch[1]))
        if entry is None or int(entry,0)!=address[1]:continue
        body=functions.get(str(address[1]),{})
        if 'Panel' not in owned_labels(body):continue
        branch=idc.next_head(comparison['ea'])
        if idc.print_insn_mnem(branch) not in ('jnz','jne'):continue
        fallback=int(idautils.DecodeInstruction(branch).ops[0].addr)
        successors=flow['blocks'].get(comparison['block'],[])
        if fallback in successors:
            excluded.extend((comparison['block'],s) for s in successors if s!=fallback)
    if excluded:
        # Verify the current-table devirtualization guard, then inspect its
        # explicit getter dispatch. Cached/inlined map initialization can join
        # unrelated allocation values and hide otherwise identical field uses.
        flow=flow_at(method['ea'],values['platform'],first_pass=True,symbolic_indices=True,
                     preserved_calls=preserved,arithmetic_conditions=True,symbolic_sums=True,excluded_edges=excluded)
    for load in flow['loads']:
        insn = idautils.DecodeInstruction(load['ea'])
        operand = decoded_operand(insn.ops[1])
        if (operand[0]=='mem' and operand[1] is not None and operand[3] is None
                and load['address'] is not None and load['address'][0]!='stack'):
            load['field_offset']=operand[2]
    for call in flow['calls']:
        insn=idautils.DecodeInstruction(call['ea'])
        operand=decoded_operand(insn.ops[0])
        if operand[0]=='mem' and operand[1] is not None and operand[3] is None:
            flow['loads'].append(dict(ea=call['ea'],value=call['target'],field_offset=operand[2]))
    try:
        layout=message_dispatch_layout(dict(flow=flow))
    except ValueError:
        continue
    getmaps=[]
    for call in flow['calls']:
        if virtual_dispatch(call) and virtual_dispatch(call)[0]==THIS:
            body=dispatch_method(data,call)
            if 'Panel' in owned_labels(body) or any(
                    'Panel' in owned_labels(functions.get(str(c['direct']),{})) for c in method_calls(body)):
                getmaps.append(body)
    if len(getmaps)==1:
        dispatchers.append((method['ea'],layout,getmaps[0],flow))
dispatch_ea,layout,getmap,dispatch_flow=sole(dispatchers,'Panel message dispatcher and map getter')
panel_labels={('const',a) for a in literals['Panel']['addresses']}

constant_returns={}
for f in functions.values():
    ret={r['value'] for r in f.get('flow',{}).get('returns',[])}
    if len(ret)==1 and next(iter(ret)) in panel_labels and not method_calls(f) and all(
            s['address'] and s['address'][0]=='stack' for s in f['flow']['stores']):
        constant_returns[f['ea']]=next(iter(ret))
def traced(ea,entry_state=None,nonzero_calls=()):
    # Use the existing-map path to prove the destination. Allocation paths need
    # not be guessed from adjacent strings or unmodelled dictionary internals.
    return flow_at(ea,values['platform'],entry_state=entry_state,preserved_calls=preserved,
                   first_pass=True,symbolic_indices=True,capture_stack=True,nonzero_calls=nonzero_calls,
                   call_returns=constant_returns,symbolic_sums=True,track_memory=True)

def label_locations(call):
    stack=[('stack',i) for i,v in enumerate(call['stack_args']) if v in panel_labels]
    return tuple(stack[:1] or [('register',r) for r in ('eax','ecx','edx') if call['registers'][r] in panel_labels])

providers={}
pending=[]
getter_flow=traced(getmap['ea'])
for call in getter_flow['calls']:
    if call['direct'] and label_locations(call):
        pending.append((call,0))
while pending:
    call,depth=pending.pop()
    if depth>REGISTRATION_CALL_DEPTH or call['direct'] in providers:
        continue
    providers[call['direct']]=label_locations(call)
    flow=traced(call['direct'],entry_state_from_call(call))
    returned=[r['value'] for r in flow['returns']]
    for child in flow['calls']:
        if child['direct'] and label_locations(child) and any(contains_value(v,('result',child['ea'])) for v in returned):
            pending.append((child,depth+1))

def is_provider(call):
    return call['direct'] in providers and any(
        (call['stack_args'][location] if kind=='stack' else call['registers'][location]) in panel_labels
        for kind,location in providers[call['direct']])

registrars=[]
focus_labels={('const',a) for a in literals['SetFocus']['addresses']}
for ea in roots['setfocus_all']:
    owner=functions[str(ea)]
    if any(s['value'] in focus_labels for s in owner.get('flow',{}).get('stores',[])):
        registrars.append(dict(ea=ea,root=ea,flow=traced(ea)))
    for call in method_calls(owner):
        helper=functions.get(str(call['direct']),{})
        panel_helper='Panel' in owned_labels(helper) or any(c['direct'] in constant_returns for c in method_calls(helper))
        if call['direct'] and panel_helper and any(contains_value(call['stack_args']+list(call['registers'].values()),label)
                                                  for label in focus_labels):
            registrars.append(dict(ea=call['direct'],root=ea,caller=call['ea'],flow=traced(call['direct'],entry_state_from_call(call))))
for registrar in registrars:
    registrar['providers']=[c['ea'] for c in registrar['flow']['calls'] if is_provider(c)]
    if registrar['providers']:
        if registrar.get('caller'):
            source=next(c for ea in roots['setfocus_all'] for c in method_calls(functions[str(ea)]) if c['ea']==registrar['caller'])
            entry=entry_state_from_call(source)
        else:
            entry=None
        registrar['flow']=traced(registrar['ea'],entry,registrar['providers'])

def copy_loop_size(load,store):
    source=idautils.DecodeInstruction(load['ea'])
    dest=idautils.DecodeInstruction(store['ea'])
    src,dst=decoded_operand(source.ops[1]),decoded_operand(dest.ops[0])
    if (src[0]!='mem' or dst[0]!='mem' or not src[3] or src[3]!=dst[3] or src[4]!=dst[4]
            or decoded_operand(source.ops[0]) != decoded_operand(dest.ops[1])):
        return None
    block=next((b for b in ida_gdl.FlowChart(ida_funcs.get_func(load['ea'])) if b.start_ea<=load['ea']<b.end_ea),None)
    if not block or not block.start_ea<=store['ea']<block.end_ea:
        return None
    increment,limit,backedge=None,None,False
    for ea in idautils.Heads(store['ea']+dest.size,block.end_ea):
        insn=idautils.DecodeInstruction(ea);m=idc.print_insn_mnem(ea)
        a,b=decoded_operand(insn.ops[0]),decoded_operand(insn.ops[1])
        if m=='add' and a[:2]==('reg',src[3]) and b[0]=='imm':increment=b[1]
        if m=='inc' and a[:2]==('reg',src[3]):increment=1
        if m=='cmp' and a[:2]==('reg',src[3]) and b[0]=='imm':limit=b[1]
        if m in ('jb','jnz','jne','jl') and int(insn.ops[0].addr)==load['ea']:backedge=True
    return limit*src[4] if increment and increment*src[4]==4 and limit and backedge else None

def record_fields(snapshot,base):
    fields={int(k)-base[1]:v for k,v in snapshot.items()}
    return fields if fields.get(0) in {('const',a) for a in literals['SetFocus']['addresses']} else None

records=[]
def project_return(call,depth=0):
    if depth>RETURN_PROJECTION_DEPTH or not call['direct'] or not is_code_address(call['direct']):return None
    try: body=traced(call['direct'],entry_state_from_call(call))
    except ValueError:return None
    calls={c['ea']:c for c in body['calls']}
    def resolve(value):
        if not isinstance(value,tuple):return value
        if value[0]=='result' and value[1] in calls:return project_return(calls[value[1]],depth+1)
        return tuple(resolve(v) for v in value)
    returns={resolve(r['value']) for r in body['returns']}
    return next(iter(returns)) if len(returns)==1 and None not in returns else None

map_getter_calls={('result',c['ea']) for c in dispatch_flow['calls'] if virtual_dispatch(c)
                  and virtual_dispatch(c)[0]==THIS and dispatch_method(data,c)['ea']==getmap['ea']}
dispatch_calls={c['ea']:c for c in dispatch_flow['calls']}
def entry_storage_offsets(value,depth=0):
    if value is None or depth>RETURN_PROJECTION_DEPTH:return set()
    if value[0]=='load' and value[1] in map_getter_calls:return {value[2]}
    if value[0]=='choice':
        parts=[entry_storage_offsets(v,depth+1) for v in value[1:]]
        return set.union(*parts) if parts and all(parts) else set()
    if value[0]=='address':return entry_storage_offsets(value[1],depth+1)
    if value[0]=='indexed':
        return entry_storage_offsets(value[1],depth+1) or entry_storage_offsets(value[2],depth+1)
    if value[0]=='result' and value[1] in dispatch_calls:
        return entry_storage_offsets(project_return(dispatch_calls[value[1]]),depth+1)
    return set()
storage_offsets=[entry_storage_offsets(base) for base in layout['record_bases']]
if not storage_offsets or not all(storage_offsets):
    raise ValueError('message dispatcher has no proven map entries array')
entries_offset=sole(set.union(*storage_offsets),'message-map entries array field')

def consume(ea,flow,maps,fields=None,record=None,depth=0,destinations=()):
    if depth>REGISTRATION_CALL_DEPTH:return
    if record is not None and any(s['address']==record or (
            isinstance(s['address'],tuple) and s['address'][:2]==('address',record)) for s in flow['stores']):
        raise ValueError('message consumer modifies its source record')
    array_roots={('load',m,entries_offset) for m in maps}|set(destinations)
    storage={s['value'] for s in flow['stores'] if s['value'] and any(
        s['address']==(m if entries_offset==0 else ('address',m,entries_offset)) for m in maps)}
    calls={c['ea']:c for c in flow['calls']}
    projected={}
    def project(value):
        if value[0]=='result' and value[1] in calls:
            if value not in projected:projected[value]=project_return(calls[value[1]])
            return projected[value]
        return None
    def map_owned(value):
        return map_storage_owned(value,array_roots,storage,project)
    # Unrolled SIMD copies retain each lane's actual source address. Require
    # contiguous source/destination coverage in one block, not a nearby literal.
    lanes=[s for s in flow['stores'] if s.get('copy_source') and map_owned(s['address'])]
    for first in lanes:
        source=first['copy_source'];destination=first['address']
        bound=fields if source==record and record is not None else record_fields(first['stack_values'],source) if source[0]=='stack' else None
        if bound is None:continue
        copied={offset for offset in range(0,layout['count']+4,4) if any(
            s['block']==first['block'] and s['ea']>=first['ea'] and s['width']==4
            and s['copy_source']==add_value(source,offset) and s['address']==add_value(destination,offset) for s in lanes)}
        if copied==set(range(0,layout['count']+4,4)):
            records.append(dict(owner=ea,site=first['ea'],fields=bound,size=layout['count']+4,layout=layout))
    for store in flow['stores']:
        if not map_owned(store['address']):continue
        if store.get('copy'):
            source=store['value'];count=store['count']
            size=count[1]*store['width'] if count and count[0]=='const' else None
            candidates=[(source,store.get('stack_values',{}),size)]
        else:
            candidates=[(load['address'],load.get('stack_values',{}),copy_loop_size(load,store))
                        for load in flow['loads'] if load['value']==store['value'] and load['ea']<store['ea']]
        for source,snapshot,size in candidates:
            if not size or size<layout['count']+4:continue
            bound=fields if source==record and record is not None else record_fields(snapshot,source) if source and source[0]=='stack' else None
            if bound is not None:
                records.append(dict(owner=ea,site=store['ea'],fields=bound,size=size,layout=layout))
    for call in flow['calls']:
        if not call['direct'] or not is_code_address(call['direct']):continue
        inputs=call['args']+call['stack_args']+list(call['registers'].values())
        if not any(v in maps or map_owned(v) for v in inputs if isinstance(v,tuple)):continue
        candidates=[]
        if record and record in inputs:candidates.append((record,fields))
        for value in set(v for v in inputs if isinstance(v,tuple) and v[0]=='stack'):
            bound=record_fields(call['stack_values'],value)
            if bound is not None:candidates.append((value,bound))
        for source,bound in candidates:
            token=record if source==record else ('caller_stack',call['ea'],source[1])
            entry=entry_state_from_call(call)
            try: child=traced(call['direct'],entry)
            except ValueError:continue
            child_destinations=array_roots|{v for v in inputs if isinstance(v,tuple) and map_owned(v)}
            consume(call['direct'],child,maps,bound,token,depth+1,child_destinations)

for registrar in registrars:
    if registrar['providers']:
        start=len(records)
        consume(registrar['ea'],registrar['flow'],{('result',ea) for ea in registrar['providers']})
        for record in records[start:]:
            record['root']=registrar['root']
            record['fields']={offset:value for offset,value in record['fields'].items() if 0<=offset<record['size']}
data['message_records']=records
if values['platform']=='windows':
    for record in records:
        callback=record['fields'].get(record['layout']['callback'])
        if callback and callback[0]=='const' and is_code_address(callback[1]):
            materialize_entry(callback[1])
            ida_auto.auto_wait()
            functions[str(callback[1])]=safe_describe(callback[1])
"""


COLLECT = (
    r"""
import ida_auto, ida_name

def literal_evidence(text):
    needle = text.encode() + bytes([0])
    addresses, owners = set(), set()
    for se in idautils.Segments():
        segment = ida_segment.getseg(se)
        if segment.perm & ida_segment.SEGPERM_EXEC:
            continue
        raw = ida_bytes.get_bytes(segment.start_ea, segment.end_ea-segment.start_ea) or b''
        position = raw.find(needle)
        while position >= 0:
            address = int(segment.start_ea + position)
            addresses.add(address)
            for ref in idautils.XrefsTo(address, 0):
                owner = ida_funcs.get_func(ref.frm)
                if owner:
                    owners.add(int(owner.start_ea))
            position = raw.find(needle, position + 1)
    return dict(addresses=sorted(addresses), owners=sorted(owners))

literals = {s:literal_evidence(s) for s in (
    'ControlFactory','ControlName','PanelPtr','CloseFrameButtonPressed','Hotkey','Panel','SetFocus',
    'SFX Slider','Suit Slider','MP3 Volume')}
roots = {}
for label, names in (('stage1',('ControlFactory','ControlName','PanelPtr')),
                     ('stage2',('CloseFrameButtonPressed','Hotkey'))):
    roots[label] = sorted(set.intersection(*(set(literals[n]['owners']) for n in names)))
roots['setfocus_all'] = literals['SetFocus']['owners']
selected = {ea for owners in roots.values() for ea in owners}
selected.update(values.get('constructors', {}).values())
roles = {}
for cls, table in values['tables'].items():
    for index, target in table['vtable_entries'].items():
        address = int(target, 0)
        selected.add(address)
        roles.setdefault(address, []).append((cls, int(index)))

def materialize_entry(ea):
    # Current RTTI entries and registered callbacks can be decoded code without
    # a function object in warm IDBs. Never replace/split an existing function.
    segment = ida_segment.getseg(ea)
    if (ida_funcs.get_func(ea) is None and is_code_address(ea)
            and segment.type != ida_segment.SEG_XTRN
            and (values['platform'] == 'windows' or ida_segment.get_segm_name(segment) == '.text')
            and ida_bytes.is_code(ida_bytes.get_full_flags(ea))):
        if not ida_funcs.add_func(ea):
            raise ValueError('could not materialize current entry ' + hex(ea))

for ea in selected:
    if roles.get(ea):
        materialize_entry(ea)
ida_auto.auto_wait()

preserved = stack_check_helpers(selected, stack_check_preserves_registers)

functions = {}
def describe(ea):
    owner = ida_funcs.get_func(ea)
    out = dict(ea=ea, rva=ea-ida_nalt.get_imagebase(), roles=roles.get(ea,[]), strings=[])
    if owner is None or owner.start_ea != ea:
        return out
    flow = flow_at(ea, values['platform'], preserved_calls=preserved)
    out['flow'] = flow
    # Indexed addresses are needed only for container identities, keeping the
    # interface/parent traces conservative and independent of that extension.
    if any(cls == 'vgui2::PropertySheet' for cls,_ in roles.get(ea,[])) or not roles.get(ea):
        out['container_flow'] = flow_at(ea, values['platform'],
                                        preserved_calls=preserved, symbolic_indices=True)
    for p in idautils.FuncItems(ea):
        for ref in idautils.DataRefsFrom(p):
            text = idc.get_strlit_contents(ref,-1,ida_nalt.STRTYPE_C)
            if text:
                out['strings'].append((int(p),int(ref),text.decode('utf-8','replace')))
    return out

def safe_describe(ea):
    try:
        return describe(ea)
    except ValueError as exc:
        # Unrelated RTTI entries may exceed this conservative flow model.
        # They cannot participate in an accepted method identity.
        return dict(ea=ea, strings=[], flow_error=str(exc))

for ea in sorted(selected):
    functions[str(ea)] = safe_describe(ea)
extra = set()
for f in list(functions.values()):
    for call in method_calls(f):
        if call['direct'] and is_code_address(call['direct']):
            extra.add(call['direct'])
        for value in call['args'] + call['stack_args']:
            if isinstance(value,tuple) and value[0] == 'const' and is_code_address(value[1]):
                extra.add(value[1])
    for store in f.get('flow',{}).get('stores',[]):
        value = store['value']
        if isinstance(value,tuple) and value[0] == 'const' and is_code_address(value[1]):
            extra.add(value[1])
for ea in sorted(extra-selected):
    functions[str(ea)] = safe_describe(ea)
data = dict(platform=values['platform'], tables=values['tables'], literals=literals, roots=roots, functions=functions)
"""
    + REGISTRATION_COLLECT
    + r"""
factory = recover_factory_parent(data)
focus = recover_frame_focus(data, factory['getvpanel'])

def member_reference(method, offset):
    candidates = [dict(ea=e['ea'], ref_kind=e['ref_kind']) for e in method['flow'].get('addresses',[])
                  if e['value'] == ('address',THIS,offset)]
    if not candidates:
        candidates = [dict(ea=e['ea'],ref_kind='displacement') for e in method['flow']['loads']
                      if e['value'] == ('load',THIS,offset)]
    if not candidates:
        raise ValueError('member has no current referencing instruction')
    reference = candidates[0]
    insn = idautils.DecodeInstruction(reference['ea'])
    actual = {signed32(op.addr) if reference['ref_kind'] == 'displacement' else int(op.value)
              for op in insn.ops if int(op.type) == (idaapi.o_displ if reference['ref_kind'] == 'displacement' else idaapi.o_imm)}
    if actual != {offset}:
        raise ValueError('member instruction does not encode the derived offset')
    return dict(owner=method['ea'],offset=offset,**reference)

result = dict(proportional=dict(ea=factory['proportional']['ea'],index=factory['proportional']['index']),
              nav=dict(ea=focus['nav']['ea'],index=focus['nav']['index']),
              current=dict(ea=focus['current']['ea'],index=focus['current']['index']),
              nav_member=member_reference(focus['nav'],focus['nav_offset']),
              current_member=member_reference(focus['current'],focus['current_offset']),
              interfaces=focus['interfaces'])
if values.get('gameui'):
    # Preserve source roles while unfolding actual leaf container helpers.
    sheet_data = dict(data,functions={key:dict(f,flow=f.get('container_flow',f.get('flow',{})))
                                    for key,f in functions.items()})
    sheet = recover_property_sheet(sheet_data, values['active_page'], values['perform_index'])
    result['sheet'] = {label:dict(ea=m['ea'],index=m['index']) for label,m in sheet.items()}
    result['active_member'] = member_reference(sheet['GetActivePage'],values['active_page'])
    video = sole([m for m in table_methods(data,'COptionsSubVideo') if m['ea'] == values['video_predecessor']
                  or any(c['direct'] == values['video_predecessor'] for c in method_calls(m))], 'Video OnApplyChanges')
    groups = {}
    for call in method_calls(video):
        if call['direct'] and call['args'] and _member(call['args'][0]):
            groups.setdefault(call['direct'],[]).append(call)
    apply = []
    for address,calls in groups.items():
        body = functions.get(str(address),{})
        getter_results = {('result',c['ea']) for c in method_calls(body)
                          if virtual_dispatch(c) and virtual_dispatch(c)[0] == THIS}
        if len(calls) == 2 and len({c['args'][0] for c in calls}) == 2 and any(
            s['value'] in getter_results and s['width'] == 4 and isinstance(s['address'],tuple)
            and s['address'][:2] == ('address',THIS) for s in body.get('flow',{}).get('stores',[])) and any(
            c['direct'] is None and (virtual_dispatch(c) is None
                or virtual_dispatch(c)[0][0] == 'const') and any(
                isinstance(a,tuple) and a[:2] == ('address',THIS) for a in c['args'] + c['stack_args'])
            for c in method_calls(body)):
            apply.append(address)
    slider_apply = sole(apply,'CCvarSlider ApplyChanges stores GetValue and writes named cvar')
    audio = sole([m for m in table_methods(data,'COptionsSubAudio') if m['index'] == video['index']], 'Audio override')
    members = {c['args'][0] for c in method_calls(audio) if c['direct'] == slider_apply
               and c['args'] and _member(c['args'][0])}
    if len(members) != 3:
        raise ValueError('Audio override does not apply its three slider members')
    ctor = functions[str(values['constructors']['audio'])]
    constructed = set()
    for label in ('SFX Slider','Suit Slider','MP3 Volume'):
        arguments = {('const',a) for a in literals[label]['addresses']}
        creates = [c for c in method_calls(ctor) if c['direct'] and c['args']
                   and any(contains_value(c['args'] + c['stack_args'],a) for a in arguments)
                   and any(s['address'] == THIS and s['value'] == ('const',int(values['tables']['CCvarSlider']['vtable_va'],0))
                           for s in functions.get(str(c['direct']),{}).get('flow',{}).get('stores',[]))]
        stores = {('load',THIS,s['address'][2]) for c in creates for s in ctor['flow']['stores']
                  if isinstance(s['address'],tuple) and s['address'][:2] == ('address',THIS)
                  and (contains_value(s['value'],c['args'][0])
                       or contains_value(s['value'],('result',c['ea'])))}
        constructed.add(sole(stores, label + ' constructed member'))
    if constructed != members:
        raise ValueError('Audio ApplyChanges receivers differ from constructed sliders')
    multiplayer = sole([m for m in table_methods(data,'COptionsSubMultiplayer')
                         if 'cl_logofile %s\n' in owned_labels(m)], 'Multiplayer owned ClientCmd format')
    if multiplayer['index'] != video['index']:
        raise ValueError('OnApplyChanges overrides disagree on their current virtual position')
    base_apply = sole([m for m in table_methods(data,'CBasePanel')
                       if 'resource/BackgroundLayout.txt' in owned_labels(m)], 'BasePanel scheme background')
    result['options'] = {label:dict(ea=m['ea'],index=m['index']) for label,m in (
        ('COptionsSubVideo',video),('COptionsSubAudio',audio),('COptionsSubMultiplayer',multiplayer),('CBasePanel',base_apply))}
"""
)


async def private_payloads(
    session, expected_outputs, new_binary_dir, platform, image_base, *, gameui=False, tables=None, existing=None
):
    """Return fully validated payloads; the caller emits after all work succeeds."""
    tables = {} if tables is None else dict(tables)
    for cls in COMMON_CLASSES + (GAMEUI_CLASSES if gameui else ()):
        if cls in tables:
            continue
        short = cls.split("::")[-1]
        alias = (
            (f"??_7{short}@vgui2@@6B@" if "::" in cls else f"??_7{short}@@6B@")
            if platform == "windows"
            else (f"_ZTVN5vgui2{len(short)}{short}E" if "::" in cls else f"_ZTV{len(short)}{short}")
        )
        table = await preprocess_vtable_via_mcp(session, cls, image_base, platform, symbol_aliases=[alias])
        if table is None:
            raise ValueError(f"{cls}: no current RTTI table")
        tables[cls] = table
    tables = {
        cls: dict(table, vtable_entries={str(index): address for index, address in table["vtable_entries"].items()})
        for cls, table in tables.items()
    }
    values = dict(tables=tables, platform=platform, gameui=gameui)
    if gameui:
        constructors = {}
        for key, symbol in (
            ("audio", "COptionsSubAudio_ctor"),
            ("multiplayer", "COptionsSubMultiplayer_ctor"),
            ("base", "CBasePanel_ctor"),
        ):
            record = _load_yaml_mapping(Path(new_binary_dir) / f"{symbol}.{platform}.yaml")
            if record is None:
                raise ValueError(f"missing declared constructor input: {symbol}")
            constructors[key] = int(record["func_va"], 0)
        video_stem = (
            "COptionsSubVideo_OnApplyChanges"
            if _output_for_symbol(expected_outputs, "COptionsSubVideo_OnApplyChanges") is None
            else "COptionsSubVideo_ApplyVidSettings"
        )
        video = _load_yaml_mapping(Path(new_binary_dir) / f"{video_stem}.{platform}.yaml")
        if video is None:
            raise ValueError("missing declared video predecessor")
        values.update(
            constructors=constructors,
            video_predecessor=int(video["func_va"], 0),
            active_page=existing["active_page"],
            perform_index=existing["methods"]["perform"]["index"],
        )
    initial, remaining = COLLECT.split("extra = set()", 1)
    dependencies, final = remaining.split(REGISTRATION_COLLECT, 1)
    found = await walk_stages(
        session,
        [
            Path(identity.__file__).read_text(encoding="utf-8") + initial,
            "extra = set()" + dependencies,
            REGISTRATION_COLLECT + final,
        ],
        values,
    )
    if found.get("error"):
        raise ValueError(found["error"])
    payloads = {}
    prefix = "ClientVGUI" if _output_for_symbol(expected_outputs, "ClientVGUI_Panel_SetProportional") else "vgui2"
    functions = {
        f"{prefix}_Panel_SetProportional": (
            "vgui2::Panel::SetProportional(bool)",
            "vgui2::Panel",
            found["proportional"],
        )
    }
    if gameui:
        functions.update(
            {
                "GameUI_EditablePanel_GetFocusNavGroup": (
                    "vgui2::EditablePanel::GetFocusNavGroup()",
                    "vgui2::EditablePanel",
                    found["nav"],
                ),
                "GameUI_FocusNavGroup_GetCurrentFocus": (
                    "vgui2::FocusNavGroup::GetCurrentFocus()",
                    "vgui2::FocusNavGroup",
                    found["current"],
                ),
                **{
                    f"GameUI_PropertySheet_{label}": (
                        f"vgui2::PropertySheet::{label}({args})",
                        "vgui2::PropertySheet",
                        found["sheet"][label],
                    )
                    for label, args in SHEET_ARGUMENTS.items()
                },
                **{
                    f"{cls}_{'ApplySchemeSettings' if cls == 'CBasePanel' else 'OnApplyChanges'}": (
                        f"{cls}::{'ApplySchemeSettings(vgui2::IScheme*)' if cls == 'CBasePanel' else 'OnApplyChanges()'}",
                        cls,
                        target,
                    )
                    for cls, target in found["options"].items()
                },
            }
        )
    signatures = {}
    for symbol, (name, cls, target) in functions.items():
        if _output_for_symbol(expected_outputs, symbol) is None:
            continue
        payload = await function_payload(session, target["ea"], image_base, name, table=cls, index=target["index"])
        if payload is None:
            raise ValueError(f"{name}: no unique generated signature")
        payloads[symbol] = payload
        signatures[target["ea"]] = payload
    members = {
        f"{'GameUI' if gameui else prefix}_EditablePanel_m_NavGroup": (
            "vgui2::EditablePanel",
            "m_NavGroup",
            found["nav_member"],
            None,
        )
    }
    if gameui:
        members.update(
            {
                "GameUI_FocusNavGroup__currentFocus": (
                    "vgui2::FocusNavGroup",
                    "_currentFocus",
                    found["current_member"],
                    4,
                ),
                "GameUI_PropertySheet__activePage": ("vgui2::PropertySheet", "_activePage", found["active_member"], 4),
            }
        )
    for symbol, (cls, member, reference, size) in members.items():
        if _output_for_symbol(expected_outputs, symbol) is None:
            continue
        owner = signatures.get(reference["owner"]) or await function_payload(
            session, reference["owner"], image_base, f"{cls}::{member} offset owner"
        )
        if owner is None:
            raise ValueError(f"{symbol}: no unique offset owner signature")
        payload = dict(
            struct_name=cls,
            member_name=member,
            offset=hex(reference["offset"]),
            offset_sig=owner["func_sig"],
            offset_sig_disp=hex(reference["ea"] - reference["owner"]),
        )
        if size is not None:
            payload["size"] = hex(size)
        if reference["ref_kind"] != "displacement":
            payload["offset_sig_ref_kind"] = reference["ref_kind"]
        if owner.get("func_sig_allow_across_function_boundary"):
            payload["offset_sig_allow_across_function_boundary"] = True
        payloads[symbol] = payload
    for symbol, (cls, name) in INTERFACES.items():
        index = found["interfaces"][name]
        if _output_for_symbol(expected_outputs, symbol) is not None:
            payloads[symbol] = dict(func_name=name, vtable_name=cls, vfunc_index=index, vfunc_offset=hex(index * 4))
        elif not gameui and prefix != "ClientVGUI":
            shared = _load_yaml_mapping(Path(new_binary_dir).parent / "gameui" / f"{symbol}.{platform}.yaml")
            if shared is None or shared.get("func_name") != name or shared.get("vfunc_index") != index:
                raise ValueError(f"{symbol}: current host disagrees with the shared interface input")
    return payloads


def emit_private_payloads(expected_outputs, payloads):
    for symbol, payload in payloads.items():
        output = _output_for_symbol(expected_outputs, symbol)
        (write_struct_offset_yaml if "member_name" in payload else write_func_yaml)(output, payload)
