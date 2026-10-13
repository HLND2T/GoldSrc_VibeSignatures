"""IDA collection and artifact emission for ComboBox Unicode menu symbols."""

from pathlib import Path

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
import ida_preprocessor_scripts._vgui_private_method_identity as base_identity
import ida_preprocessor_scripts._combobox_unicode_identity as identity


IDENTITY_SOURCE = (
    Path(base_identity.__file__).read_text(encoding="utf-8")
    + "\n"
    + Path(identity.__file__).read_text(encoding="utf-8").split("# IDA_BODY", 1)[1]
)

COLLECT = r"""
import ida_auto, ida_name, ida_hexrays

def literal_evidence(text):
    needle=text.encode()+bytes([0])
    addresses,owners=set(),set()
    for se in idautils.Segments():
        seg=ida_segment.getseg(se)
        if seg.perm & ida_segment.SEGPERM_EXEC:continue
        raw=ida_bytes.get_bytes(seg.start_ea,seg.end_ea-seg.start_ea) or b''
        pos=raw.find(needle)
        while pos>=0:
            ea=int(seg.start_ea+pos)
            addresses.add(ea)
            for ref in idautils.DataRefsTo(ea):
                f=ida_funcs.get_func(ref)
                if f:owners.add(int(f.start_ea))
            pos=raw.find(needle,pos+1)
    return dict(addresses=sorted(addresses),owners=sorted(owners))

literals={s:literal_evidence(s) for s in ('autoresize','localize','north','north-west',
    '1 - resize right','[nothing currently selected]','SetText','text','#Spec_PlayerItem_Team','UserData','player')}
names=('#Spec_PlayerItem_Team','UserData') if values['client'] else ('autoresize','localize')
if any(len(literals[n]['addresses'])!=1 for n in names):raise ValueError('anchor literal is not unique')
root=sole(set.intersection(*(set(literals[n]['owners']) for n in names)),'anchored owner')
selected={root}
roles={}
if values['client'] and values['platform']=='windows':
    address=int(values['tables']['CSpectatorGUI']['vtable_va'],0)
    locator=ida_bytes.get_dword(address-4)
    adjustment=ida_bytes.get_dword(locator+4)
    descriptor=ida_bytes.get_dword(locator+12)
    type_name=idc.get_strlit_contents(descriptor+8,-1,ida_nalt.STRTYPE_C)
    if not adjustment or type_name!=b'.?AVCSpectatorGUI@@':
        raise ValueError('spectator secondary table lacks current MSVC RTTI identity')
for cls,table in values['tables'].items():
    for index,address in table['vtable_entries'].items():
        ea=int(address,0)
        selected.add(ea)
        roles.setdefault(ea,[]).append((cls,int(index)))
preserved=stack_check_helpers(selected,stack_check_preserves_registers)
# IDA identifies the compiler's cookie helper independently. Verify its normal
# path preserves registers before treating this epilogue call as transparent.
for ea in selected:
    for site in idautils.FuncItems(ea):
        target=local_call_target(site) if idc.print_insn_mnem(site)=='call' else None
        if not target or '__security_check_cookie' not in ida_name.get_name(target):continue
        items=list(idautils.FuncItems(target))
        if len(items)!=4 or [idc.print_insn_mnem(p) for p in items]!=['cmp','jnz','retn','jmp']:continue
        insn=idautils.DecodeInstruction(items[0]);branch=idautils.DecodeInstruction(items[1])
        if reg4(insn.ops[0])=='ecx' and insn.ops[1].type==idaapi.o_mem and int(branch.ops[0].addr)==items[3]:
            preserved.add(target)
functions={}
def describe(ea):
    if str(ea) in functions:return functions[str(ea)]
    f=ida_funcs.get_func(ea)
    if f is None and is_code_address(ea) and ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
        seg=ida_segment.getseg(ea)
        if values['platform']=='windows' or ida_segment.get_segm_name(seg)=='.text':
            ida_funcs.add_func(ea)
            f=ida_funcs.get_func(ea)
    if f is None or f.start_ea!=ea:
        return dict(ea=ea,strings=[],flow_error='missing current function entry')
    method=dict(ea=ea,roles=roles.get(ea,[]),strings=[])
    try:method['flow']=flow_at(ea,values['platform'],preserved_calls=preserved,first_pass=True)
    except ValueError as exc:method['flow_error']=str(exc)
    for p in idautils.FuncItems(ea):
        for ref in idautils.DataRefsFrom(p):
            text=idc.get_strlit_contents(ref,-1,ida_nalt.STRTYPE_C)
            if text:method['strings'].append((int(p),int(ref),text.decode('utf-8','replace')))
    functions[str(ea)]=method
    return method

def padded(method):
    for call in method_calls(method):
        call['args']=call['args']+[None]*max(0,9-len(call['args']))
    return method

def table_method(cls,index):
    table=values['tables'][cls]['vtable_entries']
    if str(index) not in table:raise ValueError('dispatch exceeds current '+cls+' table')
    return dict(describe(int(table[str(index)],0)),index=index)

def from_call(call,cls):
    dispatch=virtual_dispatch(call)
    if dispatch:return table_method(cls,dispatch[1])
    entries=values['tables'][cls]['vtable_entries']
    index=sole([int(i) for i,a in entries.items() if int(a,0)==call['direct']],cls+' direct table entry')
    return table_method(cls,index)

def current_purge(method,depth=0):
    # Exception-handler chunks are not reachable from the ordinary entry.
    # Tail forwarding derives its cleanup from the current Menu target.
    flow=method.get('flow',{})
    cleanups=set()
    for returned in flow.get('returns',[]):
        insn=idautils.DecodeInstruction(returned['ea'])
        cleanups.add(int(insn.ops[0].value) if insn.ops[0].type==idaapi.o_imm else 0)
    if len(cleanups)==1:return next(iter(cleanups))
    if not cleanups and depth<4:
        for call in method_calls(method):
            dispatch=virtual_dispatch(call)
            if call.get('tail') and dispatch and member_value(dispatch[0]):
                return current_purge(table_method('vgui2::Menu',dispatch[1]),depth+1)
            if call.get('tail') and call['direct'] and is_code_address(call['direct']):
                return current_purge(describe(call['direct']),depth+1)
    raise ValueError('current reachable callee cleanup is ambiguous')

def constructor_receivers(method,cls):
    receivers=set()
    table=('const',int(values['tables'][cls]['vtable_va'],0))
    for call in method_calls(method):
        if not call['direct'] or not is_code_address(call['direct']) or call['args'][0] is None:continue
        ctor=describe(call['direct'])
        if any(s['address']==THIS and s['value']==table and s['width']==4 for s in ctor.get('flow',{}).get('stores',[])):
            receivers.update((call['args'][0],('result',call['ea'])))
    return receivers

def local_buffer_agreement(method,menu_call,conversion):
    # Dynamic alloca makes ESP-relative output provenance unknown in the small
    # machine tracer. Compare CTree operands at those two verified machine CALLs;
    # only aliases of a local stack object/alloca result qualify as the buffer.
    cfunc=ida_hexrays.decompile(method['ea'])
    if cfunc is None:return False
    class Visitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self,ida_hexrays.CV_FAST)
            self.calls={};self.assigns={}
        def visit_expr(self,e):
            if e.op==ida_hexrays.cot_call:self.calls[int(e.ea)]=e
            if e.op==ida_hexrays.cot_asg and e.x.op==ida_hexrays.cot_var:
                self.assigns.setdefault(int(e.x.v.idx),[]).append(e.y)
            return 0
    visitor=Visitor();visitor.apply_to(cfunc.body,None)
    def normalized(expr,seen=()):
        while expr.op==ida_hexrays.cot_cast:expr=expr.x
        if expr.op==ida_hexrays.cot_var:
            index=int(expr.v.idx)
            if index in seen:return None
            writes=visitor.assigns.get(index,[])
            if len(writes)==1:return normalized(writes[0],seen+(index,))
            var=cfunc.get_lvars()[index]
            return ('local',index) if var.is_stk_var() and not var.is_arg_var else ('var',index)
        if expr.op==ida_hexrays.cot_ref:
            value=normalized(expr.x,seen)
            return ('ref',value) if value else None
        if expr.op==ida_hexrays.cot_call and expr.x.op==ida_hexrays.cot_helper and expr.x.helper=='alloca':
            return ('alloca',int(expr.ea))
        return None
    def local(value):
        return value is not None and (value[0] in ('local','alloca') or value[0]=='ref' and local(value[1]))
    menu=visitor.calls.get(menu_call['ea']);convert=visitor.calls.get(conversion['ea'])
    if menu is None or convert is None:return False
    menu_args=list(menu.a);convert_args=list(convert.a)
    # This supplemental comparison is used only for the cdecl Linux bodies;
    # machine provenance already suffices for known Windows stack buffers.
    if len(menu_args)!=5 or len(convert_args)!=4:return False
    output=normalized(convert_args[2]);item=normalized(menu_args[1])
    return local(output) and output==item

def add_wide_facts(method,menu_index,dropdown):
    converted=[]
    for call in method_calls(method):
        dispatch=virtual_dispatch(call)
        if not dispatch or dispatch!=(('load',THIS,dropdown),menu_index):continue
        for conversion in method_calls(method):
            target=virtual_dispatch(conversion)
            if not target or target[0] is None or target[0][0]!='result':continue
            if len(conversion['args'])<3 or len(call['args'])<2:continue
            if conversion['args'][1]!=('arg',1) or conversion['ea']>=call['ea']:continue
            destination=conversion['args'][2]
            if destination is not None and destination[0]=='stack' and call['args'][1]==destination:
                converted.append(call['ea'])
            elif aligned_stack_buffer(method,call,conversion):
                converted.append(call['ea'])
            elif values['platform']=='linux' and local_buffer_agreement(method,call,conversion):
                converted.append(call['ea'])
    method['converted_menu_calls']=converted
    return method

def aligned_stack_buffer(method,menu_call,conversion):
    # Old GCC keeps an aligned alloca buffer in a callee-saved register. CTree
    # can omit the conversion operands when its inferred prototype is wrong.
    # Bind the two actual outgoing argument stores and the stack-derived LEA/
    # alignment definition; any intervening write invalidates the identity.
    if values['platform']!='linux':return False
    items=list(idautils.FuncItems(method['ea']))
    def argument_register(call,offset):
        writes=[]
        for ea in items:
            if not call['block']<=ea<call['ea']:continue
            insn=idautils.DecodeInstruction(ea)
            op=decoded_operand(insn.ops[0])
            if op[:3]==('mem','esp',offset) and changed_operand(insn,0):writes.append((ea,insn))
        if not writes:return None
        ea,insn=writes[-1]
        return (ea,reg4(insn.ops[1])) if idc.print_insn_mnem(ea)=='mov' and insn.ops[1].type==idaapi.o_reg else None
    output=argument_register(conversion,8);item=argument_register(menu_call,4)
    if not output or not item or output[1]!=item[1] or output[1] not in ('ebx','esi','edi'):return False
    register=output[1]
    writes=[]
    for ea in items:
        if ea>=item[0]:break
        insn=idautils.DecodeInstruction(ea)
        if any(op.type==idaapi.o_reg and reg4(op)==register and changed_operand(insn,i) for i,op in enumerate(insn.ops)):
            writes.append((ea,insn))
    if len(writes)<2 or writes[-1][0]>=output[0]:return False
    lea,alignment=writes[-2:]
    if idc.print_insn_mnem(lea[0])!='lea' or decoded_operand(lea[1].ops[1])[:2]!=('mem','esp'):return False
    mask=alignment[1].ops[1]
    if idc.print_insn_mnem(alignment[0])!='and' or mask.type!=idaapi.o_imm:return False
    inverse=(~int(mask.value))&0xffffffff
    return 0<inverse<0x80000000 and inverse&(inverse+1)==0

owner=padded(describe(root))
result={}
if not values['client']:
    result['predecessor']=sole([dict(ea=root,index=int(i)) for i,a in values['tables']['vgui2::BuildModeDialog']['vtable_entries'].items()
                               if int(a,0)==root],'BuildModeDialog current virtual entry')
    label_receivers=constructor_receivers(owner,'vgui2::Label')
    combo_receivers=constructor_receivers(owner,'vgui2::ComboBox')
    constructor_results={v[1] for v in label_receivers|combo_receivers if v and v[0]=='result'}
    if constructor_results:
        owner=padded(dict(owner,flow=flow_at(root,values['platform'],preserved_calls=preserved,first_pass=True,
                                           nonzero_calls=constructor_results)))
    status={('const',a) for a in literals['[nothing currently selected]']['addresses']}
    text_call=sole([c for c in method_calls(owner) if c['args'][1] in status and virtual_dispatch(c)],'status Label SetText')
    color_call=sole([c for c in method_calls(owner) if virtual_dispatch(c) and c['args'][:2]==[text_call['args'][0],('const',1)]],
                    'same status Label dull color')
    alignment_call=sole([c for c in method_calls(owner) if virtual_dispatch(c) and c['args'][0] in label_receivers
                        and c['args'][1]==('const',5)],'constructed Label east alignment')
    labels={('const',a) for n in ('north','north-west','1 - resize right') for a in literals[n]['addresses']}
    calls=[c for c in method_calls(owner) if c['args'][1] in labels and c['args'][2]==('const',0)
           and c['args'][0] in combo_receivers]
    methods={from_call(c,'vgui2::ComboBox')['index']:from_call(c,'vgui2::ComboBox') for c in calls}
    narrow_method=sole(methods.values(),'constructed ComboBox narrow AddItem')
    evidence=add_item_evidence(narrow_method,literals)
    if evidence is None:raise ValueError('narrow AddItem did not preserve its message/target/userData')
    dropdown,menu_index=evidence['dropdown'],evidence['menu_index']
    result.update(add_a=dict(ea=narrow_method['ea'],index=narrow_method['index']),menu_add=dict(ea=table_method('vgui2::Menu',menu_index)['ea'],index=menu_index))
    for key,call in (('label_text',text_call),('label_color',color_call),('label_alignment',alignment_call)):
        method=from_call(call,'vgui2::Label');result[key]=dict(ea=method['ea'],index=method['index'])
    combo=[table_method('vgui2::ComboBox',int(i)) for i in values['tables']['vgui2::ComboBox']['vtable_entries']]
    getter=recover_menu_getter(combo,dropdown)
    result['getter']=dict(ea=getter['ea'],index=getter['index'])
    candidates=[]
    for method in combo:
        if method['ea'] not in set(literals['SetText']['owners']) & set(literals['text']['owners']):continue
        method=add_wide_facts(method,menu_index,dropdown)
        if add_item_evidence(method,literals,menu_index=menu_index,dropdown=dropdown,wide=True):candidates.append(method)
    wide=sole(candidates,'current ComboBox wide AddItem')
    result['add_w']=dict(ea=wide['ea'],index=wide['index'])
    loads=[e for e in narrow_method['flow']['loads'] if e['value']==('load',THIS,dropdown) and e['width']==4]
    if not loads:raise ValueError('dropdown member has no current instruction reference')
    reference=min(e['ea'] for e in loads)
    insn=idautils.DecodeInstruction(reference)
    if dropdown not in {signed32(op.addr) for op in insn.ops if op.type==idaapi.o_displ}:
        raise ValueError('dropdown reference has no matching current displacement')
    result['member']=dict(owner=narrow_method['ea'],ea=reference,offset=dropdown)
else:
    entries=[]
    forwarding=[]
    for cls,table in values['tables'].items():
        if not cls.startswith('CSpectatorGUI'):continue
        for i,a in table['vtable_entries'].items():
            ea=int(a,0)
            body=describe(ea)
            if ea==root:entries.append(dict(ea=ea,index=int(i),table=cls))
            else:
                calls_to_root=[c for c in method_calls(body) if c['direct']==root and c['args'][0]==THIS]
                if calls_to_root:
                    entries.append(dict(ea=ea,index=int(i),table=cls))
                    forwarding.extend(calls_to_root)
    result['predecessor']=sole(entries,'original spectator virtual entry (not compiler clone)')
    if result['predecessor']['ea']!=root:
        call=sole(forwarding,'current original entry forwards to split body')
        owner=padded(dict(owner,flow=flow_at(root,values['platform'],entry_state=entry_state_from_call(call),
                                    preserved_calls=preserved,first_pass=True)))
    # Helpers may be inlined or out of line. Enumerate the current owner's
    # direct callees and require the same three-dispatch guarded update behavior.
    candidates=[owner]
    candidates.extend(describe(c['direct']) for c in method_calls(owner) if c['direct'] and is_code_address(c['direct']))
    if values['platform']=='windows':
        corrected=[]
        for method in candidates:
            purges={}
            guarded_receivers=set()
            for call in method_calls(method):
                dispatch=virtual_dispatch(call)
                if not dispatch:continue
                same=[c for c in method_calls(method) if virtual_dispatch(c) and virtual_dispatch(c)[0]==dispatch[0]]
                if len({virtual_dispatch(c)[1] for c in same})<3:continue
                if any(stripped_result(b['condition'])==('result',call['ea']) for b in method.get('flow',{}).get('branches',[])):
                    guarded_receivers.add(dispatch[0])
            for call in method_calls(method):
                dispatch=virtual_dispatch(call)
                if not dispatch or dispatch[0] not in guarded_receivers:continue
                try:
                    target=table_method('vgui2::ComboBox',dispatch[1])
                    purge=current_purge(target)
                except ValueError:continue
                purges[call['ea']]=purge
            if purges:
                method=dict(method,flow=flow_at(method['ea'],values['platform'],call_purges=purges,
                                                preserved_calls=preserved,first_pass=True))
            corrected.append(method)
        candidates=corrected
    found=[(m,e) for m in candidates if (e:=spectator_update_calls(m)) is not None]
    method,calls=sole(found,'spectator player insertion implementation')
    for key,call in (('valid',calls['check']),('update',calls['update']),('add_w',calls['add'])):
        entry=from_call(call,'vgui2::ComboBox');result[key]=dict(ea=entry['ea'],index=entry['index'])
    # The client branch is independent evidence, not a slot copied to GameUI.
    # Check the selected overload against its current-module message and Menu
    # dispatch before assigning the wchar_t identity.
    combo=[table_method('vgui2::ComboBox',int(i)) for i in values['tables']['vgui2::ComboBox']['vtable_entries']]
    narrow_candidates=[]
    for candidate in combo:
        if candidate['ea'] not in set(literals['SetText']['owners']) & set(literals['text']['owners']):continue
        evidence=add_item_evidence(candidate,literals)
        if evidence:narrow_candidates.append(evidence)
    narrow_evidence=sole(narrow_candidates,'client current narrow AddItem corroboration')
    selected_wide=table_method('vgui2::ComboBox',result['add_w']['index'])
    selected_wide=add_wide_facts(selected_wide,narrow_evidence['menu_index'],narrow_evidence['dropdown'])
    if not add_item_evidence(selected_wide,literals,menu_index=narrow_evidence['menu_index'],
                             dropdown=narrow_evidence['dropdown'],wide=True):
        raise ValueError('client branch target is not the current Unicode AddItem body')
if values['platform']=='linux':
    for key,target in result.items():
        if isinstance(target,dict) and 'ea' in target:
            symbol=ida_name.get_name(target['ea'])
            target['symbol']=symbol
            target['demangled']=ida_name.demangle_name(symbol,ida_name.MNG_SHORT_FORM)
result['anchor']=dict(ea=root,literals={n:literals[n] for n in names})
"""


async def collect(session, platform, image_base, *, client, menu=None):
    classes = (
        ["vgui2::ComboBox", "vgui2::Menu"]
        if client
        else ["vgui2::ComboBox", "vgui2::Label", "vgui2::BuildModeDialog", "vgui2::Menu"]
    )
    if client:
        classes.append("CSpectatorGUI")
    tables = {}
    for cls in classes:
        short = cls.split("::")[-1]
        alias = (
            (f"??_7{short}@vgui2@@6B@" if "::" in cls else f"??_7{short}@@6B@_0")
            if platform == "windows"
            else (f"_ZTVN5vgui2{len(short)}{short}E" if "::" in cls else f"_ZTV{len(short)}{short}")
        )
        table = await preprocess_vtable_via_mcp(session, cls, image_base, platform, symbol_aliases=[alias])
        if not table or table.get("vtable_symbol") != alias:
            raise ValueError(f"{cls}: absent or mismatched current RTTI table")
        tables[cls] = dict(table, vtable_entries={str(i): a for i, a in table["vtable_entries"].items()})
    if menu is not None:
        current = tables["vgui2::Menu"]
        incoming_entries = {str(i): int(a, 0) for i, a in menu["vtable_entries"].items()}
        current_entries = {str(i): int(a, 0) for i, a in current["vtable_entries"].items()}
        if int(menu["vtable_va"], 0) != int(current["vtable_va"], 0) or incoming_entries != current_entries:
            raise ValueError("declared Menu input disagrees with current-module RTTI table")
    found = await walk(session, IDENTITY_SOURCE + COLLECT, dict(tables=tables, platform=platform, client=client))
    if found.get("error"):
        raise ValueError(found["error"])
    return tables, found


async def emit_functions(session, outputs, image_base, functions):
    payloads = {}
    for symbol, name, cls, target in functions:
        if target.get("demangled"):
            if target["demangled"].replace(" ", "").replace("(void)", "()") != name.replace(" ", ""):
                raise ValueError(f"{symbol}: current ELF overload {target['demangled']!r} disagrees with {name!r}")
            name = target["demangled"]
        payload = await function_payload(session, target["ea"], image_base, name, table=cls, index=target["index"])
        if payload is None:
            raise ValueError(f"{symbol}: no unique output signature")
        payloads[symbol] = payload
    return payloads


async def preprocess_combo(session, outputs, directory, platform, image_base, *, client=False, debug=False):
    try:
        menu = None if client else _load_yaml_mapping(Path(directory) / f"vgui2_Menu_vtable.{platform}.yaml")
        if not client and (menu is None or menu.get("vtable_class") != "vgui2::Menu"):
            raise ValueError("missing declared current-module Menu vtable")
        tables, found = await collect(session, platform, image_base, client=client, menu=menu)
        # Early Windows controls use vgui2::KeyValues; derive that namespace
        # from the current KeyValues RTTI artifact, never from the game tag.
        kv = _load_yaml_mapping(Path(directory) / f"{'ClientVGUI_' if client else ''}KeyValues_vtable.{platform}.yaml")
        if kv is None or kv.get("vtable_class") not in ("KeyValues", "vgui2::KeyValues"):
            raise ValueError("missing declared KeyValues class identity")
        keyvalues = kv["vtable_class"]
        functions = [
            (
                "vgui2_ComboBox_AddItemW",
                f"vgui2::ComboBox::AddItem(wchar_t const*, {keyvalues} const*)",
                "vgui2::ComboBox",
                found["add_w"],
            )
        ]
        if client:
            functions += [
                (
                    "CSpectatorGUI_UpdateSpectatorPlayerList",
                    "CSpectatorGUI::UpdateSpectatorPlayerList()",
                    "CSpectatorGUI_vtable2" if platform == "windows" else "CSpectatorGUI",
                    found["predecessor"],
                ),
                (
                    "vgui2_ComboBox_IsItemIDValid",
                    "vgui2::ComboBox::IsItemIDValid(int)",
                    "vgui2::ComboBox",
                    found["valid"],
                ),
                (
                    "vgui2_ComboBox_UpdateItemW",
                    f"vgui2::ComboBox::UpdateItem(int, wchar_t const*, {keyvalues} const*)",
                    "vgui2::ComboBox",
                    found["update"],
                ),
            ]
        else:
            functions += [
                (
                    "vgui2_BuildModeDialog_SetActiveControl",
                    "vgui2::BuildModeDialog::SetActiveControl(vgui2::Panel*)",
                    "vgui2::BuildModeDialog",
                    found["predecessor"],
                ),
                (
                    "vgui2_ComboBox_AddItemA",
                    f"vgui2::ComboBox::AddItem(char const*, {keyvalues} const*)",
                    "vgui2::ComboBox",
                    found["add_a"],
                ),
                ("vgui2_ComboBox_GetMenu", "vgui2::ComboBox::GetMenu()", "vgui2::ComboBox", found["getter"]),
                (
                    "vgui2_Menu_AddMenuItem_Message",
                    f"vgui2::Menu::AddMenuItem(char const*, {keyvalues}*, vgui2::Panel*, {keyvalues} const*)",
                    "vgui2::Menu",
                    found["menu_add"],
                ),
                ("vgui2_Label_SetTextA", "vgui2::Label::SetText(char const*)", "vgui2::Label", found["label_text"]),
                (
                    "vgui2_Label_SetTextColorState",
                    "vgui2::Label::SetTextColorState(vgui2::Label::EColorState)",
                    "vgui2::Label",
                    found["label_color"],
                ),
                (
                    "vgui2_Label_SetContentAlignment",
                    "vgui2::Label::SetContentAlignment(vgui2::Label::Alignment)",
                    "vgui2::Label",
                    found["label_alignment"],
                ),
            ]
        payloads = await emit_functions(session, outputs, image_base, functions)
        if not client:
            ref = found["member"]
            owner = payloads["vgui2_ComboBox_AddItemA"]
            member = dict(
                struct_name="vgui2::ComboBox",
                member_name="m_pDropDown",
                offset=hex(ref["offset"]),
                size="0x4",
                offset_sig=owner["func_sig"],
                offset_sig_disp=hex(ref["ea"] - ref["owner"]),
            )
            if owner.get("func_sig_allow_across_function_boundary"):
                member["offset_sig_allow_across_function_boundary"] = True
            payloads["vgui2_ComboBox_m_pDropDown"] = member
        for cls, table in tables.items():
            if cls == "vgui2::Menu":
                continue
            stem = cls.replace("::", "_") + "_vtable"
            if cls == "CSpectatorGUI" and platform == "windows":
                stem += "2"
            table = dict(table)
            table.pop("_pointer_size", None)
            write_vtable_yaml(_output_for_symbol(outputs, stem), table)
        for symbol, payload in payloads.items():
            writer = write_struct_offset_yaml if "member_name" in payload else write_func_yaml
            writer(_output_for_symbol(outputs, symbol), payload)
        if debug:
            print(f"  ComboBox Unicode identities: {found}")
        return True
    except (ValueError, KeyError, TypeError) as exc:
        if debug:
            print(f"  ComboBox Unicode identity rejected: {exc}")
        return False
