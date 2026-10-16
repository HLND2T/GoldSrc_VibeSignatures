"""Recover Career name labels and Label's wide overload from current x86 evidence."""

from pathlib import Path

from ida_analyze_util import (
    _load_yaml_mapping,
    _output_for_symbol,
    preprocess_vtable_via_mcp,
    write_func_yaml,
    write_struct_offset_yaml,
)
from ida_preprocessor_scripts._career_bot_cost_common import COMMON, IDENTITY_SOURCE
from ida_preprocessor_scripts._vgui_paint_common import walk
from ida_preprocessor_scripts._vgui_private_symbols_common import function_payload


COLLECT_COMMON = r"""
def traced(ea):
    preserved=stack_check_helpers([ea],stack_check_preserves_registers)
    # MSVC's cookie check preserves registers on its only returning path.
    # Verify the complete tiny helper; its failure tail must be noreturn.
    for site in idautils.FuncItems(ea):
        target=local_call_target(site) if idc.print_insn_mnem(site)=='call' else None
        if not target:continue
        helper=ida_funcs.get_func(target)
        if not helper or helper.end_ea-helper.start_ea>32:continue
        items=list(idautils.Heads(helper.start_ea,helper.end_ea))
        if [idc.print_insn_mnem(p) for p in items] not in (['cmp','jnz','retn','jmp'],['cmp','jne','retn','jmp']):continue
        branch=idautils.DecodeInstruction(items[1])
        failure=local_call_target(items[3])
        failed=ida_funcs.get_func(failure) if failure else None
        if branch.ops[0].addr==items[3] and failed and failed.flags & ida_funcs.FUNC_NORET:
            preserved.add(target)
    return flow_at(ea,values['platform'],first_pass=True,track_memory=True,preserved_calls=preserved)

def entries(table):
    return {int(i):int(ea,0) for i,ea in table['vtable_entries'].items()}

def stack_abi(ea,expected):
    function=ida_funcs.get_func(ea)
    returns=set()
    for site in idautils.Heads(function.start_ea,function.end_ea):
        if idc.print_insn_mnem(site) not in ('ret','retn'):continue
        insn=idautils.DecodeInstruction(site)
        returns.add(int(insn.ops[0].value) if insn.ops[0].type==idaapi.o_imm else 0)
    if returns=={expected}:return True
    # ELF may end exclusively in a restored-stack tail dispatch.
    return (not returns and expected==0 and values['platform']=='linux'
            and any(c['tail'] and c['args'][0]==THIS for c in traced(ea)['calls']))

def identity(ea,mangled):
    actual=ida_name.get_name(ea)
    if values['platform']=='linux' and actual.startswith('_ZN') and actual not in mangled:
        raise ValueError('ELF symbol/overload disagrees: '+actual)

def member_operand(method,offset):
    refs=[]
    for event in method['loads']+method['stores']:
        if event['address']!=('address',THIS,offset) or event['width']!=4:continue
        insn=idautils.DecodeInstruction(event['ea'])
        if any(op.type==idaapi.o_displ and signed32(op.addr)==offset for op in insn.ops):refs.append(event['ea'])
    if offset<=0 or offset%4:raise ValueError('unaligned member')
    return dict(offset=offset,ea=sole(sorted(set(refs))[:1],'decoded member operand'))

def owner(literals,names):
    for name in names:
        if not literals[name]['addresses']:raise ValueError('literal is absent: '+name)
    return sole(set.intersection(*(set(literals[n]['owners']) for n in names)),'anchored owner '+str(names))

def ctor_store(method,table):
    va=int(table['vtable_va'],0)
    if not any(s['address'] in (THIS,('address',THIS,0)) and s['value']==('const',va) for s in method['stores']):
        raise ValueError('complete constructor lacks current primary vtable assignment')

def created_member(method,label):
    addresses={('const',ea) for ea in literal_evidence(label)['addresses']}
    calls=[c for c in method['calls'] if c['direct'] and len(c['args'])>=3
           and c['args'][0] and c['args'][0][0]=='result'
           and c['args'][1]==THIS and c['args'][2] in addresses]
    call=sole(calls,'Label constructor for '+label)
    possible={('result',call['ea']),call['args'][0]}
    stores=[s for s in method['stores'] if s['width']==4 and s['address']
            and s['address'][:2]==('address',THIS) and s['ea']>call['ea']
            and any(v in possible for v in alternatives(s['value']))
            and all(v in possible or v==('const',0) for v in alternatives(s['value']))]
    offset=sole({s['address'][2] for s in stores},'constructed '+label+' member')
    return member_operand(method,offset)

def wide_calls(method,index,offset=None):
    found=[]
    for c in method['calls']:
        d=virtual_dispatch(c)
        if not d or d[1]!=index or len(c['args'])<2 or c['args'][0]!=d[0]:continue
        obj=d[0]
        if not obj or obj[:2]!=('load',THIS) or (offset is not None and obj[2]!=offset):continue
        found.append(c)
    return found

def name_call(method):
    names={('const',ea) for ea in literal_evidence('name')['addresses']}
    return sole([c for c in method['calls'] if not c['direct'] and c['stack_args'][0] in names], 'name cvar getter')

def base_identity(table,base):
    address=int(table['vtable_va'],0)
    if values['platform']=='linux':
        ti=ida_bytes.get_dword(address-4)
        parent=ida_bytes.get_dword(ti+8)
        name=idc.get_strlit_contents(ida_bytes.get_dword(parent+4),-1,ida_nalt.STRTYPE_C)
        if name!=(str(len(base))+base).encode():raise ValueError('Itanium single base identity disagrees')
        return 0
    locator=ida_bytes.get_dword(address-4)
    hierarchy=ida_bytes.get_dword(locator+16)
    count=ida_bytes.get_dword(hierarchy+8)
    if not 1<=count<=64:raise ValueError('invalid RTTI hierarchy')
    array=ida_bytes.get_dword(hierarchy+12)
    matches=[]
    for i in range(count):
        descriptor=ida_bytes.get_dword(array+4*i)
        name=idc.get_strlit_contents(ida_bytes.get_dword(descriptor)+8,-1,ida_nalt.STRTYPE_C)
        if name==('.?AV'+base+'@@').encode():
            displacement=signed32(ida_bytes.get_dword(descriptor+8))
            if signed32(ida_bytes.get_dword(descriptor+12))!=-1:raise ValueError('virtual base is unsupported')
            matches.append(displacement)
    return sole(matches,'RTTI base displacement')
"""

LABEL = r"""
table=values['table']; slots=entries(table); found=[]
for ea in set(slots.values()):
    try:method=traced(ea)
    except ValueError:continue
    text=[]
    for c in method['calls']:
        d=virtual_dispatch(c)
        if not d or d[1]!=values['textimage_index'] or len(c['args'])<2:continue
        obj=d[0]
        if obj and obj[:2]==('load',THIS) and c['args'][:2]==[obj,('arg',1)]:text.append(c)
    if len(text)!=1:continue
    # CalculateHotkey consumes that same wide input on the Label itself.
    hotkeys=[c for c in method['calls'] if not c['tail'] and virtual_dispatch(c) and virtual_dispatch(c)[0]==THIS
             and len(c['args'])>=2 and c['args'][:2]==[THIS,('arg',1)]]
    if len(hotkeys)!=1:continue
    if not stack_abi(ea,4 if values['platform']=='windows' else 0):continue
    found.append(dict(ea=ea,index=sole([i for i,a in slots.items() if a==ea],'wide Label slot'),
                      textimage_call=text[0]['ea'],textimage_member=text[0]['args'][0][2],hotkey_call=hotkeys[0]['ea']))
result=sole(found,'Label wide text and hotkey forwarding')
identity(result['ea'],['_ZN5vgui25Label7SetTextEPKw'])
"""

CAREER = r"""
names=('resource/CareerBoxDifficulty.res','Difficulty0Button','Difficulty1Button','#Career_Difficulty%d',
       'CareerBoxScheme','TextLabel','PlayerNameLabel','MissionPackNameLabel','CareerScheme','#Cstrike_Bot_Difficulty%d')
literals={n:literal_evidence(n) for n in names}
difficulty=owner(literals,names[:4])
base=owner(literals,('CareerBoxScheme','TextLabel'))
frame=owner(literals,('PlayerNameLabel','MissionPackNameLabel'))
activate=owner(literals,('#Cstrike_Bot_Difficulty%d',))
if frame not in literals['CareerScheme']['owners']:raise ValueError('Career frame scheme is absent')
methods={key:traced(ea) for key,ea in [('difficulty',difficulty),('base',base),('frame',frame),('activate',activate)]}
for key,cls in [('difficulty','CCareerDifficultyBox'),('base','CCareerBaseBox'),('frame','CCareerBaseFrame')]:
    ctor_store(methods[key],values['tables'][cls])
base_adjustment=base_identity(values['tables']['CCareerDifficultyBox'],'CCareerBaseBox')
if base_adjustment!=0:raise ValueError('nonzero base needs an explicit complete-object projection')
base_call=sole([c for c in methods['difficulty']['calls'] if c['direct']==base],'difficulty base constructor')
if base_call['args'][:4]!=[THIS,('arg',2),('arg',1),('const',0)]:
    raise ValueError('difficulty constructor parameter order or complete-object receiver disagrees')
if values['platform']=='windows':
    if not stack_abi(difficulty,8):raise ValueError('difficulty constructor stack ABI disagrees')
    function=ida_funcs.get_func(difficulty)
    returned={v for r in methods['difficulty']['returns'] if function.start_ea<=r['ea']<function.end_ea
              for v in alternatives(r['value'])}
    if returned!={THIS}:raise ValueError('MSVC constructor does not return this')
elif not stack_abi(difficulty,0):raise ValueError('ELF constructor cleanup disagrees')
identity(difficulty,['_ZN20CCareerDifficultyBoxC1EPKcPN5vgui25PanelE','_ZN20CCareerDifficultyBoxC2EPKcPN5vgui25PanelE'])
identity(activate,['_ZN16CCareerBaseFrame8ActivateEv'])
text=created_member(methods['base'],'TextLabel')
player=created_member(methods['frame'],'PlayerNameLabel')
index=values['wide']['vfunc_index']
text_methods=[methods['difficulty']]
text_calls=wide_calls(methods['difficulty'],index,text['offset'])
for outer in methods['difficulty']['calls']:
    target=ida_funcs.get_func(outer['direct']) if outer['direct'] else None
    if not target or target.end_ea-target.start_ea>128 or outer['args'][:1]!=[THIS] or len(outer['args'])<2:continue
    helper=traced(outer['direct'])
    forwarded=wide_calls(helper,index,text['offset'])
    if len(forwarded)!=1 or forwarded[0]['args'][1]!=('arg',1):continue
    if len(helper['calls'])!=1 or any(s['address'] is None or s['address'][0]!='stack' for s in helper['stores']):continue
    text_methods.append(helper)
    text_calls.append(dict(forwarded[0],ea=outer['ea'],args=[forwarded[0]['args'][0],outer['args'][1]],wrapper=outer['direct']))
text_call=sole(text_calls,'difficulty text label wide call')
name=name_call(methods['difficulty'])
formatter=sole([c for c in methods['difficulty']['calls'] if c['direct'] and text_call['args'][1]==('result',c['ea'])],
               'difficulty wide formatter')
args=formatter['stack_args']
if args[1]!=('result',name['ea']):raise ValueError('difficulty wide text does not consume the raw name cvar')
player_call=sole(wide_calls(methods['activate'],index,player['offset']),'player name label wide call')
buffer=player_call['args'][1]
if not buffer or buffer[0]!='stack':raise ValueError('Activate player text is not the formatted local buffer')
name_call(methods['activate'])
formatters=[c for c in methods['activate']['calls'] if c['direct'] and c['stack_args'][0]==buffer
            and c['stack_args'][1] and c['stack_args'][1][0]=='stack'
            and c['stack_args'][2] and c['stack_args'][2][0]=='const' and c['ea']<player_call['ea']]
if len(formatters)!=1:raise ValueError('Activate wide buffer formatter is ambiguous')
active_slots=[i for i,ea in entries(values['tables']['CCareerBaseFrame']).items() if ea==activate]
sole(active_slots,'CareerBaseFrame Activate primary slot')
if not any(r['address']==('address',THIS,text['offset']) for m in text_methods for r in m['loads']):
    raise ValueError('difficulty text receiver has no decoded base-member load')
player=member_operand(methods['activate'],player['offset'])
result=dict(difficulty=difficulty,activate=activate,base=base,frame=frame,text=text,player=player,
            base_adjustment=base_adjustment,label_slot=index,text_call=text_call['ea'],player_call=player_call['ea'],
            literals=literals,constructor_return='this' if values['platform']=='windows' else 'void (Itanium constructor)')
"""


async def collect(session, platform, classes):
    tables = {}
    for cls in classes:
        tail = cls.split("::")[-1]
        alias = f"??_7{tail}@vgui2@@6B@" if cls.startswith("vgui2::") else f"??_7{cls}@@6B@"
        if platform == "linux":
            alias = f"_ZTVN5vgui2{len(tail)}{tail}E" if cls.startswith("vgui2::") else f"_ZTV{len(cls)}{cls}"
        table = await preprocess_vtable_via_mcp(session, cls, 0, platform, symbol_aliases=[alias])
        if not table or table.get("vtable_symbol") != alias:
            raise ValueError(f"missing or ambiguous primary RTTI for {cls}")
        tables[cls] = dict(table, vtable_entries={str(i): ea for i, ea in table["vtable_entries"].items()})
    return tables


async def preprocess_label(session, outputs, directory, platform, image_base, debug=False):
    try:
        wide = _load_yaml_mapping(Path(directory) / f"vgui2_TextImage_SetTextW.{platform}.yaml")
        if not wide or wide.get("vtable_name") != "vgui2::TextImage":
            raise ValueError("missing declared TextImage wide input")
        tables = await collect(session, platform, ["vgui2::Label"])
        found = await walk(
            session,
            IDENTITY_SOURCE + COMMON + COLLECT_COMMON + LABEL,
            dict(table=tables["vgui2::Label"], textimage_index=wide["vfunc_index"], platform=platform),
        )
        if found.get("error"):
            raise ValueError(found["error"])
        payload = await function_payload(
            session,
            found["ea"],
            image_base,
            "vgui2::Label::SetText(wchar_t const*)",
            table="vgui2::Label",
            index=found["index"],
        )
        if not payload:
            raise ValueError("wide Label lacks a unique signature")
        write_func_yaml(_output_for_symbol(outputs, "vgui2_Label_SetTextW"), payload)
        if debug:
            print(f"  Label wide evidence: {found}")
        return True
    except (ValueError, KeyError, TypeError) as exc:
        if debug:
            print(f"  Label wide rejected: {exc}")
        return False


async def preprocess_names(session, outputs, directory, platform, image_base, debug=False):
    try:
        wide = _load_yaml_mapping(Path(directory) / f"vgui2_Label_SetTextW.{platform}.yaml")
        if not wide or wide.get("vtable_name") != "vgui2::Label":
            raise ValueError("missing declared Label wide input")
        tables = await collect(session, platform, ["CCareerDifficultyBox", "CCareerBaseBox", "CCareerBaseFrame"])
        found = await walk(
            session,
            IDENTITY_SOURCE + COMMON + COLLECT_COMMON + CAREER,
            dict(tables=tables, wide=wide, platform=platform),
        )
        if found.get("error"):
            raise ValueError(found["error"])
        payloads = {}
        for symbol, key, name in (
            (
                "CCareerDifficultyBox_ctor",
                "difficulty",
                "CCareerDifficultyBox::CCareerDifficultyBox(char const*, vgui2::Panel*)",
            ),
            ("CCareerBaseFrame_Activate", "activate", "CCareerBaseFrame::Activate()"),
        ):
            payload = await function_payload(session, found[key], image_base, name)
            if not payload:
                raise ValueError(f"{symbol}: no unique signature")
            payloads[symbol] = payload
        # Member signatures use their actual operand owner, including the base constructor.
        for symbol, key, cls, member, owner_key in (
            ("CCareerBaseBox_m_pTextLabel", "text", "CCareerBaseBox", "m_pTextLabel", "base"),
            ("CCareerBaseFrame_m_pPlayerName", "player", "CCareerBaseFrame", "m_pPlayerName", "activate"),
        ):
            owner = await function_payload(session, found[owner_key], image_base, cls + " member owner")
            if not owner:
                raise ValueError(f"{symbol}: no owner signature")
            ref = found[key]
            payload = dict(
                struct_name=cls,
                member_name=member,
                offset=hex(ref["offset"]),
                size="0x4",
                offset_sig=owner["func_sig"],
                offset_sig_disp=hex(ref["ea"] - found[owner_key]),
            )
            if owner.get("func_sig_allow_across_function_boundary"):
                payload["offset_sig_allow_across_function_boundary"] = True
            payloads[symbol] = payload
        for symbol, payload in payloads.items():
            writer = write_struct_offset_yaml if "member_name" in payload else write_func_yaml
            writer(_output_for_symbol(outputs, symbol), payload)
        if debug:
            print(f"  Career player name evidence: {found}")
        return True
    except (ValueError, KeyError, TypeError) as exc:
        if debug:
            print(f"  Career player name rejected: {exc}")
        return False
