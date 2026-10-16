"""Current-binary evidence for Career costs and TextImage's Unicode overload.

Discovery uses literals, RTTI and decoded receiver/value flow. Signatures are
generated only after discovery; old artifacts never participate in selection.
"""

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
import ida_preprocessor_scripts._vgui_private_method_identity as identity


IDENTITY_SOURCE = Path(identity.__file__).read_text(encoding="utf-8")

COMMON = r"""
import ida_hexrays, ida_name, json

def literal_evidence(text):
    needle=text.encode('ascii')+b'\0'
    addresses,owners,sites=set(),set(),set()
    for se in idautils.Segments():
        segment=ida_segment.getseg(se)
        if segment.perm & ida_segment.SEGPERM_EXEC:continue
        raw=ida_bytes.get_bytes(segment.start_ea,segment.end_ea-segment.start_ea) or b''
        pos=raw.find(needle)
        while pos>=0:
            address=int(segment.start_ea+pos)
            addresses.add(address)
            for ref in elf_data_refs_to(address):
                function=ida_funcs.get_func(ref)
                if function:
                    sites.add(int(ref));owners.add(int(function.start_ea))
            pos=raw.find(needle,pos+1)
    return dict(addresses=sorted(addresses),owners=sorted(owners),sites=sorted(sites))

def flow(ea):
    return flow_at(ea,values['platform'],first_pass=True,track_memory=True)

def demangled(ea):
    name=ida_name.get_name(ea)
    return ida_name.demangle_name(name,ida_name.MNG_SHORT_FORM) if name else None

def known_identity(ea,expected):
    # Stripped Windows/Sven functions are identified by current-binary flow.
    # When ELF carries a real C++ symbol it must agree, including const/overload.
    name=ida_name.get_name(ea)
    actual=demangled(ea)
    mangled={
        'CBotButton::SetCharacter(CCareerCharacter const*)':'_ZN10CBotButton12SetCharacterEPK16CCareerCharacter',
        'CCareerCharacter::GetPoints() const':'_ZNK16CCareerCharacter9GetPointsEv',
        'vgui2::TextImage::SetText(wchar_t const*)':'_ZN5vgui29TextImage7SetTextEPKw',
    }
    if values['platform']=='linux' and name.startswith('_ZN'):
        # IDA's short demangler omits the const qualifier on GetPoints.
        # Compare the complete Itanium identity instead of losing that ABI fact.
        if name!=mangled[expected]:
            raise ValueError('ELF identity disagrees: '+repr(actual)+' != '+expected)
    return expected

def strip_cast(expr):
    while expr.op==ida_hexrays.cot_cast:expr=expr.x
    return expr

def number(expr,value):
    expr=strip_cast(expr)
    return expr.op==ida_hexrays.cot_num and expr.numval()==value

def cost_calls(ea):
    cfunc=ida_hexrays.decompile(ea)
    if cfunc is None:raise ValueError('Career function has no decompilation')
    class Visitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
            self.found=[]
        def visit_expr(self,e):
            if e.op!=ida_hexrays.cot_add:return 0
            for left,right in ((e.x,e.y),(e.y,e.x)):
                mod=strip_cast(left)
                if not number(right,ord('0')) or mod.op not in (ida_hexrays.cot_smod,ida_hexrays.cot_umod):continue
                if not number(mod.y,10):continue
                call=strip_cast(mod.x)
                if call.op==ida_hexrays.cot_call and strip_cast(call.x).op==ida_hexrays.cot_obj:
                    self.found.append(dict(ea=int(call.ea),target=int(strip_cast(call.x).obj_ea)))
            return 0
    visitor=Visitor();visitor.apply_to(cfunc.body,None)
    return visitor.found
"""

TEXTIMAGE = r"""
entries={int(i):int(ea,0) for i,ea in values['table']['vtable_entries'].items()}
methods={}
for ea in set(entries.values()):
    try:methods[ea]=flow(ea)
    except ValueError:continue
narrow=[]
for ea,method in methods.items():
    # SetText(char const*) tests its input's first byte for the localization
    # token prefix '#'. Neither a table position nor declaration order is used.
    comparisons=[c for c in method['comparisons']
                 if ('const',ord('#')) in c['values'] and contains_value(c['values'],('arg',1))]
    if not comparisons:continue
    dispatches=[(c,virtual_dispatch(c)) for c in method['calls'] if virtual_dispatch(c)]
    own=[(c,d) for c,d in dispatches if d[0]==THIS and c['args'][0]==THIS]
    indices={d[1] for c,d in own}
    if len(indices)!=1:continue
    index=next(iter(indices))
    if index not in entries or entries[index]==ea:continue
    # The conversion writes a local Unicode buffer subsequently passed to
    # the same object's wide SetText. Require actual argument provenance.
    converted=[]
    for conversion,dispatch in dispatches:
        if dispatch[0]==THIS or len(conversion['args'])<3:continue
        destination=conversion['args'][2]
        if not destination or destination[0]!='stack':continue
        if not contains_value(conversion['args'][1],('arg',1)):continue
        for call,target in own:
            if target[1]==index and contains_value(call['args'][1],destination) and conversion['ea']<call['ea']:
                converted.append((conversion['ea'],call['ea']))
    if not converted:continue
    narrow.append(dict(ea=ea,index=index,target=entries[index],converted=converted))
selected=sole(narrow,'TextImage narrow-to-wide conversion')
wide=selected['target'];method=methods.get(wide)
if not method:raise ValueError('wide TextImage entry has no decoded flow')
if callee_stack_purge(wide)!=(4 if values['platform']=='windows' else 0):
    raise ValueError('TextImage wide overload has a different argument ABI')
# MSVC inlines its UTF-16 loops; ELF normally calls wcslen/wcscpy with
# 32-bit wchar_t. Validate that this is a wide-string body, not Label::SetText.
wide_reads=[r for r in method['loads'] if r['width']==2 and contains_value(r['address'],('arg',1))]
wide_calls=set()
for c in method['calls']:
    # External PLT entries need not resolve to a local function. Their loader
    # import name and current arguments still identify the wide CRT operation.
    target=c['direct'] or (c['target'][1] if c['target'] and c['target'][0]=='const' else None)
    name=ida_name.get_name(target) if target else ''
    arguments=c['stack_args'] if values['platform']=='windows' else c['args']
    for symbol,position,role in (('wcslen',0,'length'),('wcscpy',1,'copy'),('wcsncpy',1,'copy')):
        if symbol in name and len(arguments)>position and contains_value(arguments[position],('arg',1)):
            wide_calls.add(role)
if not wide_reads and wide_calls!={'length','copy'}:raise ValueError('wide string read/copy evidence is absent')
name=known_identity(wide,'vgui2::TextImage::SetText(wchar_t const*)')
result=dict(ea=wide,index=selected['index'],name=name,narrow=selected)
"""

CAREER = r"""
literals={s:literal_evidence(s) for s in ('#Career_Cost','BotPointsFont','BotNameFont','EmptyChar')}
for name in ('#Career_Cost','BotPointsFont','BotNameFont'):
    if len(literals[name]['addresses'])!=1:raise ValueError('literal is not unique: '+name)
root=sole(literals['#Career_Cost']['owners'],'Career cost owner')
if any(root not in literals[name]['owners'] for name in ('BotPointsFont','BotNameFont','EmptyChar')):
    raise ValueError('Career cost owner lacks its other character-display branches')
owner=flow_at(root,values['platform'],first_pass=True,track_memory=True)
point=sole(cost_calls(root),'GetPoints participating in modulo-ten ASCII conversion')
if local_call_target(point['ea'])!=point['target']:
    raise ValueError('GetPoints CTree call disagrees with current machine CALL')
call=sole([c for c in owner['calls'] if c['ea']==point['ea']],'current GetPoints call')
receiver=call['args'][0]
stores=[s for s in owner['stores'] if s['address'] and s['address'][:2]==('address',THIS)
        and s['value']==('arg',1) and s['width']==4 and s['ea']<point['ea']]
character_offset=sole({s['address'][2] for s in stores},'stored character parameter')
if receiver not in (('arg',1),('load',THIS,character_offset)):
    raise ValueError('GetPoints receiver does not come from the character parameter')
wide_index=values['wide']['vfunc_index']
cost_sites=[s for s in literals['#Career_Cost']['sites'] if ida_funcs.get_func(s).start_ea==root]
font_sites=[s for s in literals['BotPointsFont']['sites'] if ida_funcs.get_func(s).start_ea==root]
costs=[]
for c in owner['calls']:
    dispatch=virtual_dispatch(c)
    if not dispatch or dispatch[1]!=wide_index or dispatch[0]!=c['args'][0]:continue
    obj=dispatch[0]
    if not obj or obj[:2]!=('load',THIS):continue
    if not c['args'][1] or c['args'][1][0]!='stack':continue
    if not any(point['ea']<s<c['ea'] for s in cost_sites):continue
    if not any(c['ea']<s for s in font_sites):continue
    costs.append(dict(ea=c['ea'],offset=obj[2],buffer=c['args'][1]))
cost=sole(costs,'localized cost wide TextImage receiver')
# An independently decoded this-relative operand must yield the member value.
# Its signature points at the actual LEA/load, never an array element as a GV.
references=[]
for r in owner['addresses']:
    if r['value']==('address',THIS,cost['offset']) and r['ref_kind']=='displacement':references.append(r['ea'])
for r in owner['loads']:
    if r['address']==('address',THIS,cost['offset']) and r['width']==4:references.append(r['ea'])
references=[ea for ea in references if any(op.type==idaapi.o_displ and signed32(op.addr)==cost['offset']
            for op in idautils.DecodeInstruction(ea).ops)]
if not references:raise ValueError('m_pText has no independently decoded member operand')
if cost['offset']<=0 or cost['offset']%4:raise ValueError('m_pText pointer array is misaligned')
points=flow(point['target'])
# An unoptimized GameUI can leave BotProfile::GetCost out of line. Expand
# only proven leaf getters, using the actual profile receiver at that CALL.
# IDA/FLIRT may mislabel an identical tiny getter as an unrelated library
# method; its bytes and object-derived return, not that label, are evidence.
leaves={str(c['direct']):dict(flow=flow(c['direct'])) for c in points['calls'] if c['direct']}
points=expand_leaf_returns(dict(functions=leaves),dict(flow=points))['flow']
returned={v for r in points['returns'] for v in alternatives(r['value'])}
scalars={v for v in returned if v and v[0]=='load' and isinstance(v[1],tuple)
         and v[1][:2]==('load',THIS) and isinstance(v[2],int)}
profiles={v[1] for v in scalars}
guards={b['condition'] for b in points['branches']}
if not scalars or any(v not in scalars and v!=('const',0) and not (v in profiles and v in guards) for v in returned):
    raise ValueError('GetPoints does not return an unmodified full-width profile scalar or zero')
if callee_stack_purge(point['target'])!=0:raise ValueError('GetPoints has unexpected explicit arguments')
root_name=known_identity(root,'CBotButton::SetCharacter(CCareerCharacter const*)')
points_name=known_identity(point['target'],'CCareerCharacter::GetPoints() const')
result=dict(root=dict(ea=root,name=root_name),points=dict(ea=point['target'],name=points_name),
            member=dict(offset=cost['offset'],ea=min(references)),character_offset=character_offset,
            cost=cost,literals=literals)
"""


async def preprocess_textimage(session, outputs, platform, image_base, debug=False):
    try:
        cls = "vgui2::TextImage"
        alias = "??_7TextImage@vgui2@@6B@" if platform == "windows" else "_ZTVN5vgui29TextImageE"
        table = await preprocess_vtable_via_mcp(session, cls, image_base, platform, symbol_aliases=[alias])
        if not table or table.get("vtable_symbol") != alias:
            raise ValueError("TextImage primary RTTI table is absent or ambiguous")
        table = dict(table, vtable_entries={str(i): ea for i, ea in table["vtable_entries"].items()})
        found = await walk(session, IDENTITY_SOURCE + COMMON + TEXTIMAGE, dict(table=table, platform=platform))
        if found.get("error"):
            raise ValueError(found["error"])
        payload = await function_payload(
            session, found["ea"], image_base, found["name"], table=cls, index=found["index"]
        )
        if not payload:
            raise ValueError("TextImage wide entry has no unique output signature")
        table.pop("_pointer_size", None)
        write_vtable_yaml(_output_for_symbol(outputs, "vgui2_TextImage_vtable"), table)
        write_func_yaml(_output_for_symbol(outputs, "vgui2_TextImage_SetTextW"), payload)
        if debug:
            print(f"  TextImage Unicode evidence: {found}")
        return True
    except (ValueError, KeyError, TypeError) as exc:
        if debug:
            print(f"  TextImage Unicode rejected: {exc}")
        return False


async def preprocess_career(session, outputs, directory, platform, image_base, debug=False):
    try:
        wide = _load_yaml_mapping(Path(directory) / f"vgui2_TextImage_SetTextW.{platform}.yaml")
        if not wide or wide.get("vtable_name") != "vgui2::TextImage":
            raise ValueError("missing declared current-module wide TextImage input")
        found = await walk(session, IDENTITY_SOURCE + COMMON + CAREER, dict(wide=wide, platform=platform))
        if found.get("error"):
            raise ValueError(found["error"])
        payloads = {}
        for symbol, key in (("CBotButton_SetCharacter", "root"), ("CCareerCharacter_GetPoints", "points")):
            target = found[key]
            payload = await function_payload(session, target["ea"], image_base, target["name"])
            if not payload:
                raise ValueError(f"{symbol}: no unique output signature")
            payloads[symbol] = payload
        owner = payloads["CBotButton_SetCharacter"]
        member = dict(
            struct_name="CBotButton",
            member_name="m_pText",
            offset=hex(found["member"]["offset"]),
            offset_sig=owner["func_sig"],
            offset_sig_disp=hex(found["member"]["ea"] - found["root"]["ea"]),
        )
        if owner.get("func_sig_allow_across_function_boundary"):
            member["offset_sig_allow_across_function_boundary"] = True
        for symbol, payload in payloads.items():
            write_func_yaml(_output_for_symbol(outputs, symbol), payload)
        write_struct_offset_yaml(_output_for_symbol(outputs, "CBotButton_m_pText"), member)
        if debug:
            print(f"  Career bot cost evidence: {found}")
        return True
    except (ValueError, KeyError, TypeError) as exc:
        if debug:
            print(f"  Career bot cost rejected: {exc}")
        return False
