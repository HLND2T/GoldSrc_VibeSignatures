"""Additional Windows Career preflight/input evidence, independently rediscovered.

The direct GV locator is deliberate: all five independently selected profile
consumers must agree on the complete pointer path, and actual operand bytes
must name its root. This is stronger than choosing a nearby global or an LLM
guess. Windows HL10210, HL8684 and the issue #940 CS GameUI register it.
"""

from pathlib import Path

from ida_analyze_util import (
    gv_resolution_fields_via_mcp,
    write_func_yaml,
    write_gv_yaml,
    write_scalar_yaml,
    write_struct_offset_yaml,
)
from ida_preprocessor_scripts._career_bot_cost_common import COMMON, IDENTITY_SOURCE
from ida_preprocessor_scripts._career_player_name_common import COLLECT_COMMON, collect
from ida_preprocessor_scripts._career_storage_common import discover_storage
from ida_preprocessor_scripts._career_storage_identity import unique
from ida_preprocessor_scripts._vgui_paint_common import walk
from ida_preprocessor_scripts._vgui_private_symbols_common import function_payload
from ida_preprocessor_scripts import _career_runtime_identity as runtime_identity
from ida_preprocessor_scripts import _career_storage_identity as storage_identity


RUNTIME = r"""
cache={}
def method(ea):
    if ea not in cache:cache[ea]=traced(ea)
    return cache[ea]
def direct_name(c,name):
    target=c['direct']
    if target:return ida_name.get_name(target).lstrip('_')==name
    target=c['target']
    return bool(target and target[0]=='load' and target[1] and target[1][0]=='const'
                and ida_name.get_name(target[1][1]).lstrip('_')==name)
def member(value):
    if not value or value[:2]!=('load',THIS) or value[2]<=0:raise ValueError('Missing this-relative member')
    return value[2]
def reference(owner,address):
    reads=[r for r in method(owner)['loads'] if r['address']==('const',address) and r['width']==4]
    candidates=[]
    for r in reads:
        insn=idautils.DecodeInstruction(r['ea'])
        for op in insn.ops:
            if op.type==idaapi.o_mem and op.addr==address:
                candidates.append(dict(gv_ea=address,insn_ea=r['ea'],insn_len=insn.size,insn_disp=op.offb,owner=owner))
    if not candidates:raise ValueError('No decoded absolute pointer load')
    return min(candidates,key=lambda c:c['insn_ea'])

storage=values['storage'];functions=storage['functions'];groups=storage['groups']
create=functions['CCareerGame_CreateBlankProfile']['ea']
save=functions['CCareerGame_SaveProfile']['ea']
command=functions['CCareerProfileFrame_OnCommand']['ea']
new_command=functions['CCareerNewProfileBox_OnCommand']['ea']
paths=[sites[0]['stack_args'][2] for group,sites in groups.items() if group.endswith('_profile_path_format_callsite')]
root,offsets=common_pointer_chain(paths,3)
globals={'TheCareerDefinitions':reference(create,root)}
members={'CareerDefinitionManager_m_activeCareer':('CareerDefinitionManager','m_activeCareer',offsets[0],4),
         'CareerDefinition_m_saveDir':('CareerDefinition','m_saveDir',offsets[1],4)}
receivers=[c['this'] for c in method(command)['calls'] if c['direct']==create]
game_root,_=common_pointer_chain(receivers,1)
globals['TheCareerGame']=reference(command,game_root)

# The serializer is the same complete thiscall selected by both write owners.
buffer=storage['analysis_functions']['CCareerGame::CreateProfileBuffer(CCareerProfileData*, unsigned char*, int, bool)']['ea']
body=method(buffer)
initializers=[c for c in body['calls'] if c['direct'] and c['stack_args'][:2]==[('arg',2),('arg',3)]]
init=unique(initializers,'bounded writer initialization')
writer_offset=member(init['this'])
overflow=unique([s for s in method(init['direct'])['stores'] if s['width']==1 and s['value']==('const',0)
                 and s['address'] and s['address'][:2]==('address',THIS)],'writer overflow flag')
overflow_offset=overflow['address'][2]
members['CCareerGame_m_writer']=('CCareerGame','m_writer',writer_offset,4)
members['BufferWriter_m_overflow']=('BufferWriter','m_overflow',overflow_offset,1)
first_path=groups['CCareerGame_SaveProfile_profile_path_format_callsite'][0]['ea']
autosave_offsets=set()
for comparison in method(save)['comparisons']:
    if comparison['ea']>=first_path:continue
    insn=idautils.DecodeInstruction(comparison['ea'])
    byte_offsets={signed32(op.addr) for op in insn.ops
                  if op.type==idaapi.o_displ and ida_ua.get_dtype_size(op.dtype)==1}
    byte_offsets.update(r['address'][2] for r in method(save)['loads']
                        if r['ea']<=comparison['ea'] and r['width']==1 and r['address']
                        and r['address'][:2]==('address',THIS))
    for value in comparison['values']:
        autosave_offsets.update(offset for offset in byte_member_offsets(value,THIS,byte_offsets) if offset>0)
members['CCareerGame_m_needAutosave']=('CCareerGame','m_needAutosave',unique(autosave_offsets,'early autosave guard'),1)
if primary_returns(buffer)!=[16]:raise ValueError('Serializer ABI cleanup changed')

# Older GameUI factors the native writer out of both Create and Save. Follow
# only a shared direct child owning wb Open, or Create's own inlined writer.
wb=literal_evidence('wb')
shared_writers={c['direct'] for c in method(create)['calls'] if c['direct']} & {
                c['direct'] for c in method(save)['calls'] if c['direct']} & set(wb['owners'])
opens=[(owner,c) for owner in {create}|shared_writers for c in method(owner)['calls']
       if c['stack_args'][1] in {('const',a) for a in wb['addresses']}]
writer,opened=unique(opens,'native profile Open')
getter=unique([c for c in method(writer)['calls'] if c['direct'] and opened['this']==('result',c['ea'])],'filesystem getter')
returned=unique({r['value'] for r in method(getter['direct'])['returns']},'filesystem leaf return')
fs_root,_=pointer_chain(returned,1)
globals['vgui2_g_pFileSystemInterface']=reference(getter['direct'],fs_root)

# The name entry must be captured before its native 64-byte apply buffer.
apply=unique([c for c in method(new_command)['calls'] if c['direct'] and c['this'] and c['this'][:2]==('load',THIS)
              and c['stack_args'][0]==('const',1)],'new profile name apply')
members['CCareerNewProfileBox_m_pEntry']=('CCareerNewProfileBox','m_pEntry',member(apply['this']),4)
tables=values['tables'];entry_table=tables['CCvarTextEntry'];text_table=tables['vgui2::TextEntry']
reads=[c for c in method(apply['direct'])['calls'] if c['this']==THIS and c['stack_args'][0]
       and c['stack_args'][0][0]=='stack' and c['stack_args'][1] and c['stack_args'][1][0]=='const']
read=unique(reads,'bounded native input read')
target=read['target']
if not target or target[0]!='load' or target[1]!=('load',THIS,0) or target[2]%4:raise ValueError('Input read is not a this vcall')
narrow_index=target[2]//4
if entry_table['vtable_entries'][str(narrow_index)]!=text_table['vtable_entries'][str(narrow_index)]:
    raise ValueError('Name entry overrides the proven TextEntry getter')
wide=[]
for index,address in text_table['vtable_entries'].items():
    ea=int(address,0)
    copies=[c for c in method(ea)['calls'] if direct_name(c,'wcsncpy')]
    if len(copies)!=1:continue
    copied=copies[0]
    if copied['stack_args'][0]!=('arg',1):continue
    length_loads=[r for r in method(ea)['loads'] if r['address'] and r['address'][:2]==('address',THIS)
                  and r['width']==4 and r['value']!=copied['stack_args'][1]]
    if len(length_loads)!=1:continue
    if primary_returns(ea)!=[8]:continue
    if entry_table['vtable_entries'][index]!=address:raise ValueError('Name entry overrides wide getter')
    wide.append(dict(ea=ea,index=int(index),table='vgui2::TextEntry',length=length_loads[0]['address'][2]))
wide=unique(wide,'bounded wide TextEntry getter')
# DWARF names the length as the nested vector's m_Size. Keep its cumulative
# TextEntry-relative offset, as used by the actual getter, in the artifact.
members['vgui2_TextEntry_m_TextStream_m_Size']=('vgui2::TextEntry','m_TextStream.m_Size',wide['length'],4)
result=dict(globals=globals,members=members,serializer=buffer,wide=wide,
            input_capacity=read['stack_args'][1][1],writer_init=init['direct'],overflow_store=overflow['ea'])
"""


async def discover_runtime(session):
    found = await discover_storage(session, "windows")
    tables = await collect(session, "windows", ["vgui2::TextEntry", "CCvarTextEntry"])
    # Reuse the same current-binary trace semantics as the base contract.
    from ida_preprocessor_scripts._career_storage_collect import COLLECT

    prefix = COLLECT[: COLLECT.index("texts=(")]
    code = (
        IDENTITY_SOURCE
        + COMMON
        + COLLECT_COMMON
        + Path(storage_identity.__file__).read_text(encoding="utf-8")
        + Path(runtime_identity.__file__).read_text(encoding="utf-8")
    )
    result = await walk(session, code + prefix + RUNTIME, dict(platform="windows", storage=found, tables=tables))
    if result.get("error"):
        raise ValueError(result["error"])
    return result


async def preprocess_runtime(session, expected_outputs, directory, platform, image_base, debug=False):
    if platform != "windows":
        return False
    try:
        found = await discover_runtime(session)
        payloads = {}
        for stem, item in found["globals"].items():
            owner = await function_payload(session, item["owner"], image_base, stem)
            resolution = await gv_resolution_fields_via_mcp(
                session, item["insn_ea"], item["insn_disp"], item["gv_ea"], image_base, platform
            )
            if not owner or resolution is None:
                raise ValueError("Cannot validate the actual global pointer operand")
            payloads[stem] = dict(
                gv_name="vgui2::g_pFileSystemInterface" if stem == "vgui2_g_pFileSystemInterface" else stem,
                gv_va=hex(item["gv_ea"]),
                gv_rva=hex(item["gv_ea"] - image_base),
                gv_sig=owner["func_sig"],
                gv_sig_va=owner["func_va"],
                gv_inst_offset=hex(item["insn_ea"] - item["owner"]),
                gv_inst_length=hex(item["insn_len"]),
                gv_inst_disp=hex(item["insn_disp"]),
                **resolution,
            )
            if owner.get("func_sig_allow_across_function_boundary"):
                payloads[stem]["gv_sig_allow_across_function_boundary"] = True
        for stem, (struct, member, offset, size) in found["members"].items():
            payloads[stem] = dict(struct_name=struct, member_name=member, offset=hex(offset), size=hex(size))
        payloads["CCareerGame_CreateProfileBuffer"] = await function_payload(
            session,
            found["serializer"],
            image_base,
            "CCareerGame::CreateProfileBuffer(CCareerProfileData*, unsigned char*, int, bool)",
        )
        wide = found["wide"]
        payloads["vgui2_TextEntry_GetTextW"] = await function_payload(
            session,
            wide["ea"],
            image_base,
            "vgui2::TextEntry::GetText(wchar_t*, int)",
            table=wide["table"],
            index=wide["index"],
        )
        payloads["CareerStorage_runtime_contract_version"] = dict(
            scalar_name="CareerStorage_runtime_contract_version", scalar_value=1
        )
        payloads["CCareerNewProfileBox_native_input_capacity"] = dict(
            scalar_name="CCareerNewProfileBox_native_input_capacity", scalar_value=found["input_capacity"]
        )
        outputs = {Path(p).name.removesuffix(f".{platform}.yaml"): p for p in expected_outputs}
        if set(outputs) != set(payloads) or not all(payloads.values()):
            raise ValueError("Runtime preflight inventory differs")
        for stem, payload in payloads.items():
            writer = (
                write_gv_yaml
                if "gv_name" in payload
                else write_struct_offset_yaml
                if "member_name" in payload
                else write_scalar_yaml
                if "scalar_name" in payload
                else write_func_yaml
            )
            writer(outputs[stem], payload)
        if debug:
            print(f"Career runtime preflight: {len(payloads)} records: {found}")
        return True
    except (KeyError, TypeError, ValueError) as exc:
        if debug:
            print(f"Career runtime preflight rejected: {exc}")
        return False
