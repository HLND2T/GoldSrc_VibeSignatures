#!/usr/bin/env python3
"""Recover the SvEngine ELF realloc PLT entry from texture-vector growth.

The allocation call is selected by its current ELF JUMP_SLOT binding to
realloc, within the verified InsertBefore predecessor. The artifact describes
the callable PLT entry in hw.so, not the undefined symbol or libc's body.
The generic generator masks the lazy-binding relocation selector as if it
were an address (its small integer happens to fall in ELF's first segment).
Preserve that verified selector in the output signature, masking the GOT
address and relative jump. No signature is used for discovery.
"""

from pathlib import Path

from ida_analyze_util import (
    _find_unique_bytes,
    _output_for_symbol,
    parse_mcp_result,
    preprocess_common_skill,
    write_func_yaml,
)
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact

OWNER = "CUtlVector_gltexture_t_InsertBefore"
MEMBERS = ["m_Memory.m_pMemory", "m_Memory.m_nAllocationCount", "m_Size"]
STRUCT = "CUtlVector_gltexture_t"
MEMBER_NAMES = [f"{STRUCT}_{member}".replace(".", "_") for member in MEMBERS]
LLM_DECOMPILE = [
    {
        "symbol_name": name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [f"references/{{gamever}}/engine/{OWNER}.{{platform}}.yaml"],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {f"{OWNER}.{{platform}}.yaml": "required"},
        "expected_size": 4,
    }
    for name in MEMBER_NAMES
]

PLT_QUERY = r"""
import ida_bytes, ida_funcs, ida_nalt, ida_segment, idaapi, idautils, idc, json, struct
owner = OWNER_PLACEHOLDER
matches = {}
with open(ida_nalt.get_input_file_path(), 'rb') as stream:
    binary = stream.read()
# IDA merges ELF metadata into LOAD rather than exposing .rel.plt segments.
# Read the exact lifecycle-verified input's ELF32 section/link records.
sections = {}
if binary[:6] == b'\x7fELF\x01\x01' and struct.unpack_from('<H', binary, 18)[0] == 3:
    section_offset = struct.unpack_from('<I', binary, 32)[0]
    section_size, section_count, names_index = struct.unpack_from('<HHH', binary, 46)
    if section_size >= 40 and section_offset + section_count * section_size <= len(binary):
        headers = [struct.unpack_from('<10I', binary, section_offset+i*section_size) for i in range(section_count)]
        names = headers[names_index]
        names_data = binary[names[4]:names[4]+names[5]]
        for header in headers:
            name = names_data[header[0]:].split(b'\0')[0]
            sections[name] = header
rel = sections.get(b'.rel.plt')
sym = sections.get(b'.dynsym')
strings = sections.get(b'.dynstr')
if not idaapi.inf_is_64bit() and ida_nalt.get_imagebase() == 0 and rel and sym and strings:
    for ea in idautils.FuncItems(owner):
        if idc.print_insn_mnem(ea).lower() != 'call':
            continue
        targets = list(idautils.CodeRefsFrom(ea, 0))
        if len(targets) != 1:
            continue
        target = int(targets[0])
        segment = ida_segment.getseg(target)
        function = ida_funcs.get_func(target)
        raw = ida_bytes.get_bytes(target, 16)
        if (not segment or ida_segment.get_segm_name(segment) != '.plt'
                or not function or function.start_ea != target
                or target + 16 > segment.end_ea or not raw
                or raw[:2] != b'\xff\x25' or raw[6] != 0x68 or raw[11] != 0xe9):
            continue
        slot = int.from_bytes(raw[2:6], 'little')
        selector = int.from_bytes(raw[7:11], 'little')
        relocation = rel[4] + selector
        if selector % 8 or selector + 8 > rel[5]:
            continue
        relocation_slot, info = struct.unpack_from('<II', binary, relocation)
        if relocation_slot != slot or info & 0xff != 7:
            continue
        symbol_offset = (info >> 8) * 16
        if symbol_offset + 16 > sym[5]:
            continue
        name_offset = struct.unpack_from('<I', binary, sym[4]+symbol_offset)[0]
        if name_offset >= strings[5]:
            continue
        name = binary[strings[4]+name_offset:strings[4]+strings[5]].split(b'\0')[0]
        if name != b'realloc':
            continue
        signature = 'FF 25 ?? ?? ?? ?? 68 ' + ' '.join('%02X' % b for b in raw[7:11]) + ' E9 ?? ?? ?? ??'
        matches[target] = {'func_va': hex(target), 'func_size': hex(function.end_ea-target), 'func_sig': signature}
json.dumps(list(matches.values()))
"""


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    llm_config=None,
    debug=False,
):
    if platform != "linux":
        return False
    owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, OWNER)
    output = _output_for_symbol(expected_outputs, "realloc")
    if owner is None or output is None:
        return False
    code = PLT_QUERY.replace("OWNER_PLACEHOLDER", str(owner["owner_ea"]))
    raw = await session.call_tool("py_eval", {"code": code})
    matches = parse_mcp_result(raw)
    if not isinstance(matches, list) or len(matches) != 1:
        if debug:
            print(f"{skill_name}: realloc PLT candidates {matches!r}")
        return False
    candidate = matches[0]
    address = int(candidate["func_va"], 0)
    if await _find_unique_bytes(session, candidate["func_sig"]) != address:
        if debug:
            print(f"{skill_name}: non-unique realloc PLT signature {candidate}")
        return False
    if not await preprocess_common_skill(
        session=session,
        expected_outputs=[path for path in expected_outputs if Path(path) != output],
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        struct_member_names=MEMBER_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[
            (
                name,
                [
                    "struct_name",
                    "member_name",
                    "offset",
                    "size",
                    "offset_sig",
                    "offset_sig_disp",
                    "offset_sig_allow_across_function_boundary:true",
                ],
            )
            for name in MEMBER_NAMES
        ],
        debug=debug,
    ):
        return False
    write_func_yaml(
        output,
        {
            "func_name": "realloc",
            **candidate,
            "func_rva": hex(address - int(image_base)),
            "func_sig_allow_across_function_boundary": True,
        },
    )
    return True
