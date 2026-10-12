#!/usr/bin/env python3
"""Recover sv.models through the guarded indexed load in ModelFrames.

Direct-locator exception: each anchored body has one model-indexed four-byte
pointer access. Decode the actual ModRM/SIB and locally materialized base
(absolute, GOT-loaded sv, or GOTOFF LEA). The generic LLM address inspector
cannot represent SvEngine's indexed member load after a GOT pointer; this
current-instruction walk is more robust. The independent guard and mapped sv
member validate the result. No reference address/member offset/signature or
call ordinal discovers the table. Annotated references remain binary evidence.
"""

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, write_gv_yaml
from ida_preprocessor_scripts._engine_private_globals_common import owner_context, run_walk
from ida_preprocessor_scripts._server_physics_common import LAYOUT_PY, MODEL_SIB_PY, finish_globals

WALK = (
    LAYOUT_PY
    + MODEL_SIB_PY
    + r"""
start, server = int(values['owner']), int(values['sv'])
entry, address, displacement, encoded, pic = indexed_model_access(start, server)
ordinary_scan = scan
# Feed the independently decoded SIB address into the guard/stride probe.
def scan(owner):
    entries = ordinary_scan(owner)
    for item in entries or []:
        if item['ea'] == entry['ea']:
            item['targets'] = {address}
    return entries
layout = model_layout(start, address, server)
located = access(entry, address)
located['insn_disp'] = hex(displacement)
result = {'gv': located, 'encoded': encoded, 'pic': pic, 'scalars': layout}
"""
)


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    function = _load_yaml_mapping(f"{new_binary_dir}/ModelFrames.{platform}.yaml")
    server = _load_yaml_mapping(f"{new_binary_dir}/sv.{platform}.yaml")
    if not function or not server:
        return False
    start = int(function["func_va"], 0)
    located = await run_walk(session, WALK, {"owner": start, "sv": int(server["gv_va"], 0)})
    if debug:
        print(f"{skill_name}: {located}")
    if located.get("error"):
        return False
    owner = await owner_context(session, start, image_base, function["func_name"])
    output = _output_for_symbol(expected_outputs, "sv_models")
    if owner is None or output is None:
        return False
    item = located["gv"]
    address = int(item["gv_ea"], 0)
    payload = {
        "gv_name": "sv_models",
        "gv_va": hex(address),
        "gv_rva": hex(address - image_base),
        "gv_sig": owner["function"]["func_sig"],
        "gv_sig_va": hex(start),
        "gv_inst_offset": hex(int(item["insn_ea"], 0) - start),
        "gv_inst_length": item["insn_len"],
        "gv_inst_disp": item["insn_disp"],
    }
    if owner["allow_across"]:
        payload["gv_sig_allow_across_function_boundary"] = True
    if located["pic"]:
        payload["gv_pic_addend"] = hex((address - image_base - located["encoded"]) & 0xFFFFFFFF)
    write_gv_yaml(output, payload)
    return await finish_globals(session, expected_outputs, platform)
