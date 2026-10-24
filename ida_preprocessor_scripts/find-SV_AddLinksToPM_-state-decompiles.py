#!/usr/bin/env python3
"""Recover the state read by the inlined ELF server area walker.

pmove and pr_strings are pointer-variable addresses; truepositions is an array
base; svs_maxclients is an int field and sv_unlag_value is a float cvar field.
The instruction resolver preserves PIC addends and interior-field offsets.
"""

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, preprocess_common_skill, write_gv_yaml
from ida_preprocessor_scripts._engine_private_globals_common import run_walk
from ida_preprocessor_scripts._native_rcon_globals_common import GV_FIELDS
from ida_preprocessor_scripts._server_physics_common import finish_globals

LLM_DECOMPILE = [
    {
        "symbol_name": "pmove",
        "prompt_path": "prompt/server_physent_state.md",
        "reference_yaml_paths": ["references/{gamever}/engine/SV_AddLinksToPM_.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"SV_AddLinksToPM_.{platform}.yaml": "required"},
    },
    {
        "symbol_name": "pr_strings",
        "prompt_path": "prompt/server_physent_state.md",
        "reference_yaml_paths": ["references/{gamever}/engine/SV_AddLinksToPM_.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"SV_AddLinksToPM_.{platform}.yaml": "required"},
    },
    {
        "symbol_name": "svs_maxclients",
        "prompt_path": "prompt/server_physent_state.md",
        "reference_yaml_paths": ["references/{gamever}/engine/SV_AddLinksToPM_.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"SV_AddLinksToPM_.{platform}.yaml": "required"},
    },
    {
        "symbol_name": "sv_unlag_value",
        "prompt_path": "prompt/server_physent_state.md",
        "reference_yaml_paths": ["references/{gamever}/engine/SV_AddLinksToPM_.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"SV_AddLinksToPM_.{platform}.yaml": "required"},
    },
    {
        "symbol_name": "truepositions",
        "prompt_path": "prompt/server_physent_state.md",
        "reference_yaml_paths": ["references/{gamever}/engine/SV_AddLinksToPM_.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"SV_AddLinksToPM_.{platform}.yaml": "required"},
    },
]

NAMES = ["pmove", "pr_strings", "svs_maxclients", "sv_unlag_value", "truepositions"]

MAXCLIENTS_FIELD = r"""
ea=values['instruction']
insn=idautils.DecodeInstruction(ea)
offset=0
if idc.print_insn_mnem(ea)=='lea':
    # SvEngine materializes svs, then immediately reads its maxclients field.
    following=idautils.DecodeInstruction(ea+int(insn.size))
    if following is None or idc.print_insn_mnem(ea+int(insn.size))!='mov' or int(following.ops[1].type)!=int(idaapi.o_displ) or reg4(following.ops[1])!=reg4(insn.ops[0]):
        raise ValueError('svs address lacks immediate maxclients field read')
    offset=signed32(following.ops[1].addr)
    if offset<=0 or offset>256 or ida_ua.get_dtype_size(following.ops[1].dtype)!=4:
        raise ValueError('invalid maxclients field read')
result={'offset':offset}
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
    _ = skill_name, old_yaml_map
    found = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        gv_names=NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(name, GV_FIELDS) for name in NAMES],
        debug=debug,
    )
    if not found:
        return False
    output = _output_for_symbol(expected_outputs, "svs_maxclients")
    data = _load_yaml_mapping(output)
    instruction = int(data["gv_sig_va"], 0) + int(data["gv_inst_offset"], 0)
    field = await run_walk(session, MAXCLIENTS_FIELD, {"instruction": instruction})
    if field.get("error") or "offset" not in field:
        return False
    if field["offset"]:
        data["gv_va"] = hex(int(data["gv_va"], 0) + field["offset"])
        data["gv_rva"] = hex(int(data["gv_rva"], 0) + field["offset"])
        data["gv_address_offset"] = field["offset"]
        write_gv_yaml(output, data)
    return await finish_globals(session, expected_outputs, platform)
