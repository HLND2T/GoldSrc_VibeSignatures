#!/usr/bin/env python3
"""Recover the parse counter, byte stride and entity origin of the transparent list.

``r_entorigin`` arrives here as well: on every family except SvEngine the
transparent-entity loader copies ``currententity->origin`` into it while walking
the list, so the same predecessor reference serves all three targets. SvEngine
does not touch it in that body at all and is therefore not covered.
"""

import json
from pathlib import Path

from ida_analyze_util import (
    _export_llm_function,
    _load_yaml_mapping,
    _output_for_symbol,
    _parse_int,
    parse_mcp_result,
    preprocess_common_skill,
)
from ida_scalar import build_stack_operand_export_py_eval, recover_masked_index_stride
from scalar_artifact import SCALAR_FIELDS

LLM_DECOMPILE = [
    {
        "symbol_name": "cl_parsecount",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/R_DrawTEntitiesOnList.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"R_DrawTEntitiesOnList.{platform}.yaml": "required"},
    },
    {
        "symbol_name": "size_of_frame",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/R_DrawTEntitiesOnList.{platform}.yaml"],
        "expected_result_sections": ["found_scalar"],
        "dependency_policy": {"R_DrawTEntitiesOnList.{platform}.yaml": "required"},
    },
    {
        "symbol_name": "r_entorigin",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/R_DrawTEntitiesOnList.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"R_DrawTEntitiesOnList.{platform}.yaml": "required"},
    },
]
GV_FIELDS = [
    "gv_name",
    "gv_va",
    "gv_rva",
    "gv_sig",
    "gv_sig_va",
    "gv_inst_offset",
    "gv_inst_length",
    "gv_inst_disp",
    "gv_sig_allow_across_function_boundary:true",
]

# cl.parsecount may be a register-relative member, including Sven Linux.
# Reference semantics distinguish it from CL_UPDATE_MASK; the shared CFG address
# resolver proves the register base. Operand spelling alone cannot identify it.


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
    predecessor = _load_yaml_mapping(Path(new_binary_dir) / f"R_DrawTEntitiesOnList.{platform}.yaml")
    if not predecessor:
        return False
    exported = await _export_llm_function(session, _parse_int(predecessor.get("func_va"), "func_va"))
    if not exported or not exported.get("procedure"):
        return False
    try:
        stack = parse_mcp_result(
            await session.call_tool(
                "py_eval",
                {"code": build_stack_operand_export_py_eval(_parse_int(predecessor.get("func_va"), "func_va"))},
            )
        )
        if not isinstance(stack, dict) or not isinstance(stack.get("stack_displacements"), dict):
            return False
        value, evidence = recover_masked_index_stride(
            exported["disasm_code"], stack_displacements=stack["stack_displacements"]
        )
    except ValueError as exc:
        print(f"size_of_frame: {exc}")
        if debug:
            print(exported["disasm_code"])
        return False
    print("size_of_frame evidence: " + json.dumps(evidence))
    scalar_spec = {**LLM_DECOMPILE[1], "expected_value": value}
    gv_names = ["cl_parsecount"]
    gv_specs = [dict(LLM_DECOMPILE[0])]
    desired_fields = [("cl_parsecount", GV_FIELDS)]
    # SvEngine writes r_entorigin in its entity dispatcher instead, so the
    # config that covers this skill without that output must not require it.
    if _output_for_symbol(expected_outputs, "r_entorigin") is not None:
        gv_names.append("r_entorigin")
        gv_specs.append(dict(LLM_DECOMPILE[2]))
        desired_fields.append(("r_entorigin", GV_FIELDS))
    desired_fields.append(("size_of_frame", list(SCALAR_FIELDS)))
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        gv_names=gv_names,
        scalar_names=["size_of_frame"],
        llm_decompile_specs=[*gv_specs, scalar_spec],
        llm_config=llm_config,
        generate_yaml_desired_fields=desired_fields,
        debug=debug,
    )
