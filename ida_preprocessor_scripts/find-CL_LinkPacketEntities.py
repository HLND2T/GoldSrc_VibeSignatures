#!/usr/bin/env python3
"""Locate CL_LinkPacketEntities by its own unique missing-model diagnostic.

engine/cl_ents.c prints ``Tried to link edict %i without model\n`` inside
CL_LinkPacketEntities. The exact C string has one instance in every configured
engine binary; its data xrefs must resolve to one owning function. An old
artifact signature is never used for discovery.
"""

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, preprocess_common_skill, write_func_yaml
from ida_preprocessor_scripts._engine_entity_interpolation_common import function_identity

TARGET = "CL_LinkPacketEntities"
FUNC_XREFS = [
    {
        "func_name": TARGET,
        "xref_strings": ["FULLMATCH:Tried to link edict %i without model\n"],
    }
]
FIELDS = [(TARGET, ["func_name", "func_sig", "func_va", "func_rva", "func_size"])]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    found = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[TARGET],
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=FIELDS,
        debug=debug,
    )
    if not found:
        return False
    identity = function_identity(new_binary_dir, platform, TARGET)
    if identity != TARGET:
        output = _output_for_symbol(expected_outputs, TARGET)
        artifact = _load_yaml_mapping(output) if output is not None else None
        if not artifact or artifact.get("func_name") != TARGET:
            return False
        artifact["func_name"] = identity
        write_func_yaml(output, artifact)
    return True
