#!/usr/bin/env python3
"""Locate CASDocumentation methods through their own registration diagnostics.

Windows 5.15/5.16 has exactly one string and owning function for each diagnostic.
ELF 5.16 has a resolved EnumValue diagnostic xref. The ELF 5.15 diagnostic pointers
(and ELF 5.16 property pointer) lack recorded IDA string xrefs, so those production
outputs use the separately verified Color24/OpenFile call predecessors instead.
"""

from ida_analyze_util import preprocess_common_skill
from cas_documentation_artifacts import publish_documentation_identities

FUNC_XREFS = [
    {
        "func_name": "CASDocumentation_RegisterObjectProperty",
        "xref_strings": [
            "FULLMATCH:CASDocumentation::RegisterMethod: class '%s' not registered prior to property '%s' registration!\n"
        ],
    },
    {
        "func_name": "CASDocumentation_RegisterEnumValue",
        "xref_strings": [
            "FULLMATCH:CASDocumentation::RegisterEnumValue: enum '%s' not registered prior to value '%s' registration!\n"
        ],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CASDocumentation_RegisterObjectProperty",
        ["func_name", "func_va", "func_rva", "func_size", "func_sig", "func_sig_allow_across_function_boundary:true"],
    ),
    (
        "CASDocumentation_RegisterEnumValue",
        ["func_name", "func_va", "func_rva", "func_size", "func_sig", "func_sig_allow_across_function_boundary:true"],
    ),
]


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    debug=False,
):
    _ = skill_name, old_yaml_map
    xrefs = FUNC_XREFS if platform == "windows" else FUNC_XREFS[1:]
    targets = [spec["func_name"] for spec in xrefs]
    success = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=targets,
        func_xrefs=xrefs,
        generate_yaml_desired_fields=[spec for spec in GENERATE_YAML_DESIRED_FIELDS if spec[0] in targets],
        debug=debug,
    )
    if success:
        publish_documentation_identities(expected_outputs, platform)
    return success
