#!/usr/bin/env python3
"""Locate CASDocumentation registration callers through their own exact literals.

Four PE32/ELF32 Sven 5.15/5.16 inputs were verified. Custom-entity Think docs and
Color24 structure each have one owner. OpenFile flag docs have two Windows owners:
exclude the CVirtualFileSystem body owning Global file system instance, leaving
the standalone OpenFile flag registration. Linux has one owner before exclusion.
The isalnum(char) declaration belongs to a separate Windows helper but to
RegisterSCScriptVarious on Linux; keep these predecessor identities distinct.
No old artifact or generated signature bypasses string-based discovery.
"""

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _output_for_symbol,
    preprocess_common_skill,
    preprocess_func_xrefs_via_mcp,
    write_func_yaml,
)

FUNC_XREFS = [
    {
        "func_name": "RegisterSCScriptCustomEntityDependencies",
        "xref_strings": ["FULLMATCH:Function definition for custom entity Think functions"],
    },
    {"func_name": "RegisterSCScriptColor24", "xref_strings": ["FULLMATCH:Color24 structure"]},
    {
        "func_name": "RegisterSCScriptOpenFileFlag",
        "xref_strings": ["FULLMATCH:Flags passed to FileSystem::OpenFile."],
        "exclude_strings": ["FULLMATCH:Global file system instance"],
    },
]
CHARACTER_CALLERS = {"windows": "RegisterSCScriptCharacterFunctions", "linux": "RegisterSCScriptVarious"}
# Windows char/string registration helpers share the first 256 masked bytes.
# Cover the char registration's final calls and return within its own body.
# These budgets affect output validation only, never string-based discovery.
CHARACTER_OUTPUT_SIGNATURE_BYTES = (512, 1024)
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "RegisterSCScriptCustomEntityDependencies",
        ["func_name", "func_va", "func_rva", "func_size", "func_sig", "func_sig_allow_across_function_boundary:true"],
    ),
    (
        "RegisterSCScriptColor24",
        ["func_name", "func_va", "func_rva", "func_size", "func_sig", "func_sig_allow_across_function_boundary:true"],
    ),
    (
        "RegisterSCScriptOpenFileFlag",
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
    targets = [spec["func_name"] for spec in FUNC_XREFS]
    success = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=targets,
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=[spec for spec in GENERATE_YAML_DESIRED_FIELDS if spec[0] in targets],
        debug=debug,
    )
    if not success:
        return False
    name = CHARACTER_CALLERS[platform]
    candidate = await preprocess_func_xrefs_via_mcp(
        session=session,
        func_name=name,
        xref_strings=["FULLMATCH:bool isalnum(char character)"],
        xref_gvs=[],
        xref_signatures=[],
        xref_funcs=[],
        exclude_funcs=[],
        exclude_strings=[],
        exclude_gvs=[],
        exclude_signatures=[],
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        debug=debug,
    )
    if candidate is None:
        return False
    if not candidate.get("func_sig"):
        address = int(candidate["func_va"], 0)
        for byte_limit in CHARACTER_OUTPUT_SIGNATURE_BYTES:
            candidate = await _inspect_function_via_mcp(
                session,
                address,
                image_base,
                name,
                signature_byte_limit=byte_limit,
            )
            if candidate is not None:
                break
    if candidate is None or not candidate.get("func_sig"):
        return False
    candidate.pop("_pointer_size", None)
    output = _output_for_symbol(expected_outputs, name)
    if output is None:
        return False
    write_func_yaml(output, candidate)
    return True
