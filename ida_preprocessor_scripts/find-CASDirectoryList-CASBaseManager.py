#!/usr/bin/env python3
"""Locate directory creation and type-query evidence by target-owned diagnostics.

CreateDirectory's duplicate-directory warning and KeepIfPrevious's string-array
type error each identify one body on Sven 5.15/5.16 PE32 and ELF32. The latter
selects the CScriptArray const* overload, not the CString const& overload.
GetTypeInfoByName's cache-insertion error directly identifies its Windows body;
Linux has the literal but no recorded PIC xref, so its call is recovered by the
separate KeepIfPrevious decompile finder. Never repair xrefs or use old signatures
to turn the absent Linux xref into a discovery result.

Windows methods use thiscall (asext adapts it with fastcall and an unused EDX).
Linux uses i386 stack arguments and a 24-byte libstdc++ __cxx11 string. The
CreateDirectory body returns a CASDirectory pointer despite asext's void typedef.
MSVC SEH headers can collide within the default output budget; the extended
output budget reaches the diagnostic-owning path or string-array comparison
inside the located body. Generated signatures are output validation only.
"""

from ida_analyze_util import preprocess_common_skill
from cas_directory_manager_artifacts import publish_directory_manager_identities

TARGET_FUNCTION_NAMES = [
    "CASDirectoryList_CreateDirectory",
    "CASPersistence_KeepIfPrevious",
    "CASBaseManager_GetTypeInfoByName",
]
FUNC_XREFS = [
    {
        "func_name": "CASDirectoryList_CreateDirectory",
        "xref_strings": ["FULLMATCH:CASDirectoryList::CreateDirectory: Directory '%s' already exists!\n"],
    },
    {
        "func_name": "CASPersistence_KeepIfPrevious",
        "xref_strings": ["FULLMATCH:CASPersistence::KeepIfPrevious: array type must be string!\n"],
    },
    {
        "func_name": "CASBaseManager_GetTypeInfoByName",
        "xref_strings": [
            "FULLMATCH:CASBaseManager::GetTypeInfoByName: failed to insert object type '%s' in cache! (cache size: %u)\n"
        ],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        name,
        ["func_name", "func_va", "func_rva", "func_size", "func_sig", "func_sig_allow_across_function_boundary:true"],
    )
    for name in TARGET_FUNCTION_NAMES
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    if platform not in {"windows", "linux"}:
        return False
    targets = [
        name for name in TARGET_FUNCTION_NAMES if platform == "windows" or name != "CASBaseManager_GetTypeInfoByName"
    ]
    success = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=targets,
        func_xrefs=[spec for spec in FUNC_XREFS if spec["func_name"] in targets],
        generate_yaml_desired_fields=[spec for spec in GENERATE_YAML_DESIRED_FIELDS if spec[0] in targets],
        debug=debug,
    )
    if success:
        publish_directory_manager_identities(expected_outputs, platform)
    return success
