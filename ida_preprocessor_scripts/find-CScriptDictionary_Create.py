#!/usr/bin/env python3
"""Locate the engine-taking dictionary factory, distinct from Create(asBYTE*).

Windows: one verified body pattern covers both PE32 inputs. It starts at
entry +0x24: allocate 48 bytes, initialize the dictionary vptr/container,
set refCount=1 and gcFlag=false, retain the engine argument, and read cache
1003. Call/vptr addresses are wildcarded. The allocation statement separates
Create from the constructor; the returned object and GC notification separate
it from the inline generic factory. No whole-header pattern is used.

Linux: the deterministically anchored registration yields the generic factory.
Recover its GetEngine -> Create(engine) -> return-location store direct call
through found_call, resolving the 5.15 PLT to the actual body. Both ELF bodies
allocate 44 bytes, return null on allocation failure, and construct the object.
The output identity follows the retained 5.15 ELF overload.
"""

from ida_analyze_util import preprocess_common_skill
from llm_spec import select_llm_specs
from script_dictionary_artifacts import publish_dictionary_identities

BODY_SIGNATURE = (
    "6A 30 E8 ?? ?? ?? ?? 8B F0 83 C4 04 89 75 F0 8D 4E 10 C7 06 ?? ?? ?? ?? "
    "E8 ?? ?? ?? ?? 8B 4D 08 C7 46 08 01 00 00 00 C6 46 0C 00 89 4E 04 8B 01 68 EB 03 00 00"
)
LLM_DECOMPILE = {
    "linux": [
        {
            "symbol_name": "CScriptDictionary_Create",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/ScriptDictionaryFactory_Generic.{platform}.yaml"],
            "expected_result_sections": ["found_call"],
            "dependency_policy": {"ScriptDictionaryFactory_Generic.{platform}.yaml": "required"},
        }
    ],
}
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CScriptDictionary_Create",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "func_sig",
            "func_sig_resolve_jmp_thunk:true",
            "func_sig_allow_across_function_boundary:true",
        ],
    )
]


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
    success = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=["CScriptDictionary_Create"],
        func_xrefs=[{"func_name": "CScriptDictionary_Create", "xref_signatures": [BODY_SIGNATURE]}]
        if platform == "windows"
        else None,
        llm_decompile_specs=select_llm_specs(LLM_DECOMPILE, branch=platform) if platform == "linux" else None,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
    return success and await publish_dictionary_identities(session, expected_outputs, platform, image_base)
