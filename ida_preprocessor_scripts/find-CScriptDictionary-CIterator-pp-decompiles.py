#!/usr/bin/env python3
"""Recover Linux prefix ++ from InitializeEntity's dictionary traversal.

Prefix/postfix bodies are byte-identical in both ELF inputs. Select the call
that advances the current iterator after the key/value success or warning
branches and before the end/inequality loop test. It has only iterator this,
not the postfix int argument. Validate the current call through found_call,
including 5.15 PLT resolution. Output identity and uniqueness come from the
resolved body; an extended output signature distinguishes identical siblings.
"""

from pathlib import Path

import yaml

from ida_analyze_util import _find_byte_matches, preprocess_common_skill
from script_dictionary_artifacts import publish_dictionary_identities

LLM_DECOMPILE = [
    {
        "symbol_name": "CScriptDictionary_CIterator_operator_PP",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/server/CASEntityFuncs_InitializeEntity.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"CASEntityFuncs_InitializeEntity.{platform}.yaml": "required"},
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CScriptDictionary_CIterator_operator_PP",
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
    if platform != "linux":
        return False
    success = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=["CScriptDictionary_CIterator_operator_PP"],
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
    if not success:
        return False
    # Verification only: the identical increment bodies cannot discover the
    # prefix overload. The validated predecessor call supplies that identity.
    matches = await _find_byte_matches(session, "8B 44 24 04 8B 10 8B 0A 89 08 C3")
    if matches is None:
        return False
    for output in expected_outputs:
        payload = yaml.safe_load(Path(output).read_text(encoding="utf-8"))
        if int(payload["func_va"], 0) not in matches:
            return False
    return await publish_dictionary_identities(session, expected_outputs, platform, image_base)
