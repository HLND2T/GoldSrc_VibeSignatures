#!/usr/bin/env python3
"""Preprocess script for find-LoadBlobFile."""

import json
from pathlib import Path

import yaml

from ida_analyze_util import parse_mcp_result, preprocess_common_skill


TARGET_FUNCTION_NAMES = ["LoadBlobFile"]

SOURCE_FUNCTION_NAMES = {
    "windows": "NLoadBlob",
    "linux": "NLoadBlobFile",
}

LLM_DECOMPILE = [
    {
        "symbol_name": "LoadBlobFile",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/{gamever}/engine/LoadBlobFile_Caller.{platform}.yaml",
        ],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {
            "LoadBlobFile_Caller.{platform}.yaml": "required",
        },
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    ("LoadBlobFile", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
]


async def _restore_source_function_name(session, expected_outputs, platform):
    try:
        payload = yaml.safe_load(Path(expected_outputs[0]).read_text(encoding="utf-8"))
        func_va = int(payload["func_va"], 0)
    except (IndexError, KeyError, TypeError, ValueError, OSError, yaml.YAMLError):
        return False
    source_name = SOURCE_FUNCTION_NAMES[platform]
    raw = await session.call_tool(
        "py_eval",
        {
            "code": (
                "import ida_name, json\n"
                f"json.dumps(bool(ida_name.set_name({func_va}, {json.dumps(source_name)}, ida_name.SN_FORCE)))"
            )
        },
    )
    return parse_mcp_result(raw) is True


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
    _ = skill_name
    success = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
    return bool(success) and await _restore_source_function_name(session, expected_outputs, platform)
