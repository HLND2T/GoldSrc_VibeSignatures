#!/usr/bin/env python3
"""Locate the direct caller used to recover LoadBlobFile."""

import json
from pathlib import Path

import yaml

from ida_analyze_util import parse_mcp_result, preprocess_common_skill


TARGET_FUNCTION_NAMES = ["LoadBlobFile_Caller"]

SOURCE_FUNCTION_NAMES = {
    "windows": "NLoadBlobFile",
    "linux": "ClientDLL_Init",
}

FUNC_XREFS_BY_PLATFORM = {
    "windows": [
        {
            "func_name": "LoadBlobFile_Caller",
            "xref_strings": ["FULLMATCH:NULL != hmoduleT"],
            "xref_gvs": [],
            "xref_signatures": [],
            "xref_funcs": [],
            "exclude_funcs": [],
            "exclude_strings": [],
            "exclude_gvs": [],
            "exclude_signatures": [],
        }
    ],
    "linux": [
        {
            "func_name": "LoadBlobFile_Caller",
            "xref_strings": ["FULLMATCH:ScreenShake"],
            "xref_gvs": [],
            "xref_signatures": [],
            "xref_funcs": [],
            "exclude_funcs": [],
            "exclude_strings": [],
            "exclude_gvs": [],
            "exclude_signatures": [],
        }
    ],
}

GENERATE_YAML_DESIRED_FIELDS = [
    ("LoadBlobFile_Caller", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS_BY_PLATFORM[platform],
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
    return bool(success) and await _restore_source_function_name(session, expected_outputs, platform)
