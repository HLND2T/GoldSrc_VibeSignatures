#!/usr/bin/env python3
"""Recover the actual location-color array, known as BaseTextColor in MetaHook.

Use GetTextColor's color-4 return, or the same branch in HL25 Windows Colorize.
References intentionally use CS bodies: Half-Life lacks this location-color
selector. cstrike-8684 supplies both platforms of the standalone body;
czero-10210 supplies the Windows-only inline predecessor (identical to CS).
The selected current instruction/data operand is validated by the shared LLM
pipeline, and the returned data is independently checked as float[3] {0,.8,0}.
Generate into temporary outputs until that extra check passes, preserving any
existing artifact if discovery or validation fails.
"""

import json
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml

from ida_analyze_util import parse_mcp_result, preprocess_common_skill, write_gv_yaml

TARGET_GLOBAL_NAMES = ["g_LocationColor"]
FIELDS = ["gv_name", "gv_va", "gv_rva", "gv_sig", "gv_sig_va", "gv_inst_offset", "gv_inst_length", "gv_inst_disp"]
CHECK_COLOR = r"""
import ida_bytes, ida_segment, json, struct
address = ADDRESS
segment = ida_segment.getseg(address)
data = ida_bytes.get_bytes(address, 12) if segment and not (segment.perm & 1) else None
result = json.dumps({'valid': data == struct.pack('<fff', 0.0, 0.8, 0.0)})
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
    inline = platform == "windows" and Path(new_binary_dir).parent.name in {"cstrike-10210", "czero-10210"}
    owner = "SayTextLine_Colorize" if inline else "GetTextColor"
    reference_gamever = "czero-10210" if inline else "cstrike-8684"
    specs = [
        {
            "symbol_name": "g_LocationColor",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": [f"references/{reference_gamever}/client/{owner}.{{platform}}.yaml"],
            "expected_result_sections": ["found_gv"],
            "dependency_policy": {f"{owner}.{{platform}}.yaml": "required"},
        }
    ]
    with TemporaryDirectory(prefix="gsvibe-location-color-") as temporary:
        temporary_outputs = [Path(temporary) / Path(output).name for output in expected_outputs]
        if not await preprocess_common_skill(
            session=session,
            expected_outputs=temporary_outputs,
            old_yaml_map=None,
            new_binary_dir=new_binary_dir,
            platform=platform,
            image_base=image_base,
            gv_names=TARGET_GLOBAL_NAMES,
            llm_decompile_specs=specs,
            llm_config=llm_config,
            generate_yaml_desired_fields=[("g_LocationColor", FIELDS)],
            debug=debug,
        ):
            return False
        validated = []
        for temporary_output in temporary_outputs:
            artifact = yaml.safe_load(temporary_output.read_text(encoding="utf-8"))
            address = int(str(artifact["gv_va"]), 0)
            checked = parse_mcp_result(
                await session.call_tool("py_eval", {"code": CHECK_COLOR.replace("ADDRESS", json.dumps(address))})
            )
            if not isinstance(checked, dict) or checked.get("valid") is not True:
                if debug:
                    print(f"  g_LocationColor: returned operand is not the verified location color array: {checked}")
                return False
            validated.append(artifact)
        for output, artifact in zip(expected_outputs, validated):
            write_gv_yaml(output, artifact)
    return True
