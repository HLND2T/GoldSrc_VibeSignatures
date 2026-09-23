#!/usr/bin/env python3
"""Recover client render gates and the sound listener vectors from V_RenderView.

cls_state and cls_signon are addresses of cls.state and cls.signon, not
standalone ELF objects. Both gate entry to rendering. The listener origin
receives r_origin and the listener angles receive ref_params.viewangles under
!onlyClientDraw; zeroing order and adjacent storage are not identity evidence.
SvEngine has no con_forcedup gate and Linux uses PIC/GOT addressing. Preserve
the shared validator's current-binary resolution fields for those operands.
"""

from pathlib import Path

import yaml

from ida_analyze_util import preprocess_common_skill, write_gv_yaml
from ida_preprocessor_scripts.renderer_elf_symbols import preserve_global_identities

GV_NAMES = ["cls_state", "cls_signon", "r_soundOrigin", "r_playerViewportAngles"]
GV_FIELDS = [
    "gv_name",
    "gv_va",
    "gv_rva",
    "gv_sig",
    "gv_sig_va",
    "gv_inst_offset",
    "gv_inst_length",
    "gv_inst_disp",
    "gv_pic_addend?",
    "gv_address_offset?",
]
LLM_DECOMPILE = [
    {
        "symbol_name": name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/V_RenderView.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"V_RenderView.{platform}.yaml": "required"},
    }
    for name in GV_NAMES
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
    if not await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        gv_names=GV_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(name, GV_FIELDS) for name in GV_NAMES],
        debug=debug,
    ):
        return False
    # Retained ELF object symbols independently reject an interior vector
    # component even when its referencing instruction is otherwise valid.
    await preserve_global_identities(session, expected_outputs, platform)
    for output in expected_outputs:
        path = Path(output)
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        if payload["gv_name"] in {"cls_state", "cls_signon"}:
            payload["gv_name"] = payload["gv_name"].replace("cls_", "cls.", 1)
            write_gv_yaml(path, payload)
    return True
