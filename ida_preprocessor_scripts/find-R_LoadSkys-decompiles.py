#!/usr/bin/env python3
"""Recover sky-loading globals from the matching R_LoadSkys implementation.

``R_LoadSkys`` gates on ``gLoadSky`` at entry, loads the six
``gfx/env/<sky><suf>`` faces, and stores ``gLoadSky = false`` on the way out.
Classic builds clear/read ``gSkyTexNumber`` for deletion and binding; BLOB
builds use fixed IDs there and write the array in the BMP/TGA upload paths.
Both globals become visible in one annotated predecessor body, and the LLM-selected
instruction is decoded by the shared x86 resolver for every family form:
direct absolute operands on the Windows builds, ``mov esi, offset`` on non-PIC
ELF, and a fixed texture-id array slot (``0x16A8``-based) on the newer CoF/BLOB
engine revisions.

The SvEngine family keeps the same two globals but reads them from its own
loader, so it is covered by ``find-R_LoadSkyBox_SvEngine-decompiles`` instead of
this script.
"""

from llm_spec import select_llm_specs
from pathlib import Path

from ida_analyze_util import preprocess_common_skill


TARGET_GLOBAL_NAMES = ["gLoadSky", "gSkyTexNumber"]

BLOB_WINDOWS_GAMEVERS = frozenset({"hl-3248", "hl-3266", "hl-3329", "hl-3647"})

LLM_DECOMPILE = {
    "default": [
        {
            "symbol_name": "gLoadSky",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/engine/R_LoadSkys.{platform}.yaml"],
            "expected_result_sections": ["found_gv"],
            "dependency_policy": {"R_LoadSkys.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "gSkyTexNumber",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/engine/R_LoadSkys.{platform}.yaml"],
            "expected_result_sections": ["found_gv"],
            "dependency_policy": {"R_LoadSkys.{platform}.yaml": "required"},
        },
    ],
    "blob": [
        {
            "symbol_name": "gLoadSky",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/hl-3248/engine/R_LoadSkys.windows.yaml"],
            "expected_result_sections": ["found_gv"],
            "dependency_policy": {"R_LoadSkys.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "gSkyTexNumber",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/hl-3248/engine/R_LoadSkys.windows.yaml"],
            "expected_result_sections": ["found_gv"],
            "dependency_policy": {"R_LoadSkys.{platform}.yaml": "required"},
        },
    ],
}


def _llm_branch(new_binary_dir, platform):
    gamever = Path(new_binary_dir).resolve().parent.name
    branch = "blob" if platform == "windows" and gamever in BLOB_WINDOWS_GAMEVERS else "default"
    return branch


GV_FIELDS = [
    "gv_name",
    "gv_va",
    "gv_rva",
    "gv_sig",
    "gv_sig_va",
    "gv_inst_offset",
    "gv_inst_length",
    "gv_inst_disp",
]

GENERATE_YAML_DESIRED_FIELDS = [(name, GV_FIELDS) for name in TARGET_GLOBAL_NAMES]


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
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        gv_names=TARGET_GLOBAL_NAMES,
        llm_decompile_specs=select_llm_specs(LLM_DECOMPILE, branch=_llm_branch(new_binary_dir, platform)),
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
