#!/usr/bin/env python3
"""Recover the classic sky-loading globals from the R_LoadSkys reference.

``R_LoadSkys`` gates on ``gLoadSky`` at entry, clears the six ``gSkyTexNumber``
slots while the flag is off, refills them from the six ``gfx/env/<sky><suf>``
faces, and stores ``gLoadSky = false`` on the way out.  Both globals therefore
become visible in one annotated predecessor body, and the LLM-selected
instruction is decoded by the shared x86 resolver for every family form:
direct absolute operands on the Windows builds, ``mov esi, offset`` on non-PIC
ELF, and a fixed texture-id array slot (``0x16A8``-based) on the newer CoF/BLOB
engine revisions.

The SvEngine family keeps the same two globals but reads them from its own
loader, so it is covered by ``find-R_LoadSkyBox_SvEngine-decompiles`` instead of
this script.
"""

from ida_analyze_util import preprocess_common_skill


TARGET_GLOBAL_NAMES = ["gLoadSky", "gSkyTexNumber"]

REFERENCE_YAML_PATHS = [
    "references/{gamever}/engine/R_LoadSkys.{platform}.yaml",
]
DEPENDENCY_POLICY = {
    "R_LoadSkys.{platform}.yaml": "required",
}

LLM_DECOMPILE = [
    {
        "symbol_name": name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": REFERENCE_YAML_PATHS,
        "expected_result_sections": ["found_gv"],
        "dependency_policy": DEPENDENCY_POLICY,
    }
    for name in TARGET_GLOBAL_NAMES
]

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
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
