#!/usr/bin/env python3
"""Recover the SvEngine sky-loading globals from the outer loader reference.

SvEngine's public ``R_LoadSkyBox_SvEngine`` starts by testing ``gLoadSky`` and
returning when it is clear, deletes every live ``gSkyTexNumber`` entry through a
``lea esi, gSkyTexNumber`` / ``lea edi, <array end>`` loop, forwards the skybox
name to the internal loader, falls back to the ``desert`` skybox, and finishes
by broadcasting ``r_missingtexture`` into the six slots and clearing
``gLoadSky``.  The annotated predecessor body therefore pins both globals, and
the shared x86 resolver handles the MSVC absolute operands as well as the PIC
``(gLoadSky - GOT)[ebx]`` form of the Linux builds.

The classic hl/CoF/HL25 family keeps the same two globals in ``R_LoadSkys``, so
it is covered by ``find-R_LoadSkys-decompiles`` instead of this script.
"""

from ida_analyze_util import preprocess_common_skill


TARGET_GLOBAL_NAMES = ["gLoadSky", "gSkyTexNumber"]

REFERENCE_YAML_PATHS = [
    "references/{gamever}/engine/R_LoadSkyBox_SvEngine.{platform}.yaml",
]
DEPENDENCY_POLICY = {
    "R_LoadSkyBox_SvEngine.{platform}.yaml": "required",
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
