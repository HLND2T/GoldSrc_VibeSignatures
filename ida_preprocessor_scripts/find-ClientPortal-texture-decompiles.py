"""Linux texture scalars from the outlined portal GL initializer."""

from llm_spec import select_llm_specs
from pathlib import Path
from ida_analyze_util import _load_yaml_mapping, _parse_int, preprocess_common_skill
from ida_preprocessor_scripts._portal_layout_ida import run_layout_walk
from scalar_artifact import SCALAR_FIELDS


LLM_DECOMPILE = {
    "ClientPortal": [
        {
            "symbol_name": "ClientPortal_texture_id_offset",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/client/ClientPortal_CreateTexture.{platform}.yaml"],
            "expected_result_sections": ["found_scalar"],
            "dependency_policy": {"ClientPortal_CreateTexture.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "ClientPortal_texture_width_offset",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/client/ClientPortal_CreateTexture.{platform}.yaml"],
            "expected_result_sections": ["found_scalar"],
            "dependency_policy": {"ClientPortal_CreateTexture.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "ClientPortal_texture_height_offset",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/client/ClientPortal_CreateTexture.{platform}.yaml"],
            "expected_result_sections": ["found_scalar"],
            "dependency_policy": {"ClientPortal_CreateTexture.{platform}.yaml": "required"},
        },
    ],
    "PortalSource": [
        {
            "symbol_name": "PortalSource_texture_id_offset",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/client/PortalSource_CreateTexture.{platform}.yaml"],
            "expected_result_sections": ["found_scalar"],
            "dependency_policy": {"PortalSource_CreateTexture.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "PortalSource_texture_width_offset",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/client/PortalSource_CreateTexture.{platform}.yaml"],
            "expected_result_sections": ["found_scalar"],
            "dependency_policy": {"PortalSource_CreateTexture.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "PortalSource_texture_height_offset",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/client/PortalSource_CreateTexture.{platform}.yaml"],
            "expected_result_sections": ["found_scalar"],
            "dependency_policy": {"PortalSource_CreateTexture.{platform}.yaml": "required"},
        },
    ],
}


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
    if platform != "linux":
        return False
    source_name = (
        "PortalSource"
        if any(Path(path).name.startswith("PortalSource_") for path in expected_outputs)
        else "ClientPortal"
    )
    name = f"{source_name}_CreateTexture"
    payload = _load_yaml_mapping(Path(new_binary_dir) / f"{name}.{platform}.yaml")
    if not payload or payload.get("func_name") != name:
        return False
    try:
        values = await run_layout_walk(
            session,
            {"ea": _parse_int(payload["func_va"], "func_va")},
            "result = linux_texture_offsets(decode_function(values['ea']))",
        )
    except (ValueError, KeyError) as exc:
        if debug:
            print(exc)
        return False
    verified = {f"{source_name}_{key}_offset": value for key, value in values.items()}
    specs = select_llm_specs(LLM_DECOMPILE, branch=source_name, symbols=list(verified), expected_values=verified)
    if debug:
        print("Portal Linux texture offsets verified:", verified)
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        scalar_names=list(verified),
        llm_decompile_specs=specs,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(name, list(SCALAR_FIELDS)) for name in verified],
        debug=debug,
    )
