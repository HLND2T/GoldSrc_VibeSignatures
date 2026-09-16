"""Recover legacy ClientPortal's entity indirection at CalculateClipPlane."""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping, _parse_int, preprocess_common_skill
from ida_preprocessor_scripts._portal_layout_ida import run_layout_walk
from scalar_artifact import SCALAR_FIELDS


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
    render_name = "ClientPortalManager_RenderPortals"
    clip_name = "PortalSource_CalculateClipPlane"
    try:
        render = _load_yaml_mapping(Path(new_binary_dir) / f"{render_name}.{platform}.yaml")
        clip = _load_yaml_mapping(Path(new_binary_dir) / f"{clip_name}.{platform}.yaml")
        values = await run_layout_walk(
            session,
            {
                "render": _parse_int(render["func_va"], "func_va"),
                "clip": _parse_int(clip["func_va"], "func_va"),
                "platform": platform,
            },
            """
getters = {ea: getter_return(decode_function(ea), values['platform']) for ea in callees(values['render'])}
result = client_transform_offsets(decode_function(values['render']), values['platform'], values['clip'], getters)
""",
        )
    except (TypeError, ValueError, KeyError) as exc:
        if debug:
            print(exc)
        return False
    verified = {
        "ClientPortal_mode_offset": values["mode"],
        "ClientPortal_entity_offset": values["entity"],
        "cl_entity_origin_offset": values["origin"],
        "cl_entity_angles_offset": values["angles"],
    }
    if debug:
        print("ClientPortal verified entity layout:", verified)
    specs = [
        {
            "symbol_name": name,
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/client/ClientPortalManager_RenderPortals.{platform}.yaml"],
            "dependency_policy": {f"{render_name}.{{platform}}.yaml": "required"},
            "expected_result_sections": ["found_scalar"],
            "expected_value": value,
        }
        for name, value in verified.items()
    ]
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        scalar_names=list(verified),
        llm_decompile_specs=specs,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(name, list(SCALAR_FIELDS)) for name in verified],
        debug=debug,
    )
