#!/usr/bin/env python3
"""Map software scissor storage from the verified EngineSurface push body.

References preserve scalar Windows/GoldSrc writes and the SvEngine Linux SIMD
store. The shared operand validator handles current ELF PIC addends; neither a
four-store count nor adjacency to the enable flag determines the rectangle.
"""

from ida_analyze_util import preprocess_common_skill
from ida_preprocessor_scripts._vgui_paint_common import artifact, function_address, walk

TARGETS = ["g_bScissor", "g_ScissorRect"]
OWNER = "EngineSurface_pushMakeCurrent"
LLM_DECOMPILE = [
    dict(
        symbol_name=name,
        prompt_path="prompt/call_llm_decompile.md",
        reference_yaml_paths=[f"references/{{gamever}}/engine/{OWNER}.{{platform}}.yaml"],
        expected_result_sections=["found_gv"],
        dependency_policy={f"{OWNER}.{{platform}}.yaml": "required"},
    )
    for name in TARGETS
]
FIELDS = [
    "gv_name",
    "gv_va",
    "gv_rva",
    "gv_sig",
    "gv_sig_va",
    "gv_inst_offset",
    "gv_inst_length",
    "gv_inst_disp",
    "gv_pic_addend?",
]

VERIFY = r"""
push=flow_at(values['push'],values['platform'])
pop=flow_at(values['pop'],values['platform'])
def flag_stores(flow,value):
    return [s for s in flow['stores'] if s['width']==1 and s['value']==('const',value) and s['address']==('const',values['flag'])]
rect=[s for s in push['stores'] if s['address'] and s['address'][0]=='const' and values['rect']<=s['address'][1]<values['rect']+16]
covered=set()
for store in rect:
    covered.update(range(store['address'][1]-values['rect'],store['address'][1]-values['rect']+store['width']))
result={'valid':bool(flag_stores(push,1) and flag_stores(pop,0) and covered==set(range(16)))}
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
    if not await preprocess_common_skill(
        session,
        expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        gv_names=TARGETS,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(name, FIELDS) for name in TARGETS],
        debug=debug,
    ):
        return False
    flag = artifact(new_binary_dir, "g_bScissor", platform)
    rect = artifact(new_binary_dir, "g_ScissorRect", platform)
    found = await walk(
        session,
        VERIFY,
        dict(
            push=function_address(new_binary_dir, OWNER, platform),
            pop=function_address(new_binary_dir, "EngineSurface_popMakeCurrent", platform),
            flag=int(flag["gv_va"], 0),
            rect=int(rect["gv_va"], 0),
            platform=platform,
        ),
    )
    if debug and not found.get("valid"):
        print(found)
    return bool(found.get("valid"))
