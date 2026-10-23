#!/usr/bin/env python3
"""Recover RoundEnd's business-command override from its own surrender dialog.

Pattern B: exact dialog name/title/text xrefs intersect in one function, which
must occur once in the current RoundEnd primary vtable produced by #397.
That producer proves the resource constructor, primary address point and
unadjusted Frame inheritance. Neither old signatures nor fixed slots locate it.
Linux's original symbol distinguishes this override from Frame/QueryBox methods.
The surrender/disconnect, unpause and vguicancel literals independently constrain
the command body; generated signatures only validate the discovered entry.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, preprocess_common_skill, write_func_yaml
from ida_preprocessor_scripts._career_bot_cost_common import COMMON, IDENTITY_SOURCE
from ida_preprocessor_scripts._career_player_name_common import COLLECT_COMMON
from ida_preprocessor_scripts._vgui_paint_common import walk
from ida_preprocessor_scripts.renderer_elf_symbols import STT_FUNC, current_elf_symbols, select_symbol


SYMBOL = "CCSCareerRoundEndMenu_OnCommand"
CANONICAL = "CCSCareerRoundEndMenu::OnCommand(char const*)"
MANGLED = "_ZN21CCSCareerRoundEndMenu9OnCommandEPKc"
ANCHORS = ["CareerBoxSurrender", "#Career_Surrender", "#GameUI_QuitConfirmationText"]
FUNC_XREFS = [{"func_name": SYMBOL, "xref_strings": ["FULLMATCH:" + text for text in ANCHORS]}]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        SYMBOL,
        ["func_name", "func_va", "func_rva", "func_size", "func_sig", "vtable_name", "vfunc_index", "vfunc_offset"],
    )
]
VERIFY = r"""
literals={text:literal_evidence(text) for text in values['anchors']}
if any(len(v['addresses'])!=1 or len(v['owners'])!=1 for v in literals.values()):
    raise ValueError('dialog anchor must be unique in the current binary')
ea=owner(literals,values['anchors'])
for text in ('disconnect','surrender','unpause\n','vguicancel'):
    if ea not in literal_evidence(text)['owners']:
        raise ValueError('RoundEnd command branch is absent: '+repr(text))
identity(ea,['_ZN21CCSCareerRoundEndMenu9OnCommandEPKc'])
if not stack_abi(ea,4 if values['platform']=='windows' else 0):
    raise ValueError('OnCommand argument cleanup disagrees')
result=dict(ea=ea,literals=literals)
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    evidence = await walk(
        session, IDENTITY_SOURCE + COMMON + COLLECT_COMMON + VERIFY, dict(platform=platform, anchors=ANCHORS)
    )
    if debug:
        print(f"  RoundEnd OnCommand evidence: {evidence}")
    if evidence.get("error"):
        return False
    if platform == "linux":
        symbols = await current_elf_symbols(session, [MANGLED])
        if image_base + select_symbol(symbols, MANGLED, STT_FUNC) != evidence["ea"]:
            return False
    success = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[SYMBOL],
        func_xrefs=FUNC_XREFS,
        func_vtable_relations=[(SYMBOL, "CCSCareerRoundEndMenu_vtable")],
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
    if not success:
        return False
    output = _output_for_symbol(expected_outputs, SYMBOL)
    payload = _load_yaml_mapping(Path(output))
    if int(payload["func_va"], 0) != evidence["ea"]:
        return False
    payload.update(func_name=CANONICAL, vtable_name="CCSCareerRoundEndMenu")
    write_func_yaml(output, payload)
    return True
