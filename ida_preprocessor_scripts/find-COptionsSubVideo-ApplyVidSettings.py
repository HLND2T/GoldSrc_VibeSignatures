#!/usr/bin/env python3
"""Find video settings by its owned command format and verify its ABI role.

GoldSrc/CoF formats width, height and depth; Sven formats width and height.
Only hl-10210 Windows inlines ApplyVidSettings into virtual OnApplyChanges.
The output in that build names the real OnApplyChanges function, not a
fictitious zero-argument ApplyVidSettings overload.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, preprocess_common_skill, write_func_yaml
from ida_preprocessor_scripts._client_vgui_private_common import run_walk
from ida_preprocessor_scripts._gameui_dialog_common import prepare_c_strings


APPLY = "COptionsSubVideo_ApplyVidSettings"
INLINE = "COptionsSubVideo_OnApplyChanges"


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    if not await prepare_c_strings(session):
        return False
    gamever = Path(new_binary_dir).parent.name
    inline = gamever == "hl-10210" and platform == "windows"
    name = INLINE if inline else APPLY
    fields = [
        "func_name",
        "func_va",
        "func_rva",
        "func_size",
        "func_sig",
        "func_sig_allow_across_function_boundary:true",
    ]
    literal = "_setvideomode %i %i\n" if gamever.startswith("svencoop-") else "_setvideomode %i %i %i\n"
    found = await preprocess_common_skill(
        session,
        expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[name],
        func_xrefs=[{"func_name": name, "xref_strings": [f"FULLMATCH:{literal}"]}],
        generate_yaml_desired_fields=[(name, fields)],
        debug=debug,
    )
    if not found:
        return False
    output = _output_for_symbol(expected_outputs, name)
    data = _load_yaml_mapping(output)
    video = _load_yaml_mapping(Path(new_binary_dir) / f"COptionsSubVideo_ctor.{platform}.yaml")
    if data is None or video is None:
        return False
    target = int(data["func_va"], 0)
    constructor = int(video["func_va"], 0)
    checked = await run_walk(
        session,
        """
import ida_name
symbol = ('??_7COptionsSubVideo@@6B@' if values['platform'] == 'windows'
          else '_ZTV16COptionsSubVideo')
table = int(ida_name.get_name_ea(idaapi.BADADDR, symbol))
if table == idaapi.BADADDR:
    raise ValueError('COptionsSubVideo vtable missing')
table += 8 if values['platform'] == 'linux' else 0
slots = valid_vtable_slots(table, maximum=256)
if not slots:
    raise ValueError('invalid video page vtable')
matching = [i for i, ea in enumerate(slots) if ea == values['target']]
ctor = ida_funcs.get_func(values['constructor'])
if ctor is None or int(ctor.start_ea) != values['constructor']:
    raise ValueError('validated video constructor is not a current-IDB function')
callers = [int(x.frm) for x in idautils.XrefsTo(values['target'], 0)
           if direct_call_target(int(x.frm)) == values['target']]
caller_owners = {int(ida_funcs.get_func(ea).start_ea) for ea in callers
                 if ida_funcs.get_func(ea) is not None}
virtual_callers = [i for i, ea in enumerate(slots) if ea in caller_owners]
result = {'matching_slots': matching, 'callers': callers, 'virtual_callers': virtual_callers}
""",
        {"platform": platform, "target": target, "constructor": constructor},
    )
    if checked.get("error"):
        if debug:
            print(f"  Video settings role check failed: {checked}")
        return False
    slots = checked["matching_slots"]
    callers = checked["callers"]
    if inline:
        if len(slots) != 1 or callers:
            return False
        data.update(
            func_name="COptionsSubVideo::OnApplyChanges()",
            vtable_name="COptionsSubVideo",
            vfunc_index=slots[0],
            vfunc_offset=hex(slots[0] * 4),
        )
    else:
        if slots or len(callers) != 1 or len(checked["virtual_callers"]) != 1:
            return False
        data["func_name"] = "COptionsSubVideo::ApplyVidSettings(bool)"
    write_func_yaml(output, data)
    return True
