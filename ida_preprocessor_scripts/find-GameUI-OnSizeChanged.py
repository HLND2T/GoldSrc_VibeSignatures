#!/usr/bin/env python3
"""Inherit Panel/EditablePanel::OnSizeChanged and mark two of EditablePanel's calls.

Both overrides take the IClientPanel::OnSizeChanged slot proven by vgui2's
VPanel::SetSize. EditablePanel's override must directly call Panel's.

Inside EditablePanel::OnSizeChanged, SetBounds is the unique direct callee that
passes the bounds finder's Panel::SetBounds body proof (SetPos/SetSize
forwarding), and it must be called exactly once. Its receiver must be the
result of one direct call on `this` with one further argument:
Panel::GetChild(this, i). That call must also be the only call to GetChild in
the override. Inlining or any other count fails
closed; no fixed address, slot or signature locates either call.
"""

from pathlib import Path

from ida_analyze_util import (
    _find_unique_bytes,
    _load_yaml_mapping,
    _output_for_symbol,
    preprocess_common_skill,
    preprocess_vtable_via_mcp,
    write_func_yaml,
    write_patch_yaml,
    write_vtable_yaml,
)
from ida_preprocessor_scripts._func_to_func_callsites_common import generate_callsite_signatures
from ida_preprocessor_scripts._panel_bounds_callsites_common import bounds_identity_source
from ida_preprocessor_scripts._vgui_paint_common import walk

SLOT = "../vgui2/vgui2_IClientPanel_OnSizeChanged"
TABLES = (
    ("vgui2::Panel", "vgui2_Panel", ["??_7Panel@vgui2@@6B@", "_ZTVN5vgui25PanelE"]),
    ("vgui2::EditablePanel", "vgui2_EditablePanel", ["??_7EditablePanel@vgui2@@6B@", "_ZTVN5vgui213EditablePanelE"]),
)
# Old Windows Panel::OnSizeChanged is a 20-byte tail jump also present at the end
# of another function; the signature may only extend into following padding.
FIELDS = [
    "func_name",
    "func_va",
    "func_rva",
    "func_size",
    "func_sig",
    "func_sig_allow_across_function_boundary:true",
    "vtable_name",
    "vfunc_offset",
    "vfunc_index",
]
GETCHILD = "vgui2_EditablePanel_OnSizeChanged_call_GetChild_callsite_0"
SETBOUNDS = "vgui2_EditablePanel_OnSizeChanged_call_SetBounds_callsite_0"

CALLSITES = r"""
owner = values["owner"]
flow = flow_at(owner, platform)
calls = call_map(flow)
if values["base"] not in {c["direct"] for c in flow["calls"] if not c.get("tail")}:
    raise ValueError("EditablePanel::OnSizeChanged does not call Panel::OnSizeChanged")
setters = [c for c in flow["calls"] if c["direct"] == target]
if len(setters) != 1 or setters[0].get("tail"):
    raise ValueError("SetBounds call is not unique: " + repr([hex(c["ea"]) for c in setters]))
setter = setters[0]
receiver = setter["this"] if platform == "windows" else setter["stack_args"][0]
producers = {v[1] for v in alternatives(receiver) if v and v[0] == "result"}
if len(producers) != 1 or None in alternatives(receiver):
    raise ValueError("SetBounds receiver is not one call result")
child = calls.get(producers.pop())
if not child or not child["direct"] or child.get("tail"):
    raise ValueError("SetBounds receiver is not a direct call result")
getchild = child["direct"]
# The loop index merges across iterations, so only the receiver is a known value.
# Windows additionally proves the single explicit argument through the callee's RET.
if (child["this"] if platform == "windows" else child["stack_args"][0]) != THIS or (
    platform == "windows" and callee_stack_purge(getchild) != WORD_SIZE
):
    raise ValueError("SetBounds receiver is not GetChild(this, index)")
if [c["ea"] for c in flow["calls"] if c["direct"] == getchild] != [child["ea"]]:
    raise ValueError("GetChild call is not unique")
result = dict(setbounds=hex(target), getchild=hex(getchild), sites={"GetChild": child["ea"], "SetBounds": setter["ea"]})
"""


async def _write_callsites(session, expected_outputs, sites, image_base):
    rows = {sites["GetChild"]: GETCHILD, sites["SetBounds"]: SETBOUNDS}
    signatures = await generate_callsite_signatures(session, rows)
    if not signatures or {s["ea"] for s in signatures["sites"]} != set(rows):
        return False
    payloads = []
    for site in signatures["sites"]:
        ea = site["ea"]
        output = _output_for_symbol(expected_outputs, rows[ea])
        if output is None or await _find_unique_bytes(session, site["patch_sig"]) != ea:
            return False
        payloads.append(
            (
                output,
                dict(
                    patch_name=rows[ea],
                    patch_va=hex(ea),
                    patch_rva=hex(ea - image_base),
                    patch_sig=site["patch_sig"],
                    patch_sig_disp=site["patch_sig_disp"],
                ),
            )
        )
    for output, payload in payloads:
        write_patch_yaml(output, payload)
    return True


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    for class_name, stem, aliases in TABLES:
        table = await preprocess_vtable_via_mcp(
            session, class_name, image_base, platform, debug=debug, symbol_aliases=aliases
        )
        output = _output_for_symbol(expected_outputs, f"{stem}_vtable")
        if not table or output is None:
            return False
        table.pop("_pointer_size", None)
        write_vtable_yaml(output, table)
    names = [f"{stem}_OnSizeChanged" for _, stem, _ in TABLES]
    if not await preprocess_common_skill(
        session,
        [_output_for_symbol(expected_outputs, name) for name in names],
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        inherit_vfuncs=[(name, stem, SLOT, True) for name, (_, stem, _) in zip(names, TABLES)],
        generate_yaml_desired_fields=[(name, FIELDS) for name in names],
        debug=debug,
    ):
        return False
    addresses = []
    for name, (class_name, _, _) in zip(names, TABLES):
        output = _output_for_symbol(expected_outputs, name)
        data = _load_yaml_mapping(output)
        data.update(func_name=f"{class_name}::OnSizeChanged(int, int)", vtable_name=class_name)
        write_func_yaml(output, data)
        addresses.append(int(data["func_va"], 0))
    base, override = addresses
    if base == override:
        return False
    record = _load_yaml_mapping(Path(new_binary_dir) / f"vgui2_Panel_Init.{platform}.yaml")
    if not record or record.get("func_name") != "vgui2::Panel::Init(int, int, int, int)":
        return False
    found = await walk(
        session,
        bounds_identity_source(CALLSITES),
        dict(
            platform=platform,
            init=int(record["func_va"], 0),
            scaled=False,
            owner=override,
            base=base,
            bounds_owner=override,
        ),
    )
    if found.get("error") or "sites" not in found:
        if debug:
            print(found)
        return False
    if debug:
        print(f"EditablePanel::OnSizeChanged: SetBounds={found['setbounds']}, GetChild={found['getchild']}")
    return await _write_callsites(session, expected_outputs, found["sites"], image_base)
