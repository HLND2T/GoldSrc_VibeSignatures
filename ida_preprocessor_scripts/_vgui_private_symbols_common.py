"""Shared current-binary collection and emission for the private VGUI chains."""

from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    preprocess_vtable_via_mcp,
    write_func_yaml,
    write_struct_offset_yaml,
)
from ida_preprocessor_scripts._vgui_paint_common import walk
import ida_preprocessor_scripts._vgui_private_method_identity as identity


COMMON_CLASSES = ("vgui2::Panel", "vgui2::Frame", "vgui2::EditablePanel", "vgui2::FocusNavGroup")
GAMEUI_CLASSES = (
    "vgui2::PropertySheet",
    "COptionsSubVideo",
    "COptionsSubAudio",
    "COptionsSubMultiplayer",
    "CBasePanel",
    "CCvarSlider",
)
INTERFACES = {
    "ISurface_SupportsFeature": (
        "vgui2::ISurface",
        "vgui2::ISurface::SupportsFeature(vgui2::ISurface::SurfaceFeature_e)",
    ),
    "IInput_GetAppModalSurface": ("vgui2::IInput", "vgui2::IInput::GetAppModalSurface()"),
    "ISchemeManager_ReloadSchemes": ("vgui2::ISchemeManager", "vgui2::ISchemeManager::ReloadSchemes()"),
}
SHEET_ARGUMENTS = {
    "AddPage": "vgui2::Panel*, char const*",
    "SetActivePage": "vgui2::Panel*",
    "SetTabWidth": "int",
    "GetActivePage": "",
    "ResetAllData": "",
    "ApplyChanges": "",
    "GetPage": "int",
    "DeletePage": "vgui2::Panel*",
    "GetActiveTab": "",
    "GetActiveTabTitle": "char*, int",
    "GetTabTitle": "int, char*, int",
    "GetActivePageNum": "",
    "GetNumPages": "",
    "DisablePage": "char const*",
    "EnablePage": "char const*",
    "ChangeActiveTab": "int",
}


async def function_payload(session, ea, image_base, name, *, table=None, index=None):
    candidate = None
    across = False
    for limit in (None, 128, 256, 512, 1024, 2048, 4096):
        candidate = await _inspect_function_via_mcp(
            session, ea, image_base, name, signature_byte_limit=limit, allow_relative_call_discriminator=True
        )
        if candidate:
            break
    if not candidate:
        candidate = await _inspect_function_via_mcp(session, ea, image_base, name, allow_across_function_boundary=True)
        across = bool(candidate)
    if not candidate:
        return None
    payload = {field: candidate[field] for field in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    if across or len(payload["func_sig"].split()) > int(payload["func_size"], 0):
        payload["func_sig_allow_across_function_boundary"] = True
    if table is not None:
        payload.update(vtable_name=table, vfunc_index=index, vfunc_offset=hex(index * 4))
    return payload


COLLECT = r"""
import ida_auto, ida_name

def literal_evidence(text):
    needle = text.encode() + bytes([0])
    addresses, owners = set(), set()
    for se in idautils.Segments():
        segment = ida_segment.getseg(se)
        if segment.perm & ida_segment.SEGPERM_EXEC:
            continue
        raw = ida_bytes.get_bytes(segment.start_ea, segment.end_ea-segment.start_ea) or b''
        position = raw.find(needle)
        while position >= 0:
            address = int(segment.start_ea + position)
            addresses.add(address)
            for ref in idautils.XrefsTo(address, 0):
                owner = ida_funcs.get_func(ref.frm)
                if owner:
                    owners.add(int(owner.start_ea))
            position = raw.find(needle, position + 1)
    return dict(addresses=sorted(addresses), owners=sorted(owners))

literals = {s:literal_evidence(s) for s in (
    'ControlFactory','ControlName','PanelPtr','CloseFrameButtonPressed','Hotkey','Panel','SetFocus',
    'SFX Slider','Suit Slider','MP3 Volume')}
roots = {}
for label, names in (('stage1',('ControlFactory','ControlName','PanelPtr')),
                     ('stage2',('CloseFrameButtonPressed','Hotkey'))):
    roots[label] = sorted(set.intersection(*(set(literals[n]['owners']) for n in names)))
roots['setfocus_all'] = literals['SetFocus']['owners']
selected = {ea for owners in roots.values() for ea in owners}
selected.update(values.get('constructors', {}).values())
roles = {}
for cls, table in values['tables'].items():
    for index, target in table['vtable_entries'].items():
        address = int(target, 0)
        selected.add(address)
        roles.setdefault(address, []).append((cls, int(index)))

def materialize_entry(ea):
    # Current RTTI entries and registered callbacks can be decoded code without
    # a function object in warm IDBs. Never replace/split an existing function.
    segment = ida_segment.getseg(ea)
    if (ida_funcs.get_func(ea) is None and is_code_address(ea)
            and segment.type != ida_segment.SEG_XTRN
            and (values['platform'] == 'windows' or ida_segment.get_segm_name(segment) == '.text')
            and ida_bytes.is_code(ida_bytes.get_full_flags(ea))):
        if not ida_funcs.add_func(ea):
            raise ValueError('could not materialize current entry ' + hex(ea))

for ea in selected:
    if roles.get(ea):
        materialize_entry(ea)
ida_auto.auto_wait()

preserved = set()
for ea in selected:
    for site in idautils.FuncItems(ea):
        if idc.print_insn_mnem(site) != 'call':
            continue
        target = local_call_target(site)
        if not target or target in preserved:
            continue
        items = list(idautils.FuncItems(target))
        mnemonics = [idc.print_insn_mnem(p) for p in items]
        # _chkesp: flags select an immediate normal ret; the error path saves
        # and restores registers around int 3. Inspect the current helper body.
        if not (len(items) >= 3 and mnemonics[:2] == ['jnz','retn']
                and mnemonics[-1] == 'retn' and 'int' in mnemonics):
            continue
        instructions = []
        for p in items:
            insn = idautils.DecodeInstruction(p)
            m = idc.print_insn_mnem(p)
            item = dict(ea=int(p),mnemonic=m)
            if m in ('push','pop') and int(insn.ops[0].type) == idaapi.o_reg:
                item['register'] = reg4(insn.ops[0])
            if m == 'int' and int(insn.ops[0].type) == idaapi.o_imm:
                item['trap'] = int(insn.ops[0].value)
            elif m == 'int' and ida_bytes.get_byte(p) == 0xCC:
                item['trap'] = 3
            if m in ('jnz','jne'):
                item['branch'] = int(insn.ops[0].addr)
            if m in ('ret','retn'):
                item['purge'] = int(insn.ops[0].value) if int(insn.ops[0].type) == idaapi.o_imm else 0
            instructions.append(item)
        if stack_check_preserves_registers(instructions):
            preserved.add(target)

functions = {}
def describe(ea):
    owner = ida_funcs.get_func(ea)
    out = dict(ea=ea, rva=ea-ida_nalt.get_imagebase(), roles=roles.get(ea,[]), strings=[])
    if owner is None or owner.start_ea != ea:
        return out
    flow = flow_at(ea, values['platform'], preserved_calls=preserved)
    out['flow'] = flow
    # Indexed addresses are needed only for container identities, keeping the
    # interface/parent traces conservative and independent of that extension.
    if any(cls == 'vgui2::PropertySheet' for cls,_ in roles.get(ea,[])) or not roles.get(ea):
        out['container_flow'] = flow_at(ea, values['platform'],
                                        preserved_calls=preserved, symbolic_indices=True)
    for p in idautils.FuncItems(ea):
        for ref in idautils.DataRefsFrom(p):
            text = idc.get_strlit_contents(ref,-1,ida_nalt.STRTYPE_C)
            if text:
                out['strings'].append((int(p),int(ref),text.decode('utf-8','replace')))
    return out

def safe_describe(ea):
    try:
        return describe(ea)
    except ValueError as exc:
        # Unrelated RTTI entries may exceed this conservative flow model.
        # They cannot participate in an accepted method identity.
        return dict(ea=ea, strings=[], flow_error=str(exc))

for ea in sorted(selected):
    functions[str(ea)] = safe_describe(ea)
extra = set()
for f in list(functions.values()):
    for call in method_calls(f):
        if call['direct'] and is_code_address(call['direct']):
            extra.add(call['direct'])
        for value in call['args'] + call['stack_args']:
            if isinstance(value,tuple) and value[0] == 'const' and is_code_address(value[1]):
                extra.add(value[1])
    for store in f.get('flow',{}).get('stores',[]):
        value = store['value']
        if isinstance(value,tuple) and value[0] == 'const' and is_code_address(value[1]):
            extra.add(value[1])
callbacks = set()
if values['platform'] == 'windows':
    labels = {('const',ea) for ea in literals['SetFocus']['addresses']}
    for owner in roots['setfocus_all']:
        callbacks.update(value[1] for value in message_callback_constants(functions[str(owner)],labels)
                         if is_code_address(value[1]))
    for ea in callbacks:
        materialize_entry(ea)
    ida_auto.auto_wait()
for ea in sorted((extra | callbacks)-selected):
    functions[str(ea)] = safe_describe(ea)
data = dict(platform=values['platform'], tables=values['tables'], literals=literals, roots=roots, functions=functions)
factory = recover_factory_parent(data)
focus = recover_frame_focus(data, factory['getvpanel'])

def member_reference(method, offset):
    candidates = [dict(ea=e['ea'], ref_kind=e['ref_kind']) for e in method['flow'].get('addresses',[])
                  if e['value'] == ('address',THIS,offset)]
    if not candidates:
        candidates = [dict(ea=e['ea'],ref_kind='displacement') for e in method['flow']['loads']
                      if e['value'] == ('load',THIS,offset)]
    if not candidates:
        raise ValueError('member has no current referencing instruction')
    reference = candidates[0]
    insn = idautils.DecodeInstruction(reference['ea'])
    actual = {signed32(op.addr) if reference['ref_kind'] == 'displacement' else int(op.value)
              for op in insn.ops if int(op.type) == (idaapi.o_displ if reference['ref_kind'] == 'displacement' else idaapi.o_imm)}
    if actual != {offset}:
        raise ValueError('member instruction does not encode the derived offset')
    return dict(owner=method['ea'],offset=offset,**reference)

result = dict(proportional=dict(ea=factory['proportional']['ea'],index=factory['proportional']['index']),
              nav=dict(ea=focus['nav']['ea'],index=focus['nav']['index']),
              current=dict(ea=focus['current']['ea'],index=focus['current']['index']),
              nav_member=member_reference(focus['nav'],focus['nav_offset']),
              current_member=member_reference(focus['current'],focus['current_offset']),
              interfaces=focus['interfaces'])
if values.get('gameui'):
    # Preserve source roles while unfolding actual leaf container helpers.
    sheet_data = dict(data,functions={key:dict(f,flow=f.get('container_flow',f.get('flow',{})))
                                    for key,f in functions.items()})
    sheet = recover_property_sheet(sheet_data, values['active_page'], values['perform_index'])
    result['sheet'] = {label:dict(ea=m['ea'],index=m['index']) for label,m in sheet.items()}
    result['active_member'] = member_reference(sheet['GetActivePage'],values['active_page'])
    video = sole([m for m in table_methods(data,'COptionsSubVideo') if m['ea'] == values['video_predecessor']
                  or any(c['direct'] == values['video_predecessor'] for c in method_calls(m))], 'Video OnApplyChanges')
    groups = {}
    for call in method_calls(video):
        if call['direct'] and call['args'] and _member(call['args'][0]):
            groups.setdefault(call['direct'],[]).append(call)
    apply = []
    for address,calls in groups.items():
        body = functions.get(str(address),{})
        getter_results = {('result',c['ea']) for c in method_calls(body)
                          if virtual_dispatch(c) and virtual_dispatch(c)[0] == THIS}
        if len(calls) == 2 and len({c['args'][0] for c in calls}) == 2 and any(
            s['value'] in getter_results and s['width'] == 4 and isinstance(s['address'],tuple)
            and s['address'][:2] == ('address',THIS) for s in body.get('flow',{}).get('stores',[])) and any(
            c['direct'] is None and (virtual_dispatch(c) is None
                or virtual_dispatch(c)[0][0] == 'const') and any(
                isinstance(a,tuple) and a[:2] == ('address',THIS) for a in c['args'] + c['stack_args'])
            for c in method_calls(body)):
            apply.append(address)
    slider_apply = sole(apply,'CCvarSlider ApplyChanges stores GetValue and writes named cvar')
    audio = sole([m for m in table_methods(data,'COptionsSubAudio') if m['index'] == video['index']], 'Audio override')
    members = {c['args'][0] for c in method_calls(audio) if c['direct'] == slider_apply
               and c['args'] and _member(c['args'][0])}
    if len(members) != 3:
        raise ValueError('Audio override does not apply its three slider members')
    ctor = functions[str(values['constructors']['audio'])]
    constructed = set()
    for label in ('SFX Slider','Suit Slider','MP3 Volume'):
        arguments = {('const',a) for a in literals[label]['addresses']}
        creates = [c for c in method_calls(ctor) if c['direct'] and c['args']
                   and any(contains_value(c['args'] + c['stack_args'],a) for a in arguments)
                   and any(s['address'] == THIS and s['value'] == ('const',int(values['tables']['CCvarSlider']['vtable_va'],0))
                           for s in functions.get(str(c['direct']),{}).get('flow',{}).get('stores',[]))]
        stores = {('load',THIS,s['address'][2]) for c in creates for s in ctor['flow']['stores']
                  if isinstance(s['address'],tuple) and s['address'][:2] == ('address',THIS)
                  and (contains_value(s['value'],c['args'][0])
                       or contains_value(s['value'],('result',c['ea'])))}
        constructed.add(sole(stores, label + ' constructed member'))
    if constructed != members:
        raise ValueError('Audio ApplyChanges receivers differ from constructed sliders')
    multiplayer = sole([m for m in table_methods(data,'COptionsSubMultiplayer')
                         if 'cl_logofile %s\n' in owned_labels(m)], 'Multiplayer owned ClientCmd format')
    if multiplayer['index'] != video['index']:
        raise ValueError('OnApplyChanges overrides disagree on their current virtual position')
    base_apply = sole([m for m in table_methods(data,'CBasePanel')
                       if 'resource/BackgroundLayout.txt' in owned_labels(m)], 'BasePanel scheme background')
    result['options'] = {label:dict(ea=m['ea'],index=m['index']) for label,m in (
        ('COptionsSubVideo',video),('COptionsSubAudio',audio),('COptionsSubMultiplayer',multiplayer),('CBasePanel',base_apply))}
"""


async def private_payloads(
    session, expected_outputs, new_binary_dir, platform, image_base, *, gameui=False, tables=None, existing=None
):
    """Return fully validated payloads; the caller emits after all work succeeds."""
    tables = {} if tables is None else dict(tables)
    for cls in COMMON_CLASSES + (GAMEUI_CLASSES if gameui else ()):
        if cls in tables:
            continue
        short = cls.split("::")[-1]
        alias = (
            (f"??_7{short}@vgui2@@6B@" if "::" in cls else f"??_7{short}@@6B@")
            if platform == "windows"
            else (f"_ZTVN5vgui2{len(short)}{short}E" if "::" in cls else f"_ZTV{len(short)}{short}")
        )
        table = await preprocess_vtable_via_mcp(session, cls, image_base, platform, symbol_aliases=[alias])
        if table is None:
            raise ValueError(f"{cls}: no current RTTI table")
        tables[cls] = table
    tables = {
        cls: dict(table, vtable_entries={str(index): address for index, address in table["vtable_entries"].items()})
        for cls, table in tables.items()
    }
    values = dict(tables=tables, platform=platform, gameui=gameui)
    if gameui:
        constructors = {}
        for key, symbol in (
            ("audio", "COptionsSubAudio_ctor"),
            ("multiplayer", "COptionsSubMultiplayer_ctor"),
            ("base", "CBasePanel_ctor"),
        ):
            record = _load_yaml_mapping(Path(new_binary_dir) / f"{symbol}.{platform}.yaml")
            if record is None:
                raise ValueError(f"missing declared constructor input: {symbol}")
            constructors[key] = int(record["func_va"], 0)
        video_stem = (
            "COptionsSubVideo_OnApplyChanges"
            if _output_for_symbol(expected_outputs, "COptionsSubVideo_OnApplyChanges") is None
            else "COptionsSubVideo_ApplyVidSettings"
        )
        video = _load_yaml_mapping(Path(new_binary_dir) / f"{video_stem}.{platform}.yaml")
        if video is None:
            raise ValueError("missing declared video predecessor")
        values.update(
            constructors=constructors,
            video_predecessor=int(video["func_va"], 0),
            active_page=existing["active_page"],
            perform_index=existing["methods"]["perform"]["index"],
        )
    found = await walk(session, Path(identity.__file__).read_text(encoding="utf-8") + COLLECT, values)
    if found.get("error"):
        raise ValueError(found["error"])
    payloads = {}
    prefix = "ClientVGUI" if _output_for_symbol(expected_outputs, "ClientVGUI_Panel_SetProportional") else "vgui2"
    functions = {
        f"{prefix}_Panel_SetProportional": (
            "vgui2::Panel::SetProportional(bool)",
            "vgui2::Panel",
            found["proportional"],
        )
    }
    if gameui:
        functions.update(
            {
                "GameUI_EditablePanel_GetFocusNavGroup": (
                    "vgui2::EditablePanel::GetFocusNavGroup()",
                    "vgui2::EditablePanel",
                    found["nav"],
                ),
                "GameUI_FocusNavGroup_GetCurrentFocus": (
                    "vgui2::FocusNavGroup::GetCurrentFocus()",
                    "vgui2::FocusNavGroup",
                    found["current"],
                ),
                **{
                    f"GameUI_PropertySheet_{label}": (
                        f"vgui2::PropertySheet::{label}({args})",
                        "vgui2::PropertySheet",
                        found["sheet"][label],
                    )
                    for label, args in SHEET_ARGUMENTS.items()
                },
                **{
                    f"{cls}_{'ApplySchemeSettings' if cls == 'CBasePanel' else 'OnApplyChanges'}": (
                        f"{cls}::{'ApplySchemeSettings(vgui2::IScheme*)' if cls == 'CBasePanel' else 'OnApplyChanges()'}",
                        cls,
                        target,
                    )
                    for cls, target in found["options"].items()
                },
            }
        )
    signatures = {}
    for symbol, (name, cls, target) in functions.items():
        if _output_for_symbol(expected_outputs, symbol) is None:
            continue
        payload = await function_payload(session, target["ea"], image_base, name, table=cls, index=target["index"])
        if payload is None:
            raise ValueError(f"{name}: no unique generated signature")
        payloads[symbol] = payload
        signatures[target["ea"]] = payload
    members = {
        f"{'GameUI' if gameui else prefix}_EditablePanel_m_NavGroup": (
            "vgui2::EditablePanel",
            "m_NavGroup",
            found["nav_member"],
            None,
        )
    }
    if gameui:
        members.update(
            {
                "GameUI_FocusNavGroup__currentFocus": (
                    "vgui2::FocusNavGroup",
                    "_currentFocus",
                    found["current_member"],
                    4,
                ),
                "GameUI_PropertySheet__activePage": ("vgui2::PropertySheet", "_activePage", found["active_member"], 4),
            }
        )
    for symbol, (cls, member, reference, size) in members.items():
        if _output_for_symbol(expected_outputs, symbol) is None:
            continue
        owner = signatures.get(reference["owner"]) or await function_payload(
            session, reference["owner"], image_base, f"{cls}::{member} offset owner"
        )
        if owner is None:
            raise ValueError(f"{symbol}: no unique offset owner signature")
        payload = dict(
            struct_name=cls,
            member_name=member,
            offset=hex(reference["offset"]),
            offset_sig=owner["func_sig"],
            offset_sig_disp=hex(reference["ea"] - reference["owner"]),
        )
        if size is not None:
            payload["size"] = hex(size)
        if reference["ref_kind"] != "displacement":
            payload["offset_sig_ref_kind"] = reference["ref_kind"]
        if owner.get("func_sig_allow_across_function_boundary"):
            payload["offset_sig_allow_across_function_boundary"] = True
        payloads[symbol] = payload
    for symbol, (cls, name) in INTERFACES.items():
        index = found["interfaces"][name]
        if _output_for_symbol(expected_outputs, symbol) is not None:
            payloads[symbol] = dict(func_name=name, vtable_name=cls, vfunc_index=index, vfunc_offset=hex(index * 4))
        elif not gameui and prefix != "ClientVGUI":
            shared = _load_yaml_mapping(Path(new_binary_dir).parent / "gameui" / f"{symbol}.{platform}.yaml")
            if shared is None or shared.get("func_name") != name or shared.get("vfunc_index") != index:
                raise ValueError(f"{symbol}: current host disagrees with the shared interface input")
    return payloads


def emit_private_payloads(expected_outputs, payloads):
    for symbol, payload in payloads.items():
        output = _output_for_symbol(expected_outputs, symbol)
        (write_struct_offset_yaml if "member_name" in payload else write_func_yaml)(output, payload)
