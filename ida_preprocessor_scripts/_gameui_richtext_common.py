"""Shared RichText LLM callee validation and current-binary CR guard checks."""

from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    preprocess_common_skill,
    write_func_yaml,
)
import ida_preprocessor_scripts._richtext_identity as _richtext_identity
from ida_preprocessor_scripts._vgui_paint_common import walk

ANSI = "GameUI_RichText_InsertStringA"
WIDE = "GameUI_RichText_InsertStringW"
CHAR = "GameUI_RichText_InsertChar"
PATCH = "GameUI_RichText_CarriageReturn_branch"
MAX_OUTPUT_SIGNATURE_BYTES = 256
REAL_NAMES = {WIDE: "vgui2::RichText::InsertString(wchar_t const*)", CHAR: "vgui2::RichText::InsertChar(wchar_t)"}

CHECK = (
    Path(_richtext_identity.__file__).read_text(encoding="utf-8")
    + r"""
import ida_gdl

def body_blocks(ea):
    blocks = []
    for b in ida_gdl.FlowChart(ida_funcs.get_func(ea)):
        instructions = []
        for item in idautils.Heads(b.start_ea, b.end_ea):
            insn = idautils.DecodeInstruction(item)
            if insn is None:
                raise ValueError('undecodable RichText instruction')
            mnemonic = insn.get_canon_mnem()
            instructions.append(dict(ea=int(item), mnem=mnemonic,
                branch=int(insn.ops[0].addr) if mnemonic in ('jz','je','jnz','jne') else None))
        blocks.append(dict(start=int(b.start_ea), succs=[int(s.start_ea) for s in b.succs()], insns=instructions))
    return blocks

def verify_wide(ea, flow, blocks):
    width = 2 if values['platform'] == 'windows' else 4
    loads = [load for load in flow['loads'] if load['address'] == TEXT and load['width'] == width]
    if not loads:
        raise ValueError('wide text is not loaded through the string argument at its ABI width')
    # A cycle must actually advance a wide pointer; merely accepting a pointer
    # argument is not sufficient to distinguish GetText or InsertChar.
    graph = {b['start']:b['succs'] for b in blocks}
    cyclic = set()
    for b in blocks:
        if any(b['start'] in reachable_until(graph, s, None) for s in b['succs']):
            cyclic.add(b['start'])
    advances = []
    for b in blocks:
        if b['start'] not in cyclic:
            continue
        for item in b['insns']:
            insn = idautils.DecodeInstruction(item['ea'])
            operands = [decoded_operand(op) for op in insn.ops if op.type != idaapi.o_void]
            if pointer_increment(insn.get_canon_mnem(), operands, width):
                advances.append(item['ea'])
    if not advances:
        raise ValueError('missing wide-character loop increment')
    layouts = [call for call in flow['calls'] if virtual_call(call) and call['args'][1:3] == [('const',0),('const',0)]]
    repaints = [call for call in flow['calls'] if virtual_call(call)]
    flags = [store for store in flow['stores'] if member_address(store['address']) and store['value'] == ('const',1)
             and store['width'] == 1]
    if not layouts or not flags or len({call['target'] for call in repaints}) < 2:
        raise ValueError('wide insertion does not invalidate layout, set recalculation and repaint')
    return {'width':width, 'loads':[load['ea'] for load in loads], 'advances':advances}

target = int(values['target'])
function = ida_funcs.get_func(target)
if function is None or int(function.start_ea) != target:
    raise ValueError('RichText target is not a function start')
flow = flow_at(target, values['platform'], first_pass=True)
blocks = body_blocks(target)
if values.get('owner') is not None:
    owner = int(values['owner'])
    sites = [int(item) for item in idautils.FuncItems(owner) if local_call_target(item) == target
             and idc.print_insn_mnem(item) == 'call']
    if not sites:
        raise ValueError('target is not a direct callee of the verified predecessor')
if values['kind'] == 'wide':
    result = verify_wide(target, flow, blocks)
elif values['kind'] == 'char':
    result = character_guard(flow, blocks, False)
    owner_flow = flow_at(int(values['owner']), values['platform'], first_pass=True)
    calls = [call for call in owner_flow['calls'] if call['direct'] == target and receiver(call) == THIS
             and len(call['args']) >= 2 and unnarrow(call['args'][1]) == ('load',TEXT,0)]
    if not calls:
        raise ValueError('InsertChar does not receive the current wide character on the same RichText object')
elif values['kind'] == 'patch':
    if values['wide']:
        verify_wide(target, flow, blocks)
    result = character_guard(flow, blocks, values['wide'])
else:
    raise ValueError('unknown RichText check')
"""
)


async def recover_callee(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    image_base,
    owner_name,
    target_name,
    reference,
    llm_config,
    debug,
):
    owner = _load_yaml_mapping(Path(new_binary_dir) / f"{owner_name}.{platform}.yaml")
    output = _output_for_symbol(expected_outputs, target_name)
    if owner is None or output is None:
        return False
    spec = dict(
        symbol_name=target_name,
        prompt_path="prompt/call_llm_decompile.md",
        reference_yaml_paths=[reference],
        expected_result_sections=["found_call"],
        dependency_policy={f"{owner_name}.{{platform}}.yaml": "required"},
    )
    accepted = False
    try:
        found = await preprocess_common_skill(
            session=session,
            expected_outputs=expected_outputs,
            old_yaml_map=None,
            new_binary_dir=new_binary_dir,
            platform=platform,
            image_base=image_base,
            func_names=[target_name],
            llm_decompile_specs=[spec],
            llm_config=llm_config,
            # The helper's default 24 fixed bytes cover only a shared debug
            # prologue on 3266/3329. Enable its larger inspection budget, then
            # regenerate a strictly in-function signature before publication.
            generate_yaml_desired_fields=[
                (
                    target_name,
                    [
                        "func_name",
                        "func_va",
                        "func_rva",
                        "func_size",
                        "func_sig",
                        "func_sig_allow_across_function_boundary:true",
                    ],
                )
            ],
            debug=debug,
        )
        if not found:
            return False
        data = _load_yaml_mapping(output)
        owner_va, target_va = int(str(owner["func_va"]), 0), int(str(data["func_va"]), 0)
        checked = await walk(
            session,
            CHECK,
            dict(owner=owner_va, target=target_va, platform=platform, kind="wide" if target_name == WIDE else "char"),
        )
        if not checked or checked.get("error"):
            raise ValueError(str(checked))
        data = await _inspect_function_via_mcp(
            session,
            target_va,
            image_base,
            REAL_NAMES[target_name],
            signature_byte_limit=MAX_OUTPUT_SIGNATURE_BYTES,
        )
        if not data or not data.get("func_sig"):
            raise ValueError("no unique in-function output signature")
        write_func_yaml(output, data)
        accepted = True
        return True
    except Exception as exc:  # MCP/worker failures also invalidate the intermediate artifact.
        if debug:
            print(f"  RichText callee validation failed: {exc}")
        return False
    finally:
        if not accepted:
            Path(output).unlink(missing_ok=True)
