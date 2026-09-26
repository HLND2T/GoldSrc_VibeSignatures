"""Validated member writer for the paint-context value-flow locators."""

from ida_analyze_util import (
    _inspect_llm_instruction,
    _inspect_function_via_mcp,
    _output_for_symbol,
    write_struct_offset_yaml,
    preprocess_common_skill,
    _load_yaml_mapping,
    write_func_yaml,
)


async def write_member(session, outputs, name, struct, member, insn, offset, image_base):
    detail = await _inspect_llm_instruction(session, insn)
    if not detail or hex(offset) not in detail.get("displacements", []):
        return False
    function = await _inspect_function_via_mcp(session, int(detail["func_start"], 0), image_base, "__member_owner")
    if not function or not function.get("func_sig"):
        return False
    output = _output_for_symbol(outputs, name)
    if output is None:
        return False
    write_struct_offset_yaml(
        output,
        dict(
            struct_name=struct,
            member_name=member,
            offset=hex(offset),
            size="4",
            offset_sig=function["func_sig"],
            offset_sig_disp=insn - int(function["func_va"], 0),
        ),
    )
    return True


async def inherit_context(session, outputs, directory, platform, image_base, class_name, methods, debug=False):
    fields = [
        "func_name",
        "func_va",
        "func_rva",
        "func_size",
        "func_sig",
        "vtable_name",
        "vfunc_offset",
        "vfunc_index",
        "func_sig_allow_across_function_boundary:true",
    ]
    found = await preprocess_common_skill(
        session,
        outputs,
        old_yaml_map=None,
        new_binary_dir=directory,
        platform=platform,
        image_base=image_base,
        inherit_vfuncs=[(name, class_name + "_vtable", base, True) for name, base, display in methods],
        generate_yaml_desired_fields=[(name, fields) for name, base, display in methods],
        debug=debug,
    )
    if not found:
        return False
    for name, base, display in methods:
        path = _output_for_symbol(outputs, name)
        data = _load_yaml_mapping(path)
        data.update(func_name=display, vtable_name=class_name)
        write_func_yaml(path, data)
    return True
