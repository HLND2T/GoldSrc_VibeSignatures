"""Recover the public client ABI table from a verified Metahook blob initializer."""

from pathlib import Path

from decrypt_blob import BlobFormatError, build_pe, parse_blob

# HLSDK engine/APIProxy.h cldll_func_t; LoadBlob.cpp invokes export_point(pv).
CLIENT_EXPORT_COUNT = 43
CLIENT_EXPORT_SLOTS = {"CL_IsThirdPerson": 15, "V_CalcRefdef": 19, "HUD_GetStudioModelInterface": 39}
POINTER_SIZE = 4


def recover_client_export_table(instructions):
    """Prove one complete stack-built table copied into the first cdecl argument.

    Only straight-line MOV/LEA, stack bookkeeping and REP MOVSD are supported.
    Track decoded byte displacements, never IDA stack-variable names or store order.
    """
    registers = {"esp": ("stack", 0)}
    stack = {}
    tables = []

    def address(operand):
        base = registers.get(operand.get("base"))
        return None if base is None else (base[0], base[1] + operand.get("disp", 0))

    def value(operand):
        if operand.get("size") != POINTER_SIZE:
            return None
        if operand["kind"] == "reg":
            return registers.get(operand["reg"])
        if operand["kind"] == "imm":
            return ("constant", operand["value"])
        location = address(operand)
        if location and location[0] == "stack" and location[1] in stack:
            return stack[location[1]]
        if location == ("stack", POINTER_SIZE):
            return ("argument", 0)
        return None

    for index, instruction in enumerate(instructions):
        mnemonic = instruction["mnemonic"]
        operands = instruction["operands"]
        if mnemonic in {"mov", "lea"} and len(operands) == 2:
            destination, source = operands
            result = address(source) if mnemonic == "lea" else value(source)
            if destination["kind"] == "reg":
                if destination["size"] != POINTER_SIZE or destination["reg"] == "esp":
                    return None
                registers[destination["reg"]] = result
            elif mnemonic == "mov":
                location = address(destination)
                if location and location[0] == "stack":
                    if destination["size"] != POINTER_SIZE or location[1] % POINTER_SIZE:
                        return None
                    stack[location[1]] = result
                elif destination["kind"] != "absolute":
                    return None
            else:
                return None
        elif mnemonic in {"push", "pop"} and len(operands) == 1:
            if operands[0].get("size") != POINTER_SIZE:
                return None
            offset = registers["esp"][1]
            if mnemonic == "push":
                stack[offset - POINTER_SIZE] = value(operands[0])
                registers["esp"] = ("stack", offset - POINTER_SIZE)
            elif operands[0]["kind"] == "reg" and operands[0]["reg"] != "esp":
                registers[operands[0]["reg"]] = stack.pop(offset, None)
                registers["esp"] = ("stack", offset + POINTER_SIZE)
            else:
                return None
        elif mnemonic in {"add", "sub"} and len(operands) == 2:
            if operands[0] != {"kind": "reg", "reg": "esp", "size": POINTER_SIZE}:
                return None
            amount = value(operands[1])
            if amount is None or amount[0] != "constant":
                return None
            registers["esp"] = ("stack", registers["esp"][1] + amount[1] * (1 if mnemonic == "add" else -1))
        elif mnemonic == "rep movsd":
            source, destination, count = (registers.get(name) for name in ("esi", "edi", "ecx"))
            if destination == ("argument", 0):
                if not source or source[0] != "stack" or count != ("constant", CLIENT_EXPORT_COUNT):
                    return None
                entries = [stack.get(source[1] + slot * POINTER_SIZE) for slot in range(CLIENT_EXPORT_COUNT)]
                if any(entry is None or entry[0] != "constant" or entry[1] <= 0 for entry in entries):
                    return None
                tables.append([entry[1] for entry in entries])
            elif not destination or destination[0] != "constant":
                return None
            registers.update(esi=None, edi=None, ecx=("constant", 0))
        elif mnemonic in {"ret", "retn"} and not operands:
            return (
                tables[0]
                if len(tables) == 1 and registers["esp"] == ("stack", 0) and index == len(instructions) - 1
                else None
            )
        else:
            return None
    return None


_EXPORT_INITIALIZER = r"""
import ida_bytes, ida_funcs, ida_segment, ida_ua, idautils, idc, json, re
entry = BLOB_ENTRY
instructions = []
function_starts = set()
executable_addresses = set()
owner = ida_funcs.get_func(entry)
if owner and owner.start_ea == entry:
    for ea in idautils.FuncItems(entry):
        decoded = idautils.DecodeInstruction(ea)
        if decoded is None:
            break
        operands = []
        for i, op in enumerate(decoded.ops):
            if op.type == ida_ua.o_void:
                break
            operand = {"kind": "unsupported", "size": ida_ua.get_dtype_size(op.dtype)}
            text = idc.print_operand(ea, i).lower()
            if op.type == ida_ua.o_reg:
                operand.update(kind="reg", reg=text)
            elif op.type == ida_ua.o_imm:
                operand.update(kind="imm", value=int(op.value))
                func = ida_funcs.get_func(op.value)
                if func and func.start_ea == op.value:
                    function_starts.add(int(op.value))
                segment = ida_segment.getseg(op.value)
                if segment and segment.perm & ida_segment.SEGPERM_EXEC and ida_bytes.is_loaded(op.value):
                    executable_addresses.add(int(op.value))
            elif op.type == ida_ua.o_mem and not re.search(r"\be(?:ax|bx|cx|dx|si|di|bp|sp)\b", text):
                operand.update(kind="absolute")
            elif op.type in (ida_ua.o_displ, ida_ua.o_phrase):
                regs = re.findall(r"\be(?:ax|bx|cx|dx|si|di|bp|sp)\b", text)
                if len(regs) == 1 and "*" not in text:
                    displacement = int(op.addr) if op.type == ida_ua.o_displ else 0
                    if displacement & 0x80000000:
                        displacement -= 0x100000000
                    operand.update(kind="mem", base=regs[0], disp=displacement)
            operands.append(operand)
        mnemonic = idc.print_insn_mnem(ea).lower()
        if ida_bytes.get_bytes(ea, 2) == b"\xf3\xa5":
            mnemonic, operands = "rep movsd", []
        instructions.append({"mnemonic": mnemonic, "operands": operands})
result = json.dumps({"instructions": instructions, "function_starts": sorted(function_starts), "executable_addresses": sorted(executable_addresses)})
"""


async def locate_blob_client_entries(session, input_path, image_base):
    """Bind the original blob header to the exact decrypted PE before decoding."""
    from ida_analyze_util import parse_mcp_result

    binary = Path(input_path)
    if not binary.name.endswith(".decrypt.dll"):
        return {}
    original = binary.with_name(binary.name.removesuffix(".decrypt.dll") + ".dll")
    try:
        blob = parse_blob(original.read_bytes())
        if blob.header.image_base != image_base or build_pe(blob) != binary.read_bytes():
            return {}
    except (OSError, BlobFormatError):
        return {}
    code = _EXPORT_INITIALIZER.replace("BLOB_ENTRY", str(blob.header.export_point))
    located = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    if not isinstance(located, dict):
        return {}
    table = recover_client_export_table(located.get("instructions", []))
    if table is None or not set(table).issubset(located.get("executable_addresses", [])):
        return {}
    # Warm autoanalysis need not define unused ABI callbacks as functions. Only
    # the roots we consume require exact function starts and signature validation.
    if not {table[slot] for slot in CLIENT_EXPORT_SLOTS.values()}.issubset(located.get("function_starts", [])):
        return {}
    return {name: [table[slot]] for name, slot in CLIENT_EXPORT_SLOTS.items()}
