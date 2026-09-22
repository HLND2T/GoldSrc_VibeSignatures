"""Behavioral fixtures for parameter-directed vector-copy recovery."""

import copy
import unittest
from types import SimpleNamespace as NS

from ida_preprocessor_scripts._studio_view_info import WALK, recover_vectors


def reg(name, width=4):
    return {"kind": "reg", "name": name, "width": width}


def mem(offset, base=None, disp32=False):
    return {"kind": "mem", "offset": offset, "base": base, "width": 4, "disp32": disp32}


def immediate(value):
    return {"kind": "imm", "value": value}


def fixture(mode="mov", frame=False, order=(0, 1, 2, 3)):
    # Deliberately nonmonotonic addresses: address sorting would swap roles.
    bases = (0x8000, 0x5000, 0x9000, 0x6000)
    code, slots = [], {}

    def emit(mnemonic, *operands):
        site = {"insn_ea": hex(0x1000 + len(code) * 8), "insn_len": "0x8", "insn_disp": "0x2"}
        code.append({"mnem": mnemonic, "ops": list(operands), "site": site})
        return site

    if mode in ("got", "gotoff"):
        emit("picbase", reg("ebx"), immediate(0x4000))
    if frame:
        emit("push", reg("ebp"))
        emit("mov", reg("ebp"), reg("esp"))
        emit("sub", reg("esp"), immediate(12))
    for argument in order:
        base = bases[argument]
        emit("mov", reg("ecx"), mem((8 if frame else 4) + argument * 4, "ebp" if frame else "esp"))
        if mode == "got":
            slot = 0x4100 + argument * 4
            slots[slot] = base
            origin = emit("mov", reg("eax"), mem(slot - 0x4000, "ebx", True))
        elif mode == "gotoff":
            origin = emit("lea", reg("eax"), mem(base - 0x4000, "ebx", True))
        for component in range(3):
            source = mem(component * 4, "eax") if mode in ("got", "gotoff") else mem(base + component * 4, disp32=True)
            destination = mem(component * 4, "ecx")
            if mode == "x87":
                emit("fld", source)
                emit("fstp", destination)
            else:
                mnemonic = "movss" if mode in ("sse", "got", "gotoff") else "mov"
                emit(mnemonic, reg("xmm0" if mnemonic == "movss" else "edx"), source)
                emit(mnemonic, destination, reg("xmm0" if mnemonic == "movss" else "edx"))
    if frame:
        emit("add", reg("esp"), immediate(12))
        emit("pop", reg("ebp"))
    emit("retn")
    return code, slots, bases


class VectorCopyTests(unittest.TestCase):
    def recover(self, code, slots=None):
        return recover_vectors(code, [(0x4000, 0xA000)], slots or {})

    def test_scalar_sse_x87_and_pic_copies_follow_arguments(self):
        for mode in ("mov", "sse", "x87", "got", "gotoff"):
            for frame in (False, True):
                with self.subTest(mode=mode, frame=frame):
                    code, slots, bases = fixture(mode, frame, order=(2, 0, 3, 1))
                    result = self.recover(code, slots)
                    self.assertEqual(list(bases), [int(item["gv_ea"], 0) for item in result])

    def test_interleaved_loads_retain_provenance(self):
        code, slots, bases = fixture()
        # Interleave two component loads before either store.
        code[3]["ops"][0] = reg("eax")
        code[4]["ops"][1] = reg("eax")
        code[2], code[3] = code[3], code[2]
        result = self.recover(code)
        self.assertEqual(hex(bases[0]), result[0]["gv_ea"])
        self.assertEqual(code[1]["site"], {k: result[0][k] for k in code[1]["site"]})

    def test_pic_provenance_names_address_load_not_register_dereference(self):
        for mode in ("got", "gotoff"):
            code, slots, _ = fixture(mode)
            result = self.recover(code, slots)
            for argument in range(4):
                self.assertEqual(code[2 + argument * 8]["site"]["insn_ea"], result[argument]["insn_ea"])

    def test_unknown_control_flow_and_clobbers_fail_closed(self):
        for mnemonic in ("call", "jz", "jmp", "xor", "mul"):
            code, _, _ = fixture()
            code.insert(2, {"mnem": mnemonic, "ops": [reg("edx")]})
            with self.subTest(mnemonic=mnemonic), self.assertRaises(ValueError):
                self.recover(code)

    def test_missing_duplicate_and_noncontiguous_components_fail(self):
        original, _, _ = fixture()
        cases = []
        missing = copy.deepcopy(original)
        del missing[2]
        cases.append(missing)
        duplicate = copy.deepcopy(original)
        duplicate.insert(3, copy.deepcopy(duplicate[2]))
        cases.append(duplicate)
        wrong_source = copy.deepcopy(original)
        wrong_source[3]["ops"][1]["offset"] += 16
        cases.append(wrong_source)
        for index, code in enumerate(cases):
            with self.subTest(case=index), self.assertRaises((ValueError, KeyError)):
                self.recover(code)

    def test_partial_load_and_nonwritable_source_fail(self):
        for change in ("width", "offset"):
            code, _, _ = fixture()
            code[1]["ops"][1][change] = 2 if change == "width" else 0xB000
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.recover(code)

    def test_got_pointee_and_output_alias_are_rejected(self):
        code, slots, _ = fixture("got")
        slots[0x4100] = 0xB000
        with self.assertRaises(ValueError):
            self.recover(code, slots)
        code, slots, _ = fixture("got")
        slots[0x4104] = slots[0x4100]
        with self.assertRaises(ValueError):
            self.recover(code, slots)

    def test_balanced_x87_and_stack_are_required(self):
        code, _, _ = fixture("x87")
        code.insert(0, {"mnem": "fstp", "ops": [mem(0, "ecx")]})
        with self.assertRaises(ValueError):
            self.recover(code)
        code, _, _ = fixture()
        code.insert(-1, {"mnem": "push", "ops": [reg("ebp")]})
        with self.assertRaises(ValueError):
            self.recover(code)


class OperandDecodingTests(unittest.TestCase):
    """Exercise the IDA adapter as well as the platform-independent walk."""

    def decode(self, operand_text=None, mode="sse"):
        code, _, _ = fixture(mode)
        instructions = {}
        texts = {}
        for index, row in enumerate(code):
            ea = 0x1000 + index * 8
            implicit_x87 = row["mnem"] in ("fld", "fstp")
            operands = [NS(type=11, shown=lambda: False)] if implicit_x87 else []
            for slot, operand in enumerate(row["ops"]):
                slot += int(implicit_x87)
                kind = operand["kind"]
                if kind == "reg":
                    # The bug-triggering IDA representation: full XMM width.
                    width = 16 if operand["name"].startswith("xmm") else 4
                    op = NS(type=1, reg=operand["name"], dtype=width, offb=0)
                else:
                    base = operand.get("base")
                    op = NS(type=4 if base else 2, addr=operand["offset"], dtype=4, offb=2 if operand["disp32"] else 0)
                    texts[ea, slot] = f"[{base}+{operand['offset']}]" if base else "global"
                    if operand_text and index == 2 and slot == 0:
                        texts[ea, slot] = operand_text
                op.shown = lambda: True
                operands.append(op)
            instructions[ea] = NS(ops=operands + [NS(type=0)], size=8)
        segment = NS(start_ea=0x4000, end_ea=0xA000)
        namespace = {
            "values": {"owner": 0x1000},
            "ida_funcs": NS(get_func=lambda _: NS(start_ea=0x1000)),
            "idaapi": NS(o_void=0, o_reg=1, o_mem=2, o_phrase=3, o_displ=4, o_imm=5, inf_is_64bit=lambda: False),
            "ida_segment": NS(getseg=lambda _: segment),
            "ida_ua": NS(get_dtype_size=lambda value: value),
            "idautils": NS(
                Segments=lambda: [0x4000],
                FuncItems=lambda _: list(instructions),
                DecodeInstruction=instructions.get,
                DataRefsFrom=lambda _: [],
            ),
            "idc": NS(
                print_insn_mnem=lambda ea: code[(ea - 0x1000) // 8]["mnem"],
                print_operand=lambda ea, index: texts.get((ea, index), ""),
            ),
            "is_writable_data": lambda ea: 0x4000 <= ea < 0xA000,
            "reg4": lambda op: op.reg,
            "signed32": lambda value: value,
        }
        exec(WALK, namespace)
        return namespace["result"]["vectors"]

    def test_movss_uses_scalar_lane_despite_full_xmm_dtype(self):
        self.assertEqual(["0x8000", "0x5000", "0x9000", "0x6000"], [v["gv_ea"] for v in self.decode()])

    def test_x87_implicit_first_operand_is_not_a_memory_operand(self):
        self.assertEqual(["0x8000", "0x5000", "0x9000", "0x6000"], [v["gv_ea"] for v in self.decode(mode="x87")])

    def test_indexed_or_segment_relative_destination_is_rejected(self):
        for operand in ("[ecx+eax]", "[ecx*2]", "fs:[ecx]"):
            with self.subTest(operand=operand), self.assertRaises(ValueError):
                self.decode(operand)


if __name__ == "__main__":
    unittest.main()
