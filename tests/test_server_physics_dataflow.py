"""Synthetic regressions for x87 widths and branched pointer provenance."""

import struct
import sys
import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch

from ida_preprocessor_scripts._server_physics_common import FRAME_PY, LAYOUT_PY, MODEL_SIB_PY


VOID, REG, MEM, PHRASE, DISPL, IMM = range(6)


def operand(kind, reg=None, addr=0, value=0, dtype=4):
    return NS(type=kind, reg=reg, addr=addr, value=value, dtype=dtype)


def entry(ea, mnemonic, *operands, targets=(), written=(), disasm=None):
    return {
        "ea": ea,
        "mnem": mnemonic,
        "insn": NS(ops=list(operands) + [operand(VOID)]),
        "targets": set(targets),
        "written": set(written),
        "disasm": disasm or mnemonic,
    }


API = NS(o_void=VOID, o_reg=REG, o_mem=MEM, o_phrase=PHRASE, o_displ=DISPL, o_imm=IMM)


class PhysicsDataflowTests(unittest.TestCase):
    def test_indexed_got_member_resolves_array_instead_of_container(self):
        pointer = operand(DISPL, "ebx", addr=0x20)
        indexed = operand(DISPL, "edx", addr=0x140)
        indexed.offb = 3
        entries = [
            entry(100, "mov", operand(REG, "edx"), pointer),
            entry(101, "mov", operand(REG, "eax"), indexed, disasm="mov eax, [edx+eax*4+140h]"),
        ]
        for item in entries:
            item["insn"].size = 7
        namespace = {
            "idaapi": API,
            "ida_ua": NS(get_dtype_size=lambda dtype: dtype),
            "ida_idp": NS(get_reg_name=lambda reg, width: ["eax", "ecx", "edx", "ebx"][reg]),
            "ida_bytes": NS(
                get_bytes=lambda ea, size: bytes.fromhex("8b 84 82 40 01 00 00"), get_dword=lambda ea: 0x5000
            ),
            "got_anchor": lambda start: (0x1000, "ebx"),
            "is_got": lambda ea: ea == 0x1020,
            "is_writable_data": lambda ea: 0x5000 <= ea < 0x6000,
            "scan": lambda start: entries,
            "reg4": lambda op: op.reg,
            "signed32": lambda value: value,
            "changed_operand": lambda insn, index: index == 0,
        }
        exec(MODEL_SIB_PY, namespace)
        _, address, displacement, encoded, pic = namespace["indexed_model_access"](100, 0x5000)
        self.assertEqual((0x5140, 3, 0x140, True), (address, displacement, encoded, pic))
        namespace["ida_bytes"].get_dword = lambda ea: 0
        with self.assertRaisesRegex(ValueError, "not unique/resolved"):
            namespace["indexed_model_access"](100, 0x5000)

    def test_absolute_sib_table_is_not_pic(self):
        indexed = operand(MEM, addr=0x5140)
        indexed.offb = 3
        item = entry(100, "push", indexed, disasm="push table[ecx*4]")
        item["insn"].size = 7
        namespace = {
            "idaapi": API,
            "ida_ua": NS(get_dtype_size=lambda dtype: dtype),
            "ida_idp": NS(get_reg_name=lambda reg, width: "ebp"),
            "ida_bytes": NS(get_bytes=lambda ea, size: bytes.fromhex("ff 34 8d 40 51 00 00")),
            "got_anchor": lambda start: (None, None),
            "is_writable_data": lambda ea: ea == 0x5140,
            "scan": lambda start: [item],
            "reg4": lambda op: op.reg,
            "changed_operand": lambda insn, index: False,
        }
        exec(MODEL_SIB_PY, namespace)
        _, address, _, encoded, pic = namespace["indexed_model_access"](100, 0x5000)
        self.assertEqual((0x5140, 0x5140, False), (address, encoded, pic))

    def test_hidden_x87_operand_uses_memory_width_and_stack_exchange(self):
        constant, target = 0x4000, 0x5000
        hidden = operand(11, dtype=8)
        entries = [
            entry(0x100, "fld", hidden, operand(MEM, addr=constant), disasm="fld dword ptr [constant]"),
            entry(0x101, "fld", hidden, operand(REG, "st"), disasm="fld st"),
            entry(0x102, "fxch", hidden, operand(REG, "st"), disasm="fxch st(1)"),
            entry(0x103, "fucomip", hidden, operand(REG, "st"), disasm="fucomip st, st(1)"),
            entry(
                0x104,
                "fstp",
                hidden,
                operand(MEM, addr=target, dtype=8),
                targets=[target],
                written=[target],
                disasm="fstp qword ptr [frame]",
            ),
        ]
        namespace = {
            "idaapi": API,
            "ida_ua": NS(get_dtype_size=lambda dtype: dtype),
            "ida_bytes": NS(get_bytes=lambda addr, size: struct.pack("<f", 0.25)),
            "idautils": NS(DataRefsFrom=lambda ea: [constant] if ea == 0x100 else []),
            "is_readable_data": lambda ea: ea == constant,
            "is_writable_data": lambda ea: ea == target,
            "scan": lambda start: entries,
            "changed_operand": lambda insn, index: False,
        }
        with patch.dict(sys.modules, {"ida_lines": NS(tag_remove=lambda line: line)}):
            exec(FRAME_PY, namespace)
            found = namespace["frame_clamps"](0x100)
            self.assertEqual({target}, set(found))
            self.assertEqual(0.25, found[target][0][1])
            # An implicit 8-byte stack operand cannot prove a float store is double.
            entries[-1]["insn"].ops[1].dtype = 4
            self.assertEqual({}, namespace["frame_clamps"](0x100))

    def node_fixture(self, conflicting):
        instructions = {
            100: entry(100, "push", operand(REG, "ebp")),
            101: entry(101, "mov", operand(REG, "ebp"), operand(REG, "esp")),
            102: entry(102, "mov", operand(REG, "ebx"), operand(DISPL, "ebp", addr=8)),
            103: entry(103, "mov", operand(DISPL, "ebp", addr=-8), operand(REG, "ebx")),
            104: entry(104, "mov", operand(REG, "ebx"), operand(IMM, value=0)),
            105: entry(
                105,
                "mov",
                operand(DISPL, "ebp", addr=-8) if conflicting else operand(REG, "ebx"),
                operand(IMM, value=0),
            ),
            106: entry(106, "mov", operand(REG, "ebx"), operand(DISPL, "ebp", addr=-8)),
            107: entry(107, "mov", operand(REG, "eax"), operand(PHRASE, "ebx")),
            108: entry(108, "cmp", operand(REG, "eax"), operand(IMM, value=-1)),
        }
        predecessors = {0: [], 1: [0], 2: [0], 3: [1, 2]}
        blocks = [
            NS(id=i, start_ea=start, end_ea=end)
            for i, start, end in [(0, 100, 104), (1, 104, 105), (2, 105, 106), (3, 106, 109)]
        ]
        for block in blocks:
            block.preds = lambda index=block.id: [blocks[parent] for parent in predecessors[index]]
        namespace = {
            "idaapi": API,
            "ida_funcs": NS(get_func=lambda start: object()),
            "ida_ua": NS(get_dtype_size=lambda dtype: dtype),
            "idautils": NS(Heads=lambda start, end: range(start, end), DataRefsFrom=lambda ea: []),
            "scan": lambda start: list(instructions.values()),
            "reg4": lambda op: op.reg,
            "signed32": lambda value: value,
            "changed_operand": lambda insn, index: insn.ops[index].type == REG and index == 0,
            "is_got": lambda ea: False,
        }
        return namespace, NS(FlowChart=lambda function: blocks)

    def test_node_pointer_survives_spill_across_branch_merge(self):
        namespace, flowchart = self.node_fixture(False)
        with patch.dict(sys.modules, {"ida_gdl": flowchart}):
            exec(LAYOUT_PY, namespace)
            self.assertEqual({0}, namespace["node_fields"](100)["axis"])

    def test_conflicting_stack_origin_is_not_a_node_pointer(self):
        namespace, flowchart = self.node_fixture(True)
        with patch.dict(sys.modules, {"ida_gdl": flowchart}):
            exec(LAYOUT_PY, namespace)
            self.assertEqual(set(), namespace["node_fields"](100)["axis"])

    def test_node_initialized_in_stack_keeps_child_pointer_at_loop_merge(self):
        root = 0x5000
        instructions = {
            100: entry(100, "push", operand(REG, "ebp")),
            101: entry(101, "mov", operand(REG, "ebp"), operand(REG, "esp")),
            102: entry(102, "mov", operand(DISPL, "ebp", addr=-4), operand(IMM, value=root), targets=[root]),
            103: entry(103, "mov", operand(REG, "ecx"), operand(DISPL, "ebp", addr=-4)),
            104: entry(104, "mov", operand(REG, "edx"), operand(DISPL, "ecx", addr=8)),
            105: entry(105, "mov", operand(DISPL, "ebp", addr=-4), operand(REG, "edx")),
            106: entry(106, "mov", operand(REG, "ecx"), operand(DISPL, "ebp", addr=-4)),
            107: entry(107, "cmp", operand(PHRASE, "ecx"), operand(IMM, value=-1)),
        }
        blocks = [
            NS(id=0, start_ea=100, end_ea=103),
            NS(id=1, start_ea=103, end_ea=106),
            NS(id=2, start_ea=106, end_ea=108),
        ]
        blocks[0].preds = lambda: []
        blocks[1].preds = lambda: [blocks[0], blocks[1]]
        blocks[2].preds = lambda: [blocks[1]]
        namespace = {
            "idaapi": API,
            "ida_funcs": NS(get_func=lambda start: object()),
            "ida_ua": NS(get_dtype_size=lambda dtype: dtype),
            "idautils": NS(Heads=lambda start, end: range(start, end), DataRefsFrom=lambda ea: []),
            "scan": lambda start: list(instructions.values()),
            "reg4": lambda op: op.reg,
            "signed32": lambda value: value,
            "is_got": lambda ea: False,
            "changed_operand": lambda insn, index: insn.ops[index].type == REG and index == 0,
        }
        with patch.dict(sys.modules, {"ida_gdl": NS(FlowChart=lambda function: blocks)}):
            exec(LAYOUT_PY, namespace)
            fields = namespace["node_fields"](100, root)
            self.assertEqual({0}, fields["axis"])
            self.assertEqual({8}, fields["children"])


if __name__ == "__main__":
    unittest.main()
