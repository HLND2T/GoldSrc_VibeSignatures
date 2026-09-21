import unittest
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch

from ida_preprocessor_scripts.x86_call_arguments import recover_call_arguments


class RefdefArgumentTests(unittest.TestCase):
    """Run the actual locator walk with decoded x86 instructions."""

    def locate(self, body, *, block_start=0x1000):
        api = NS(o_void=0, o_reg=1, o_mem=2, o_phrase=3, o_displ=4, o_imm=5, o_near=7)
        constants = dict(reg=1, mem=2, stack=4, imm=5, pic=4)
        entries = []
        sp = 0
        for index, (mnem, operands) in enumerate(body + [("call", [("imm", 0x7000)])]):
            ops = []
            targets = set()
            for kind, value in operands:
                ops.append(
                    NS(
                        type=constants[kind],
                        value=value,
                        addr=value if isinstance(value, int) else 0,
                        reg="esp" if kind == "stack" else "ebx" if kind == "pic" else value,
                        dtype=4,
                    )
                )
                if kind in ("imm", "mem", "pic") and isinstance(value, int) and 0x3000 <= value <= 0x6000:
                    targets.add(value)
            ops += [NS(type=0, dtype=0)] * (3 - len(ops))
            entries.append(
                dict(
                    ea=0x1000 + index * 8,
                    mnem=mnem,
                    targets=targets,
                    disp=1,
                    len=5,
                    disasm=mnem,
                    insn=NS(ops=ops),
                    sp=sp,
                )
            )
            if mnem == "push":
                sp -= 4
        site = entries[-1]["ea"]
        callee = [
            dict(ea=0x2000, mnem="call", targets={0x5010}, insn=NS(ops=[NS(type=2)])),
            dict(ea=0x2008, mnem="call", targets={0x6000}, insn=NS(ops=[NS(type=2)])),
        ]

        def operand_text(ea, index):
            op = next(e for e in entries if e["ea"] == ea)["insn"].ops[index]
            return "[esp]" if getattr(op, "reg", None) == "esp" else ""

        path = (
            Path(__file__).resolve().parents[1]
            / "ida_preprocessor_scripts/find-r_refdef-ClientDLL_DrawNormalTriangles.py"
        )
        spec = importlib.util.spec_from_file_location("refdef_locator_test", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        ns = dict(
            values=dict(setdev="0x7000", cl_funcs="0x5000", span=0x120, window=12),
            callers=lambda _: {(0x1000, site)},
            scan=lambda ea: entries if ea == 0x1000 else callee,
            direct_calls=lambda _: {0x2000: [0x1100]},
            single_globals=lambda es: {next(iter(e["targets"])): [i] for i, e in enumerate(es) if e["targets"]},
            access=lambda e, gv: dict(gv_ea=hex(gv), insn_ea=hex(e["ea"])),
            idaapi=api,
            ida_funcs=NS(get_func=lambda _: NS(start_ea=0x1000)),
            ida_ua=NS(get_dtype_size=lambda dtype: dtype),
            idc=NS(print_operand=operand_text),
            idautils=NS(DataRefsFrom=lambda _: []),
            reg4=lambda op: op.reg,
            signed32=lambda value: value,
            got_anchor=lambda _: (0, "ebx"),
            is_writable_data=lambda ea: 0x3000 <= ea <= 0x6000,
            is_got=lambda _: False,
            recover_call_arguments=recover_call_arguments,
        )
        modules = {
            "ida_frame": NS(get_spd=lambda _, ea: next(e["sp"] for e in entries if e["ea"] == ea)),
            "ida_gdl": NS(FlowChart=lambda _: [NS(start_ea=block_start, end_ea=site + 8)]),
        }
        with patch.dict(sys.modules, modules):
            exec(module.WALK, ns)
        return ns["result"]

    def test_unrelated_load_after_push_is_not_the_argument(self):
        result = self.locate([("push", [("imm", 0x3000)]), ("mov", [("reg", "eax"), ("mem", 0x4000)])])
        self.assertEqual("0x3000", result["gv"]["gv_ea"])

    def test_reserved_stack_immediate_and_pic_register_copy(self):
        for body in (
            [("mov", [("stack", 0), ("imm", 0x3000)])],
            [
                ("lea", [("reg", "eax"), ("pic", 0x3000)]),
                ("mov", [("reg", "edx"), ("reg", "eax")]),
                ("mov", [("stack", 0), ("reg", "edx")]),
            ],
        ):
            with self.subTest(body=body):
                self.assertEqual("0x3000", self.locate(body)["gv"]["gv_ea"])

    def test_unknown_argument_sources_fail_closed(self):
        for body in (
            [("mov", [("reg", "eax"), ("mem", 0x3000)]), ("push", [("reg", "eax")])],
            [
                ("lea", [("reg", "eax"), ("pic", 0x3000)]),
                ("add", [("reg", "eax"), ("imm", 4)]),
                ("push", [("reg", "eax")]),
            ],
            [("push", [("imm", 0x3000)]), ("mov", [("stack", 0), ("reg", "eax")])],
            [("mov", [("stack", 4), ("imm", 0x3000)])],
            [("push", [("imm", 0x3000)]), ("call", [("imm", 0x7000)])],
        ):
            with self.subTest(body=body):
                self.assertIn("error", self.locate(body))

    def test_does_not_reuse_argument_from_another_basic_block(self):
        self.assertIn("error", self.locate([("push", [("imm", 0x3000)])], block_start=0x1008))


class CallArgumentsTests(unittest.TestCase):
    def test_right_to_left_pushes(self):
        instructions = [
            {"mnem": "push", "sp": 0, "ops": [("imm", 1)]},
            {"mnem": "push", "sp": -4, "ops": [("imm", 770)]},
            {"mnem": "call", "sp": -8, "ops": []},
        ]
        self.assertEqual([770, 1], recover_call_arguments(instructions, 2, 2))

    def test_register_to_reserved_stack_and_zero(self):
        instructions = [
            {"mnem": "mov", "sp": -16, "ops": [("reg", "eax"), ("imm", 24)]},
            {"mnem": "mov", "sp": -16, "ops": [("stack", -16), ("reg", "eax")]},
            {"mnem": "xor", "sp": -16, "ops": [("reg", "edx"), ("reg", "edx")]},
            {"mnem": "mov", "sp": -16, "ops": [("stack", -12), ("reg", "edx")]},
            {"mnem": "call", "sp": -16, "ops": []},
        ]
        self.assertEqual([24, 0], recover_call_arguments(instructions, 4, 2))

    def test_unknown_overwrite_and_call_clobber(self):
        for overwrite in ("add", "call"):
            with self.subTest(overwrite=overwrite):
                instructions = [
                    {"mnem": "mov", "sp": -4, "ops": [("reg", "eax"), ("imm", 1)]},
                    {"mnem": overwrite, "sp": -4, "ops": [("reg", "eax"), ("imm", 2)]},
                    {"mnem": "mov", "sp": -4, "ops": [("stack", -4), ("reg", "eax")]},
                    {"mnem": "call", "sp": -4, "ops": []},
                ]
                self.assertEqual([None], recover_call_arguments(instructions, 3, 1))

    def test_branch_prevents_cross_path_inference(self):
        instructions = [
            {"mnem": "push", "sp": 0, "ops": [("imm", 7)]},
            {"mnem": "jne", "sp": -4, "ops": []},
            {"mnem": "call", "sp": -4, "ops": []},
        ]
        self.assertEqual([None], recover_call_arguments(instructions, 2, 1))

    def test_callee_saved_register_survives_conditional_jump(self):
        instructions = [
            {"mnem": "mov", "sp": -16, "ops": [("reg", "ebp"), ("imm", 0x5000)], "ea": 0x10},
            {"mnem": "test", "sp": -16, "ops": [("reg", "eax"), ("reg", "eax")], "ea": 0x14},
            {"mnem": "jz", "sp": -16, "ops": [("imm", 0x40)], "ea": 0x16},
            {"mnem": "mov", "sp": -16, "ops": [("stack", -12), ("reg", "ebp")], "ea": 0x18},
            {"mnem": "mov", "sp": -16, "ops": [("stack", -16), ("imm", 0x800)], "ea": 0x1C},
            {"mnem": "call", "sp": -16, "ops": [], "ea": 0x20},
        ]
        self.assertEqual([0x800, 0x5000], recover_call_arguments(instructions, 5, 2))

    def test_jcc_that_skips_assignment_does_not_prove_register(self):
        instructions = [
            {"mnem": "jz", "sp": -16, "ops": [("imm", 0x18)], "ea": 0x10},
            {"mnem": "mov", "sp": -16, "ops": [("reg", "ebp"), ("imm", 0x5000)], "ea": 0x14},
            {"mnem": "mov", "sp": -16, "ops": [("stack", -12), ("reg", "ebp")], "ea": 0x18},
            {"mnem": "mov", "sp": -16, "ops": [("stack", -16), ("imm", 0x800)], "ea": 0x1C},
            {"mnem": "call", "sp": -16, "ops": [], "ea": 0x20},
        ]
        self.assertEqual([0x800, None], recover_call_arguments(instructions, 4, 2))

    def test_jcc_with_conflicting_reaching_values_is_unknown(self):
        instructions = [
            {"mnem": "mov", "sp": -16, "ops": [("reg", "ebp"), ("imm", 0x6000)], "ea": 0x10},
            {"mnem": "jz", "sp": -16, "ops": [("imm", 0x1C)], "ea": 0x14},
            {"mnem": "mov", "sp": -16, "ops": [("reg", "ebp"), ("imm", 0x5000)], "ea": 0x18},
            {"mnem": "mov", "sp": -16, "ops": [("stack", -12), ("reg", "ebp")], "ea": 0x1C},
            {"mnem": "mov", "sp": -16, "ops": [("stack", -16), ("imm", 0x800)], "ea": 0x20},
            {"mnem": "call", "sp": -16, "ops": [], "ea": 0x24},
        ]
        self.assertEqual([0x800, None], recover_call_arguments(instructions, 5, 2))

    def test_caller_saved_register_still_dies_at_conditional_jump(self):
        instructions = [
            {"mnem": "mov", "sp": -16, "ops": [("reg", "eax"), ("imm", 0x5000)], "ea": 0x10},
            {"mnem": "jz", "sp": -16, "ops": [("imm", 0x40)], "ea": 0x14},
            {"mnem": "mov", "sp": -16, "ops": [("stack", -16), ("reg", "eax")], "ea": 0x18},
            {"mnem": "call", "sp": -16, "ops": [], "ea": 0x1C},
        ]
        self.assertEqual([None], recover_call_arguments(instructions, 3, 1))

    def test_call_does_not_prove_reused_stack_contents(self):
        instructions = [
            {"mnem": "mov", "sp": -4, "ops": [("stack", -4), ("imm", 7)]},
            {"mnem": "call", "sp": -4, "ops": []},
            {"mnem": "call", "sp": -4, "ops": []},
        ]
        self.assertEqual([None], recover_call_arguments(instructions, 2, 1))
