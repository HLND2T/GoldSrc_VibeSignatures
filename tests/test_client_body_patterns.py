import ast
import runpy
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from ida_preprocessor_scripts import _client_body_patterns as locator


class ClientMouseEpilogueTests(unittest.TestCase):
    def early_return(self, instructions):
        source = runpy.run_path(
            str(Path(__file__).resolve().parents[1] / "ida_preprocessor_scripts/find-client-mouse-guards.py")
        )["WALK"]
        function = next(
            node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef) and node.name == "early_return"
        )
        idc = SimpleNamespace(
            print_insn_mnem=lambda ea: instructions[ea][0] if ea < len(instructions) else "",
            print_operand=lambda ea, index: instructions[ea][index + 1],
            next_head=lambda ea, end: ea + 1,
        )
        namespace = {"idc": idc, "idaapi": SimpleNamespace(BADADDR=-1)}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "<mouse-epilogue>", "exec"), namespace)
        return namespace["early_return"](0)

    def test_accepts_full_frame_pointer_epilogue(self):
        self.assertTrue(
            self.early_return(
                [
                    ("pop", "edi"),
                    ("pop", "esi"),
                    ("pop", "ebx"),
                    ("mov", "esp", "ebp"),
                    ("pop", "ebp"),
                    ("retn",),
                ]
            )
        )

    def test_rejects_side_effect_before_return(self):
        self.assertFalse(self.early_return([("call", "callback"), ("retn",)]))


class ClientStudioConstructorTests(unittest.TestCase):
    def constructor_tables(self, *, overwrite_spill=False):
        source = runpy.run_path(
            str(Path(__file__).resolve().parents[1] / "ida_preprocessor_scripts/find-client-studio-interface.py")
        )["LOCATE"]
        function = next(
            node
            for node in ast.parse(source).body
            if isinstance(node, ast.FunctionDef) and node.name == "constructor_tables"
        )
        types = SimpleNamespace(o_reg=1, o_mem=2, o_phrase=3, o_displ=4, o_imm=5, o_near=6)

        def op(kind=0, addr=0, value=0):
            return SimpleNamespace(type=kind, addr=addr, value=value)

        obj, table = 0x5000, 0x6000
        instructions = {
            0: ("mov", "ecx", "object", op(1), op(5, value=obj)),
            1: ("call", "constructor", "", op(6, addr=10), op()),
            2: ("ret", "", "", op(), op()),
            10: ("mov", "[ebp+var_4]", "ecx", op(4, addr=-4), op(1)),
            11: ("call", "base_constructor", "", op(6, addr=20), op()),
            12: ("mov", "eax", "[ebp+var_4]", op(1), op(4, addr=-4)),
            13: ("mov", "dword ptr [eax]", "table", op(3), op(5, value=table)),
            14: ("ret", "", "", op(), op()),
        }
        if overwrite_spill:
            instructions[11] = ("mov", "[ebp+var_4]", "0", op(4, addr=-4), op(5))
        namespace = {
            "idautils": SimpleNamespace(DecodeInstruction=lambda ea: SimpleNamespace(ops=instructions[ea][3:], size=1)),
            "idc": SimpleNamespace(
                print_insn_mnem=lambda ea: instructions[ea][0],
                print_operand=lambda ea, index: instructions[ea][index + 1],
                next_head=lambda ea: ea + 1,
            ),
            "ida_ua": types,
            "ida_bytes": SimpleNamespace(is_code=lambda flags: True, get_full_flags=lambda ea: 1),
            "mapped": lambda ea: True,
            "data": lambda ea: ea in {obj, table},
            "expand": lambda values: values,
            "refs": lambda ea: {obj} if ea == 0 else set(),
            "resolve_elf_plt": lambda ea: ea,
            "linear_body": lambda ea: [2] if ea == 2 else range(10, 15),
            "returns_msvc_this": lambda ea: False,
        }
        exec(compile(ast.Module(body=[function], type_ignores=[]), "<studio-constructor>", "exec"), namespace)
        return namespace["constructor_tables"](0, obj)

    def test_recovers_this_spilled_across_base_constructor_call(self):
        self.assertEqual({0x6000}, self.constructor_tables())

    def test_rejects_overwritten_this_spill(self):
        self.assertEqual(set(), self.constructor_tables(overwrite_spill=True))


class ClientBodyPatternTests(unittest.IsolatedAsyncioTestCase):
    async def test_ambiguous_first_pattern_cannot_fall_through_to_unique_later_pattern(self):
        with (
            patch.object(locator, "_find_byte_matches", AsyncMock(side_effect=[[0x1000, 0x2000], [0x3000]])) as find,
            patch.object(locator, "_inspect_function_via_mcp", AsyncMock()) as inspect,
            patch.object(locator, "write_func_yaml") as write,
        ):
            result = await locator.preprocess_body_patterns(None, [], {"Example": ["AA", "BB"]}, 0)
        self.assertFalse(result)
        self.assertEqual(1, find.await_count)
        inspect.assert_not_awaited()
        write.assert_not_called()

    async def test_group_failure_does_not_write_earlier_valid_outputs(self):
        session = SimpleNamespace(call_tool=AsyncMock(return_value={"owner": 0x1000}))
        candidate = dict(func_name="First", func_sig="AA", func_va="0x1000", func_rva="0x1000", func_size="0x1")
        with (
            patch.object(locator, "_find_byte_matches", AsyncMock(side_effect=[[0x1000], []])),
            patch.object(locator, "parse_mcp_result", side_effect=lambda value: value),
            patch.object(locator, "_inspect_function_via_mcp", AsyncMock(return_value=candidate)),
            patch.object(locator, "_output_for_symbol", return_value="First.yaml"),
            patch.object(locator, "write_func_yaml") as write,
        ):
            result = await locator.preprocess_body_patterns(session, [], {"First": ["AA"], "Second": ["BB"]}, 0)
        self.assertFalse(result)
        write.assert_not_called()

    async def test_cross_boundary_output_requires_a_successful_second_inspection(self):
        session = SimpleNamespace(call_tool=AsyncMock(return_value={"owner": 0x1000}))
        candidate = dict(func_name="Example", func_sig="AA BB", func_va="0x1000", func_rva="0x1000", func_size="0x1")
        with (
            patch.object(locator, "_find_byte_matches", AsyncMock(return_value=[0x1000])),
            patch.object(locator, "parse_mcp_result", side_effect=lambda value: value),
            patch.object(locator, "_inspect_function_via_mcp", AsyncMock(side_effect=[None, candidate])) as inspect,
            patch.object(locator, "_output_for_symbol", return_value="Example.yaml"),
            patch.object(locator, "write_func_yaml") as write,
        ):
            result = await locator.preprocess_body_patterns(session, [], {"Example": ["AA"]}, 0)
        self.assertTrue(result)
        self.assertEqual(2, inspect.await_count)
        inspect.assert_awaited_with(session, 0x1000, 0, "Example", allow_across_function_boundary=True)
        write.assert_called_once_with("Example.yaml", {**candidate, "func_sig_allow_across_function_boundary": True})
