"""Behavior checks for the decoded x86 push-immediate locator."""

import ast
import sys
import types
import unittest
from unittest.mock import patch

from ida_analyze_util import parse_mcp_result
from ida_preprocessor_scripts._push_immediate_locator import (
    find_immediate_functions,
    find_push_immediate_functions,
    find_string_immediate_functions,
    wrap_locator_source,
)


def instruction(mnemonic, value, *, kind=5, encoded_size=4):
    return types.SimpleNamespace(
        get_canon_mnem=lambda: mnemonic,
        ops=[types.SimpleNamespace(type=kind, value=value)],
        size=encoded_size + 1,
    )


class PushImmediateLocatorTests(unittest.TestCase):
    def test_worker_helpers_share_globals_when_outer_exec_uses_separate_scopes(self):
        source = (
            "import json\n"
            "def inner(): return 37\n"
            "def outer(): return inner()\n"
            "result = json.dumps({'value': outer()})\n"
        )
        code = ast.parse(wrap_locator_source(source))
        globals_scope, locals_scope = {}, {}
        exec(compile(ast.Module(body=code.body[:-1], type_ignores=[]), "<worker>", "exec"), globals_scope, locals_scope)
        returned = eval(compile(ast.Expression(code.body[-1].value), "<worker>", "eval"), globals_scope, locals_scope)
        response = types.SimpleNamespace(structured_content={"result": returned, "stdout": "", "stderr": ""})
        self.assertEqual({"value": 37}, parse_mcp_result(response))

    def locate(
        self,
        bodies,
        required=(768, 28),
        *,
        x86=True,
        bits32=True,
        data_items=(),
        locator=find_push_immediate_functions,
        strings=(),
        **locator_options,
    ):
        items = {}
        instructions = {}
        for start, body in bodies.items():
            items[start] = [start + index * 8 for index in range(len(body))]
            instructions.update(zip(items[start], body))

        class StringItem:
            def __init__(self, ea, value):
                self.ea, self.value = ea, value

            def __str__(self):
                return self.value

        def owner(ea):
            for start, addresses in items.items():
                if ea == start or ea in addresses:
                    return types.SimpleNamespace(start_ea=start)
            return None

        modules = {
            "ida_ida": types.SimpleNamespace(
                inf_is_32bit_exactly=lambda: bits32,
                inf_get_procname=lambda: "metapc" if x86 else "ARM",
            ),
            "ida_bytes": types.SimpleNamespace(get_flags=lambda ea: ea not in data_items, is_code=bool),
            "ida_ua": types.SimpleNamespace(o_imm=5),
            "ida_funcs": types.SimpleNamespace(get_func=owner),
            "idautils": types.SimpleNamespace(
                Functions=lambda: iter(bodies),
                FuncItems=lambda start: iter(items[start]),
                DecodeInstruction=lambda ea: instructions[ea],
                Strings=lambda: [StringItem(ea, value) for ea, value, _ in strings],
                XrefsTo=lambda ea: [
                    types.SimpleNamespace(frm=ref) for address, _, refs in strings if address == ea for ref in refs
                ],
            ),
        }
        with patch.dict(sys.modules, modules):
            return locator(required, **locator_options)

    def test_accepts_short_and_full_immediate_encodings(self):
        body = [instruction("push", 768), instruction("push", 28, encoded_size=1)]
        self.assertEqual([0x1000], self.locate({0x1000: body}))

    def test_rejects_same_values_in_other_instructions(self):
        bodies = {
            0x1000: [instruction("push", 768), instruction("add", 28)],
            0x2000: [instruction("cmp", 768), instruction("sub", 28)],
            0x3000: [instruction("or", 768), instruction("push", 28)],
        }
        self.assertEqual([], self.locate(bodies))

    def test_rejects_memory_operands_and_register_pushes(self):
        for kind in (1, 2, 3, 4):
            with self.subTest(kind=kind):
                body = [instruction("push", 768, kind=kind), instruction("push", 28)]
                self.assertEqual([], self.locate({0x1000: body}))

    def test_does_not_combine_constants_from_different_functions(self):
        self.assertEqual([], self.locate({0x1000: [instruction("push", 768)], 0x2000: [instruction("push", 28)]}))

    def test_returns_all_candidates_without_picking_first(self):
        body = [instruction("push", 768), instruction("push", 28)]
        self.assertEqual([0x2000, 0x1000], self.locate({0x2000: body, 0x1000: body}))

    def test_repeated_constants_do_not_duplicate_candidates(self):
        body = [instruction("push", 28), instruction("push", 768), instruction("push", 28)]
        self.assertEqual([0x1000], self.locate({0x1000: body}))

    def test_ignores_non_code_items(self):
        body = [instruction("push", 768), instruction("push", 28), None]
        self.assertEqual([0x1000], self.locate({0x1000: body}, data_items=(0x1010,)))

    def test_decode_failure_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "decode"):
            self.locate({0x1000: [None]})

    def test_rejects_non_x86_or_non_32bit_databases(self):
        for options in ({"x86": False}, {"bits32": False}):
            with self.subTest(options=options), self.assertRaisesRegex(ValueError, "x86-32"):
                self.locate({}, **options)

    def test_requires_a_nonempty_set_of_uint32_values(self):
        for required in ((), (-1,), (1 << 32,), (True,), ("28",)):
            with self.subTest(required=required), self.assertRaises(ValueError):
                self.locate({}, required)

    def test_accepts_mov_source_immediate_but_not_destination_displacement(self):
        mov = instruction("mov", 768)
        mov.ops.insert(0, types.SimpleNamespace(type=4, value=28))
        self.assertEqual([], self.locate({0x1000: [mov]}, locator=find_immediate_functions))
        body = [mov, instruction("mov", 28)]
        self.assertEqual([0x1000], self.locate({0x1000: body}, locator=find_immediate_functions))

    def test_only_intersects_functions_that_own_the_exact_string(self):
        body = [instruction("mov", 768), instruction("mov", 28)]
        self.assertEqual(
            [0x2000],
            self.locate(
                {0x1000: body, 0x2000: body},
                locator=find_string_immediate_functions,
                literal="format",
                strings=[(0x9000, "format", [0x2008]), (0x9100, "format-extra", [0x1000])],
            ),
        )

    def test_excludes_exact_function_entry_not_its_callers(self):
        body = [instruction("push", 768), instruction("push", 28)]
        self.assertEqual(
            [0x1000],
            self.locate(
                {0x1000: body + [instruction("call", 0x2000, kind=7)], 0x2000: body},
                locator=find_string_immediate_functions,
                literal="format",
                strings=[(0x9000, "format", [0x1000, 0x2000])],
                exclude_funcs=[0x2000],
            ),
        )

    def test_no_string_owners_does_not_fall_back_to_all_functions(self):
        body = [instruction("push", 768), instruction("push", 28)]
        self.assertEqual(
            [],
            self.locate(
                {0x1000: body},
                locator=find_string_immediate_functions,
                literal="format",
                strings=[(0x9000, "format", [])],
            ),
        )

    def test_missing_or_duplicate_literal_fails_closed(self):
        for strings in ([], [(0x9000, "format", []), (0x9100, "format", [])]):
            with self.subTest(strings=strings), self.assertRaisesRegex(ValueError, "string"):
                self.locate({}, locator=find_string_immediate_functions, literal="format", strings=strings)

    def test_exclusion_must_resolve_to_an_exact_function_entry(self):
        body = [instruction("push", 768), instruction("push", 28)]
        for excluded in (0x1008, 0x9999):
            with self.subTest(excluded=excluded), self.assertRaisesRegex(ValueError, "entry"):
                self.locate(
                    {0x1000: body},
                    locator=find_string_immediate_functions,
                    literal="format",
                    strings=[(0x9000, "format", [0x1000])],
                    exclude_funcs=[excluded],
                )

    def test_unowned_code_reference_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "owner"):
            self.locate(
                {}, locator=find_string_immediate_functions, literal="format", strings=[(0x9000, "format", [0x7777])]
            )


if __name__ == "__main__":
    unittest.main()
