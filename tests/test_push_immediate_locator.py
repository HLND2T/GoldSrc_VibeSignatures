"""Behavior checks for the decoded x86 push-immediate locator."""

import sys
import types
import unittest
from unittest.mock import patch

from ida_preprocessor_scripts._push_immediate_locator import find_push_immediate_functions


def instruction(mnemonic, value, *, kind=5, encoded_size=4):
    return types.SimpleNamespace(
        get_canon_mnem=lambda: mnemonic,
        ops=[types.SimpleNamespace(type=kind, value=value)],
        size=encoded_size + 1,
    )


class PushImmediateLocatorTests(unittest.TestCase):
    def locate(self, bodies, required=(768, 28), *, x86=True, bits32=True, data_items=()):
        items = {}
        instructions = {}
        for start, body in bodies.items():
            items[start] = [start + index * 8 for index in range(len(body))]
            instructions.update(zip(items[start], body))
        modules = {
            "ida_ida": types.SimpleNamespace(
                inf_is_32bit_exactly=lambda: bits32,
                inf_get_procname=lambda: "metapc" if x86 else "ARM",
            ),
            "ida_bytes": types.SimpleNamespace(get_flags=lambda ea: ea not in data_items, is_code=bool),
            "ida_ua": types.SimpleNamespace(o_imm=5),
            "idautils": types.SimpleNamespace(
                Functions=lambda: iter(bodies),
                FuncItems=lambda start: iter(items[start]),
                DecodeInstruction=lambda ea: instructions[ea],
            ),
        }
        with patch.dict(sys.modules, modules):
            return find_push_immediate_functions(required)

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


if __name__ == "__main__":
    unittest.main()
