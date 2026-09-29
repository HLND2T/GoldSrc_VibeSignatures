"""Exercise the CoF constructor locator against a mutable synthetic IDB."""

import ast
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


FINDER = Path(__file__).resolve().parents[1] / "ida_preprocessor_scripts/find-COptionsSubMultiplayer_ctor.py"
TREE = ast.parse(FINDER.read_text(encoding="utf-8"))
LOCATOR = next(
    node.args[1].value
    for node in ast.walk(TREE)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "run_walk"
)
ENTRY, STORE, SITE, RETURN, END = 0x1000, 0x1004, 0x1008, 0x100C, 0x1010
TABLE, LITERAL = 0x2000, 0x3000


class ConstructorLocatorTests(unittest.TestCase):
    def run_locator(self, state, *, valid_store=True):
        heads = [ENTRY - 4, ENTRY, STORE, SITE, RETURN, END]

        def add_func(entry, end):
            state["created"] += 1
            state["function"] = SimpleNamespace(start_ea=entry, end_ea=end)
            return True

        namespace = {
            "idaapi": SimpleNamespace(BADADDR=-1),
            "valid_vtable_slots": lambda *args, **kwargs: [ENTRY],
            "exact_string_eas": lambda text: [LITERAL],
            "idautils": SimpleNamespace(
                XrefsTo=lambda address, flags: [SimpleNamespace(frm=SITE if address == LITERAL else STORE)],
                DecodeInstruction=lambda address: SimpleNamespace(
                    get_canon_mnem=lambda: "mov",
                    ops=[SimpleNamespace(type=1), SimpleNamespace(type=3, value=TABLE if valid_store else 0)],
                ),
            ),
            "ida_bytes": SimpleNamespace(
                is_code=lambda flags: True,
                get_flags=lambda address: 1,
                prev_head=lambda address, limit: max(head for head in heads if head < address),
                next_head=lambda address, limit: min(head for head in heads if head > address),
            ),
            "ida_segment": SimpleNamespace(
                getseg=lambda address: SimpleNamespace(start_ea=ENTRY - 8, end_ea=END + 4, perm=1),
                SEGPERM_EXEC=1,
            ),
            "ida_funcs": SimpleNamespace(get_func=lambda address: state["function"], add_func=add_func),
            "idc": SimpleNamespace(print_insn_mnem=lambda address: "ret" if address in (ENTRY - 4, RETURN) else "push"),
            "ida_ua": SimpleNamespace(o_phrase=1, o_displ=2, o_imm=3),
            "imm_value": lambda operand: operand.value,
        }
        with patch.dict(sys.modules, ida_name=SimpleNamespace(get_name_ea=lambda *args: TABLE)):
            exec(LOCATOR, namespace)
        return namespace["result"]

    def test_reuses_existing_valid_constructor_without_creating_function(self):
        state = {"function": SimpleNamespace(start_ea=ENTRY, end_ea=END), "created": 0}
        self.assertEqual(ENTRY, self.run_locator(state)["target"])
        self.assertEqual(0, state["created"])

    def test_recovers_missing_constructor_and_can_run_again(self):
        state = {"function": None, "created": 0}
        first = self.run_locator(state)
        self.assertEqual(first, self.run_locator(state))
        self.assertEqual(1, state["created"])

    def test_rejects_existing_function_with_wrong_boundaries(self):
        state = {"function": SimpleNamespace(start_ea=ENTRY - 4, end_ea=END), "created": 0}
        with self.assertRaises(ValueError):
            self.run_locator(state)
        self.assertEqual(0, state["created"])

    def test_rejects_wrong_vptr_before_creating_or_reusing_function(self):
        for function in (None, SimpleNamespace(start_ea=ENTRY, end_ea=END)):
            with self.subTest(function=function):
                state = {"function": function, "created": 0}
                with self.assertRaisesRegex(ValueError, "not a constructor vptr store"):
                    self.run_locator(state, valid_store=False)
                self.assertEqual(0, state["created"])
