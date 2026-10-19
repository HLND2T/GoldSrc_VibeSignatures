"""Synthetic regressions for typed x86 client-context dataflow.

Conflicting local definitions and register live-ins must not become client
pointers. Equivalent branch definitions and typed-pointer byte arithmetic
must agree with the independently decoded storage/field operands.
"""

import sys
import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch

from ida_preprocessor_scripts._udp_download_common import DATAFLOW_PY


OPS = {
    name: index
    for index, name in enumerate(
        ("cast", "str", "obj", "ref", "idx", "asg", "var", "call", "eq", "ne", "num", "ptr", "memptr", "add")
    )
}


class Type:
    def __init__(self, width=4, pointed=None):
        self.width, self.pointed = width, pointed

    def get_size(self):
        return self.width

    def is_ptr(self):
        return self.pointed is not None

    def get_pointed_object(self):
        return Type(self.pointed)


def expr(op, **fields):
    return NS(op=OPS[op], type=Type(), **fields)


def arg(index):
    return expr("var", v=NS(idx=index))


def number(value):
    return expr("num", numval=lambda: value)


class ContextDataflowTests(unittest.TestCase):
    def setUp(self):
        class Visitor:
            def __init__(self, flags):
                pass

            def apply_to(self, body, parent):
                pass

        self.hexrays = NS(CV_FAST=0, ctree_visitor_t=Visitor, **{"cot_" + k: v for k, v in OPS.items()})
        self.ns = {"is_writable_data": lambda ea: 0x8000 <= ea < 0x9000}
        with patch.dict(sys.modules, {"ida_hexrays": self.hexrays}):
            exec(DATAFLOW_PY, self.ns)
        self.tree = self.ns["Tree"].__new__(self.ns["Tree"])
        self.tree.args, self.tree.defs = [0], {}

    def test_equivalent_branch_definitions_preserve_argument(self):
        self.tree.defs[1] = [arg(0), expr("cast", x=arg(0))]
        self.assertEqual(self.tree.value(arg(1)), ("arg", 0))

    def test_conflicting_definitions_do_not_select_client(self):
        self.tree.defs[1] = [arg(0), number(0)]
        self.assertEqual(self.tree.value(arg(1)), ("local", 1))

    def test_recursive_alias_is_unknown(self):
        self.tree.defs[1] = [arg(2)]
        self.tree.defs[2] = [arg(1)]
        self.assertEqual(self.tree.value(arg(1)), ("local", 1))

    def test_pointer_addition_uses_byte_offset(self):
        pointer = arg(0)
        pointer.type = Type(pointed=4)
        expression = expr("add", x=pointer, y=number(50951))
        self.assertEqual(self.ns["relative_to"](self.tree.value(expression), ("arg", 0)), 203804)

    def test_array_index_and_member_have_same_byte_address(self):
        array = expr("idx", x=arg(0), y=number(7))
        member = expr("memptr", x=arg(0), m=28)
        self.assertEqual(self.tree.value(array), self.tree.value(member))

    def test_unknown_pointer_width_fails_closed(self):
        pointer = arg(0)
        pointer.type = Type(pointed=-1)
        value = self.tree.value(expr("add", x=pointer, y=number(4)))
        self.assertIsNone(self.ns["relative_to"](value, ("arg", 0)))

    def test_stack_arguments_exclude_register_live_ins(self):
        def variable(offset):
            return NS(location=NS(is_stkoff=lambda: offset is not None, stkoff=lambda: offset))

        self.hexrays.decompile = lambda _: NS(
            argidx=[0, 1, 2], body=None, get_lvars=lambda: [variable(None), variable(40), variable(36)]
        )
        tree = self.ns["Tree"](0x1000)
        self.assertEqual(tree.args, [2, 1])
        self.assertEqual(tree.value(arg(2)), ("arg", 0))
        self.assertEqual(tree.value(arg(0)), ("local", 0))

    def test_storage_must_be_writable_aligned_dword(self):
        def assignment(address, width):
            lhs = expr("obj", obj_ea=address)
            lhs.type = Type(width)
            return expr("asg", x=lhs, y=arg(0), ea=0x1000)

        self.tree.assignments = [
            assignment(0x8000, 4),
            assignment(0x8001, 4),
            assignment(0x8004, 1),
            assignment(0x7000, 4),
        ]
        self.assertEqual(self.tree.stores(), [(0x8000, ("arg", 0), 0x1000)])

    def test_empty_and_ambiguous_candidates_are_rejected(self):
        for candidates in ([], [0x8000, 0x8004]):
            with self.subTest(candidates=candidates), self.assertRaises(ValueError):
                self.ns["unique"](candidates, "storage")


if __name__ == "__main__":
    unittest.main()
