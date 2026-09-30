import importlib
import unittest
from unittest.mock import AsyncMock, patch

from ida_preprocessor_scripts._client_viewport_singleton import (
    bounded_body,
    constant_factory_return,
    linear_stack,
    unique_constructed_base,
)
from ida_preprocessor_scripts._x86_vcall_flow import entry_state_from_call, trace_function
from ida_preprocessor_scripts.x86_call_arguments import recover_call_arguments


def instruction(mnemonic, *operands):
    return {"mnem": mnemonic, "ops": list(operands)}


class BoundedBodyTests(unittest.TestCase):
    def body(self, *instructions, start=0x1000):
        return [{"ea": start + i, "next_ea": start + i + 1, **item} for i, item in enumerate(instructions)]

    def test_embedded_registration_uses_its_own_entry_and_stack(self):
        body = self.body(
            instruction("push", ("imm", 0x4000)),
            instruction("push", ("imm", 0x2000)),
            {**instruction("call", ("imm", 0x3000)), "purge": 8},
            instruction("ret"),
        )
        decoded = {item["ea"]: item for item in body}
        decoded[0xFFF] = {"ea": 0xFFF, "next_ea": 0x1000, **instruction("ret")}
        enclosing = linear_stack([decoded[0xFFF], *body])
        self.assertEqual([None, None], recover_call_arguments(enclosing, 3, 2))
        selected = bounded_body(0x1000, decoded.get, 16)
        selected = linear_stack(selected)
        self.assertEqual([0x2000, 0x4000], recover_call_arguments(selected, 2, 2))
        self.assertEqual([0, -4, -8, 0], [item["sp"] for item in selected])

    def test_stops_at_return_before_unrelated_body(self):
        body = self.body(instruction("mov", ("reg", "eax"), ("imm", 0x4004)), instruction("ret"), instruction("call"))
        result = bounded_body(0x1000, {item["ea"]: item for item in body}.get, 16)
        self.assertEqual(0x4004, constant_factory_return(result))
        self.assertEqual(2, len(result))

    def test_tail_jump_requires_the_proven_external_target(self):
        body = self.body(instruction("mov", ("reg", "ecx"), ("imm", 0x4000)), {**instruction("jmp"), "direct": 0x2000})
        decode = {item["ea"]: item for item in body}.get
        self.assertIsNone(bounded_body(0x1000, decode, 16))
        self.assertIsNone(bounded_body(0x1000, decode, 16, tail_target=0x3000))
        self.assertEqual(body, bounded_body(0x1000, decode, 16, tail_target=0x2000))

    def test_rejects_branches_traps_missing_return_and_instruction_limit(self):
        for mnemonic in ("jnz", "loop", "jmp", "int3", "ud2", "hlt", "retf"):
            body = self.body(instruction(mnemonic), instruction("ret"))
            with self.subTest(mnemonic=mnemonic):
                self.assertIsNone(bounded_body(0x1000, {item["ea"]: item for item in body}.get, 16))
        body = self.body(instruction("nop"), instruction("ret"))
        decode = {item["ea"]: item for item in body}.get
        self.assertIsNone(bounded_body(0x1000, decode, 1))
        self.assertIsNone(bounded_body(0x1002, decode, 16))

    def test_unknown_stack_effect_and_call_cleanup_are_rejected(self):
        for item in (
            instruction("call", ("imm", 0x3000)),
            instruction("mov", ("reg", "esp"), ("reg", "eax")),
            instruction("pop", ("reg", "esp")),
            {**instruction("push", ("reg", "eax", 2))},
            instruction("push", ("mem", "eax", 0, None, 1, 2)),
            instruction("sub", ("reg", "esp", 2), ("imm", 4)),
        ):
            with self.subTest(item=item):
                self.assertIsNone(linear_stack(self.body(item, instruction("ret"))))

    def test_tail_caller_transfers_receiver_to_embedded_constructor(self):
        caller = linear_stack(
            self.body(
                instruction("mov", ("reg", "ecx", 4), ("imm", 0x5000)),
                {**instruction("jmp", ("imm", 0x2000)), "direct": 0x2000, "tail": True},
            )
        )
        call = trace_function([{"start": 0x1000, "succs": [], "insns": caller}], 0x1000, "windows")["calls"][0]
        constructor = linear_stack(
            self.body(
                instruction("push", ("reg", "esi", 4)),
                instruction("mov", ("reg", "esi", 4), ("reg", "ecx", 4)),
                {**instruction("call", ("imm", 0x3000)), "purge": 0},
                instruction("mov", ("mem", "esi", 0, None, 1, 4), ("imm", 0x8000)),
                instruction("mov", ("mem", "esi", 12, None, 1, 4), ("imm", 0x8100)),
                instruction("pop", ("reg", "esi", 4)),
                instruction("ret"),
                start=0x2000,
            )
        )
        flow = trace_function(
            [{"start": 0x2000, "succs": [], "insns": constructor}],
            0x2000,
            "windows",
            entry_state=entry_state_from_call(call),
        )
        self.assertEqual(0x5000, unique_constructed_base(0x500C, 0x8000, flow["stores"], lambda _: 12))


class SignatureOwnerTests(unittest.IsolatedAsyncioTestCase):
    async def test_embedded_or_missing_owner_uses_verified_access_signature(self):
        finder = importlib.import_module("ida_preprocessor_scripts.find-client-viewport-singleton")
        for signature_owner in (None, "0x1000"):
            with self.subTest(signature_owner=signature_owner):
                located = {
                    "pointer_size": 4,
                    "accesses": [
                        {
                            "owner": "0x1020",
                            "signature_owner": signature_owner,
                            "body_end": "0x102a",
                            "base": "0x5000",
                            "site": "0x1020",
                            "length": 5,
                            "displacement": 1,
                        }
                    ],
                }
                signature = "B9 ?? ?? ?? ?? E9 ?? ?? ?? ?? 90"
                with (
                    patch.object(finder, "run_walk", AsyncMock(return_value=located)),
                    patch.object(finder, "inspect_unique_function", AsyncMock()) as inspect,
                    patch.object(finder, "run_signature", AsyncMock(return_value={"patch_sig": signature})) as generate,
                    patch.object(finder, "write_located_globals", AsyncMock(return_value=True)) as write,
                ):
                    result = await finder.preprocess_skill(
                        object(), "test", ["__g_CZEROViewPort_singleton.windows.yaml"], {}, None, "windows", 0
                    )
                self.assertTrue(result)
                inspect.assert_not_awaited()
                self.assertEqual(0x1020, generate.await_args.args[1])
                owner = write.await_args.args[4]
                self.assertEqual(0x1020, owner["owner_ea"])
                self.assertEqual(0x102A, owner["owner_end"])
                self.assertTrue(owner["allow_across"])
                self.assertEqual("0x1020", owner["function"]["func_va"])

    async def test_nonunique_signature_cannot_emit_an_artifact(self):
        finder = importlib.import_module("ida_preprocessor_scripts.find-client-viewport-singleton")
        located = {
            "pointer_size": 4,
            "accesses": [
                {
                    "owner": "0x1020",
                    "signature_owner": None,
                    "body_end": "0x102a",
                    "base": "0x5000",
                    "site": "0x1020",
                    "length": 5,
                    "displacement": 1,
                }
            ],
        }
        with (
            patch.object(finder, "run_walk", AsyncMock(return_value=located)),
            patch.object(finder, "run_signature", AsyncMock(return_value=None)),
            patch.object(finder, "write_located_globals", AsyncMock()) as write,
        ):
            result = await finder.preprocess_skill(
                object(), "test", ["__g_CZEROViewPort_singleton.windows.yaml"], {}, None, "windows", 0
            )
        self.assertFalse(result)
        write.assert_not_awaited()


class ConstantFactoryTests(unittest.TestCase):
    def test_direct_return_and_register_copy(self):
        for address in (0x4104, 0xB208):
            with self.subTest(address=address):
                body = [
                    instruction("mov", ("reg", "edx"), ("imm", address)),
                    instruction("mov", ("reg", "eax"), ("reg", "edx")),
                    instruction("ret"),
                ]
                self.assertEqual(address, constant_factory_return(body))

    def test_null_preserving_subobject_conversion(self):
        for address, expected in ((0x9100, 0x910C), (0, 0)):
            with self.subTest(address=address):
                body = [
                    instruction("mov", ("reg", "eax"), ("imm", address)),
                    instruction("neg", ("reg", "eax")),
                    instruction("sbb", ("reg", "eax"), ("reg", "eax")),
                    instruction("and", ("reg", "eax"), ("imm", 0x910C)),
                    instruction("retn"),
                ]
                self.assertEqual(expected, constant_factory_return(body))

    def test_unknown_value_or_carry_is_rejected(self):
        for prefix in (
            [instruction("mov", ("reg", "eax"), ("unknown", None)), instruction("neg", ("reg", "eax"))],
            [instruction("mov", ("reg", "eax"), ("imm", 0x8100))],
        ):
            with self.subTest(prefix=prefix):
                body = prefix + [instruction("sbb", ("reg", "eax"), ("reg", "eax")), instruction("ret")]
                self.assertIsNone(constant_factory_return(body))

    def test_unsupported_control_flow_cannot_reuse_a_constant(self):
        for mnemonic in ("call", "jmp", "jnz", "mul"):
            with self.subTest(mnemonic=mnemonic):
                body = [instruction("mov", ("reg", "eax"), ("imm", 0x8100)), instruction(mnemonic), instruction("ret")]
                self.assertIsNone(constant_factory_return(body))

    def test_a_return_is_required(self):
        self.assertIsNone(constant_factory_return([instruction("mov", ("reg", "eax"), ("imm", 0x8100))]))

    def test_partial_register_write_is_not_a_pointer_return(self):
        self.assertIsNone(
            constant_factory_return(
                [
                    instruction("mov", ("reg", "eax", 2), ("imm", 0x8100)),
                    instruction("ret"),
                ]
            )
        )


def store(address, table, width=4):
    return {"address": ("const", address), "value": ("const", table), "width": width}


class ConstructedObjectTests(unittest.TestCase):
    def test_offset_comes_from_current_table_metadata(self):
        for offset in (4, 12, 0x38):
            with self.subTest(offset=offset):
                self.assertEqual(
                    0x6100,
                    unique_constructed_base(
                        0x6100 + offset,
                        0x3000,
                        [store(0x6100, 0x3000), store(0x6100 + offset, 0x3100)],
                        lambda table: offset if table == 0x3100 else None,
                    ),
                )

    def test_another_class_or_disagreeing_offset_is_rejected(self):
        for offset in (None, 8):
            with self.subTest(offset=offset):
                self.assertIsNone(
                    unique_constructed_base(
                        0x6104,
                        0x3000,
                        [store(0x6100, 0x3000), store(0x6104, 0x3100)],
                        lambda _: offset,
                    )
                )

    def test_both_primary_and_secondary_installs_are_required(self):
        for stores in ([store(0x6100, 0x3000)], [store(0x6104, 0x3100)]):
            with self.subTest(stores=stores):
                self.assertIsNone(unique_constructed_base(0x6104, 0x3000, stores, lambda _: 4))

    def test_vptr_installs_must_write_complete_x86_pointers(self):
        for width in (1, 2, 8):
            for index in (0, 1):
                with self.subTest(width=width, index=index):
                    stores = [store(0x6100, 0x3000), store(0x6104, 0x3100)]
                    stores[index]["width"] = width
                    self.assertIsNone(unique_constructed_base(0x6104, 0x3000, stores, lambda _: 4))

    def test_conflicting_complete_objects_fail_closed(self):
        self.assertIsNone(
            unique_constructed_base(
                0x610C,
                0x3000,
                [store(0x6100, 0x3000), store(0x6108, 0x3000), store(0x610C, 0x3100), store(0x610C, 0x3200)],
                lambda table: {0x3100: 12, 0x3200: 4}.get(table),
            )
        )


if __name__ == "__main__":
    unittest.main()
