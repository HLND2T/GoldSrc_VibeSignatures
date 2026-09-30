import unittest

from ida_preprocessor_scripts._client_viewport_singleton import constant_factory_return, unique_constructed_base


def instruction(mnemonic, *operands):
    return {"mnem": mnemonic, "ops": list(operands)}


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
