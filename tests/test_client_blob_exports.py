import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from ida_preprocessor_scripts._client_blob_exports import locate_blob_client_entries, recover_client_export_table


def reg(name):
    return {"kind": "reg", "reg": name, "size": 4}


def imm(value):
    return {"kind": "imm", "value": value, "size": 4}


def mem(base, disp=0, size=4):
    return {"kind": "mem", "base": base, "disp": disp, "size": size}


def ins(mnemonic, *operands):
    return {"mnemonic": mnemonic, "operands": list(operands)}


def initializer():
    return [
        ins("sub", reg("esp"), imm(172)),
        ins("mov", reg("eax"), mem("esp", 176)),
        ins("push", reg("esi")),
        ins("push", reg("edi")),
        ins("lea", reg("esi"), mem("esp", 8)),
        ins("mov", reg("edi"), reg("eax")),
        ins("mov", reg("ecx"), imm(43)),
        *(ins("mov", mem("esp", 8 + i * 4), imm(0x500000 + i * 16)) for i in reversed(range(43))),
        ins("rep movsd"),
        ins("pop", reg("edi")),
        ins("pop", reg("esi")),
        ins("add", reg("esp"), imm(172)),
        ins("retn"),
    ]


class ClientBlobExportsTests(unittest.TestCase):
    def test_recovers_complete_argument_table_by_stack_offset(self):
        self.assertEqual([0x500000 + i * 16 for i in range(43)], recover_client_export_table(initializer()))

    def test_incomplete_wrong_copy_and_clobbered_tables_fail_closed(self):
        for replacement in (
            ins("mov", reg("edi"), imm(0x600000)),
            ins("mov", reg("esi"), imm(0x600000)),
            ins("mov", reg("ecx"), imm(42)),
            ins("lea", reg("edi"), mem("eax", 4)),
            ins("mov", mem("esp", 8), reg("edx")),
            ins("mov", mem("esp", 8, size=2), imm(1)),
            ins("call", imm(0x700000)),
            ins("jmp", imm(0x700000)),
        ):
            with self.subTest(replacement=replacement):
                code = initializer()
                code.insert(-5, replacement)
                self.assertIsNone(recover_client_export_table(code))
        code = initializer()
        del code[7]
        self.assertIsNone(recover_client_export_table(code))

    def test_multiple_copies_and_overwritten_argument_fail_closed(self):
        code = initializer()
        code[-4:-4] = [
            ins("lea", reg("esi"), mem("esp", 8)),
            ins("mov", reg("edi"), reg("eax")),
            ins("mov", reg("ecx"), imm(43)),
            ins("rep movsd"),
        ]
        self.assertIsNone(recover_client_export_table(code))
        code = initializer()
        code.insert(1, ins("mov", mem("esp", 176), imm(0x600000)))
        self.assertIsNone(recover_client_export_table(code))

    def test_prior_nonstack_copy_does_not_supply_client_exports(self):
        code = initializer()
        code[4:4] = [
            ins("mov", reg("esi"), mem("eax")),
            ins("mov", reg("edi"), imm(0x600000)),
            ins("mov", reg("ecx"), imm(29)),
            ins("rep movsd"),
        ]
        self.assertEqual([0x500000 + i * 16 for i in range(43)], recover_client_export_table(code))

    def test_argument_offset_and_stack_balance_must_be_proven(self):
        for index, replacement in (
            (1, ins("mov", reg("eax"), mem("esp", 180))),
            (-2, ins("add", reg("esp"), imm(168))),
        ):
            code = initializer()
            code[index] = replacement
            self.assertIsNone(recover_client_export_table(code))


class ClientBlobIdentityTests(unittest.IsolatedAsyncioTestCase):
    async def test_binary_bytes_image_base_and_function_starts_must_match(self):
        cases = (
            (b"matching-pe", 0x400000, True, True),
            (b"different-pe", 0x400000, True, False),
            (b"matching-pe", 0x500000, True, False),
            (b"matching-pe", 0x400000, False, False),
        )
        for binary_bytes, image_base, complete_functions, accepted in cases:
            with self.subTest(binary_bytes=binary_bytes, image_base=image_base, complete_functions=complete_functions):
                with TemporaryDirectory() as directory:
                    binary = Path(directory) / "client.decrypt.dll"
                    binary.write_bytes(binary_bytes)
                    binary.with_name("client.dll").write_bytes(b"blob")
                    functions = [0x500000 + i * 16 for i in range(43)]
                    session = SimpleNamespace(
                        call_tool=AsyncMock(
                            return_value={
                                "instructions": initializer(),
                                "function_starts": functions if complete_functions else functions[:-1],
                            }
                        )
                    )
                    blob = SimpleNamespace(header=SimpleNamespace(image_base=0x400000, export_point=0x401000))
                    with (
                        patch("ida_preprocessor_scripts._client_blob_exports.parse_blob", return_value=blob),
                        patch("ida_preprocessor_scripts._client_blob_exports.build_pe", return_value=b"matching-pe"),
                    ):
                        result = await locate_blob_client_entries(session, str(binary), image_base)
                    if accepted:
                        self.assertEqual(
                            {
                                "CL_IsThirdPerson": [functions[15]],
                                "V_CalcRefdef": [functions[19]],
                                "HUD_GetStudioModelInterface": [functions[39]],
                            },
                            result,
                        )
                    else:
                        self.assertEqual({}, result)
                    if binary_bytes != b"matching-pe" or image_base != 0x400000:
                        session.call_tool.assert_not_called()
