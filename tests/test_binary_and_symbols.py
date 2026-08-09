from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from binary_format import BinaryFormatError, inspect_binary, validate_binary
from binary_hashing import hash_file
from ida_analyze_util import (
    SymbolArtifactError,
    normalize_signature,
    normalize_symbol_artifact,
    resolve_x86_global_reference,
    signature_matches,
)
from ida_llm_decompile import LlmConfig, request_json
from ida_mcp_session import detect_database_requirement, normalize_binary_identity_path, select_database_session
from tests.test_support import write_elf32, write_pe32, write_pe64


class BinaryFormatTests(unittest.TestCase):
    def test_detects_pe32_and_elf32_i386(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe = inspect_binary(write_pe32(root / "a.dll"))
            elf = inspect_binary(write_elf32(root / "a.so"))
            self.assertEqual(("windows", 32, "I386"), (pe.platform, pe.bits, pe.machine))
            self.assertEqual(("linux", 32, "I386"), (elf.platform, elf.bits, elf.machine))

    def test_rejects_x64_and_platform_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(BinaryFormatError):
                inspect_binary(write_pe64(root / "x64.dll"))
            with self.assertRaises(BinaryFormatError):
                validate_binary(write_pe32(root / "x86.dll"), "linux")

    def test_hashes_include_required_inventory_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "data.bin"
            path.write_bytes(b"GoldSrc")
            result = hash_file(path)
            self.assertEqual(hashlib.sha256(b"GoldSrc").hexdigest(), result["sha256"])
            self.assertEqual(7, result["size"])
            self.assertEqual(8, len(result["crc32"]))
            self.assertEqual(16, len(result["crc64"]))


class SignatureAndSymbolTests(unittest.TestCase):
    def test_normalizes_and_matches_wildcard_signature(self):
        signature = normalize_signature("aa bb ? dd")
        self.assertEqual("AA BB ?? DD", signature)
        self.assertEqual([1], signature_matches(b"\x00\xaa\xbb\xcc\xdd", signature))

    def test_supports_all_symbol_categories(self):
        payloads = {
            "func": {"func_sig": "aa bb"},
            "gv": {"gv_sig": "aa bb"},
            "vfunc": {"vfunc_sig": "aa bb"},
            "vtable": {"vtable_sig": "aa bb"},
            "patch": {"patch_sig": "aa bb"},
            "struct": {"offset_sig": "aa bb"},
            "structmember": {"offset_sig": "aa bb", "struct": "A", "member": "b"},
        }
        for kind, extra in payloads.items():
            with self.subTest(kind=kind):
                result = normalize_symbol_artifact({"name": "symbol", "type": kind, **extra})
                self.assertEqual(kind, result["type"])
        self.assertEqual("0x4", normalize_symbol_artifact({"name": "v", "type": "vfunc"})["vfunc_slot_size"])

    def test_rejects_non_x86_vfunc_slot(self):
        with self.assertRaises(SymbolArtifactError):
            normalize_symbol_artifact({"name": "v", "type": "vfunc", "vfunc_slot_size": 8})


class X86GlobalResolverTests(unittest.TestCase):
    def test_operand_reference_and_two_dereferences(self):
        memory = {0x1000: 0x2000, 0x2000: (0x3000).to_bytes(4, "little")}
        self.assertEqual(
            0x3000,
            resolve_x86_global_reference(
                operands=[{"address": 0x1000}], gv_ref_deref_count=2, read_u32=memory.__getitem__
            ),
        )

    def test_data_xrefs_are_sorted_before_indexing(self):
        self.assertEqual(
            0x2000,
            resolve_x86_global_reference(data_xrefs=[0x3000, 0x1000, 0x2000], gv_ref_kind="data_xref", gv_ref_index=1),
        )

    def test_deref_count_is_bounded(self):
        with self.assertRaises(SymbolArtifactError):
            resolve_x86_global_reference(operands=[1], gv_ref_deref_count=3)


class OptionalIntegrationHelpersTests(unittest.TestCase):
    def test_mcp_database_contract_and_identity_selection(self):
        tool = SimpleNamespace(name="py_eval", inputSchema={"required": ["database"]})
        self.assertTrue(detect_database_requirement([tool]))
        sessions = [
            {
                "session_id": "one",
                "input_path": "D:/Game/hw.dll.i64",
                "is_active": True,
            }
        ]
        selected = select_database_session(sessions, expected_binary="d:\\game\\hw.dll")
        self.assertEqual("one", selected["session_id"])
        self.assertEqual(
            normalize_binary_identity_path("D:/Game/hw.dll"),
            normalize_binary_identity_path("/mnt/d/Game/hw.dll.i64"),
        )

    def test_openai_wrapper_extracts_structured_json_without_network(self):
        response = SimpleNamespace(output_text='```json\n{"address": "0x10"}\n```')
        client = SimpleNamespace(responses=SimpleNamespace(create=lambda **_kwargs: response))
        result = request_json(
            "Find the symbol",
            config=LlmConfig(model="test", api_key="not-a-real-key"),
            client=client,
        )
        self.assertEqual({"address": "0x10"}, result)


if __name__ == "__main__":
    unittest.main()
