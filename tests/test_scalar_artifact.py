import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

import yaml

from scalar_artifact import resolve_scalar, select_scalar_value, validate_scalar_artifact
from ida_scalar import recover_masked_index_stride


class ScalarArtifactTests(unittest.TestCase):
    def payload(self):
        return {"scalar_name": "stride", "scalar_value": 17080}

    def test_value_is_not_an_address(self):
        self.assertEqual(17080, resolve_scalar(self.payload()))
        for value in (0, 1, 0xFFFFFFFF):
            self.assertEqual(value, resolve_scalar({"scalar_name": "constant", "scalar_value": value}))

    def test_invalid_value_or_old_instruction_contract(self):
        for value in (True, False, -1, 2**32, 1.5, "17080", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_scalar_artifact({"scalar_name": "stride", "scalar_value": value})
        with self.assertRaises(ValueError):
            validate_scalar_artifact({**self.payload(), "scalar_sig_va": "0x401000"})

    def test_equal_values_fold_and_conflicts_fail(self):
        self.assertEqual(self.payload(), select_scalar_value("stride", [self.payload(), self.payload()], 17080))
        for entries in (
            [],
            [self.payload(), {"scalar_name": "stride", "scalar_value": 340}],
            [{"scalar_name": "stride", "scalar_value": 340}, self.payload()],
        ):
            with self.assertRaises(ValueError):
                select_scalar_value("stride", entries, 17080)

    def test_artifact_snapshot_store_json_round_trip(self):
        from ida_analyze_util import canonical_symbol_yaml_bytes
        from gamesymbol_snapshot_lib.operations import pack_snapshot
        from gamesymbol_snapshot_lib.metadata import write_metadata
        from gamesymbol_store import SnapshotSymbolStore
        from gamesymbols_json import encode_dataset
        from tests.test_gamesymbols_json import fixture

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tag, config = fixture(root)
            data = yaml.safe_load(config.read_text())
            data["modules"][0]["symbols"] = [{"name": "symbol", "category": "scalar"}]
            config.write_text(yaml.safe_dump(data))
            for platform in ("windows", "linux"):
                (root / "bin_artifacts" / tag / "engine" / f"symbol.{platform}.yaml").write_bytes(
                    canonical_symbol_yaml_bytes(self.payload())
                )
            snapshot = root / f"{tag}.yaml"
            pack_snapshot(tag, root / "bin", config, snapshot, artifactdir=root / "bin_artifacts")
            store = SnapshotSymbolStore.open(snapshot, expected_game_version=tag, config_path=config)
            self.assertEqual(self.payload(), store.require("engine", "symbol.windows.yaml"))
            copy = store.require("engine", "symbol.windows.yaml")
            copy["scalar_value"] = 1
            self.assertEqual(17080, store.require("engine", "symbol.windows.yaml")["scalar_value"])
            metadata = root / "metadata.yaml"
            write_metadata(snapshot_path=snapshot, config_path=config, game_version=tag, output_path=metadata)
            dataset = encode_dataset(snapshot.read_bytes(), metadata.read_bytes(), tag)
            self.assertEqual(5, dataset["schemaVersion"])
            self.assertEqual(8, dataset["source"]["snapshotSchemaVersion"])
            self.assertEqual({"scalar"}, {record["kind"] for record in dataset["records"]})
            self.assertEqual(self.payload(), dataset["records"][0]["payload"])

    def test_legacy_snapshot_cannot_carry_scalar(self):
        from gamesymbol_snapshot_lib.codec import build_snapshot_document, canonical_yaml_bytes, parse_snapshot_bytes
        from gamesymbol_snapshot_lib.errors import SnapshotSchemaError

        for version in range(1, 8):
            with self.subTest(version=version), self.assertRaises(SnapshotSchemaError):
                build_snapshot_document(
                    "game-1",
                    "sha256:" + "a" * 64,
                    {"engine/stride.windows.yaml": self.payload()},
                    schema_version=version,
                )
        document = build_snapshot_document(
            "game-1",
            "sha256:" + "a" * 64,
            {"engine/stride.windows.yaml": self.payload()},
            last_publish_time="2026-09-11T00:00:00Z",
            binaries={},
        )
        document["schema_version"] = 7
        with self.assertRaises(SnapshotSchemaError):
            parse_snapshot_bytes(canonical_yaml_bytes(document))


class FrameStrideTests(unittest.TestCase):
    def code(self, body, argument="push eax\npush 3"):
        return "and eax, ecx\n" + body + "\n" + argument + "\ncall dword ptr [ebx+8]"

    def test_imul_ignores_entity_multiplier(self):
        code = self.code("imul ecx, eax, 4318h\nimul eax, edx, 154h\nlea eax, base[eax+ecx]")
        self.assertEqual(17176, recover_masked_index_stride(code)[0])

    def test_optimized_lea_shift_sub_chain(self):
        code = self.code(
            "lea ecx, [eax+eax*8]\nshl ecx, 3\nsub ecx, eax\n"
            "lea ecx, [ecx+ecx*2]\nlea eax, [eax+ecx*2]\nlea ecx, [eax+eax*4]\n"
            "lea eax, base[edx+ecx*8]"
        )
        self.assertEqual(17080, recover_masked_index_stride(code)[0])

    def test_linux_stack_argument_and_copies(self):
        code = self.code(
            "imul eax, 42B8h\nmov edx, eax\nlea eax, base[edx+esi*4]",
            "mov [esp+4], eax\nmov [esp], 0",
        )
        self.assertEqual(17080, recover_masked_index_stride(code)[0])
        code = self.code(
            "imul eax, 8518h\nmov ecx, [esp+var_2c]\nmov ecx, [ecx]\ndec ecx\n"
            "imul ecx, 154h\nlea eax, [eax+ecx+2427bch]",
            "mov [esp+4], eax\nmov [esp], 0",
        )
        self.assertEqual(34072, recover_masked_index_stride(code)[0])

    def test_clobber_branch_unsupported_arithmetic_and_wrong_slot_fail(self):
        code = self.code(
            "imul ecx, eax, 4318h\nmov eax, ecx", "push eax\nmov eax, interface\npush 3\nmov eax, [eax+8]"
        ).replace("call dword ptr [ebx+8]", "call eax")
        self.assertEqual(17176, recover_masked_index_stride(code)[0])
        with self.assertRaises(ValueError):
            recover_masked_index_stride(code.replace("call eax", "mov eax, other\ncall eax"))
        for tail in ("mov al, 1", "xor eax, eax", "jmp target", "shr eax, 1", "call helper", "xchg ecx, eax"):
            with self.subTest(tail=tail), self.assertRaises(ValueError):
                recover_masked_index_stride(self.code("imul eax, 42B8h\n" + tail))
        with self.assertRaises(ValueError):
            recover_masked_index_stride(self.code("imul eax, 42B8h").replace("[ebx+8]", "[ebx+4]"))

    def test_all_paths_must_agree(self):
        first = self.code("imul eax, 42B8h")
        self.assertEqual(17080, recover_masked_index_stride(first + "\n" + first)[0])
        with self.assertRaises(ValueError):
            recover_masked_index_stride(first + "\n" + self.code("imul eax, 4318h"))
        with self.assertRaises(ValueError):
            recover_masked_index_stride(first + "\n" + self.code("imul eax, 42B8h\nshr eax, 1"))

    def test_only_second_stack_argument_counts(self):
        for argument in (
            "mov [esp+8], eax\nmov [esp], 0",
            "mov [esp+4], eax\nmov [esp], 0\npush 0",
            "mov [esp+4], eax\nmov [esp+4], edx\nmov [esp], 0",
        ):
            with self.subTest(argument=argument), self.assertRaises(ValueError):
                recover_masked_index_stride(self.code("imul eax, 42B8h", argument))
        code = self.code("imul eax, 42B8h", "0x401000: mov [esp+5ch+pname], eax\n0x401004: mov [esp+5ch+cap], 0")
        self.assertEqual(
            17080, recover_masked_index_stride(code, stack_displacements={str(0x401000): 4, str(0x401004): 0})[0]
        )
        with self.assertRaises(ValueError):
            recover_masked_index_stride(code, stack_displacements={str(0x401000): 8, str(0x401004): 0})


class ScalarLlmTests(unittest.IsolatedAsyncioTestCase):
    async def test_wrong_value_retries_without_instruction_requirement(self):
        from ida_llm_decompile import call_llm_decompile, _empty_llm_decompile_result

        responses = []
        for value in (340, 17080):
            response = _empty_llm_decompile_result()
            response["found_scalar"] = [{"scalar_name": "stride", "scalar_value": value}]
            responses.append(yaml.safe_dump(response))
        transport = Mock(side_effect=responses)
        result = await call_llm_decompile(
            model="test",
            symbol_name_list=["stride"],
            expected_result_sections={"stride": ["found_scalar"]},
            instruction_validations={"stride": {"expected_value": 17080}},
            target_disasm_codes=["0x401000: lea eax, [ecx+ecx*8]"],
            prompt_template="Find {symbol_name_list} in {target_blocks}.",
            target_blocks="target",
            max_retries=2,
            call_llm_text_func=transport,
        )
        self.assertEqual(2, transport.call_count)
        self.assertEqual(17080, int(result["found_scalar"][0]["scalar_value"]))
