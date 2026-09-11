import tempfile
import unittest
from pathlib import Path

import yaml

from scalar_artifact import resolve_scalar, select_scalar_value, validate_scalar_artifact


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

    def test_explicit_scalar_candidate_round_trip(self):
        from ida_analyze_util import canonical_symbol_yaml_bytes
        from gamesymbol_snapshot_lib.candidate import build_candidate_snapshot, guard_candidate
        from gamesymbol_store import SnapshotSymbolStore, SnapshotConfigMismatchError
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
            session = root / "session.json"
            info = build_candidate_snapshot(
                game_version=tag,
                bin_root=root / "bin",
                artifact_root=root / "bin_artifacts",
                config_path=config,
                output_path=snapshot,
                session_path=session,
                schema_version=8,
            )
            self.assertEqual(8, info.snapshot_schema_version)
            self.assertEqual(info, guard_candidate(candidate_path=snapshot, session_path=session))
            with self.assertRaises(SnapshotConfigMismatchError):
                SnapshotSymbolStore.open(
                    snapshot,
                    expected_game_version=tag,
                    config_path=config,
                    analysis_output_contract_version=2,
                )
            store = SnapshotSymbolStore.open(
                snapshot,
                expected_game_version=tag,
                config_path=config,
                analysis_output_contract_version=3,
            )
            self.assertEqual(self.payload(), store.require("engine", "symbol.windows.yaml"))
            copy = store.require("engine", "symbol.windows.yaml")
            copy["scalar_value"] = 1
            self.assertEqual(17080, store.require("engine", "symbol.windows.yaml")["scalar_value"])

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
            schema_version=8,
            analysis_output_contract_version=3,
            last_publish_time="2026-09-11T00:00:00Z",
            binaries={},
        )
        document["schema_version"] = 7
        with self.assertRaises(SnapshotSchemaError):
            parse_snapshot_bytes(canonical_yaml_bytes(document))
        document["schema_version"] = 8
        document["analysis_output_contract_version"] = 2
        with self.assertRaises(SnapshotSchemaError):
            parse_snapshot_bytes(canonical_yaml_bytes(document))


class CandidateFormatTests(unittest.TestCase):
    def test_explicit_profiles_build_and_reopen_without_relaxing_default(self):
        from gamesymbol_candidate import main
        from gamesymbol_snapshot_lib.codec import SCHEMA_VERSION, parse_snapshot_bytes, snapshot_writer_output_contract
        from gamesymbol_snapshot_lib.candidate import guard_candidate
        from gamesymbol_store import SnapshotSymbolStore
        from tests.test_snapshot_candidate import fixture

        for selected in (None, 7, 8):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                tag, config, _, _ = fixture(root)
                snapshot, session = root / f"{tag}.yaml", root / "session.json"
                args = [
                    "build",
                    "-gamever",
                    tag,
                    "-bindir",
                    str(root / "bin"),
                    "-artifactdir",
                    str(root / "bin_artifacts"),
                    "-configyaml",
                    str(config),
                    "-output",
                    str(snapshot),
                    "-session",
                    str(session),
                ]
                if selected is not None:
                    args.extend(["-snapshot-schema-version", str(selected)])
                self.assertEqual(0, main(args))
                schema = SCHEMA_VERSION if selected is None else selected
                output_version = snapshot_writer_output_contract(schema)
                document = parse_snapshot_bytes(snapshot.read_bytes())
                self.assertEqual(schema, document["schema_version"])
                self.assertEqual(output_version, document["analysis_output_contract_version"])
                self.assertEqual(
                    schema, guard_candidate(candidate_path=snapshot, session_path=session).snapshot_schema_version
                )
                self.assertEqual(
                    2,
                    SnapshotSymbolStore.open(
                        snapshot,
                        expected_game_version=tag,
                        config_path=config,
                        analysis_output_contract_version=output_version,
                    ).file_count,
                )

    def test_unsupported_writer_profiles_fail_closed(self):
        from gamesymbol_snapshot_lib.codec import snapshot_writer_output_contract
        from gamesymbol_snapshot_lib.errors import SnapshotSchemaError

        for version in (True, False, 1, 6, 9, "8", 8.0, None):
            with self.subTest(version=version), self.assertRaises(SnapshotSchemaError):
                snapshot_writer_output_contract(version)
