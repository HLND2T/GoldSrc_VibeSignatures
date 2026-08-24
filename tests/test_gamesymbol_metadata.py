from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from gamesymbol_snapshot_lib.metadata import (
    MetadataContractError,
    build_metadata_document,
    canonical_metadata_bytes,
    compare_metadata,
    parse_metadata_bytes,
    raw_sha256,
    verify_metadata,
    write_metadata,
)
from gamesymbol_snapshot_lib.errors import SnapshotError
from gamesymbol_snapshot_lib.operations import pack_snapshot
from gamesymbol_snapshot_lib.paths import iter_snapshot_paths, metadata_path_for_snapshot
from tests.test_support import write_config, write_elf32, write_pe32


def metadata_fixture(root: Path, *, alias=None, artifact=None):
    tag = "game-1"
    skill = {"name": "find", "expected_output": ["symbol.{platform}.yaml"]}
    symbol = {"name": "symbol", "category": "func"}
    if alias is not None:
        symbol["alias"] = alias
    if artifact is not None:
        symbol["artifact"] = artifact
    config = write_config(root / "config.yaml", skill=skill, symbols=[symbol])
    game_root = root / "bin" / tag / "engine"
    write_pe32(game_root / "hw.dll")
    write_elf32(game_root / "hw.so")
    (game_root / "symbol.windows.yaml").write_text("func_name: symbol\nfunc_va: '0x10'\n", encoding="utf-8")
    (game_root / "symbol.linux.yaml").write_text("func_name: symbol\nfunc_va: '0x20'\n", encoding="utf-8")
    snapshot = root / f"{tag}.yaml"
    pack_snapshot(tag, root / "bin", config, snapshot, last_publish_time="2026-01-02T03:04:05Z")
    return tag, config, snapshot


class MetadataCodecTests(unittest.TestCase):
    def test_projects_only_alias_fields_and_resolved_owner_identities(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tag, config, snapshot = metadata_fixture(root, alias=["symbol_alias", "symbol_alias_2"])
            document = build_metadata_document(
                snapshot_path=snapshot,
                config_path=config,
                expected_game_version=tag,
            )
            self.assertEqual(
                [
                    {
                        "name": "engine",
                        "symbols": [
                            {
                                "name": "symbol",
                                "artifacts": [
                                    {"platform": "windows", "artifact": "symbol"},
                                    {"platform": "linux", "artifact": "symbol"},
                                ],
                                "alias": ["symbol_alias", "symbol_alias_2"],
                            }
                        ],
                    }
                ],
                document["modules"],
            )
            self.assertEqual(raw_sha256(snapshot.read_bytes()), document["snapshot_sha256"])
            self.assertRegex(document["config_sha256"], r"^[0-9a-f]{64}$")
            raw = canonical_metadata_bytes(document)
            self.assertEqual(
                document, parse_metadata_bytes(raw, expected_game_version=tag, snapshot_bytes=snapshot.read_bytes())
            )

    def test_string_alias_is_normalized_and_empty_duplicate_or_invalid_aliases_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tag, config, snapshot = metadata_fixture(root, alias="symbol_alias")
            document = build_metadata_document(
                snapshot_path=snapshot,
                config_path=config,
                expected_game_version=tag,
            )
            self.assertEqual(["symbol_alias"], document["modules"][0]["symbols"][0]["alias"])

        for alias in ("", ["ok", "ok"], ["ok", 1], [" ok"]):
            with self.subTest(alias=alias), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                with self.assertRaises((MetadataContractError, SnapshotError, ValueError)):
                    tag, config, snapshot = metadata_fixture(root, alias=alias)
                    build_metadata_document(
                        snapshot_path=snapshot,
                        config_path=config,
                        expected_game_version=tag,
                    )

    def test_tampered_binding_owner_and_noncanonical_bytes_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tag, config, snapshot = metadata_fixture(root, alias=["symbol_alias"])
            metadata = root / f"{tag}.metadata.yaml"
            write_metadata(snapshot_path=snapshot, config_path=config, game_version=tag, output_path=metadata)
            document = yaml.safe_load(metadata.read_bytes())
            mutations = (
                {**document, "snapshot_sha256": "0" * 64},
                {
                    **document,
                    "modules": [
                        {
                            "name": "engine",
                            "symbols": [
                                {
                                    "name": "symbol",
                                    "artifacts": [{"platform": "windows", "artifact": "unknown"}],
                                    "alias": ["symbol_alias"],
                                }
                            ],
                        }
                    ],
                },
            )
            for mutation in mutations:
                with self.subTest(mutation=mutation):
                    metadata.write_bytes(canonical_metadata_bytes(mutation))
                    with self.assertRaises(MetadataContractError):
                        verify_metadata(
                            metadata_path=metadata,
                            snapshot_path=snapshot,
                            config_path=config,
                            game_version=tag,
                        )
            metadata.write_bytes(canonical_metadata_bytes(document) + b"\n")
            with self.assertRaises(MetadataContractError):
                verify_metadata(metadata_path=metadata, snapshot_path=snapshot, config_path=config, game_version=tag)

    def test_compare_reports_first_difference_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tag, config, snapshot = metadata_fixture(root, alias=["symbol_alias"])
            actual = root / f"{tag}.metadata.yaml"
            expected = root / "expected.metadata.yaml"
            write_metadata(snapshot_path=snapshot, config_path=config, game_version=tag, output_path=actual)
            expected.write_bytes(actual.read_bytes())
            compare_metadata(
                actual_path=actual,
                expected_path=expected,
                snapshot_path=snapshot,
                config_path=config,
                game_version=tag,
            )
            document = yaml.safe_load(expected.read_bytes())
            document["modules"][0]["symbols"][0]["alias"] = ["changed"]
            expected.write_bytes(canonical_metadata_bytes(document))
            with self.assertRaisesRegex(MetadataContractError, r"\$\.modules\[0\]\.symbols\[0\]\.alias\[0\]"):
                compare_metadata(
                    actual_path=actual,
                    expected_path=expected,
                    snapshot_path=snapshot,
                    config_path=config,
                    game_version=tag,
                )

    def test_snapshot_enumerator_excludes_companions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "hl-10210.yaml").write_text("snapshot", encoding="utf-8")
            (root / "hl-10210.metadata.yaml").write_text("metadata", encoding="utf-8")
            (root / "invalid.yaml").write_text("invalid", encoding="utf-8")
            self.assertEqual((root / "hl-10210.yaml",), iter_snapshot_paths(root))
            self.assertEqual(root / "hl-10210.metadata.yaml", metadata_path_for_snapshot(root / "hl-10210.yaml"))


if __name__ == "__main__":
    unittest.main()
