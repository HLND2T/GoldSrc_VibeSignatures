from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from bin_artifact_contract import (
    BinArtifactContractError,
    build_game_artifact_inventory,
    compare_repository_artifact_root,
)
from gamesymbol_snapshot_lib.config import load_contract
from ida_analyze_util import canonical_symbol_yaml_bytes
from tests.test_support import write_config


class BinArtifactContractTests(unittest.TestCase):
    def fixture(self, root: Path):
        game_version = "game-1"
        config = write_config(
            root / "config.yaml",
            skill={"name": "find", "expected_output": ["symbol.{platform}.yaml"]},
        )
        artifact_game_root = root / "bin_artifacts" / game_version / "engine"
        artifact_game_root.mkdir(parents=True)
        for platform, address in (("windows", "0x10"), ("linux", "0x20")):
            (artifact_game_root / f"symbol.{platform}.yaml").write_bytes(
                canonical_symbol_yaml_bytes({"func_name": "symbol", "func_va": address})
            )
        return game_version, config, artifact_game_root

    def test_contract_exposes_distinct_binary_and_artifact_roots(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            game_version, config, _artifact_game_root = self.fixture(root)
            contract = load_contract(
                config,
                game_version,
                root / "bin",
                artifactdir=root / "bin_artifacts",
            )
            self.assertEqual(root / "bin" / game_version, contract.binary_game_root)
            self.assertEqual(root / "bin_artifacts" / game_version, contract.artifact_game_root)

    def test_inventory_is_sorted_and_content_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            game_version, config, artifact_game_root = self.fixture(root)
            first = build_game_artifact_inventory(game_version, config, root / "bin_artifacts")
            self.assertEqual(
                ["engine/symbol.linux.yaml", "engine/symbol.windows.yaml"],
                [entry.path for entry in first.entries],
            )
            self.assertEqual(
                frozenset({"engine:windows:find"}),
                first.owners_by_path["engine/symbol.windows.yaml"],
            )
            (artifact_game_root / "symbol.windows.yaml").write_bytes(
                canonical_symbol_yaml_bytes({"func_name": "symbol", "func_va": "0x11"})
            )
            second = build_game_artifact_inventory(game_version, config, root / "bin_artifacts")
            self.assertNotEqual(first.digest, second.digest)

    def test_rejects_missing_extra_noncanonical_and_nested_files(self):
        mutations = ("missing", "extra", "noncanonical", "nested")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                game_version, config, artifact_game_root = self.fixture(root)
                if mutation == "missing":
                    (artifact_game_root / "symbol.windows.yaml").unlink()
                elif mutation == "extra":
                    (artifact_game_root / "extra.yaml").write_text("ok: true\n", encoding="utf-8")
                elif mutation == "noncanonical":
                    (artifact_game_root / "symbol.windows.yaml").write_bytes(
                        b"func_va: '0x10'\r\nfunc_name: symbol\r\n"
                    )
                else:
                    nested = artifact_game_root / "nested"
                    nested.mkdir()
                    (nested / "extra.yaml").write_text("ok: true\n", encoding="utf-8")
                with self.assertRaises(BinArtifactContractError):
                    build_game_artifact_inventory(game_version, config, root / "bin_artifacts")

    def test_rejects_semantically_valid_yaml_with_noncanonical_field_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            game_version, config, artifact_game_root = self.fixture(root)
            (artifact_game_root / "symbol.windows.yaml").write_bytes(b"func_va: '0x10'\nfunc_name: symbol\n")

            with self.assertRaisesRegex(BinArtifactContractError, "canonical symbol YAML"):
                build_game_artifact_inventory(game_version, config, root / "bin_artifacts")

    def test_repository_root_comparison_requires_exact_external_rebuild(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            rebuilt = root / "rebuilt"
            repo.mkdir()
            game_version, config, artifact_game_root = self.fixture(repo)
            configs = repo / "configs"
            configs.mkdir()
            config.replace(configs / f"{game_version}.yaml")
            (configs / "config.yaml").write_text("gamevers:\n  - game-1\n", encoding="utf-8")
            import subprocess

            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "add", "configs", "bin_artifacts"], check=True)
            target = rebuilt / game_version / "engine"
            target.mkdir(parents=True)
            for source in artifact_game_root.iterdir():
                (target / source.name).write_bytes(source.read_bytes())
            self.assertEqual(2, len(compare_repository_artifact_root(repo, rebuilt).paths))
            (target / "symbol.windows.yaml").write_bytes(
                canonical_symbol_yaml_bytes({"func_name": "symbol", "func_va": "0x99"})
            )
            with self.assertRaisesRegex(
                BinArtifactContractError,
                r"missing=\[\]; extra=\[\]; changed=\['engine/symbol\.windows\.yaml'\]",
            ):
                compare_repository_artifact_root(repo, rebuilt)


if __name__ == "__main__":
    unittest.main()
