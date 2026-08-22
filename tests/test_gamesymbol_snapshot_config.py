from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from gamesymbol_snapshot_lib.config import load_contract
from gamesymbol_snapshot_lib.errors import SnapshotConfigError


def write_config(
    path: Path,
    *,
    skills: list[dict],
    symbols: list[dict],
    description: str | None = None,
    source_path: str | None = "Game/hw.dll",
) -> Path:
    module = {
        "name": "engine",
        "description": description,
        "module_windows": "hw.dll",
        "skills": skills,
        "symbols": symbols,
    }
    if source_path is not None:
        module["path_windows"] = source_path
    path.write_text(yaml.safe_dump({"modules": [module]}, sort_keys=False), encoding="utf-8")
    return path


def skill(name: str, output: str, **overrides) -> dict:
    value = {"name": name, "expected_output": [output]}
    value.update(overrides)
    return value


class SnapshotContractConfigTests(unittest.TestCase):
    def test_runtime_contract_retains_plan_nodes_and_unique_owners(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = write_config(
                root / "config.yaml",
                skills=[skill("find", "Symbol.{platform}.yaml", aliases=["find-alias"])],
                symbols=[{"name": "Symbol", "category": "func", "alias": ["_Symbol"]}],
            )

            contract = load_contract(config, "game-1", root / "bin")

            self.assertEqual(("engine:windows:find",), tuple(contract.nodes))
            node = contract.nodes["engine:windows:find"]
            self.assertEqual(("engine", "find", "windows"), node.logical_key)
            self.assertEqual(frozenset({"engine/Symbol.windows.yaml"}), node.outputs)
            self.assertEqual(frozenset({"func"}), node.categories)
            self.assertEqual(frozenset({node.node_id}), contract.owners_by_path["engine/Symbol.windows.yaml"])
            self.assertEqual(contract.analysis_plan.nodes[0].id, node.node_id)

    def test_fingerprint_excludes_display_order_and_retry_but_includes_analysis_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = write_config(
                root / "first.yaml",
                skills=[
                    skill("one", "One.{platform}.yaml", max_retries=1),
                    skill("two", "Two.{platform}.yaml", description="first", aliases=["two-alias"]),
                ],
                symbols=[{"name": "One", "category": "func"}, {"name": "Two", "category": "gv"}],
                description="first module",
            )
            reordered = write_config(
                root / "reordered.yaml",
                skills=[
                    skill("two", "Two.{platform}.yaml", description="changed", aliases=["two-alias"]),
                    skill("one", "One.{platform}.yaml", max_retries=20),
                ],
                symbols=[{"name": "One", "category": "func"}, {"name": "Two", "category": "gv"}],
                description="changed module",
            )
            changed = write_config(
                root / "changed.yaml",
                skills=[
                    skill("one", "One.{platform}.yaml"),
                    skill("two", "Two.{platform}.yaml", aliases=["different"]),
                ],
                symbols=[{"name": "One", "category": "func"}, {"name": "Two", "category": "gv"}],
            )

            first_contract = load_contract(first, "game-1", root / "bin")
            reordered_contract = load_contract(reordered, "game-1", root / "bin")
            changed_contract = load_contract(changed, "game-1", root / "bin")

            first_fingerprints = {key: node.fingerprint for key, node in first_contract.nodes.items()}
            reordered_fingerprints = {key: node.fingerprint for key, node in reordered_contract.nodes.items()}
            self.assertEqual(first_fingerprints, reordered_fingerprints)
            self.assertNotEqual(
                first_contract.nodes["engine:windows:two"].fingerprint,
                changed_contract.nodes["engine:windows:two"].fingerprint,
            )

    def test_module_only_target_has_same_fingerprint_as_legacy_source_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            legacy = write_config(
                root / "legacy.yaml",
                skills=[skill("find", "Symbol.{platform}.yaml")],
                symbols=[{"name": "Symbol", "category": "func"}],
            )
            module_only = write_config(
                root / "module-only.yaml",
                skills=[skill("find", "Symbol.{platform}.yaml")],
                symbols=[{"name": "Symbol", "category": "func"}],
                source_path=None,
            )

            legacy_contract = load_contract(legacy, "game-1", root / "bin")
            module_contract = load_contract(module_only, "game-1", root / "bin")

            self.assertEqual(set(legacy_contract.binary_targets), set(module_contract.binary_targets))
            self.assertIsNone(module_contract.binary_targets[("engine", "windows")].source_path)
            self.assertEqual(
                legacy_contract.nodes["engine:windows:find"].fingerprint,
                module_contract.nodes["engine:windows:find"].fingerprint,
            )

    def test_zero_and_multiple_artifact_owners_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            zero = write_config(
                root / "zero.yaml",
                skills=[],
                symbols=[{"name": "Unowned", "category": "func"}],
            )
            with self.assertRaisesRegex(SnapshotConfigError, "no producer"):
                load_contract(zero, "game-1", root / "bin")

            multiple_document = {
                "modules": [
                    {
                        "name": "engine",
                        "path_windows": "Game/hw.dll",
                        "module_windows": "hw.dll",
                        "path_linux": "Game/hw.so",
                        "module_linux": "hw.so",
                        "skills": [skill("find", "Shared.yaml")],
                        "symbols": [{"name": "Shared", "category": "func", "artifact": "Shared.yaml"}],
                    }
                ]
            }
            multiple = root / "multiple.yaml"
            multiple.write_text(yaml.safe_dump(multiple_document, sort_keys=False), encoding="utf-8")
            with self.assertRaisesRegex(SnapshotConfigError, "Multiple artifact producers"):
                load_contract(multiple, "game-1", root / "bin")


if __name__ == "__main__":
    unittest.main()
