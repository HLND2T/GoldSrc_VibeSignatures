from __future__ import annotations

import io
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from bin_artifact_contract import (
    BinArtifactContractError,
    build_game_artifact_inventory,
    compare_repository_artifact_root,
)
from gamesymbol_snapshot_lib.config import load_contract
from ida_analyze_util import canonical_symbol_yaml_bytes
from tests.test_anchor_drift import VFUNC_PAYLOAD
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
            ) as raised:
                compare_repository_artifact_root(repo, rebuilt)
            self.assertIn("expected (tracked checkout): size=", str(raised.exception))
            self.assertIn("-func_va: '0x10'", str(raised.exception))
            self.assertIn("+func_va: '0x99'", str(raised.exception))

            (target / "symbol.linux.yaml").unlink()
            (target / "extra.yaml").write_bytes(b"extra: true\n")
            with self.assertRaises(BinArtifactContractError) as raised:
                compare_repository_artifact_root(repo, rebuilt)
            message = str(raised.exception)
            self.assertIn("Missing required symbol YAML", message)
            self.assertIn(
                "missing=['engine/symbol.linux.yaml']; extra=['engine/extra.yaml']; changed=['engine/symbol.windows.yaml']",
                message,
            )
            self.assertIn("+func_va: '0x99'", message)

            (target / "symbol.linux.yaml").write_bytes((artifact_game_root / "symbol.linux.yaml").read_bytes())
            (target / "extra.yaml").unlink()
            for raw, reason in (
                (b"func_name: symbol\r\nfunc_va: '0x10'\r\n", "canonical"),
                (b"\xff\n", "Invalid bin artifact contract"),
            ):
                with self.subTest(raw=raw):
                    (target / "symbol.windows.yaml").write_bytes(raw)
                    with self.assertRaises(BinArtifactContractError) as raised:
                        compare_repository_artifact_root(repo, rebuilt)
                    self.assertIn(reason, str(raised.exception))
                    self.assertIn("actual (isolated rebuild): size=", str(raised.exception))


class AnchorDriftRepositoryFixture:
    """Track a checkout of one anchored artifact plus an isolated rebuild of it."""

    PAYLOAD: dict
    SYMBOL_NAME: str
    CATEGORY: str
    FILENAME: str
    NUMERIC_ANCHOR_FIELDS: tuple[str, ...]

    def test_null_numeric_anchor_fails_closed(self):
        for field in self.NUMERIC_ANCHOR_FIELDS:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                rebuilt = self.fixture(root)
                self.rebuilt_artifact(rebuilt).write_bytes(canonical_symbol_yaml_bytes({**self.PAYLOAD, field: None}))
                with self.assertRaisesRegex(BinArtifactContractError, "inventory differs"):
                    self.compare(root, rebuilt)

    def symbol_declarations(self) -> list[dict]:
        return [{"name": self.SYMBOL_NAME, "category": self.CATEGORY}]

    def fixture(self, root: Path) -> Path:
        repo = root / "repo"
        repo.mkdir()
        config = write_config(
            repo / "config.yaml",
            skill={"name": "find", "expected_output": [f"{self.SYMBOL_NAME}.{{platform}}.yaml"]},
            symbols=self.symbol_declarations(),
            both_platforms=False,
        )
        configs = repo / "configs"
        configs.mkdir()
        config.replace(configs / "game-1.yaml")
        (configs / "config.yaml").write_text("gamevers:\n  - game-1\n", encoding="utf-8")
        artifact = repo / "bin_artifacts" / "game-1" / "engine" / self.FILENAME
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(canonical_symbol_yaml_bytes(self.PAYLOAD))
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "add", "configs", "bin_artifacts"], check=True)

        rebuilt = root / "rebuilt"
        target = rebuilt / "game-1" / "engine"
        target.mkdir(parents=True)
        (target / artifact.name).write_bytes(artifact.read_bytes())
        return rebuilt

    def rebuilt_artifact(self, rebuilt: Path) -> Path:
        return rebuilt / "game-1" / "engine" / self.FILENAME

    def compare(self, root: Path, rebuilt: Path):
        return compare_repository_artifact_root(root / "repo", rebuilt)


class GlobalAnchorDriftTests(AnchorDriftRepositoryFixture, unittest.TestCase):
    PAYLOAD = {
        "gv_name": "gWorldToScreen",
        "gv_va": "0x2c20100",
        "gv_rva": "0xf20100",
        "gv_sig": "55 8B EC 83 E4 F8 83 EC 10 53 55 56 57 68 01 17 00 00",
        "gv_sig_va": "0x1d46430",
        "gv_inst_offset": "0x8",
        "gv_inst_length": "0x5",
        "gv_inst_disp": "0x1",
    }
    SYMBOL_NAME = "gWorldToScreen"
    CATEGORY = "gv"
    FILENAME = "gWorldToScreen.windows.yaml"
    NUMERIC_ANCHOR_FIELDS = ("gv_inst_disp",)

    def test_anchor_only_drift_is_accepted_and_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rebuilt = self.fixture(root)
            self.rebuilt_artifact(rebuilt).write_bytes(
                canonical_symbol_yaml_bytes({**self.PAYLOAD, "gv_inst_offset": "0xc", "gv_sig_va": "0x1d46470"})
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                inventory = self.compare(root, rebuilt)

            self.assertEqual(1, len(inventory.paths))
            self.assertIn("Anchor drift accepted", stdout.getvalue())
            self.assertIn("gv_inst_offset", stdout.getvalue())

    def test_address_drift_still_fails_the_byte_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rebuilt = self.fixture(root)
            self.rebuilt_artifact(rebuilt).write_bytes(
                canonical_symbol_yaml_bytes(
                    {**self.PAYLOAD, "gv_inst_offset": "0xc", "gv_va": "0x2c20104", "gv_rva": "0xf20104"}
                )
            )

            with self.assertRaisesRegex(
                BinArtifactContractError,
                r"changed=\['engine/gWorldToScreen\.windows\.yaml'\]",
            ) as raised:
                self.compare(root, rebuilt)
            self.assertIn("-gv_va: '0x2c20100'", str(raised.exception))

    def test_non_anchor_drift_fails_closed(self):
        mutations = {
            "incoherent displacement": {"gv_inst_offset": "0xc", "gv_inst_disp": "0x7"},
            "renamed symbol": {"gv_name": "gOtherToScreen"},
            "missing anchor field": None,
            "unrelated field": {"gv_va": "0x2c20100", "gv_effective_va": "0x2c20100"},
        }
        for reason, overrides in mutations.items():
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                rebuilt = self.fixture(root)
                payload = dict(self.PAYLOAD)
                if overrides is None:
                    payload.pop("gv_inst_disp")
                    payload["gv_inst_offset"] = "0xc"
                else:
                    payload.update(overrides)
                self.rebuilt_artifact(rebuilt).write_bytes(canonical_symbol_yaml_bytes(payload))

                with self.assertRaises(BinArtifactContractError):
                    self.compare(root, rebuilt)


class StructMemberAnchorDriftTests(AnchorDriftRepositoryFixture, unittest.TestCase):
    PAYLOAD = {
        "struct_name": "CVideoMode_Common",
        "member_name": "m_ImageID",
        "offset": "0x19c",
        "offset_sig": "55 8B EC 83 EC 48 89 4D ?? 8B 4D ?? 81 C1 9C 01 00 00 E8 ?? ?? ?? ?? 85 C0 75 ??",
        "offset_sig_disp": "0xc",
        "offset_sig_ref_kind": "immediate",
        "offset_sig_addend": "0x0",
    }
    SYMBOL_NAME = "CVideoMode_Common_m_ImageID"
    CATEGORY = "structmember"
    FILENAME = "CVideoMode_Common_m_ImageID.windows.yaml"
    NUMERIC_ANCHOR_FIELDS = ("offset_sig_disp", "offset_sig_addend")

    def symbol_declarations(self) -> list[dict]:
        return [
            {"name": "CVideoMode_Common", "category": "struct"},
            {
                "name": self.SYMBOL_NAME,
                "category": self.CATEGORY,
                "struct": "CVideoMode_Common",
                "member": "m_ImageID",
            },
        ]

    def test_anchor_only_drift_is_accepted_and_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rebuilt = self.fixture(root)
            self.rebuilt_artifact(rebuilt).write_bytes(
                canonical_symbol_yaml_bytes({**self.PAYLOAD, "offset_sig_disp": "0x10"})
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                inventory = self.compare(root, rebuilt)

            self.assertEqual(1, len(inventory.paths))
            self.assertIn("Anchor drift accepted", stdout.getvalue())
            self.assertIn("offset_sig_disp", stdout.getvalue())

    def test_member_offset_drift_still_fails_the_byte_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rebuilt = self.fixture(root)
            self.rebuilt_artifact(rebuilt).write_bytes(
                canonical_symbol_yaml_bytes({**self.PAYLOAD, "offset_sig_disp": "0x10", "offset": "0x1a0"})
            )

            with self.assertRaisesRegex(
                BinArtifactContractError,
                r"changed=\['engine/CVideoMode_Common_m_ImageID\.windows\.yaml'\]",
            ) as raised:
                self.compare(root, rebuilt)
            self.assertIn("-offset: '0x19c'", str(raised.exception))


class VfuncAnchorDriftTests(AnchorDriftRepositoryFixture, unittest.TestCase):
    PAYLOAD = VFUNC_PAYLOAD
    SYMBOL_NAME = VFUNC_PAYLOAD["func_name"]
    CATEGORY = "vfunc"
    FILENAME = SYMBOL_NAME + ".windows.yaml"
    NUMERIC_ANCHOR_FIELDS = ("vfunc_sig_disp",)

    def test_valid_anchor_drift_is_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rebuilt = self.fixture(root)
            self.rebuilt_artifact(rebuilt).write_bytes(
                canonical_symbol_yaml_bytes({**self.PAYLOAD, "vfunc_sig_disp": "0x20"})
            )
            with redirect_stdout(io.StringIO()):
                inventory = self.compare(root, rebuilt)
            self.assertEqual(1, len(inventory.paths))


if __name__ == "__main__":
    unittest.main()
