from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from gamesymbol_snapshot_lib.metadata import write_metadata
from gamesymbol_snapshot_lib.operations import pack_snapshot
from generated_output_contract import (
    GeneratedOutputContractError,
    GeneratedOutputProvenance,
    validate_generated_output_contract,
)
from tests.test_support import write_config, write_pe32
from update_gamedata import generate_gamedata

GAMEVER = "game-1"


def _valid_generated_output(root: Path) -> None:
    configs = root / "configs"
    configs.mkdir()
    (configs / "config.yaml").write_text(
        yaml.safe_dump({"gamevers": [GAMEVER]}, sort_keys=False),
        encoding="utf-8",
    )
    config = write_config(configs / f"{GAMEVER}.yaml", both_platforms=False)
    write_pe32(root / "bin" / GAMEVER / "engine" / "hw.dll")

    snapshots = root / "gamesymbols"
    snapshots.mkdir()
    snapshot = snapshots / f"{GAMEVER}.yaml"
    pack_snapshot(
        GAMEVER,
        root / "bin",
        config,
        snapshot,
        artifactdir=root / "bin_artifacts",
        last_publish_time="2026-01-02T03:04:05Z",
    )
    write_metadata(
        snapshot_path=snapshot,
        config_path=config,
        game_version=GAMEVER,
        output_path=snapshots / f"{GAMEVER}.metadata.yaml",
    )
    generate_gamedata(
        gamever=GAMEVER,
        snapshot_path=snapshot,
        config_path=config,
        modules_dir=root / "gamedata-generators",
        output_root=root / "gamedata" / GAMEVER,
    )


class GeneratedOutputValidatorTests(unittest.TestCase):
    def test_accepts_a_complete_generated_output_set(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _valid_generated_output(root)
            result = validate_generated_output_contract(root, expected_gamevers=[GAMEVER])
            self.assertEqual({GAMEVER}, set(result))
            self.assertIsInstance(result[GAMEVER], GeneratedOutputProvenance)

    def test_rejects_manifest_gamever_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _valid_generated_output(root)
            with self.assertRaisesRegex(GeneratedOutputContractError, "expected gamevers"):
                validate_generated_output_contract(root, expected_gamevers=["other-2"])

    def test_rejects_missing_metadata_and_config_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _valid_generated_output(root)
            (root / "gamesymbols" / f"{GAMEVER}.metadata.yaml").unlink()
            with self.assertRaisesRegex(GeneratedOutputContractError, "gamesymbol inventory"):
                validate_generated_output_contract(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _valid_generated_output(root)
            config = root / "configs" / f"{GAMEVER}.yaml"
            document = yaml.safe_load(config.read_text(encoding="utf-8"))
            document["modules"][0]["module_windows"] = "sw.dll"
            config.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
            with self.assertRaisesRegex(GeneratedOutputContractError, GAMEVER):
                validate_generated_output_contract(root)

    def test_rejects_config_file_not_declared_by_the_index(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _valid_generated_output(root)
            (root / "configs" / "orphan-2.yaml").write_text("modules: []\n", encoding="utf-8")
            with self.assertRaisesRegex(GeneratedOutputContractError, "config inventory"):
                validate_generated_output_contract(root)

    def test_rejects_tampered_gamedata_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _valid_generated_output(root)
            manifest = root / "gamedata" / GAMEVER / "gamedata-manifest.json"
            manifest.write_bytes(manifest.read_bytes() + b"\n")
            with self.assertRaisesRegex(GeneratedOutputContractError, GAMEVER):
                validate_generated_output_contract(root)


if __name__ == "__main__":
    unittest.main()
