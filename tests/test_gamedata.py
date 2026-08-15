from __future__ import annotations

import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

from gamedata_candidate import GamedataCandidateError, build_candidate, guard_candidate, publish_candidate
from gamedata_contract import (
    GamedataContractError,
    generator_contract_sha256,
)
from gamesymbol_snapshot_lib.operations import pack_snapshot
from tests.test_support import write_config, write_pe32
from update_gamedata import generate_gamedata


@contextmanager
def working_directory(path: Path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def empty_snapshot(root: Path):
    tag = "game-1"
    config = write_config(root / "config.yaml", both_platforms=False)
    write_pe32(root / "bin" / tag / "engine" / "hw.dll")
    snapshot = root / "snapshot.yaml"
    pack_snapshot(tag, root / "bin", config, snapshot, last_publish_time="2026-01-02T03:04:05Z")
    return tag, config, snapshot


class GeneratorContractTests(unittest.TestCase):
    def test_zero_generators_have_stable_empty_contract_and_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tag, config, snapshot = empty_snapshot(root)
            result = generate_gamedata(
                gamever=tag,
                snapshot_path=snapshot,
                config_path=config,
                modules_dir=root / "missing-generators",
                output_root=root / "output",
            )
            self.assertEqual([], result["files"])
            self.assertEqual(generator_contract_sha256([]), result["generator_contract_sha256"])

    def test_synthetic_generator_can_only_emit_declared_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tag, config, snapshot = empty_snapshot(root)
            generator = root / "generators" / "demo"
            generator.mkdir(parents=True)
            (generator / "gamedata.py").write_text(
                "MODULE_NAME = 'demo'\n"
                "GENERATOR_API_VERSION = 2\n"
                "OUTPUT_PATHS = ('value.txt',)\n"
                "def update(store, output_dir, *, context):\n"
                "    (output_dir / 'value.txt').write_text(context.game_version + '\\\\n', encoding='utf-8')\n",
                encoding="utf-8",
            )
            result = generate_gamedata(
                gamever=tag,
                snapshot_path=snapshot,
                config_path=config,
                modules_dir=root / "generators",
                output_root=root / "output",
            )
            self.assertEqual([f"gamedata/{tag}/demo/value.txt"], [item["path"] for item in result["files"]])

    def test_rejects_undeclared_generator_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tag, config, snapshot = empty_snapshot(root)
            generator = root / "generators" / "demo"
            generator.mkdir(parents=True)
            (generator / "gamedata.py").write_text(
                "MODULE_NAME = 'demo'\n"
                "OUTPUT_PATHS = ('declared.txt',)\n"
                "def update(store, output_dir):\n"
                "    (output_dir / 'extra.txt').write_text('bad', encoding='utf-8')\n",
                encoding="utf-8",
            )
            with self.assertRaises(GamedataContractError):
                generate_gamedata(
                    gamever=tag,
                    snapshot_path=snapshot,
                    config_path=config,
                    modules_dir=root / "generators",
                    output_root=root / "output",
                )


class GamedataCandidateTests(unittest.TestCase):
    def test_empty_candidate_guard_publish_and_tamper(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tag, config, snapshot = empty_snapshot(root)
            modules = root / "generators"
            modules.mkdir()
            candidate_root = root / ".gamedata-candidates" / "build"
            session = root / ".gamedata-candidates" / "session.json"
            build_candidate(
                gamever=tag,
                build_id="test",
                snapshot=snapshot,
                analysis_config=config,
                modules_dir=modules,
                candidate_root=candidate_root,
                session_path=session,
            )
            guard_candidate(session)
            target = root / "gamedata" / tag
            publish_candidate(session_path=session, output_dir=target)
            self.assertTrue(target.is_dir())
            snapshot.write_bytes(snapshot.read_bytes() + b"\n")
            with self.assertRaises(GamedataCandidateError):
                guard_candidate(session)

    def test_generator_contract_changes_are_detected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tag, config, snapshot = empty_snapshot(root)
            modules = root / "generators"
            modules.mkdir()
            candidate_root = root / ".gamedata-candidates" / "build"
            session = root / ".gamedata-candidates" / "session.json"
            build_candidate(
                gamever=tag,
                build_id="test",
                snapshot=snapshot,
                analysis_config=config,
                modules_dir=modules,
                candidate_root=candidate_root,
                session_path=session,
            )
            (modules / "new").mkdir()
            (modules / "new" / "gamedata.py").write_text(
                "MODULE_NAME='new'\nOUTPUT_PATHS=('x.txt',)\ndef update(store, output_dir): pass\n",
                encoding="utf-8",
            )
            with self.assertRaises(GamedataCandidateError):
                guard_candidate(session)


if __name__ == "__main__":
    unittest.main()
