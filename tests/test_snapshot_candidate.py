from __future__ import annotations

import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

from gamedata_candidate import build_candidate as build_gamedata_candidate
from gamesymbol_candidate import main as gamesymbol_candidate_main
from gamesymbol_snapshot_lib.candidate import build_candidate_snapshot, guard_candidate, publish_candidate
from gamesymbol_snapshot_lib.codec import (
    build_snapshot_document,
    canonical_snapshot_bytes,
    canonical_yaml_bytes,
    parse_snapshot_bytes,
)
from gamesymbol_snapshot_lib.errors import SnapshotMismatchError, SnapshotSchemaError
from gamesymbol_snapshot_lib.operations import pack_snapshot, restore_snapshot, verify_snapshot
from gamesymbol_store import CandidateChangedError, InvalidSymbolPathError, SnapshotSymbolStore
from tests.test_support import write_config, write_elf32, write_pe32


@contextmanager
def working_directory(path: Path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def fixture(root: Path):
    tag = "game-1"
    skill = {"name": "find", "expected_output": ["symbol.{platform}.yaml"]}
    config = write_config(root / "config.yaml", skill=skill)
    game_root = root / "bin" / tag / "engine"
    write_pe32(game_root / "hw.dll")
    write_elf32(game_root / "hw.so")
    (game_root / "symbol.windows.yaml").write_text("name: symbol\ntype: func\nfunc_addr: '0x10'\n", encoding="utf-8")
    (game_root / "symbol.linux.yaml").write_text("name: symbol\ntype: func\nfunc_addr: '0x20'\n", encoding="utf-8")
    return tag, config, game_root


class CodecTests(unittest.TestCase):
    def test_reader_accepts_schema_one_through_five(self):
        files = {"engine/a.windows.yaml": {"addr": "0x10"}}
        binaries4 = {"engine": {"windows": {"path": "Game/hw.dll", "sha256": "a" * 64, "md5": "b" * 32}}}
        binaries5 = {
            "engine": {
                "windows": {
                    "path": "Game/hw.dll",
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "crc32": "c" * 8,
                    "crc64": "d" * 16,
                    "size": 1,
                }
            }
        }
        for schema in range(1, 6):
            kwargs = {"schema_version": schema, "config_digest_version": 1 if schema == 1 else 2}
            if schema >= 4:
                kwargs.update(
                    last_publish_time="2026-01-02T03:04:05Z", binaries=binaries4 if schema == 4 else binaries5
                )
            document = build_snapshot_document("game-1", f"sha256:{'e' * 64}", files, **kwargs)
            data = canonical_snapshot_bytes(document)
            self.assertEqual(schema, parse_snapshot_bytes(data)["schema_version"])
            self.assertIn(b"'0x10'", data)

    def test_rejects_nonflat_or_case_colliding_paths(self):
        for files in (
            {"engine/nested/a.yaml": {}},
            {"engine/A.yaml": {}, "engine/a.yaml": {}},
        ):
            document = build_snapshot_document("game-1", f"sha256:{'e' * 64}", files, schema_version=3)
            with self.assertRaises(SnapshotSchemaError):
                parse_snapshot_bytes(canonical_yaml_bytes(document))


class SnapshotOperationTests(unittest.TestCase):
    def test_pack_verify_and_restore_are_byte_stable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tag, config, game_root = fixture(root)
            snapshot = root / "snapshot.yaml"
            packed = pack_snapshot(tag, root / "bin", config, snapshot, last_publish_time="2026-01-02T03:04:05Z")
            document = parse_snapshot_bytes(packed)
            self.assertEqual(5, document["schema_version"])
            self.assertEqual(2, document["config_digest_version"])
            self.assertEqual(2, document["file_count"])
            self.assertEqual({"windows", "linux"}, set(document["binaries"]["engine"]))
            self.assertEqual(packed, verify_snapshot(tag, root / "bin", config, snapshot))
            (game_root / "symbol.windows.yaml").unlink()
            restore_snapshot(tag, root / "bin", config, snapshot)
            self.assertEqual(packed, verify_snapshot(tag, root / "bin", config, snapshot))

    def test_missing_required_and_undeclared_artifacts_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tag, config, game_root = fixture(root)
            (game_root / "symbol.windows.yaml").unlink()
            with self.assertRaises(SnapshotMismatchError):
                pack_snapshot(tag, root / "bin", config, root / "snapshot.yaml")
            (game_root / "symbol.windows.yaml").write_text("ok: true\n", encoding="utf-8")
            (game_root / "undeclared.yaml").write_text("bad: true\n", encoding="utf-8")
            with self.assertRaises(SnapshotMismatchError):
                pack_snapshot(tag, root / "bin", config, root / "snapshot.yaml")

    def test_noncanonical_signature_artifact_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tag, config, game_root = fixture(root)
            (game_root / "symbol.windows.yaml").write_text(
                "name: symbol\ntype: func\nfunc_sig: aa bb\n", encoding="utf-8"
            )
            with self.assertRaises(SnapshotMismatchError):
                pack_snapshot(tag, root / "bin", config, root / "snapshot.yaml")

    def test_symbol_store_is_read_only_and_path_safe(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tag, config, _game_root = fixture(root)
            snapshot = root / "snapshot.yaml"
            pack_snapshot(tag, root / "bin", config, snapshot)
            store = SnapshotSymbolStore.open(snapshot, expected_game_version=tag, config_path=config)
            first = store.require("engine", "symbol.windows.yaml")
            first["name"] = "changed"
            self.assertEqual("symbol", store.require("engine", "symbol.windows.yaml")["name"])
            with self.assertRaises(InvalidSymbolPathError):
                store.get("../engine", "symbol.windows.yaml")


class CandidateTests(unittest.TestCase):
    def test_tamper_guard_and_guarded_atomic_publish(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tag, config, _game_root = fixture(root)
            with working_directory(root):
                candidate = root / ".candidates" / "candidate.yaml"
                session = root / ".candidates" / "session.json"
                build_candidate_snapshot(
                    game_version=tag,
                    bin_root=root / "bin",
                    config_path=config,
                    output_path=candidate,
                    session_path=session,
                    last_publish_time="2026-01-02T03:04:05Z",
                )
                guard_candidate(candidate_path=candidate, session_path=session)
                generators = root / "generators"
                generators.mkdir()
                gamedata_session = root / ".gamedata-candidates" / "session.json"
                build_gamedata_candidate(
                    gamever=tag,
                    build_id="test",
                    snapshot=candidate,
                    analysis_config=config,
                    modules_dir=generators,
                    candidate_root=root / ".gamedata-candidates" / "build",
                    session_path=gamedata_session,
                )
                self.assertEqual(
                    0,
                    gamesymbol_candidate_main(
                        [
                            "mark",
                            "-candidate",
                            str(candidate),
                            "-session",
                            str(session),
                            "-step",
                            "gamedata",
                            "-gamedata-session",
                            str(gamedata_session),
                        ]
                    ),
                )
                destination = root / "gamesymbols" / f"{tag}.yaml"
                published = publish_candidate(candidate_path=candidate, session_path=session, destination=destination)
                self.assertEqual(candidate.read_bytes(), destination.read_bytes())
                self.assertEqual(str(destination), published.path)

    def test_tampered_candidate_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tag, config, _game_root = fixture(root)
            with working_directory(root):
                candidate = root / ".candidates" / "candidate.yaml"
                session = root / ".candidates" / "session.json"
                build_candidate_snapshot(
                    game_version=tag,
                    bin_root=root / "bin",
                    config_path=config,
                    output_path=candidate,
                    session_path=session,
                )
                candidate.write_bytes(candidate.read_bytes() + b"\n")
                with self.assertRaises(CandidateChangedError):
                    guard_candidate(candidate_path=candidate, session_path=session)


if __name__ == "__main__":
    unittest.main()
