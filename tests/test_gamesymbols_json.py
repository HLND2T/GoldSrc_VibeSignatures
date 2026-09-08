from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

import yaml

from gamesymbol_candidate import main as gamesymbol_candidate_main
from gamesymbol_snapshot_lib.candidate import build_candidate_snapshot, publish_candidate
from gamesymbol_snapshot_lib.candidate_session import CandidateContractError
from gamesymbol_snapshot_lib.codec import build_snapshot_document, canonical_snapshot_bytes, parse_snapshot_bytes
from gamesymbol_snapshot_lib.metadata import canonical_metadata_bytes, write_metadata
from gamesymbol_snapshot_lib.operations import pack_snapshot
from gamesymbols_json import (
    GamesymbolsJsonError,
    _symbol_kind,
    _symbol_name,
    build_dataset_cli,
    encode_dataset,
    encode_index,
)
from release_workflow_lib.hashing import canonical_json_bytes, sha256_bytes
from tests.test_decrypt_blob import make_blob
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
    binary_module_dir = root / "bin" / tag / "engine"
    artifact_module_dir = root / "bin_artifacts" / tag / "engine"
    write_pe32(binary_module_dir / "hw.dll")
    write_elf32(binary_module_dir / "hw.so")
    artifact_module_dir.mkdir(parents=True)
    (artifact_module_dir / "symbol.windows.yaml").write_text("func_name: symbol\nfunc_va: '0x10'\n", encoding="utf-8")
    (artifact_module_dir / "symbol.linux.yaml").write_text("func_name: symbol\nfunc_va: '0x20'\n", encoding="utf-8")
    return tag, config


class EncoderTests(unittest.TestCase):
    def test_patch_payload_exports_as_patch_kind(self):
        payload = {
            "patch_name": "Cvar_Set_to_Cvar_DirectSet_callsite_0",
            "patch_va": "0x101be0d6",
            "patch_rva": "0x1be0d6",
            "patch_sig": "E8 AA BB CC DD 83 C4 08",
            "patch_sig_disp": "0x0",
        }
        self.assertEqual("patch", _symbol_kind(payload))
        self.assertEqual(
            "Cvar_Set_to_Cvar_DirectSet_callsite_0",
            _symbol_name(payload, "ignored"),
        )

    def test_encode_dataset_is_canonical_and_schema_four(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tag, config = fixture(root)
            snapshot = root / f"{tag}.yaml"
            pack_snapshot(
                tag,
                root / "bin",
                config,
                snapshot,
                artifactdir=root / "bin_artifacts",
                last_publish_time="2026-01-02T03:04:05Z",
            )
            metadata = root / f"{tag}.metadata.yaml"
            write_metadata(
                snapshot_path=snapshot,
                config_path=config,
                game_version=tag,
                output_path=metadata,
            )
            dataset = encode_dataset(snapshot.read_bytes(), metadata.read_bytes(), tag)
            raw = canonical_json_bytes(dataset)
            self.assertEqual(raw, canonical_json_bytes(dataset))
            self.assertEqual(4, dataset["schemaVersion"])
            self.assertEqual(7, dataset["source"]["snapshotSchemaVersion"])
            self.assertEqual(tag, dataset["source"]["gameVersion"])
            self.assertEqual(2, dataset["source"]["fileCount"])
            self.assertEqual({"engine"}, set(dataset["binaries"]))
            self.assertEqual({"windows", "linux"}, set(dataset["binaries"]["engine"]))
            self.assertNotIn("path", dataset["binaries"]["engine"]["windows"])
            for platform in ("windows", "linux"):
                self.assertIs(False, dataset["binaries"]["engine"][platform]["isBlob"])
            self.assertEqual([{"count": 2, "linuxCount": 1, "name": "engine", "windowsCount": 1}], dataset["modules"])
            self.assertEqual(
                {record["platform"] for record in dataset["records"]},
                {"windows", "linux"},
            )
            self.assertEqual({"symbol"}, {record["symbolName"] for record in dataset["records"]})

    def test_encode_dataset_rejects_snapshots_older_than_schema_seven(self):
        files = {"engine/symbol.windows.yaml": {"func_name": "symbol", "func_va": "0x10"}}
        binaries6 = {
            "engine": {
                "windows": {"sha256": "a" * 64, "md5": "b" * 32, "crc32": "c" * 8, "crc64": "d" * 16, "size": 1},
                "linux": {"sha256": "a" * 64, "md5": "b" * 32, "crc32": "c" * 8, "crc64": "d" * 16, "size": 1},
            }
        }
        document = build_snapshot_document(
            "game-1",
            f"sha256:{'e' * 64}",
            files,
            schema_version=6,
            last_publish_time="2026-01-02T03:04:05Z",
            binaries=binaries6,
        )
        raw = canonical_snapshot_bytes(document)
        self.assertEqual(6, parse_snapshot_bytes(raw)["schema_version"])
        metadata = canonical_metadata_bytes(
            {
                "schema_version": 1,
                "game_version": "game-1",
                "snapshot_sha256": hashlib.sha256(raw).hexdigest(),
                "config_digest_version": 2,
                "config_sha256": "e" * 64,
                "modules": [],
            }
        )
        with self.assertRaisesRegex(GamesymbolsJsonError, "schema-7"):
            encode_dataset(raw, metadata, "game-1")

    def test_non_engine_blob_publishes_is_blob_true_from_original_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tag = "game-1"
            config = root / "config.yaml"
            config.write_text(
                yaml.safe_dump(
                    {
                        "modules": [
                            {
                                "name": "client",
                                "path_windows": "Game/client.dll",
                                "module_windows": "client.dll",
                                "skills": [{"name": "find", "expected_output": ["symbol.windows.yaml"]}],
                                "symbols": [],
                            }
                        ]
                    },
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            blob = root / "bin" / tag / "client" / "client.dll"
            blob.parent.mkdir(parents=True)
            blob.write_bytes(make_blob())
            artifact_dir = root / "bin_artifacts" / tag / "client"
            artifact_dir.mkdir(parents=True)
            (artifact_dir / "symbol.windows.yaml").write_text("func_name: symbol\nfunc_va: '0x10'\n", encoding="utf-8")
            snapshot = root / f"{tag}.yaml"
            pack_snapshot(
                tag,
                root / "bin",
                config,
                snapshot,
                artifactdir=root / "bin_artifacts",
                last_publish_time="2026-01-02T03:04:05Z",
            )
            document = parse_snapshot_bytes(snapshot.read_bytes())
            blob_metadata = document["binaries"]["client"]["windows"]
            self.assertIs(True, blob_metadata["is_blob"])

            metadata = root / f"{tag}.metadata.yaml"
            write_metadata(
                snapshot_path=snapshot,
                config_path=config,
                game_version=tag,
                output_path=metadata,
            )
            dataset = encode_dataset(snapshot.read_bytes(), metadata.read_bytes(), tag)
            entry = dataset["binaries"]["client"]["windows"]
            self.assertIs(True, entry["isBlob"])
            self.assertEqual(hashlib.sha256(blob.read_bytes()).hexdigest(), entry["sha256"])
            self.assertEqual(blob.stat().st_size, entry["size"])

    def test_encode_index_sorts_family_ascending_build_descending(self):
        datasets = [
            {"schemaVersion": 4, "source": self._source(gamever), "binaries": {}, "modules": [], "records": []}
            for gamever in ("svencoop-9999", "hl-3647", "svencoop-10257", "hl-4554", "cstrike-10210")
        ]
        index = encode_index(datasets)
        self.assertEqual(4, index["schemaVersion"])
        self.assertEqual(
            ["cstrike-10210", "hl-4554", "hl-3647", "svencoop-10257", "svencoop-9999"],
            [entry["gameVersion"] for entry in index["versions"]],
        )
        for entry in index["versions"]:
            self.assertEqual(entry["url"], f"{entry['gameVersion']}.{entry['sha256']}.json")
            self.assertEqual(64, len(entry["sha256"]))

    @staticmethod
    def _source(gamever: str) -> dict:
        return {
            "gameVersion": gamever,
            "snapshotSchemaVersion": 7,
            "configDigestVersion": 2,
            "analysisOutputContractVersion": 1,
            "configSha256": f"sha256:{'a' * 64}",
            "fileCount": 1,
            "lastPublishTime": "2026-01-02T03:04:05Z",
        }


class JsonCandidateStepTests(unittest.TestCase):
    def test_json_mark_guards_and_publishes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tag, config = fixture(root)
            with working_directory(root):
                candidate = root / ".candidates" / f"{tag}.yaml"
                session = root / ".candidates" / "session.json"
                build_candidate_snapshot(
                    game_version=tag,
                    bin_root=root / "bin",
                    artifact_root=root / "bin_artifacts",
                    config_path=config,
                    output_path=candidate,
                    session_path=session,
                    last_publish_time="2026-01-02T03:04:05Z",
                )
                json_dir = root / ".json-datasets"
                json_session = root / ".candidates" / "json-session.json"
                document = build_dataset_cli(
                    snapshot_path=candidate,
                    metadata_path=candidate.with_name(f"{tag}.metadata.yaml"),
                    game_version=tag,
                    output_dir=json_dir,
                    session_path=json_session,
                )
                dataset_file = json_dir / f"{tag}.{document['dataset_sha256']}.json"
                self.assertTrue(dataset_file.is_file())
                self.assertEqual(
                    document["dataset_sha256"],
                    hashlib.sha256(dataset_file.read_bytes()).hexdigest(),
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
                            "json",
                            "-json-session",
                            str(json_session),
                        ]
                    ),
                )
                destination = root / "release-generated" / "gamesymbols" / f"{tag}.yaml"
                publish_candidate(candidate_path=candidate, session_path=session, destination=destination)
                self.assertEqual(candidate.read_bytes(), destination.read_bytes())

    def test_publish_requires_a_guarded_validation_step(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tag, config = fixture(root)
            with working_directory(root):
                candidate = root / ".candidates" / f"{tag}.yaml"
                session = root / ".candidates" / "session.json"
                build_candidate_snapshot(
                    game_version=tag,
                    bin_root=root / "bin",
                    artifact_root=root / "bin_artifacts",
                    config_path=config,
                    output_path=candidate,
                    session_path=session,
                )
                destination = root / "release-generated" / "gamesymbols" / f"{tag}.yaml"
                with self.assertRaisesRegex(CandidateContractError, "validation step"):
                    publish_candidate(candidate_path=candidate, session_path=session, destination=destination)


if __name__ == "__main__":
    unittest.main()
