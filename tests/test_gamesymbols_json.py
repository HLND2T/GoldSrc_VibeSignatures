from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

from gamesymbol_candidate import main as gamesymbol_candidate_main
from gamesymbol_snapshot_lib.candidate import build_candidate_snapshot, publish_candidate
from gamesymbol_snapshot_lib.candidate_session import CandidateContractError
from gamesymbol_snapshot_lib.metadata import write_metadata
from gamesymbol_snapshot_lib.operations import pack_snapshot
from gamesymbols_json import build_dataset_cli, encode_dataset, encode_index
from release_workflow_lib.hashing import canonical_json_bytes, sha256_bytes
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
    def test_encode_dataset_is_canonical_and_schema_three(self):
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
            self.assertEqual(3, dataset["schemaVersion"])
            self.assertEqual(tag, dataset["source"]["gameVersion"])
            self.assertEqual(2, dataset["source"]["fileCount"])
            self.assertEqual({"engine"}, set(dataset["binaries"]))
            self.assertEqual({"windows", "linux"}, set(dataset["binaries"]["engine"]))
            self.assertNotIn("path", dataset["binaries"]["engine"]["windows"])
            self.assertEqual([{"count": 2, "linuxCount": 1, "name": "engine", "windowsCount": 1}], dataset["modules"])
            self.assertEqual(
                {record["platform"] for record in dataset["records"]},
                {"windows", "linux"},
            )
            self.assertEqual({"symbol"}, {record["symbolName"] for record in dataset["records"]})

    def test_encode_index_sorts_family_ascending_build_descending(self):
        datasets = [
            {"schemaVersion": 3, "source": self._source(gamever), "binaries": {}, "modules": [], "records": []}
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
            "snapshotSchemaVersion": 6,
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
