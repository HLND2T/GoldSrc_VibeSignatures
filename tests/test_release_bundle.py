from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from gamedata_contract import (
    analysis_config_sha256,
    build_gamedata_manifest,
    generator_contract_sha256,
    write_gamedata_manifest,
)
from gamesymbol_snapshot_lib.metadata import write_metadata
from gamesymbol_snapshot_lib.operations import pack_snapshot
from ida_analyze_util import canonical_symbol_yaml_bytes
import release_bundle
from release_bundle import ReleaseBundleError, build_release_bundle, verify_release_bundle
from release_workflow_lib.hashing import canonical_json_bytes, sha256_file
from tests.test_support import write_config, write_pe32


class ReleaseBundleTests(unittest.TestCase):
    @staticmethod
    def _archive(source: Path, target: Path) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["7z", "a", "-t7z", "-mx=1", "-mmt=off", "-mtc=off", "-mta=off", str(target), "."],
            cwd=source,
            check=True,
            stdout=subprocess.DEVNULL,
        )

    @staticmethod
    def _verification_arguments(repo: Path, generated: Path, source_sha: str) -> dict:
        return {
            "repo_root": repo,
            "version": "v20260831a",
            "source_sha": source_sha,
            "build_id": "run-1-1",
            "workflow_run_url": "https://example.invalid/run/1",
            "cache_selection_sha256": sha256_file(generated / "evidence/cache-selection.json"),
        }

    @staticmethod
    def _rewrite_manifest_and_checksums(bundle: Path, mutate) -> None:
        version = "v20260831a"
        manifest_path = bundle / f"release-manifest-{version}.json"
        document = json.loads(manifest_path.read_bytes())
        mutate(document)
        manifest_path.write_bytes(canonical_json_bytes(document))
        records = [*document["assets"], release_bundle._asset_record(bundle, manifest_path.name)]
        (bundle / f"SHA256SUMS-{version}.txt").write_bytes(release_bundle._checksum_bytes(records))

    def fixture(self, root: Path):
        repo = root / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
        configs = repo / "configs"
        configs.mkdir()
        (configs / "config.yaml").write_text("gamevers:\n  - game-1\n", encoding="utf-8")
        config = write_config(
            configs / "game-1.yaml",
            skill={"name": "find", "expected_output": ["Demo.windows.yaml"]},
            symbols=[{"name": "Demo", "category": "func", "platform": "windows"}],
            both_platforms=False,
        )
        artifact = repo / "bin_artifacts" / "game-1" / "engine" / "Demo.windows.yaml"
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(canonical_symbol_yaml_bytes({"func_name": "Demo", "func_va": "0x10"}))
        binary = repo / "bin" / "game-1" / "engine" / "hw.dll"
        write_pe32(binary)

        subprocess.run(["git", "-C", str(repo / "bin"), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(repo / "bin"), "config", "user.email", "test@example.com"], check=True)
        subprocess.run(["git", "-C", str(repo / "bin"), "config", "user.name", "Test"], check=True)
        subprocess.run(["git", "-C", str(repo / "bin"), "add", "."], check=True)
        subprocess.run(["git", "-C", str(repo / "bin"), "commit", "-q", "-m", "bin"], check=True)
        bin_commit = subprocess.check_output(["git", "-C", str(repo / "bin"), "rev-parse", "HEAD"], text=True).strip()

        subprocess.run(["git", "-C", str(repo), "add", "configs", "bin_artifacts"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "update-index", "--add", "--cacheinfo", f"160000,{bin_commit},bin"],
            check=True,
        )
        subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "source"], check=True)
        source_sha = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()

        generated = root / "generated"
        gamesymbols = generated / "gamesymbols"
        gamesymbols.mkdir(parents=True)
        snapshot = gamesymbols / "game-1.yaml"
        pack_snapshot(
            "game-1",
            repo / "bin",
            config,
            snapshot,
            artifactdir=repo / "bin_artifacts",
            last_publish_time="2026-01-02T03:04:05Z",
        )
        write_metadata(
            snapshot_path=snapshot,
            config_path=config,
            game_version="game-1",
            output_path=gamesymbols / "game-1.metadata.yaml",
        )
        gamedata = generated / "gamedata" / "game-1"
        gamedata.mkdir(parents=True)
        generator_digest = generator_contract_sha256([])
        manifest = build_gamedata_manifest(
            gamever="game-1",
            candidate_sha256=__import__("hashlib").sha256(snapshot.read_bytes()).hexdigest(),
            analysis_config_sha256=analysis_config_sha256(config),
            generator_contract_digest=generator_digest,
            payload_files=[],
        )
        write_gamedata_manifest(gamedata, manifest)
        archives = generated / "archives"
        archives.mkdir()
        gamedata_stage = generated / "gamedata-stage"
        gamebin_stage = generated / "gamebin-stage"
        shutil.copytree(repo / "bin" / "game-1", gamedata_stage / "bin" / "game-1")
        shutil.copytree(repo / "bin" / "game-1", gamebin_stage / "bin" / "game-1")
        (gamedata_stage / "configs").mkdir()
        shutil.copy2(config, gamedata_stage / "configs" / "game-1.yaml")
        shutil.copytree(repo / "bin_artifacts" / "game-1", gamedata_stage / "bin_artifacts" / "game-1")
        shutil.copytree(gamesymbols, gamedata_stage / "gamesymbols")
        shutil.copytree(gamedata, gamedata_stage / "gamedata" / "game-1")
        self._archive(gamedata_stage, archives / "gamedata-game-1.7z")
        self._archive(gamebin_stage, archives / "gamebin-game-1.7z")
        evidence = generated / "evidence"
        evidence.mkdir()
        (evidence / "ida-runtime.json").write_bytes(
            canonical_json_bytes({"kernel_version": "9.3", "idalib_mcp_sha256": "d" * 64})
        )
        (evidence / "cache-selection.json").write_bytes(
            canonical_json_bytes(
                {
                    "schema_version": 1,
                    "cache_mode": "warm",
                    "source_sha": source_sha,
                    "bin_commit": bin_commit,
                    "entries": [
                        {
                            "tag": "game-1",
                            "platform": "windows",
                            "cache_key": "a" * 64,
                            "generation": "generation-1",
                            "manifest_sha256": "c" * 64,
                            "binaries": [
                                {
                                    "module": "engine",
                                    "platform": "windows",
                                    "path": "engine/hw.dll",
                                    "size": binary.stat().st_size,
                                    "sha256": sha256_file(binary),
                                }
                            ],
                        }
                    ],
                }
            )
        )
        return repo, generated, source_sha

    def test_stages_validated_artifacts_with_canonical_empty_gamever_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, _, _ = self.fixture(root)
            write_config(
                repo / "configs/game-1.yaml",
                skill={"name": "find", "expected_output": ["Demo.windows.yaml", "build_number.windows.yaml"]},
                symbols=[
                    {"name": "Demo", "category": "func", "platform": "windows"},
                    {"name": "build_number", "category": "func", "platform": "windows"},
                ],
                both_platforms=False,
            )
            lowercase_artifact = repo / "bin_artifacts/game-1/engine/build_number.windows.yaml"
            lowercase_artifact.write_bytes(
                canonical_symbol_yaml_bytes({"func_name": "build_number", "func_va": "0x20"})
            )
            (repo / "configs/config.yaml").write_text(
                "gamevers:\n  - game-1\n  - empty-1\n",
                encoding="utf-8",
            )
            write_config(
                repo / "configs/empty-1.yaml",
                symbols=[],
                both_platforms=False,
            )
            subprocess.run(["git", "-C", str(repo), "add", "configs", "bin_artifacts"], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "empty gamever"], check=True)

            rebuilt = root / "rebuilt"
            shutil.copytree(repo / "bin_artifacts/game-1", rebuilt / "game-1")
            staged = root / "staged"
            release_bundle.stage_validated_artifact_tree(
                repo_root=repo,
                artifact_root=rebuilt,
                destination=staged,
            )

            expected = repo / "bin_artifacts/game-1/engine/Demo.windows.yaml"
            actual = staged / "game-1/engine/Demo.windows.yaml"
            self.assertEqual(expected.read_bytes(), actual.read_bytes())
            self.assertTrue((staged / "empty-1").is_dir())
            self.assertEqual([], list((staged / "empty-1").iterdir()))

    def test_archive_verifier_accepts_required_empty_artifact_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage = root / "stage"
            (stage / "bin_artifacts/empty-1").mkdir(parents=True)
            archive = root / "empty-artifacts.7z"
            self._archive(stage, archive)

            release_bundle._verify_archive(
                archive,
                {},
                required_directories={"bin_artifacts/empty-1"},
            )

    def test_build_verify_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, generated, source_sha = self.fixture(root)
            bundle = root / "bundle"
            manifest = build_release_bundle(
                repo_root=repo,
                bundle_root=bundle,
                gamesymbols_root=generated / "gamesymbols",
                gamedata_root=generated / "gamedata",
                archives_root=generated / "archives",
                ida_runtime_path=generated / "evidence/ida-runtime.json",
                cache_selection_path=generated / "evidence/cache-selection.json",
                version="v20260831a",
                build_id="run-1-1",
                workflow_run_url="https://example.invalid/run/1",
                source_sha=source_sha,
            )
            self.assertNotIn("manifest_sha256", manifest)
            verify_arguments = self._verification_arguments(repo, generated, source_sha)
            self.assertEqual(manifest, verify_release_bundle(bundle_root=bundle, **verify_arguments))
            checksum = (bundle / "SHA256SUMS-v20260831a.txt").read_text(encoding="utf-8")
            self.assertIn("release-manifest-v20260831a.json", checksum)
            self.assertNotIn("SHA256SUMS-v20260831a.txt", checksum)
            archive = bundle / "archives/gamedata-game-1.7z"
            archive.write_bytes(archive.read_bytes() + b"tamper")
            with self.assertRaisesRegex(ReleaseBundleError, "asset inventory or digest"):
                verify_release_bundle(bundle_root=bundle, **verify_arguments)

    def test_rejects_extra_bundle_file_and_manifest_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, generated, source_sha = self.fixture(root)
            bundle = root / "bundle"
            build_release_bundle(
                repo_root=repo,
                bundle_root=bundle,
                gamesymbols_root=generated / "gamesymbols",
                gamedata_root=generated / "gamedata",
                archives_root=generated / "archives",
                ida_runtime_path=generated / "evidence/ida-runtime.json",
                cache_selection_path=generated / "evidence/cache-selection.json",
                version="v20260831a",
                build_id="run-1-1",
                workflow_run_url="https://example.invalid/run/1",
                source_sha=source_sha,
            )
            (bundle / "extra.txt").write_text("extra\n", encoding="utf-8")
            with self.assertRaisesRegex(ReleaseBundleError, "allowlist"):
                verify_release_bundle(
                    bundle_root=bundle,
                    **self._verification_arguments(repo, generated, source_sha),
                )
            (bundle / "extra.txt").unlink()
            manifest_path = bundle / "release-manifest-v20260831a.json"
            document = json.loads(manifest_path.read_bytes())
            document["source_subject"] = "tampered"
            manifest_path.write_bytes(canonical_json_bytes(document))
            with self.assertRaisesRegex(ReleaseBundleError, "source subject"):
                verify_release_bundle(
                    bundle_root=bundle,
                    **self._verification_arguments(repo, generated, source_sha),
                )

    def test_rejects_synchronized_archive_and_asset_inventory_tamper(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, generated, source_sha = self.fixture(root)
            bundle = root / "bundle"
            build_release_bundle(
                repo_root=repo,
                bundle_root=bundle,
                gamesymbols_root=generated / "gamesymbols",
                gamedata_root=generated / "gamedata",
                archives_root=generated / "archives",
                ida_runtime_path=generated / "evidence/ida-runtime.json",
                cache_selection_path=generated / "evidence/cache-selection.json",
                version="v20260831a",
                build_id="run-1-1",
                workflow_run_url="https://example.invalid/run/1",
                source_sha=source_sha,
            )
            verify_arguments = self._verification_arguments(repo, generated, source_sha)
            archive = bundle / "archives/gamedata-game-1.7z"
            malicious = root / "malicious"
            malicious.mkdir()
            (malicious / "unexpected.txt").write_text("attacker controlled\n", encoding="utf-8")
            archive.unlink()
            self._archive(malicious, archive)

            def refresh_archive(document):
                for record in document["assets"]:
                    if record["path"] == "archives/gamedata-game-1.7z":
                        record.update(release_bundle._asset_record(bundle, record["path"]))

            self._rewrite_manifest_and_checksums(bundle, refresh_archive)
            with self.assertRaisesRegex(ReleaseBundleError, "Archive"):
                verify_release_bundle(bundle_root=bundle, **verify_arguments)

            (root / "second").mkdir()
            repo, generated, source_sha = self.fixture(root / "second")
            second_bundle = root / "second-bundle"
            build_release_bundle(
                repo_root=repo,
                bundle_root=second_bundle,
                gamesymbols_root=generated / "gamesymbols",
                gamedata_root=generated / "gamedata",
                archives_root=generated / "archives",
                ida_runtime_path=generated / "evidence/ida-runtime.json",
                cache_selection_path=generated / "evidence/cache-selection.json",
                version="v20260831a",
                build_id="run-1-1",
                workflow_run_url="https://example.invalid/run/1",
                source_sha=source_sha,
            )
            self._rewrite_manifest_and_checksums(second_bundle, lambda document: document.update(assets=[]))
            with self.assertRaisesRegex(ReleaseBundleError, "asset inventory"):
                verify_release_bundle(
                    bundle_root=second_bundle,
                    **self._verification_arguments(repo, generated, source_sha),
                )


if __name__ == "__main__":
    unittest.main()
