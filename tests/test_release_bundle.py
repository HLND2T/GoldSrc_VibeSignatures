from __future__ import annotations

import json
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
from release_bundle import ReleaseBundleError, build_release_bundle, verify_release_bundle
from release_workflow_lib.hashing import canonical_json_bytes
from tests.test_support import write_config, write_pe32


class ReleaseBundleTests(unittest.TestCase):
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

        subprocess.run(["git", "-C", str(repo), "add", "configs", "bin_artifacts"], check=True)
        bin_commit = "b" * 40
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
        (archives / "gamedata-game-1.7z").write_bytes(b"gamedata archive")
        (archives / "gamebin-game-1.7z").write_bytes(b"gamebin archive")
        evidence = generated / "evidence"
        evidence.mkdir()
        (evidence / "ida-runtime.json").write_bytes(canonical_json_bytes({"kernel": "9.3"}))
        (evidence / "cache-selection.json").write_bytes(canonical_json_bytes({"entries": []}))
        return repo, generated, source_sha

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
            self.assertEqual(manifest, verify_release_bundle(repo_root=repo, bundle_root=bundle, version="v20260831a"))
            checksum = (bundle / "SHA256SUMS-v20260831a.txt").read_text(encoding="utf-8")
            self.assertIn("release-manifest-v20260831a.json", checksum)
            self.assertNotIn("SHA256SUMS-v20260831a.txt", checksum)
            archive = bundle / "archives/gamedata-game-1.7z"
            archive.write_bytes(archive.read_bytes() + b"tamper")
            with self.assertRaisesRegex(ReleaseBundleError, "asset digest"):
                verify_release_bundle(repo_root=repo, bundle_root=bundle, version="v20260831a")

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
                verify_release_bundle(repo_root=repo, bundle_root=bundle, version="v20260831a")
            (bundle / "extra.txt").unlink()
            manifest_path = bundle / "release-manifest-v20260831a.json"
            document = json.loads(manifest_path.read_bytes())
            document["source_subject"] = "tampered"
            manifest_path.write_bytes(canonical_json_bytes(document))
            with self.assertRaisesRegex(ReleaseBundleError, "SHA256SUMS"):
                verify_release_bundle(repo_root=repo, bundle_root=bundle, version="v20260831a")


if __name__ == "__main__":
    unittest.main()
