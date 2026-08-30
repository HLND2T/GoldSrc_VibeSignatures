from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import (
    allowed_output_path,
    file_inventory,
    inventory_sha256,
    validate_output_paths,
    write_canonical_json,
)
from release_workflow_lib.manifests import (
    build_gamever_entry,
    build_tracked_manifest,
    format_output_branch,
    parse_output_branch,
    require_gamever,
    require_mode,
    require_version,
    validate_tracked_manifest,
)
from release_workflow_lib.promotion import promote_bin, reconstruct_workspace


class BranchParsingTests(unittest.TestCase):
    def test_format_and_parse_version_branch(self):
        self.assertEqual("gamesymbols/build/v20260825a", format_output_branch("v20260825a"))
        self.assertEqual("v20260825a", parse_output_branch("gamesymbols/build/v20260825a"))
        self.assertEqual("v20260825", parse_output_branch("gamesymbols/build/v20260825"))
        for invalid in (
            "gamesymbols/build/v2026082",
            "gamesymbols/build/V20260825a",
            "gamesymbols/build/v20260825ab",
            "gamesymbols/build/v20260825a/extra",
            "feature/x",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ReleaseWorkflowError):
                parse_output_branch(invalid)

    def test_version_and_gamever_validators(self):
        self.assertEqual("v20260825a", require_version("v20260825a"))
        self.assertEqual("hl-10210", require_gamever("hl-10210"))
        self.assertEqual("svencoop-10257", require_gamever("svencoop-10257"))
        for bad in ("20260825a", "v2026082", "v20260825ab"):
            with self.subTest(bad=bad), self.assertRaises(ReleaseWorkflowError):
                require_version(bad)
        for bad in ("10210", "HL-10210", "hl-", "hl-10210-extra"):
            with self.subTest(bad=bad), self.assertRaises(ReleaseWorkflowError):
                require_gamever(bad)


class ManifestSchemaTests(unittest.TestCase):
    def _entry(self, gamever="hl-10210"):
        return build_gamever_entry(
            gamever=gamever,
            candidate_sha256="a" * 64,
            analysis_config_path=f"configs/{gamever}.yaml",
            analysis_config_sha256="b" * 64,
            gamedata_path=f"gamedata/{gamever}",
            gamedata_manifest_sha256="c" * 64,
            gamedata_inventory_sha256="d" * 64,
            generator_contract_sha256="e" * 64,
        )

    def test_build_and_validate_roundtrip(self):
        manifest = build_tracked_manifest(
            version="v20260825a",
            mode="new",
            build_id="123-1",
            source_sha="f" * 40,
            workflow_run_url="https://github.com/HLND2T/GoldSrc_VibeSignatures/actions/runs/1",
            bin_manifest_sha256="1" * 64,
            tracked_output_manifest_sha256="2" * 64,
            gamevers=[self._entry(), self._entry("svencoop-10257")],
        )
        self.assertEqual(manifest, validate_tracked_manifest(manifest))

    def test_rejects_duplicate_gamevers_and_bad_mode(self):
        entry = self._entry()
        with self.assertRaises(ReleaseWorkflowError):
            build_tracked_manifest(
                version="v20260825a",
                mode="new",
                build_id="123-1",
                source_sha="f" * 40,
                workflow_run_url="https://github.com/HLND2T/GoldSrc_VibeSignatures/actions/runs/1",
                bin_manifest_sha256="1" * 64,
                tracked_output_manifest_sha256="2" * 64,
                gamevers=[entry, entry],
            )
        self.assertEqual("republish", require_mode("republish"))
        with self.assertRaises(ReleaseWorkflowError):
            require_mode("bogus")


class OutputPathValidationTests(unittest.TestCase):
    def test_validate_output_paths_allowlist(self):
        gamevers = ["hl-10210", "svencoop-10257"]
        version = "v20260825a"
        allowed = [
            "release-manifests/v20260825a.json",
            "gamesymbols/hl-10210.yaml",
            "gamesymbols/hl-10210.metadata.yaml",
            "gamedata/hl-10210/gamedata-manifest.json",
            "gamesymbols/svencoop-10257.yaml",
            "gamedata/svencoop-10257/foo.json",
        ]
        for path in allowed:
            self.assertTrue(allowed_output_path(path, gamevers, version), path)
        for bad in ("gamesymbols/other.yaml", "gamedata/other/x.json", "README.md"):
            self.assertFalse(allowed_output_path(bad, gamevers, version))
        validate_output_paths(allowed, gamevers, version)
        with self.assertRaises(ReleaseWorkflowError):
            validate_output_paths(["gamesymbols/hl-10210.yaml"], gamevers, version)


class ReconstructWorkspaceTests(unittest.TestCase):
    def _repo_with_binary(self, root: Path) -> Path:
        repo = root / "repo"
        binary = repo / "bin" / "cof-5936" / "engine" / "hw.dll"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"existing")
        return repo

    def test_rejects_empty_stage_directory_without_removing_workspace_binaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = self._repo_with_binary(Path(temporary))

            with self.assertRaisesRegex(ReleaseWorkflowError, "STAGE_DIR is required"):
                reconstruct_workspace(repo, "", "v20260825a")

            self.assertEqual(b"existing", (repo / "bin" / "cof-5936" / "engine" / "hw.dll").read_bytes())

    def test_rejects_stage_source_overlapping_repository_bin(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = self._repo_with_binary(Path(temporary))

            with self.assertRaisesRegex(ReleaseWorkflowError, "must not overlap"):
                reconstruct_workspace(repo, repo, "v20260825a")

            self.assertEqual(b"existing", (repo / "bin" / "cof-5936" / "engine" / "hw.dll").read_bytes())

    def test_reconstructs_workspace_from_private_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = self._repo_with_binary(root)
            staged_binary = root / "stage" / "bin" / "cof-5936" / "engine" / "hw.dll"
            staged_binary.parent.mkdir(parents=True)
            staged_binary.write_bytes(b"staged")

            source = reconstruct_workspace(repo, root / "stage", "v20260825a")

            self.assertEqual((root / "stage" / "bin").resolve(), source)
            self.assertEqual(b"staged", (repo / "bin" / "cof-5936" / "engine" / "hw.dll").read_bytes())


class PromoteBinTests(unittest.TestCase):
    gamever = "hl-10210"
    version = "v20260825a"
    build_id = "123-1"

    def _prepare_stage(self, root: Path, *, accepted_payload: bytes) -> tuple[Path, Path, Path]:
        persisted_root = root / "persisted"
        stage_dir = persisted_root / "release-staging" / self.version / self.build_id
        staged_binary = stage_dir / "bin" / self.gamever / "engine" / "hw.dll"
        staged_binary.parent.mkdir(parents=True)
        staged_binary.write_bytes(b"staged")

        accepted_binary = persisted_root / "bin" / self.gamever / "engine" / "hw.dll"
        accepted_binary.parent.mkdir(parents=True)
        accepted_binary.write_bytes(accepted_payload)

        bin_files = [{"gamever": self.gamever, **item} for item in file_inventory(stage_dir / "bin" / self.gamever)]
        write_canonical_json(
            stage_dir / "manifest.json",
            {
                "version": self.version,
                "build_id": self.build_id,
                "gamevers": [{"gamever": self.gamever}],
                "bin_manifest_sha256": inventory_sha256(bin_files),
            },
        )
        return persisted_root, stage_dir, accepted_binary

    def test_promotes_verified_gamever_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            persisted_root, stage_dir, accepted_binary = self._prepare_stage(
                Path(temporary), accepted_payload=b"accepted"
            )

            result = promote_bin(
                persisted_root=persisted_root,
                stage_dir=stage_dir,
                version=self.version,
                build_id=self.build_id,
            )

            self.assertEqual({self.gamever: True}, result["promoted"])
            self.assertEqual(b"staged", accepted_binary.read_bytes())
            self.assertTrue((stage_dir / "PROMOTION_STARTED").is_file())

    def test_skips_gamever_with_identical_accepted_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            persisted_root, stage_dir, accepted_binary = self._prepare_stage(
                Path(temporary), accepted_payload=b"staged"
            )

            result = promote_bin(
                persisted_root=persisted_root,
                stage_dir=stage_dir,
                version=self.version,
                build_id=self.build_id,
            )

            self.assertEqual({}, result["promoted"])
            self.assertEqual(b"staged", accepted_binary.read_bytes())
            self.assertFalse((persisted_root / "bin" / f".{self.gamever}.{self.build_id}.backup").exists())


if __name__ == "__main__":
    unittest.main()
