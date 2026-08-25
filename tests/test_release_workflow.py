from __future__ import annotations

import unittest

from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import allowed_output_path, validate_output_paths
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
        with self.assertRaises(ReleaseWorkflowError):
            require_mode("republish")


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


if __name__ == "__main__":
    unittest.main()
