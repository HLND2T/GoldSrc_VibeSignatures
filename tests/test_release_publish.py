from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import release_publish


def completed(arguments, stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(arguments, returncode, stdout=stdout, stderr=stderr)


class ReleasePublishTests(unittest.TestCase):
    def test_preflight_accepts_absent_resume_and_published_identity(self):
        with patch.object(release_publish, "remote_state", return_value=(None, None)):
            self.assertEqual("new", release_publish.preflight("owner/repo", "v20260831a", "a" * 40))
        tag = {"object": {"type": "commit", "sha": "a" * 40}}
        notes = release_publish._release_identity_notes(
            version="v20260831a",
            source_sha="a" * 40,
            build_id="123",
            workflow_run_url="https://github.com/owner/repo/actions/runs/123",
        )
        with patch.object(
            release_publish,
            "remote_state",
            return_value=(tag, {"tag_name": "v20260831a", "draft": True, "body": notes}),
        ):
            self.assertEqual("resume", release_publish.preflight("owner/repo", "v20260831a", "a" * 40))
        with patch.object(
            release_publish,
            "remote_state",
            return_value=(tag, {"tag_name": "v20260831a", "draft": False, "body": notes}),
        ):
            self.assertEqual("published", release_publish.preflight("owner/repo", "v20260831a", "a" * 40))

    def test_preflight_rejects_tag_mismatch_and_release_without_tag(self):
        with (
            patch.object(
                release_publish,
                "remote_state",
                return_value=({"object": {"type": "commit", "sha": "b" * 40}}, None),
            ),
            self.assertRaisesRegex(release_publish.ReleasePublishError, "does not point"),
        ):
            release_publish.preflight("owner/repo", "v20260831a", "a" * 40)
        with (
            patch.object(
                release_publish,
                "remote_state",
                return_value=(None, {"tag_name": "v20260831a", "draft": True}),
            ),
            self.assertRaisesRegex(release_publish.ReleasePublishError, "without"),
        ):
            release_publish.preflight("owner/repo", "v20260831a", "a" * 40)

    def test_remote_asset_digest_prefers_github_sha256(self):
        with patch.object(release_publish, "_run") as run:
            self.assertEqual(
                "a" * 64,
                release_publish._remote_asset_sha256("owner/repo", "v20260831a", {"digest": "sha256:" + "a" * 64}),
            )
        run.assert_not_called()

    def test_preflight_reuses_draft_build_identity(self):
        tag = {"object": {"type": "commit", "sha": "a" * 40}}
        notes = release_publish._release_identity_notes(
            version="v20260831a",
            source_sha="a" * 40,
            build_id="original-build",
            workflow_run_url="https://github.com/owner/repo/actions/runs/1",
        )
        with patch.object(
            release_publish,
            "remote_state",
            return_value=(tag, {"tag_name": "v20260831a", "draft": True, "body": notes}),
        ):
            self.assertEqual(
                ("resume", "original-build", "https://github.com/owner/repo/actions/runs/1"),
                release_publish.inspect_preflight(
                    "owner/repo",
                    "v20260831a",
                    "a" * 40,
                    build_id="new-build",
                    workflow_run_url="https://github.com/owner/repo/actions/runs/2",
                ),
            )

    def test_github_lookup_only_treats_http_404_as_absent(self):
        with patch.object(
            release_publish,
            "_run",
            return_value=completed([], returncode=1, stderr="gh: Not Found (HTTP 404)"),
        ):
            self.assertIsNone(release_publish._gh_json(["api", "endpoint"], allow_not_found=True))
        with (
            patch.object(
                release_publish,
                "_run",
                return_value=completed([], returncode=1, stderr="gh: forbidden (HTTP 403)"),
            ),
            self.assertRaisesRegex(release_publish.ReleasePublishError, "403"),
        ):
            release_publish._gh_json(["api", "endpoint"], allow_not_found=True)

    def test_release_identity_refuses_different_source(self):
        notes = release_publish._release_identity_notes(
            version="v20260831a",
            source_sha="a" * 40,
            build_id="123",
            workflow_run_url="https://github.com/owner/repo/actions/runs/123",
        )
        with self.assertRaisesRegex(release_publish.ReleasePublishError, "does not match"):
            release_publish._release_identity({"body": notes}, version="v20260831a", source_sha="b" * 40)

    def test_published_release_is_idempotent_only_with_exact_assets(self):
        with tempfile.TemporaryDirectory() as temporary:
            asset = Path(temporary) / "asset.7z"
            asset.write_bytes(b"payload")
            notes = release_publish._release_identity_notes(
                version="v20260831a",
                source_sha="a" * 40,
                build_id="123",
                workflow_run_url="https://github.com/owner/repo/actions/runs/123",
            )
            release = {
                "draft": False,
                "body": notes,
                "assets": [
                    {
                        "name": asset.name,
                        "size": asset.stat().st_size,
                        "digest": "sha256:" + release_publish._sha256_file(asset),
                    }
                ],
            }
            manifest = {
                "source_sha": "a" * 40,
                "build_id": "123",
                "workflow_run_url": "https://github.com/owner/repo/actions/runs/123",
            }
            with (
                patch.object(release_publish, "verify_release_bundle", return_value=manifest),
                patch.object(
                    release_publish,
                    "inspect_preflight",
                    return_value=("published", "123", manifest["workflow_run_url"]),
                ),
                patch.object(release_publish, "remote_state", side_effect=[({}, release), ({}, release)]),
                patch.object(release_publish, "_release_assets", return_value=(asset,)),
                patch.object(release_publish, "_run") as run,
            ):
                self.assertEqual(
                    "published",
                    release_publish.publish_release(
                        repository="owner/repo",
                        repo_root=temporary,
                        bundle_root=temporary,
                        version="v20260831a",
                        source_sha=manifest["source_sha"],
                        build_id=manifest["build_id"],
                        workflow_run_url=manifest["workflow_run_url"],
                        cache_selection_sha256="b" * 64,
                    ),
                )
            run.assert_not_called()

            release["assets"] = []
            with (
                patch.object(release_publish, "verify_release_bundle", return_value=manifest),
                patch.object(
                    release_publish,
                    "inspect_preflight",
                    return_value=("published", "123", manifest["workflow_run_url"]),
                ),
                patch.object(release_publish, "remote_state", return_value=({}, release)),
                patch.object(release_publish, "_release_assets", return_value=(asset,)),
                self.assertRaisesRegex(release_publish.ReleasePublishError, "missing asset"),
            ):
                release_publish.publish_release(
                    repository="owner/repo",
                    repo_root=temporary,
                    bundle_root=temporary,
                    version="v20260831a",
                    source_sha=manifest["source_sha"],
                    build_id=manifest["build_id"],
                    workflow_run_url=manifest["workflow_run_url"],
                    cache_selection_sha256="b" * 64,
                )

    def test_matching_draft_reuses_assets_then_publishes(self):
        with tempfile.TemporaryDirectory() as temporary:
            asset = Path(temporary) / "asset.7z"
            asset.write_bytes(b"payload")
            workflow_run_url = "https://github.com/owner/repo/actions/runs/123"
            notes = release_publish._release_identity_notes(
                version="v20260831a",
                source_sha="a" * 40,
                build_id="123",
                workflow_run_url=workflow_run_url,
            )
            release = {
                "draft": True,
                "body": notes,
                "assets": [
                    {
                        "name": asset.name,
                        "size": asset.stat().st_size,
                        "digest": "sha256:" + release_publish._sha256_file(asset),
                    }
                ],
            }
            manifest = {
                "source_sha": "a" * 40,
                "build_id": "123",
                "workflow_run_url": workflow_run_url,
            }
            with (
                patch.object(release_publish, "verify_release_bundle", return_value=manifest),
                patch.object(release_publish, "inspect_preflight", return_value=("resume", "123", workflow_run_url)),
                patch.object(release_publish, "remote_state", side_effect=[({}, release), ({}, release)]),
                patch.object(release_publish, "_release_assets", return_value=(asset,)),
                patch.object(release_publish, "_run") as run,
            ):
                self.assertEqual(
                    "resume",
                    release_publish.publish_release(
                        repository="owner/repo",
                        repo_root=temporary,
                        bundle_root=temporary,
                        version="v20260831a",
                        source_sha=manifest["source_sha"],
                        build_id=manifest["build_id"],
                        workflow_run_url=manifest["workflow_run_url"],
                        cache_selection_sha256="b" * 64,
                    ),
                )
            run.assert_called_once_with(
                ["gh", "release", "edit", "v20260831a", "--repo", "owner/repo", "--draft=false", "--verify-tag"]
            )

    def test_publish_command_never_uses_clobber(self):
        self.assertNotIn("--clobber", __import__("inspect").getsource(release_publish.publish_release))


if __name__ == "__main__":
    unittest.main()
