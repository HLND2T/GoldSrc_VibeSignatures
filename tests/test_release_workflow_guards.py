from __future__ import annotations

import subprocess
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from gamedata_contract import generator_contract_sha256
from release_workflow_lib.accepted_bin import durable_inventory, materialize_accepted_bin
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import inventory_sha256, tracked_output_inventory, write_canonical_json
from release_workflow_lib.locks import accepted_bin_lock_path, version_lock
from release_workflow_lib.manifests import build_gamever_entry, build_tracked_manifest
from release_workflow_lib.promotion import verify_output_pr

GAMEVER = "hl-10210"
VERSION = "v20260825a"
OTHER_VERSION = "v20260825b"
BRANCH = f"gamesymbols/build/{VERSION}"
REPOSITORY = "HLND2T/GoldSrc_VibeSignatures"
AUTHOR = "github-actions[bot]"
WORKFLOW_RUN_URL = "https://github.com/HLND2T/GoldSrc_VibeSignatures/actions/runs/1"


def _run_git(root: Path, *arguments: str, stdin_data: bytes | None = None) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        input=stdin_data,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip()
        raise RuntimeError(detail or f"git {' '.join(arguments)} failed")
    return result.stdout.decode().strip()


def _write_bytes(root: Path, relative: str, data: bytes) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _commit(root: Path, message: str) -> str:
    _run_git(root, "add", "-A")
    _run_git(root, "commit", "-q", "-m", message)
    return _run_git(root, "rev-parse", "HEAD")


def _init_repo(root: Path) -> None:
    _run_git(root, "init", "-q")
    _run_git(root, "config", "user.email", "test@example.com")
    _run_git(root, "config", "user.name", "Test")
    _run_git(root, "config", "core.autocrlf", "false")
    _run_git(root, "config", "advice.detachedHead", "false")


def _write_source_outputs(root: Path) -> None:
    _write_bytes(root, f"gamesymbols/{GAMEVER}.yaml", b"snapshot\n")
    _write_bytes(root, f"gamesymbols/{GAMEVER}.metadata.yaml", b"metadata\n")
    _write_bytes(root, f"gamedata/{GAMEVER}/gamedata-manifest.json", b"{}\n")


def _tracked_manifest(root: Path, source_sha: str, *, version: str = VERSION) -> dict:
    inventory = tracked_output_inventory(root, [GAMEVER])
    snapshot = next(item for item in inventory if item["path"] == f"gamesymbols/{GAMEVER}.yaml")
    gamedata_files = [item for item in inventory if item["path"].startswith(f"gamedata/{GAMEVER}/")]
    return build_tracked_manifest(
        version=version,
        mode="new",
        build_id="123-1",
        source_sha=source_sha,
        workflow_run_url=WORKFLOW_RUN_URL,
        bin_manifest_sha256="1" * 64,
        tracked_output_manifest_sha256=inventory_sha256(inventory),
        gamevers=[
            build_gamever_entry(
                gamever=GAMEVER,
                candidate_sha256=snapshot["sha256"],
                analysis_config_path=f"configs/{GAMEVER}.yaml",
                analysis_config_sha256="b" * 64,
                gamedata_path=f"gamedata/{GAMEVER}",
                gamedata_manifest_sha256="c" * 64,
                gamedata_inventory_sha256=inventory_sha256(gamedata_files),
                generator_contract_sha256=generator_contract_sha256([]),
            )
        ],
    )


def _write_manifest(root: Path, manifest: dict, *, version: str = VERSION) -> None:
    write_canonical_json(root / "release-manifests" / f"{version}.json", manifest)


def _build_output_repo(root: Path, *, extra_output_files: dict[str, bytes] | None = None) -> tuple[str, str, dict]:
    _init_repo(root)
    _write_source_outputs(root)
    source_sha = _commit(root, "source")
    manifest = _tracked_manifest(root, source_sha)
    _write_manifest(root, manifest)
    for relative, data in (extra_output_files or {}).items():
        _write_bytes(root, relative, data)
    head_sha = _commit(root, "output")
    return source_sha, head_sha, manifest


def _advance_base(root: Path, source_sha: str, files: dict[str, bytes], message: str) -> str:
    _run_git(root, "checkout", "-q", "-B", "main", source_sha)
    for relative, data in files.items():
        _write_bytes(root, relative, data)
    return _commit(root, message)


def _call(root: Path, *, base_sha: str, head_sha: str, **overrides):
    arguments = {
        "repo_root": root,
        "repository": REPOSITORY,
        "head_repository": REPOSITORY,
        "author": AUTHOR,
        "branch": BRANCH,
        "base_sha": base_sha,
        "head_sha": head_sha,
    }
    arguments.update(overrides)
    return verify_output_pr(**arguments)


def _verify(root: Path, *, base_sha: str, head_sha: str, **overrides):
    _run_git(root, "checkout", "-q", head_sha)
    return _call(root, base_sha=base_sha, head_sha=head_sha, **overrides)


class VerifyOutputPrTrustTests(unittest.TestCase):
    def test_rejects_untrusted_repository_author_and_invalid_shas(self):
        dummy = "a" * 40
        with self.assertRaisesRegex(ReleaseWorkflowError, r"repository is not allowlisted"):
            _call(Path("."), base_sha=dummy, head_sha=dummy, repository="example/untrusted")
        with self.assertRaisesRegex(
            ReleaseWorkflowError, r"generated-output PR must originate from the base repository"
        ):
            _call(Path("."), base_sha=dummy, head_sha=dummy, head_repository="hzqst/GoldSrc_VibeSignatures")
        with self.assertRaisesRegex(ReleaseWorkflowError, r"generated-output PR author is not github-actions\[bot\]"):
            _call(Path("."), base_sha=dummy, head_sha=dummy, author="human")
        with self.assertRaisesRegex(ReleaseWorkflowError, r"PR base SHA must be a full 40-hex commit SHA"):
            _call(Path("."), base_sha="not-a-sha", head_sha=dummy)
        with self.assertRaisesRegex(ReleaseWorkflowError, r"PR head SHA must be a full 40-hex commit SHA"):
            _call(Path("."), base_sha=dummy, head_sha="abcd")


class VerifyOutputPrGitTests(unittest.TestCase):
    def test_accepts_exact_base_and_descendant_base_advancement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_sha, head_sha, manifest = _build_output_repo(root)
            exact = _verify(root, base_sha=source_sha, head_sha=head_sha)
            self.assertEqual(manifest["source_sha"], exact["source_sha"])
            self.assertEqual(source_sha, exact["source_sha"])

            unrelated_base = _advance_base(root, source_sha, {"README.md": b"unrelated\n"}, "unrelated default-branch")
            accepted = _verify(root, base_sha=unrelated_base, head_sha=head_sha)
            self.assertEqual(source_sha, accepted["source_sha"])

            relevant_base = _advance_base(
                root,
                source_sha,
                {"configs/hl-10210.yaml": b"modules: []\n"},
                "release-related default-branch",
            )
            relevant = _verify(root, base_sha=relevant_base, head_sha=head_sha)
            self.assertEqual(source_sha, relevant["source_sha"])

    def test_ignores_disallowed_paths_that_exist_only_on_advanced_base(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_sha, head_sha, _manifest = _build_output_repo(root)
            advanced_base = _advance_base(root, source_sha, {"docs/secret.md": b"not output\n"}, "base-only path")
            accepted = _verify(root, base_sha=advanced_base, head_sha=head_sha)
            self.assertEqual(source_sha, accepted["source_sha"])

    def test_rejects_base_that_is_not_source_descendant(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_sha, head_sha, _manifest = _build_output_repo(root)
            empty_tree = _run_git(root, "mktree", stdin_data=b"")
            unrelated = _run_git(root, "commit-tree", empty_tree, "-m", "unrelated")
            with self.assertRaisesRegex(ReleaseWorkflowError, r"PR base must descend from SOURCE_SHA"):
                _verify(root, base_sha=unrelated, head_sha=head_sha)
            with self.assertRaisesRegex(ReleaseWorkflowError, r"PR base must descend from SOURCE_SHA"):
                _verify(root, base_sha="ab" * 20, head_sha=head_sha)

    def test_rejects_output_head_that_is_not_direct_source_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_sha, head_sha, _manifest = _build_output_repo(root)
            extra_head = _run_git(root, "commit-tree", f"{head_sha}^{{tree}}", "-p", head_sha, "-m", "extra")
            with self.assertRaisesRegex(
                ReleaseWorkflowError,
                r"generated-output commit is not directly based on SOURCE_SHA",
            ):
                _verify(root, base_sha=source_sha, head_sha=extra_head)

    def test_rejects_merge_output_head(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_sha, head_sha, _manifest = _build_output_repo(root)
            _run_git(root, "checkout", "-q", "-B", "side", source_sha)
            _write_bytes(root, "side.txt", b"side\n")
            side_sha = _commit(root, "side")
            _run_git(root, "checkout", "-q", head_sha)
            _run_git(root, "merge", "--no-ff", "--no-edit", "-m", "merge-output", side_sha)
            merge_sha = _run_git(root, "rev-parse", "HEAD")
            with self.assertRaisesRegex(
                ReleaseWorkflowError,
                r"generated-output commit is not directly based on SOURCE_SHA",
            ):
                _verify(root, base_sha=source_sha, head_sha=merge_sha)

    def test_rejects_disallowed_output_only_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_sha, head_sha, _manifest = _build_output_repo(
                root,
                extra_output_files={"README.md": b"not allowed\n"},
            )
            with self.assertRaisesRegex(ReleaseWorkflowError, r"generated-output PR contains disallowed paths"):
                _verify(root, base_sha=source_sha, head_sha=head_sha)

    def test_rejects_disallowed_source_path_renamed_into_allowed_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _init_repo(root)
            _write_source_outputs(root)
            _write_bytes(root, "README.md", b"renamed-content\n")
            source_sha = _commit(root, "source")

            (root / "README.md").rename(root / "gamedata" / GAMEVER / "renamed.txt")
            _run_git(root, "add", "-A")
            _write_manifest(root, _tracked_manifest(root, source_sha))
            head_sha = _commit(root, "output-with-hidden-rename-source")

            with self.assertRaisesRegex(
                ReleaseWorkflowError,
                r"generated-output PR contains disallowed paths: README\.md",
            ):
                _verify(root, base_sha=source_sha, head_sha=head_sha)

    def test_rejects_branch_version_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_sha, head_sha, _manifest = _build_output_repo(root)
            _run_git(root, "checkout", "-q", head_sha)
            mismatched = _tracked_manifest(root, source_sha, version=OTHER_VERSION)
            _write_manifest(root, mismatched, version=VERSION)
            with self.assertRaisesRegex(ReleaseWorkflowError, r"output PR manifest identity does not match the branch"):
                _call(root, base_sha=source_sha, head_sha=head_sha)

    def test_rejects_output_that_does_not_change_release_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _init_repo(root)
            _write_source_outputs(root)
            source_sha = _commit(root, "source")
            manifest = _tracked_manifest(root, source_sha)
            _run_git(root, "commit", "--allow-empty", "-q", "-m", "output-without-manifest-delta")
            empty_head = _run_git(root, "rev-parse", "HEAD")
            _write_manifest(root, manifest)
            with self.assertRaisesRegex(
                ReleaseWorkflowError,
                rf"generated-output PR must change release-manifests/{VERSION}\.json",
            ):
                _call(root, base_sha=source_sha, head_sha=empty_head)

    def test_rejects_tampered_tracked_output_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_sha, head_sha, _manifest = _build_output_repo(root)
            _run_git(root, "checkout", "-q", head_sha)
            _write_bytes(root, f"gamesymbols/{GAMEVER}.yaml", b"tampered\n")
            _run_git(root, "add", f"gamesymbols/{GAMEVER}.yaml")
            with self.assertRaisesRegex(ReleaseWorkflowError, r"tracked output manifest hash mismatch"):
                _call(root, base_sha=source_sha, head_sha=head_sha)


class MaterializeAcceptedBinTests(unittest.TestCase):
    def _workspace(self, root: Path) -> tuple[Path, Path]:
        repo = root / "checkout"
        persisted = root / "persisted"
        (repo / "bin" / "hl-3248" / "engine").mkdir(parents=True)
        (repo / "bin" / "hl-3248" / "engine" / "tracked.txt").write_bytes(b"submodule tracked file")
        accepted = persisted / "bin" / "hl-3248" / "engine"
        accepted.mkdir(parents=True)
        (accepted / "hw.dll").write_bytes(b"accepted binary")
        (accepted / "hw.dll.i64").write_bytes(b"stale ida database")
        (accepted / "hw.dll.til").write_bytes(b"stale ida side file")
        return repo, persisted

    def test_overlays_durable_files_and_excludes_recoverable_analysis_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, persisted = self._workspace(Path(temporary))
            result = materialize_accepted_bin(repo_root=repo, persisted_root=persisted, gamever="hl-3248")
            target = repo / "bin" / "hl-3248" / "engine"
            self.assertTrue(result["materialized"])
            self.assertEqual(1, result["files"])
            self.assertEqual(durable_inventory(persisted / "bin" / "hl-3248")[1], result["hash"])
            self.assertEqual(b"accepted binary", (target / "hw.dll").read_bytes())
            self.assertEqual(b"submodule tracked file", (target / "tracked.txt").read_bytes())
            self.assertFalse((target / "hw.dll.i64").exists())
            self.assertFalse((target / "hw.dll.til").exists())

    def test_missing_persisted_tree_is_reported_without_touching_the_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, persisted = self._workspace(Path(temporary))
            (repo / "bin" / "hl-9999").mkdir()
            result = materialize_accepted_bin(repo_root=repo, persisted_root=persisted, gamever="hl-9999")
            self.assertEqual({"materialized": False, "gamever": "hl-9999", "files": 0, "hash": None}, result)
            self.assertEqual([], list((repo / "bin" / "hl-9999").iterdir()))

    def test_source_existence_is_checked_after_acquiring_the_gamever_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, persisted = self._workspace(Path(temporary))
            source = persisted / "bin" / "hl-3248"
            backup = persisted / "bin" / ".hl-3248.promotion-backup"
            source.rename(backup)

            @contextmanager
            def finish_promotion(_lock_path):
                backup.rename(source)
                yield

            with patch("release_workflow_lib.accepted_bin.version_lock", side_effect=finish_promotion) as lock:
                result = materialize_accepted_bin(
                    repo_root=repo,
                    persisted_root=persisted,
                    gamever="hl-3248",
                )
            lock.assert_called_once_with(accepted_bin_lock_path(persisted.resolve(), "hl-3248"))
            self.assertTrue(result["materialized"])
            self.assertEqual(b"accepted binary", (repo / "bin" / "hl-3248" / "engine" / "hw.dll").read_bytes())

    def test_materialization_uses_the_same_per_gamever_authority_as_promotion(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, persisted = self._workspace(Path(temporary))
            lock_path = accepted_bin_lock_path(persisted.resolve(), "hl-3248")
            self.assertEqual(
                (persisted.resolve() / "release-staging" / "locks" / "hl-3248.lock"),
                lock_path,
            )
            with version_lock(lock_path), self.assertRaisesRegex(ReleaseWorkflowError, "lock"):
                materialize_accepted_bin(repo_root=repo, persisted_root=persisted, gamever="hl-3248")

    def test_rejects_a_checkout_without_the_bin_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            _repo, persisted = self._workspace(Path(temporary))
            empty = Path(temporary) / "empty"
            empty.mkdir()
            with self.assertRaisesRegex(ReleaseWorkflowError, "checkout bin directory"):
                materialize_accepted_bin(repo_root=empty, persisted_root=persisted, gamever="hl-3248")


if __name__ == "__main__":
    unittest.main()
