from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
import urllib.request
import zipfile
from io import BytesIO
from pathlib import Path

from gamesymbol_snapshot_lib.metadata import write_metadata
from gamesymbol_snapshot_lib.operations import pack_snapshot
from release_workflow_lib.assets import build_checksum_asset, build_payload_assets, build_provenance_asset
from release_workflow_lib.content import (
    CONFIG_CONTRACT_PATHS,
    RELEASE_TOOL_CONTRACT_PATHS,
    build_content_manifest,
    verify_content_manifest,
)
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.git_objects import GitObjectRepository
from release_workflow_lib.github_api import GitHubApiError, _SafeRedirectHandler
from release_workflow_lib.hashing import canonical_json_bytes, sha256_bytes
from release_workflow_lib.manifest import parse_content_manifest_bytes
from release_workflow_lib.output import prepare_output_build, verify_output_pull_request
from release_workflow_lib.promotion import promote_release, republish_release, verify_promotion_merge
from release_workflow_lib.recovery import (
    authorize_retry,
    cleanup_completed_stage,
    load_completion_record,
    reconcile_release,
)
from release_workflow_lib.shadow import run_shadow_verification
from release_workflow_lib.staging import (
    advance_stage,
    bind_pull_request,
    build_stage_root,
    create_building_stage,
    load_marker,
    repair_pr_index,
)
from tests.test_support import write_config, write_pe32
from update_gamedata import generate_gamedata

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ".github/workflows/release-shadow.yml"
BUILD_WORKFLOW_PATH = ".github/workflows/release-build.yml"
PROMOTION_WORKFLOW_PATH = ".github/workflows/release-promotion.yml"


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        check=True,
    )
    return result.stdout.decode("utf-8").strip()


def commit_all(root: Path, message: str) -> str:
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", message)
    return git(root, "rev-parse", "HEAD")


def create_release_repository(root: Path, tags: tuple[str, ...] = ("game-1",)) -> str:
    root.mkdir(parents=True)
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.email", "test@example.com")
    git(root, "config", "user.name", "Test")
    source_paths = set(CONFIG_CONTRACT_PATHS) | set(RELEASE_TOOL_CONTRACT_PATHS)
    for relative in sorted(source_paths):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(PROJECT_ROOT / relative, destination)
    workflow = root / WORKFLOW_PATH
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text("name: Release shadow\n", encoding="utf-8")
    working = root.parent / f"{root.name}-binary-work"
    (root / "configs").mkdir()
    for tag in tags:
        config = write_config(root / "configs" / f"{tag}.yaml", both_platforms=False)
        config.write_bytes(config.read_bytes().replace(b"\r\n", b"\n"))
        binary = write_pe32(working / "bin" / tag / "engine" / "hw.dll", tag.encode("ascii"))
        snapshot = root / "gamesymbols" / f"{tag}.yaml"
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        pack_snapshot(
            tag,
            working / "bin",
            config,
            snapshot,
            last_publish_time="2026-01-02T03:04:05Z",
        )
        self_check = snapshot.read_bytes()
        if not binary.is_file() or not self_check:
            raise AssertionError("Invalid release test fixture")
        write_metadata(
            snapshot_path=snapshot,
            config_path=config,
            game_version=tag,
            output_path=root / "gamesymbols" / f"{tag}.metadata.yaml",
        )
        generate_gamedata(
            gamever=tag,
            snapshot_path=snapshot,
            config_path=config,
            modules_dir=root / "gamedata-generators",
            output_root=root / "gamedata" / tag,
        )
    seed = commit_all(root, "seed release inputs")
    git(root, "update-index", "--add", "--cacheinfo", "160000", seed, "bin")
    git(root, "commit", "-q", "-m", "bind bin gitlink")
    return git(root, "rev-parse", "HEAD")


def build(root: Path, tag: str = "game-1") -> dict:
    return build_content_manifest(
        repo=GitObjectRepository(root),
        source_ref="main",
        tag=tag,
        repository_id=12345,
        workflow_repository="owner/repository",
        workflow_path=WORKFLOW_PATH,
        workflow_ref="main",
    )


def create_merge_commit(root: Path, source_sha: str, head_sha: str) -> str:
    tree = git(root, "rev-parse", f"{head_sha}^{{tree}}")
    return git(root, "commit-tree", tree, "-p", source_sha, "-p", head_sha, "-m", "merge output")


def prepare_output_release(root: Path, persisted_root: Path) -> tuple[GitObjectRepository, dict, dict]:
    source_sha = create_release_repository(root)
    repo = GitObjectRepository(root)
    output = prepare_output_build(
        repo=repo,
        source_ref=source_sha,
        tag="game-1",
        build_id="run-1",
        repository_id=12345,
        repository="owner/repository",
        base_ref="main",
        workflow_repository="owner/repository",
        workflow_path=BUILD_WORKFLOW_PATH,
        workflow_ref=source_sha,
        persisted_root=persisted_root,
        run_id="100",
        run_attempt=1,
        lease_owner="build-100-1",
        output_path=persisted_root / "output-build.json",
    )
    bind_pull_request(
        persisted_root=persisted_root,
        tag="game-1",
        build_id="run-1",
        pr_number=17,
        pr_head_sha=output["output_head_sha"],
        pr_base_sha=source_sha,
    )
    merge_sha = create_merge_commit(root, source_sha, output["output_head_sha"])
    git(root, "update-ref", "refs/heads/main", merge_sha)
    approval = verify_promotion_merge(
        repo=repo,
        merge_ref=merge_sha,
        default_ref="main",
        head_ref=output["output_head_sha"],
        pr_number=17,
        head_branch=output["output_branch"],
        base_branch="main",
        expected_base_branch="main",
        repository_id=12345,
        repository="owner/repository",
        expected_repository_id=12345,
        expected_repository="owner/repository",
        head_repository="owner/repository",
        author_login="release-app[bot]",
        expected_author_login="release-app[bot]",
        workflow_repository="owner/repository",
        build_workflow_path=BUILD_WORKFLOW_PATH,
        build_workflow_ref=source_sha,
        persisted_root=persisted_root,
    )
    return repo, output, approval


class FakeReleaseApi:
    def __init__(self, *, fail_upload_number: int | None = None):
        self.tags = {}
        self.release = None
        self.asset_bytes = {}
        self.next_asset_id = 100
        self.upload_count = 0
        self.fail_upload_number = fail_upload_number

    def get_annotated_tag(self, tag: str):
        return self.tags.get(tag)

    def create_annotated_tag(self, *, tag: str, target_sha: str, message: str):
        del message
        identity = {"object_sha": sha256_bytes(tag.encode("utf-8"))[:40], "target_sha": target_sha}
        existing = self.tags.get(tag)
        if existing is not None and existing != identity:
            raise AssertionError("tag target drift")
        self.tags[tag] = identity
        return identity

    def get_release(self, tag: str):
        if self.release is not None and self.release["tag_name"] == tag:
            return self.refresh_release(self.release["id"])
        return None

    def create_draft_release(self, *, tag: str, target_sha: str, name: str):
        del name
        if self.release is None:
            self.release = {"id": 7, "tag_name": tag, "target_commitish": target_sha, "draft": True, "assets": []}
        return self.refresh_release(self.release["id"])

    @staticmethod
    def asset_by_name(release: dict, name: str):
        matches = [asset for asset in release["assets"] if asset["name"] == name]
        if len(matches) > 1:
            raise AssertionError("duplicate fake asset")
        return matches[0] if matches else None

    def upload_asset(self, *, release: dict, name: str, raw: bytes):
        del release
        self.upload_count += 1
        if self.fail_upload_number == self.upload_count:
            self.fail_upload_number = None
            raise RuntimeError("injected upload interruption")
        asset = {"id": self.next_asset_id, "name": name}
        self.next_asset_id += 1
        self.release["assets"].append(asset)
        self.asset_bytes[asset["id"]] = raw
        return asset

    def download_asset(self, asset: dict) -> bytes:
        return self.asset_bytes[asset["id"]]

    def delete_asset(self, asset_id: int) -> None:
        self.release["assets"] = [asset for asset in self.release["assets"] if asset["id"] != asset_id]
        self.asset_bytes.pop(asset_id)

    def refresh_release(self, release_id: int):
        if self.release is None or self.release["id"] != release_id:
            raise AssertionError("unknown fake release")
        return {**self.release, "assets": [dict(asset) for asset in self.release["assets"]]}

    def publish_release(self, release_id: int):
        if self.release["id"] != release_id:
            raise AssertionError("unknown fake release")
        self.release["draft"] = False
        return self.refresh_release(release_id)


class GitHubApiSecurityTests(unittest.TestCase):
    def test_cross_origin_redirect_strips_authorization_and_rejects_non_https(self):
        handler = _SafeRedirectHandler()
        request = urllib.request.Request(
            "https://api.github.com/repos/owner/repository/releases/assets/1",
            headers={"Authorization": "Bearer secret"},
        )
        redirected = handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://objects.example.test/release.bin",
        )
        self.assertIsNotNone(redirected)
        self.assertIsNone(redirected.get_header("Authorization"))
        same_origin = handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://api.github.com/download/1",
        )
        self.assertEqual("Bearer secret", same_origin.get_header("Authorization"))
        with self.assertRaises(GitHubApiError):
            handler.redirect_request(request, None, 302, "Found", {}, "http://objects.example.test/release.bin")


class ReleaseContentManifestTests(unittest.TestCase):
    def test_manifest_is_canonical_repeatable_and_binds_exact_git_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            create_release_repository(root)
            first = build(root)
            second = build(root)
            self.assertEqual(first, second)
            raw = canonical_json_bytes(first)
            self.assertEqual(first, parse_content_manifest_bytes(raw))
            self.assertEqual(git(root, "rev-parse", "HEAD"), first["source_sha"])
            self.assertEqual(git(root, "rev-parse", "HEAD:bin"), first["bin_gitlink_sha"])
            self.assertRegex(first["tracked_content_inventory_sha256"], r"^[0-9a-f]{64}$")
            self.assertNotIn("release-manifests", raw.decode("utf-8"))

    def test_content_inventory_excludes_tracked_release_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            create_release_repository(root)
            first = build(root)
            tracked = root / "release-manifests" / "game-1.json"
            tracked.parent.mkdir()
            tracked.write_bytes(canonical_json_bytes(first))
            git(root, "add", "release-manifests/game-1.json")
            git(root, "commit", "-q", "-m", "add release manifest")
            second = build(root)
            self.assertNotEqual(first["source_sha"], second["source_sha"])
            self.assertEqual(
                first["tracked_content_inventory_sha256"],
                second["tracked_content_inventory_sha256"],
            )

    def test_payload_tamper_extra_file_and_non_regular_mode_fail_closed(self):
        mutations = ("metadata", "config", "gamedata", "extra", "mode", "generator")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "repository"
                create_release_repository(root)
                if mutation == "metadata":
                    path = root / "gamesymbols" / "game-1.metadata.yaml"
                    path.write_bytes(path.read_bytes() + b"\n")
                elif mutation == "config":
                    path = root / "configs" / "game-1.yaml"
                    path.write_bytes(path.read_bytes() + b"# drift\n")
                elif mutation == "gamedata":
                    path = root / "gamedata" / "game-1" / "gamedata-manifest.json"
                    document = json.loads(path.read_bytes())
                    document["candidate_sha256"] = "0" * 64
                    path.write_bytes(canonical_json_bytes(document))
                elif mutation == "extra":
                    (root / "gamedata" / "game-1" / "extra.txt").write_text("extra\n", encoding="utf-8")
                elif mutation == "mode":
                    path = root / "gamesymbols" / "game-1.yaml"
                    git(root, "update-index", "--chmod=+x", path.relative_to(root).as_posix())
                else:
                    generator = root / "gamedata-generators" / "demo" / "gamedata.py"
                    generator.parent.mkdir(parents=True)
                    generator.write_text(
                        "MODULE_NAME = 'demo'\n"
                        "OUTPUT_PATHS = ('value.txt',)\n"
                        "def update(store, output_dir):\n"
                        "    (output_dir / 'value.txt').write_text('value', encoding='utf-8')\n",
                        encoding="utf-8",
                    )
                if mutation == "mode":
                    git(root, "commit", "-q", "-m", "tamper mode")
                else:
                    commit_all(root, f"tamper {mutation}")
                with self.assertRaises((ReleaseWorkflowError, ValueError)):
                    build(root)

    def test_manifest_schema_and_default_branch_drift_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            create_release_repository(root)
            document = build(root)
            raw = canonical_json_bytes(document)
            for mutation in (
                {**document, "unknown": True},
                {key: value for key, value in document.items() if key != "candidate_sha256"},
                {**document, "candidate_sha256": "SHA256:" + "0" * 64},
            ):
                with self.subTest(keys=tuple(mutation)), self.assertRaises(ReleaseWorkflowError):
                    parse_content_manifest_bytes(canonical_json_bytes(mutation))
            with self.assertRaises(ReleaseWorkflowError):
                parse_content_manifest_bytes(raw.rstrip(b"\n"))
            (root / "unrelated.txt").write_text("drift\n", encoding="utf-8")
            commit_all(root, "default branch drift")
            with self.assertRaises(ReleaseWorkflowError):
                verify_content_manifest(
                    repo=GitObjectRepository(root),
                    default_ref="main",
                    manifest_raw=raw,
                    repository_id=12345,
                    workflow_repository="owner/repository",
                    workflow_path=WORKFLOW_PATH,
                    workflow_ref="main",
                )


class ReleaseOutputAndStagingTests(unittest.TestCase):
    def test_output_commit_is_direct_parent_and_only_adds_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            persisted = Path(temporary) / "persisted"
            persisted.mkdir()
            repo, output, _approval = prepare_output_release(root, persisted)
            self.assertEqual((output["source_sha"],), repo.commit_parents(output["output_head_sha"]))
            self.assertEqual(
                ("release-manifests/game-1.json",), repo.changed_paths(output["source_sha"], output["output_head_sha"])
            )
            approval = verify_output_pull_request(
                repo=repo,
                base_ref=output["source_sha"],
                head_ref=output["output_head_sha"],
                pr_number=17,
                head_branch=output["output_branch"],
                base_branch="main",
                expected_base_branch="main",
                repository_id=12345,
                repository="owner/repository",
                expected_repository_id=12345,
                expected_repository="owner/repository",
                head_repository="owner/repository",
                author_login="release-app[bot]",
                expected_author_login="release-app[bot]",
                workflow_repository="owner/repository",
                workflow_path=BUILD_WORKFLOW_PATH,
                workflow_ref=output["source_sha"],
                persisted_root=persisted,
            )
            self.assertEqual(output["output_head_sha"], approval["head_sha"])

    def test_output_event_author_repository_and_shape_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            persisted = Path(temporary) / "persisted"
            persisted.mkdir()
            repo, output, _approval = prepare_output_release(root, persisted)
            defaults = {
                "repo": repo,
                "base_ref": output["source_sha"],
                "head_ref": output["output_head_sha"],
                "pr_number": 17,
                "head_branch": output["output_branch"],
                "base_branch": "main",
                "expected_base_branch": "main",
                "repository_id": 12345,
                "repository": "owner/repository",
                "expected_repository_id": 12345,
                "expected_repository": "owner/repository",
                "head_repository": "owner/repository",
                "author_login": "release-app[bot]",
                "expected_author_login": "release-app[bot]",
                "workflow_repository": "owner/repository",
                "workflow_path": BUILD_WORKFLOW_PATH,
                "workflow_ref": output["source_sha"],
                "persisted_root": persisted,
            }
            for mutation in (
                {"author_login": "attacker"},
                {"head_repository": "fork/repository"},
                {"repository_id": 999},
                {"head_branch": "gamesymbols/build/GAME-1/run-1"},
                {"base_branch": "release-target"},
            ):
                with self.subTest(mutation=mutation), self.assertRaises(ReleaseWorkflowError):
                    verify_output_pull_request(**(defaults | mutation))

    def test_marker_order_hash_chain_duplicate_pending_and_index_repair(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            persisted = Path(temporary) / "persisted"
            persisted.mkdir()
            repo, output, _approval = prepare_output_release(root, persisted)
            del repo
            stage = build_stage_root(persisted, "game-1", "run-1")
            ready, _raw = load_marker(stage, "READY")
            self.assertEqual(17, ready["bindings"]["pr_number"])
            index = persisted / "release-staging" / "pr-index" / "17.json"
            index.unlink()
            (stage / "READY.json").unlink()
            (stage / "PR_CREATED.json").unlink()
            repair_pr_index(
                persisted_root=persisted,
                tag="game-1",
                build_id="run-1",
                pr_number=17,
                repository_id=12345,
                repository="owner/repository",
                base_ref="main",
                output_branch_name=output["output_branch"],
                pr_head_sha=output["output_head_sha"],
                pr_base_sha=output["source_sha"],
                confirmation="repair-index:17:game-1:run-1",
            )
            self.assertTrue(index.is_file())
            load_marker(stage, "READY")
            head_path = stage / "HEAD_BOUND.json"
            original = head_path.read_bytes()
            document = json.loads(original)
            document["bindings"]["output_head_sha"] = "0" * 40
            head_path.write_bytes(canonical_json_bytes(document))
            with self.assertRaisesRegex(ReleaseWorkflowError, "hash chain"):
                load_marker(stage, "READY")
            head_path.write_bytes(original)
            manifest_raw = (stage / "content-manifest.json").read_bytes()
            with self.assertRaisesRegex(ReleaseWorkflowError, "Another active"):
                create_building_stage(
                    persisted_root=persisted,
                    manifest_raw=manifest_raw,
                    build_id="run-2",
                    repository_id=12345,
                    repository="owner/repository",
                    base_ref="main",
                    run_id="101",
                    run_attempt=1,
                    lease_owner="build-101-1",
                )
            authorize_retry(
                persisted_root=persisted,
                tag="game-1",
                build_id="run-1",
                new_build_id="run-2",
                reason="retry test",
            )
            replacement, _marker = create_building_stage(
                persisted_root=persisted,
                manifest_raw=manifest_raw,
                build_id="run-2",
                repository_id=12345,
                repository="owner/repository",
                base_ref="main",
                run_id="101",
                run_attempt=1,
                lease_owner="build-101-1",
            )
            self.assertTrue((replacement / "BUILDING.json").is_file())

    def test_stage_transition_cannot_skip_predecessor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            persisted = Path(temporary) / "persisted"
            persisted.mkdir()
            create_release_repository(root)
            manifest_raw = canonical_json_bytes(build(root))
            stage, _marker = create_building_stage(
                persisted_root=persisted,
                manifest_raw=manifest_raw,
                build_id="run-1",
                repository_id=12345,
                repository="owner/repository",
                base_ref="main",
                run_id="100",
                run_attempt=1,
                lease_owner="build-100-1",
            )
            with self.assertRaises(ReleaseWorkflowError):
                advance_stage(stage, "PR_CREATED")


class ReleasePromotionTests(unittest.TestCase):
    def test_two_parent_merge_and_deterministic_assets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            persisted = Path(temporary) / "persisted"
            persisted.mkdir()
            repo, output, approval = prepare_output_release(root, persisted)
            self.assertEqual(
                (output["source_sha"], output["output_head_sha"]), repo.commit_parents(approval["merge_sha"])
            )
            first = build_payload_assets(repo, approval["merge_sha"], "game-1")
            second = build_payload_assets(repo, approval["merge_sha"], "game-1")
            self.assertEqual(
                [(asset["name"], asset["sha256"]) for asset in first],
                [(asset["name"], asset["sha256"]) for asset in second],
            )
            archive = next(asset["bytes"] for asset in first if asset["name"].endswith(".zip"))
            with zipfile.ZipFile(BytesIO(archive)) as opened:
                self.assertEqual(sorted(opened.namelist()), opened.namelist())
                self.assertTrue(all(info.date_time == (1980, 1, 1, 0, 0, 0) for info in opened.infolist()))
            provenance = build_provenance_asset(
                tag="game-1",
                content_manifest_sha256=approval["content_manifest_sha256"],
                source_sha=approval["source_sha"],
                output_head_sha=approval["output_head_sha"],
                merge_sha=approval["merge_sha"],
                workflow_repository="owner/repository",
                workflow_path=PROMOTION_WORKFLOW_PATH,
                workflow_ref_sha=approval["source_sha"],
                run_id="200",
                run_attempt=1,
                pr_number=17,
                tag_object_sha="a" * 40,
                tag_target_sha=approval["merge_sha"],
                release_id=7,
                payload_assets=first,
            )
            checksum = build_checksum_asset("game-1", [*first, provenance])
            self.assertNotIn(checksum["name"], checksum["bytes"].decode("utf-8"))
            with self.assertRaisesRegex(ReleaseWorkflowError, "not reachable"):
                verify_promotion_merge(
                    repo=repo,
                    merge_ref=approval["merge_sha"],
                    default_ref=output["source_sha"],
                    head_ref=output["output_head_sha"],
                    pr_number=17,
                    head_branch=output["output_branch"],
                    base_branch="main",
                    expected_base_branch="main",
                    repository_id=12345,
                    repository="owner/repository",
                    expected_repository_id=12345,
                    expected_repository="owner/repository",
                    head_repository="owner/repository",
                    author_login="release-app[bot]",
                    expected_author_login="release-app[bot]",
                    workflow_repository="owner/repository",
                    build_workflow_path=BUILD_WORKFLOW_PATH,
                    build_workflow_ref=output["source_sha"],
                    persisted_root=persisted,
                )

    def test_new_promotion_rejects_preexisting_remote_state_and_resume_rejects_extra_assets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            persisted = Path(temporary) / "persisted"
            persisted.mkdir()
            repo, _output, approval = prepare_output_release(root, persisted)
            arguments = {
                "repo": repo,
                "approval": approval,
                "expected_approval_sha256": approval["approval_sha256"],
                "persisted_root": persisted,
                "workflow_repository": "owner/repository",
                "workflow_path": PROMOTION_WORKFLOW_PATH,
                "workflow_ref_sha": approval["source_sha"],
                "run_id": "200",
                "run_attempt": 1,
                "output_dir": Path(temporary) / "promotion",
            }
            preexisting = FakeReleaseApi()
            preexisting.create_annotated_tag(tag="game-1", target_sha=approval["merge_sha"], message="existing")
            with self.assertRaisesRegex(ReleaseWorkflowError, "requires.*absent"):
                promote_release(api=preexisting, **arguments)

            interrupted = FakeReleaseApi(fail_upload_number=1)
            with self.assertRaises(RuntimeError):
                promote_release(api=interrupted, **arguments)
            extra = {"id": 999, "name": "undeclared.exe"}
            interrupted.release["assets"].append(extra)
            interrupted.asset_bytes[999] = b"undeclared"
            with self.assertRaisesRegex(ReleaseWorkflowError, "undeclared assets"):
                promote_release(api=interrupted, **arguments)

    def test_promotion_interruption_resumes_and_republish_repairs_asset(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            persisted = Path(temporary) / "persisted"
            persisted.mkdir()
            repo, _output, approval = prepare_output_release(root, persisted)
            api = FakeReleaseApi(fail_upload_number=2)
            arguments = {
                "repo": repo,
                "api": api,
                "approval": approval,
                "expected_approval_sha256": approval["approval_sha256"],
                "persisted_root": persisted,
                "workflow_repository": "owner/repository",
                "workflow_path": PROMOTION_WORKFLOW_PATH,
                "workflow_ref_sha": approval["source_sha"],
                "run_id": "200",
                "run_attempt": 1,
                "output_dir": Path(temporary) / "promotion",
            }
            with self.assertRaisesRegex(RuntimeError, "injected"):
                promote_release(**arguments)
            stage = build_stage_root(persisted, "game-1", "run-1")
            load_marker(stage, "PROMOTION_STARTED")
            self.assertFalse((stage / "PROMOTED.json").exists())
            result = promote_release(**(arguments | {"run_id": "201", "run_attempt": 2}))
            self.assertEqual(7, result["release_id"])
            load_marker(stage, "PROMOTION_COMPLETE")
            completion = load_completion_record(persisted_root=persisted, tag="game-1", build_id="run-1")
            victim = api.release["assets"][0]
            api.asset_bytes[victim["id"]] = b"tampered"
            reconciliation = reconcile_release(persisted_root=persisted, tag="game-1", build_id="run-1", api=api)
            self.assertTrue(any("hash differs" in difference for difference in reconciliation["differences"]))
            republished = republish_release(
                repo=repo,
                api=api,
                completion_record=completion,
                persisted_root=persisted,
                output_dir=Path(temporary) / "republish",
            )
            self.assertEqual(completion["promotion"]["release_assets_sha256"], republished["release_assets_sha256"])
            self.assertEqual(
                [],
                reconcile_release(persisted_root=persisted, tag="game-1", build_id="run-1", api=api)["differences"],
            )

    def test_cleanup_requires_completion_then_moves_stage_and_index_to_trash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            persisted = Path(temporary) / "persisted"
            persisted.mkdir()
            repo, _output, approval = prepare_output_release(root, persisted)
            with self.assertRaises(ReleaseWorkflowError):
                cleanup_completed_stage(
                    persisted_root=persisted,
                    tag="game-1",
                    build_id="run-1",
                    confirmation="cleanup:game-1:run-1",
                )
            promote_release(
                repo=repo,
                api=FakeReleaseApi(),
                approval=approval,
                expected_approval_sha256=approval["approval_sha256"],
                persisted_root=persisted,
                workflow_repository="owner/repository",
                workflow_path=PROMOTION_WORKFLOW_PATH,
                workflow_ref_sha=approval["source_sha"],
                run_id="200",
                run_attempt=1,
                output_dir=Path(temporary) / "promotion",
            )
            target = cleanup_completed_stage(
                persisted_root=persisted,
                tag="game-1",
                build_id="run-1",
                confirmation="cleanup:game-1:run-1",
            )
            self.assertTrue((target / "PROMOTION_COMPLETE.json").is_file())
            self.assertTrue((target / "PR_INDEX.json").is_file())
            self.assertEqual(
                target,
                cleanup_completed_stage(
                    persisted_root=persisted,
                    tag="game-1",
                    build_id="run-1",
                    confirmation="cleanup:game-1:run-1",
                ),
            )


class ReleaseShadowTests(unittest.TestCase):
    def test_shadow_verifies_three_new_tags_without_mutating_repository(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            tags = ("game-1", "game-2", "game-3")
            source_sha = create_release_repository(root, tags)
            output = Path(temporary) / "evidence"
            before = git(root, "status", "--porcelain=v1")
            evidence = run_shadow_verification(
                repo=GitObjectRepository(root),
                default_ref="main",
                tags=tags,
                repository_id=12345,
                workflow_repository="owner/repository",
                workflow_path=WORKFLOW_PATH,
                workflow_ref="main",
                output_dir=output,
            )
            self.assertEqual(source_sha, evidence["source_sha"])
            self.assertEqual(["new", "new", "new"], [item["mode_decision"] for item in evidence["results"]])
            self.assertTrue((output / "shadow-evidence.json").is_file())
            self.assertEqual(before, git(root, "status", "--porcelain=v1"))


if __name__ == "__main__":
    unittest.main()
