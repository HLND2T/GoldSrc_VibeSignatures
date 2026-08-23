from __future__ import annotations

from pathlib import Path

from pull_request_route import PullRequestRouteError, parse_output_branch
from release_workflow_lib.content import build_content_manifest, verify_content_manifest
from release_workflow_lib.errors import ContentMismatchError, ReleaseWorkflowError
from release_workflow_lib.git_objects import GitObjectRepository
from release_workflow_lib.hashing import canonical_json_bytes, sha256_bytes, write_canonical_json
from release_workflow_lib.manifest import parse_content_manifest_bytes
from release_workflow_lib.staging import (
    advance_stage,
    build_stage_root,
    create_building_stage,
    load_marker,
    load_pr_index,
    output_branch,
    validated_build_id,
)


class ReleaseOutputError(ReleaseWorkflowError):
    pass


def prepare_output_build(
    *,
    repo: GitObjectRepository,
    source_ref: str,
    tag: str,
    build_id: str,
    repository_id: int,
    repository: str,
    base_ref: str,
    workflow_repository: str,
    workflow_path: str,
    workflow_ref: str,
    persisted_root: str | Path,
    run_id: str,
    run_attempt: int,
    lease_owner: str,
    output_path: str | Path,
) -> dict:
    build_id = validated_build_id(build_id)
    source_sha = repo.resolve_commit(source_ref)
    if source_sha != repo.resolve_commit(workflow_ref):
        raise ReleaseOutputError("Release build workflow ref must be the exact source commit")
    manifest_path = f"release-manifests/{tag}.json"
    if repo.entry(source_sha, manifest_path) is not None:
        raise ReleaseOutputError(f"Release content manifest already exists at source: {manifest_path}")
    document = build_content_manifest(
        repo=repo,
        source_ref=source_sha,
        tag=tag,
        repository_id=repository_id,
        workflow_repository=workflow_repository,
        workflow_path=workflow_path,
        workflow_ref=source_sha,
    )
    manifest_raw = canonical_json_bytes(document)
    stage_root, _building = create_building_stage(
        persisted_root=persisted_root,
        manifest_raw=manifest_raw,
        build_id=build_id,
        repository_id=repository_id,
        repository=repository,
        base_ref=base_ref,
        run_id=run_id,
        run_attempt=run_attempt,
        lease_owner=lease_owner,
    )
    output_head_sha = repo.create_commit_with_blob(
        parent_ref=source_sha,
        path=manifest_path,
        raw=manifest_raw,
        message=f"chore(release): stage {tag} content manifest",
    )
    head = advance_stage(stage_root, "HEAD_BOUND", binding_updates={"output_head_sha": output_head_sha})
    result = {
        "schema_version": 1,
        "tag": tag,
        "build_id": build_id,
        "source_sha": source_sha,
        "output_branch": output_branch(tag, build_id),
        "output_head_sha": output_head_sha,
        "manifest_path": manifest_path,
        "content_manifest_sha256": head["content_manifest_sha256"],
    }
    write_canonical_json(output_path, result)
    return result


def validate_output_event(
    *,
    repository_id: int,
    repository: str,
    head_repository: str,
    head_ref: str,
    base_ref: str,
    expected_base_ref: str,
    author_login: str,
    expected_repository_id: int,
    expected_repository: str,
    expected_author_login: str,
) -> tuple[str, str]:
    if repository_id != expected_repository_id or repository != expected_repository:
        raise ReleaseOutputError("Output PR event repository identity is untrusted")
    if head_repository != expected_repository:
        raise ReleaseOutputError("Output PR head repository must be the protected source repository")
    if author_login != expected_author_login or not expected_author_login:
        raise ReleaseOutputError("Output PR author is not the configured release App/bot")
    if base_ref != expected_base_ref or not expected_base_ref:
        raise ReleaseOutputError("Output PR base branch is not the configured default branch")
    try:
        identity = parse_output_branch(head_ref)
    except PullRequestRouteError as exc:
        raise ReleaseOutputError(str(exc)) from exc
    if identity is None:
        raise ReleaseOutputError("Pull request is not a generated-output branch")
    return identity


def _approval_digest(document: dict) -> str:
    return sha256_bytes(canonical_json_bytes({"domain": "goldsrc-release-output-approval:v1", **document}))


def verify_output_pull_request(
    *,
    repo: GitObjectRepository,
    base_ref: str,
    head_ref: str,
    pr_number: int,
    head_branch: str,
    base_branch: str,
    expected_base_branch: str,
    repository_id: int,
    repository: str,
    expected_repository_id: int,
    expected_repository: str,
    head_repository: str,
    author_login: str,
    expected_author_login: str,
    workflow_repository: str,
    workflow_path: str,
    workflow_ref: str,
    persisted_root: str | Path,
) -> dict:
    tag, build_id = validate_output_event(
        repository_id=repository_id,
        repository=repository,
        head_repository=head_repository,
        head_ref=head_branch,
        base_ref=base_branch,
        expected_base_ref=expected_base_branch,
        author_login=author_login,
        expected_repository_id=expected_repository_id,
        expected_repository=expected_repository,
        expected_author_login=expected_author_login,
    )
    base_sha = repo.resolve_commit(base_ref)
    head_sha = repo.resolve_commit(head_ref)
    if repo.commit_parents(head_sha) != (base_sha,):
        raise ReleaseOutputError("Output head must have the exact current base as its only parent")
    manifest_path = f"release-manifests/{tag}.json"
    if repo.changed_paths(base_sha, head_sha) != (manifest_path,):
        raise ReleaseOutputError("Phase 2 output commit may only add the current tag release manifest")
    if repo.entry(base_sha, manifest_path) is not None:
        raise ReleaseOutputError("Source commit already contains the release manifest")
    manifest_raw = repo.read_blob(head_sha, manifest_path, required_mode="100644")
    manifest = parse_content_manifest_bytes(manifest_raw)
    if manifest["game_version"] != tag or manifest["source_sha"] != base_sha:
        raise ReleaseOutputError("Output manifest tag/source identity does not match the PR")
    verify_content_manifest(
        repo=repo,
        default_ref=base_sha,
        manifest_raw=manifest_raw,
        repository_id=repository_id,
        workflow_repository=workflow_repository,
        workflow_path=workflow_path,
        workflow_ref=workflow_ref,
    )
    stage_root = build_stage_root(persisted_root, tag, build_id)
    ready, _ready_raw = load_marker(stage_root, "READY")
    index = load_pr_index(persisted_root, pr_number)
    expected_bindings = {
        "output_branch": head_branch,
        "output_head_sha": head_sha,
        "pr_number": pr_number,
        "pr_head_sha": head_sha,
        "pr_base_sha": base_sha,
        "source_sha": base_sha,
        "base_ref": expected_base_branch,
    }
    for field, expected in expected_bindings.items():
        if ready["bindings"].get(field) != expected:
            raise ReleaseOutputError(f"READY binding mismatch for {field}")
    expected_index = {
        "repository_id": repository_id,
        "repository": repository,
        "base_ref": expected_base_branch,
        "tag": tag,
        "build_id": build_id,
        "output_branch": head_branch,
        "pr_number": pr_number,
        "pr_head_sha": head_sha,
        "pr_base_sha": base_sha,
        "content_manifest_sha256": sha256_bytes(manifest_raw),
    }
    for field, expected in expected_index.items():
        if index.get(field) != expected:
            raise ReleaseOutputError(f"Private PR index mismatch for {field}")
    try:
        private_manifest = (stage_root / "content-manifest.json").read_bytes()
    except OSError as exc:
        raise ReleaseOutputError(f"Private staged manifest is unavailable: {exc}") from exc
    if private_manifest != manifest_raw or ready["content_manifest_sha256"] != sha256_bytes(manifest_raw):
        raise ContentMismatchError("Private/tracked release content manifests differ")
    approval = {
        "schema_version": 1,
        "repository_id": repository_id,
        "repository": repository,
        "pr_number": pr_number,
        "tag": tag,
        "build_id": build_id,
        "base_sha": base_sha,
        "base_ref": expected_base_branch,
        "head_sha": head_sha,
        "content_manifest_sha256": sha256_bytes(manifest_raw),
    }
    approval["approval_sha256"] = _approval_digest(approval)
    return approval
