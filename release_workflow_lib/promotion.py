from __future__ import annotations

from pathlib import Path

from analysis_config import validated_tag
from release_workflow_lib.assets import (
    build_checksum_asset,
    build_payload_assets,
    build_provenance_asset,
    write_assets,
)
from release_workflow_lib.errors import ContentMismatchError, ReleaseWorkflowError
from release_workflow_lib.git_objects import GitObjectRepository
from release_workflow_lib.hashing import canonical_json_bytes, inventory_sha256, sha256_bytes, write_canonical_json
from release_workflow_lib.output import validate_output_event, verify_output_pull_request
from release_workflow_lib.staging import (
    advance_stage,
    build_stage_root,
    load_marker,
    release_tag_lock,
    write_completion_record,
)


class ReleasePromotionError(ReleaseWorkflowError):
    pass


def _promotion_approval_digest(document: dict) -> str:
    return sha256_bytes(canonical_json_bytes({"domain": "goldsrc-release-promotion-approval:v1", **document}))


def verify_promotion_merge(
    *,
    repo: GitObjectRepository,
    merge_ref: str,
    default_ref: str,
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
    build_workflow_path: str,
    build_workflow_ref: str,
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
    merge_sha = repo.resolve_commit(merge_ref)
    if not repo.is_ancestor(merge_sha, default_ref):
        raise ReleasePromotionError("Merged output commit is not reachable from the configured default branch")
    head_sha = repo.resolve_commit(head_ref)
    parents = repo.commit_parents(merge_sha)
    if len(parents) != 2 or parents[1] != head_sha:
        raise ReleasePromotionError("Promotion requires a two-parent merge commit with the exact output head second")
    source_sha = parents[0]
    if repo.commit_parents(head_sha) != (source_sha,):
        raise ReleasePromotionError("Output head must directly parent the exact pre-merge base")
    output_approval = verify_output_pull_request(
        repo=repo,
        base_ref=source_sha,
        head_ref=head_sha,
        pr_number=pr_number,
        head_branch=head_branch,
        base_branch=base_branch,
        expected_base_branch=expected_base_branch,
        repository_id=repository_id,
        repository=repository,
        expected_repository_id=expected_repository_id,
        expected_repository=expected_repository,
        head_repository=head_repository,
        author_login=author_login,
        expected_author_login=expected_author_login,
        workflow_repository=workflow_repository,
        workflow_path=build_workflow_path,
        workflow_ref=build_workflow_ref,
        persisted_root=persisted_root,
    )
    manifest_path = f"release-manifests/{tag}.json"
    if repo.changed_paths(source_sha, merge_sha) != (manifest_path,):
        raise ReleasePromotionError("Merged output tree changed files outside the Phase 2 manifest allowlist")
    head_manifest = repo.read_blob(head_sha, manifest_path, required_mode="100644")
    merge_manifest = repo.read_blob(merge_sha, manifest_path, required_mode="100644")
    if head_manifest != merge_manifest:
        raise ContentMismatchError("Merge tree release manifest differs from the verified output head")
    approval = {
        "schema_version": 1,
        "repository_id": repository_id,
        "repository": repository,
        "pr_number": pr_number,
        "tag": tag,
        "build_id": build_id,
        "source_sha": source_sha,
        "base_ref": expected_base_branch,
        "output_head_sha": head_sha,
        "merge_sha": merge_sha,
        "content_manifest_sha256": sha256_bytes(merge_manifest),
        "output_approval_sha256": output_approval["approval_sha256"],
    }
    approval["approval_sha256"] = _promotion_approval_digest(approval)
    return approval


def _ensure_promotion_started(
    *,
    stage_root: Path,
    approval: dict,
    run_id: str,
    run_attempt: int,
    workflow_repository: str,
    workflow_path: str,
    workflow_ref_sha: str,
) -> dict:
    marker_path = stage_root / "PROMOTION_STARTED.json"
    if marker_path.is_file():
        marker, _raw = load_marker(stage_root, "PROMOTION_STARTED")
        expected = {
            "merge_sha": approval["merge_sha"],
            "promotion_run_id": marker["bindings"]["promotion_run_id"],
            "promotion_run_attempt": marker["bindings"]["promotion_run_attempt"],
        }
        if marker["bindings"]["merge_sha"] != expected["merge_sha"]:
            raise ReleasePromotionError("Existing promotion marker binds another merge commit")
        return marker
    return advance_stage(
        stage_root,
        "PROMOTION_STARTED",
        binding_updates={
            "merge_sha": approval["merge_sha"],
            "promotion_run_id": run_id,
            "promotion_run_attempt": run_attempt,
            "promotion_workflow_repository": workflow_repository,
            "promotion_workflow_path": workflow_path,
            "promotion_workflow_ref_sha": workflow_ref_sha,
        },
    )


def promote_release(**arguments) -> dict:
    approval = arguments.get("approval")
    if not isinstance(approval, dict) or not isinstance(approval.get("tag"), str):
        raise ReleasePromotionError("Promotion approval tag is missing")
    with release_tag_lock(arguments["persisted_root"], approval["tag"]):
        return _promote_release(**arguments)


def _promote_release(
    *,
    repo: GitObjectRepository,
    api,
    approval: dict,
    expected_approval_sha256: str,
    persisted_root: str | Path,
    workflow_repository: str,
    workflow_path: str,
    workflow_ref_sha: str,
    run_id: str,
    run_attempt: int,
    output_dir: str | Path,
) -> dict:
    if approval.get("approval_sha256") != expected_approval_sha256:
        raise ReleasePromotionError("Promotion writer approval digest mismatch")
    unsigned = {key: value for key, value in approval.items() if key != "approval_sha256"}
    if _promotion_approval_digest(unsigned) != expected_approval_sha256:
        raise ReleasePromotionError("Promotion approval document was tampered")
    stage_root = build_stage_root(persisted_root, approval["tag"], approval["build_id"])
    resuming = (stage_root / "PROMOTION_STARTED.json").is_file()
    if not resuming and (
        api.get_annotated_tag(approval["tag"]) is not None or api.get_release(approval["tag"]) is not None
    ):
        raise ReleasePromotionError("A new promotion requires the release tag and GitHub Release to be absent")
    existing_release = api.get_release(approval["tag"]) if resuming else None
    if (
        existing_release is not None
        and not existing_release.get("draft", False)
        and not (stage_root / "PROMOTED.json").is_file()
    ):
        raise ReleasePromotionError("A published GitHub Release cannot be repaired before PROMOTED")
    started = _ensure_promotion_started(
        stage_root=stage_root,
        approval=approval,
        run_id=run_id,
        run_attempt=run_attempt,
        workflow_repository=workflow_repository,
        workflow_path=workflow_path,
        workflow_ref_sha=workflow_ref_sha,
    )
    promotion_run_id = started["bindings"]["promotion_run_id"]
    promotion_run_attempt = started["bindings"]["promotion_run_attempt"]
    promotion_workflow_repository = started["bindings"]["promotion_workflow_repository"]
    promotion_workflow_path = started["bindings"]["promotion_workflow_path"]
    promotion_workflow_ref_sha = started["bindings"]["promotion_workflow_ref_sha"]
    tag_identity = api.create_annotated_tag(
        tag=approval["tag"],
        target_sha=approval["merge_sha"],
        message=f"GoldSrc VibeSignatures release {approval['tag']}",
    )
    if tag_identity["target_sha"] != approval["merge_sha"]:
        raise ReleasePromotionError("Immutable release tag target mismatch")
    release = api.create_draft_release(
        tag=approval["tag"],
        target_sha=approval["merge_sha"],
        name=approval["tag"],
    )
    release_id = release.get("id")
    if not isinstance(release_id, int) or isinstance(release_id, bool) or release_id < 1:
        raise ReleasePromotionError("GitHub Release ID is invalid")
    payload_assets = build_payload_assets(repo, approval["merge_sha"], approval["tag"])
    provenance = build_provenance_asset(
        tag=approval["tag"],
        content_manifest_sha256=approval["content_manifest_sha256"],
        source_sha=approval["source_sha"],
        output_head_sha=approval["output_head_sha"],
        merge_sha=approval["merge_sha"],
        workflow_repository=promotion_workflow_repository,
        workflow_path=promotion_workflow_path,
        workflow_ref_sha=promotion_workflow_ref_sha,
        run_id=promotion_run_id,
        run_attempt=promotion_run_attempt,
        pr_number=approval["pr_number"],
        tag_object_sha=tag_identity["object_sha"],
        tag_target_sha=tag_identity["target_sha"],
        release_id=release_id,
        payload_assets=payload_assets,
    )
    checksum = build_checksum_asset(approval["tag"], [*payload_assets, provenance])
    assets = [*payload_assets, provenance, checksum]
    expected_names = {asset["name"] for asset in assets}
    current_names = {asset.get("name") for asset in api.refresh_release(release_id).get("assets", [])}
    if not current_names <= expected_names:
        raise ReleasePromotionError("GitHub Release contains undeclared assets")
    output_root = Path(output_dir)
    write_assets(output_root / "assets", assets)
    downloaded = []
    for expected in assets:
        current_release = api.refresh_release(release_id)
        asset = api.asset_by_name(current_release, expected["name"])
        if asset is not None:
            raw = api.download_asset(asset)
            if len(raw) != expected["size"] or sha256_bytes(raw) != expected["sha256"]:
                api.delete_asset(asset["id"])
                asset = None
        if asset is None:
            api.upload_asset(release=current_release, name=expected["name"], raw=expected["bytes"])
            current_release = api.refresh_release(release_id)
            asset = api.asset_by_name(current_release, expected["name"])
        if asset is None:
            raise ReleasePromotionError(f"Uploaded release asset is missing: {expected['name']}")
        raw = api.download_asset(asset)
        if len(raw) != expected["size"] or sha256_bytes(raw) != expected["sha256"]:
            raise ReleasePromotionError(f"Downloaded release asset hash mismatch: {expected['name']}")
        downloaded.append({"name": expected["name"], "size": expected["size"], "sha256": expected["sha256"]})
    final_release = api.refresh_release(release_id)
    final_names = {asset.get("name") for asset in final_release.get("assets", [])}
    if final_names != expected_names:
        raise ReleasePromotionError("GitHub Release asset set does not exactly match the declared inventory")
    release_inventory_sha256 = inventory_sha256(downloaded)
    promoted = advance_stage(
        stage_root,
        "PROMOTED",
        binding_updates={
            "tag_object_sha": tag_identity["object_sha"],
            "tag_target_sha": tag_identity["target_sha"],
            "release_id": release_id,
            "release_assets_sha256": release_inventory_sha256,
        },
    )
    completion = {
        "schema_version": 1,
        "repository": approval["repository"],
        "source_sha": approval["source_sha"],
        "output_head_sha": approval["output_head_sha"],
        "merge_sha": approval["merge_sha"],
        "pr_number": approval["pr_number"],
        "workflow_repository": promotion_workflow_repository,
        "workflow_path": promotion_workflow_path,
        "workflow_ref_sha": promotion_workflow_ref_sha,
        "promotion_run_id": promotion_run_id,
        "promotion_run_attempt": promotion_run_attempt,
        "tag_object_sha": tag_identity["object_sha"],
        "tag_target_sha": tag_identity["target_sha"],
        "release_id": release_id,
        "release_assets_sha256": release_inventory_sha256,
        "assets": downloaded,
    }
    completion_path = write_completion_record(stage_root, completion)
    api.publish_release(release_id)
    advance_stage(stage_root, "PROMOTION_COMPLETE")
    result = {
        "schema_version": 1,
        "tag": approval["tag"],
        "build_id": approval["build_id"],
        "merge_sha": approval["merge_sha"],
        "tag_object_sha": promoted["bindings"]["tag_object_sha"],
        "release_id": release_id,
        "release_assets_sha256": release_inventory_sha256,
        "completion_record": str(completion_path),
    }
    write_canonical_json(output_root / "promotion-result.json", result)
    return result


def republish_release(**arguments) -> dict:
    completion_record = arguments.get("completion_record")
    if not isinstance(completion_record, dict) or not isinstance(completion_record.get("tag"), str):
        raise ReleasePromotionError("Republish completion tag is missing")
    with release_tag_lock(arguments["persisted_root"], completion_record["tag"]):
        return _republish_release(**arguments)


def _republish_release(
    *,
    repo: GitObjectRepository,
    api,
    completion_record: dict,
    persisted_root: str | Path,
    output_dir: str | Path,
) -> dict:
    del persisted_root
    if completion_record.get("schema_version") != 1 or not isinstance(completion_record.get("promotion"), dict):
        raise ReleasePromotionError("Unsupported durable completion record")
    promotion = completion_record["promotion"]
    bindings = completion_record.get("bindings")
    if not isinstance(bindings, dict):
        raise ReleasePromotionError("Durable completion bindings are missing")
    required = {
        "repository",
        "source_sha",
        "output_head_sha",
        "merge_sha",
        "pr_number",
        "workflow_repository",
        "workflow_path",
        "workflow_ref_sha",
        "promotion_run_id",
        "promotion_run_attempt",
        "tag_object_sha",
        "tag_target_sha",
        "release_id",
        "release_assets_sha256",
        "assets",
    }
    if set(promotion) != {"schema_version", *required} or promotion["schema_version"] != 1:
        raise ReleasePromotionError("Durable completion promotion identity is incomplete")
    try:
        tag = validated_tag(completion_record.get("tag"))
    except (TypeError, ValueError) as exc:
        raise ReleasePromotionError(f"Durable completion tag is invalid: {exc}") from exc
    for field in ("tag_object_sha", "tag_target_sha", "release_id", "release_assets_sha256"):
        if bindings.get(field) != promotion[field]:
            raise ReleasePromotionError(f"Durable completion binding mismatch for {field}")
    tag_identity = api.get_annotated_tag(tag)
    if tag_identity != {
        "object_sha": promotion["tag_object_sha"],
        "target_sha": promotion["tag_target_sha"],
    }:
        raise ReleasePromotionError("Immutable release tag identity differs from completion")
    release = api.get_release(tag)
    if release is None or release.get("id") != promotion["release_id"]:
        raise ReleasePromotionError("GitHub Release identity differs from completion")
    if release.get("draft", False):
        raise ReleasePromotionError("Durably completed GitHub Release must be published")
    payload_assets = build_payload_assets(repo, promotion["merge_sha"], tag)
    provenance = build_provenance_asset(
        tag=tag,
        content_manifest_sha256=completion_record["content_manifest_sha256"],
        source_sha=promotion["source_sha"],
        output_head_sha=promotion["output_head_sha"],
        merge_sha=promotion["merge_sha"],
        workflow_repository=promotion["workflow_repository"],
        workflow_path=promotion["workflow_path"],
        workflow_ref_sha=promotion["workflow_ref_sha"],
        run_id=promotion["promotion_run_id"],
        run_attempt=promotion["promotion_run_attempt"],
        pr_number=promotion["pr_number"],
        tag_object_sha=promotion["tag_object_sha"],
        tag_target_sha=promotion["tag_target_sha"],
        release_id=promotion["release_id"],
        payload_assets=payload_assets,
    )
    checksum = build_checksum_asset(tag, [*payload_assets, provenance])
    assets = [*payload_assets, provenance, checksum]
    expected_names = {asset["name"] for asset in assets}
    current_names = {asset.get("name") for asset in release.get("assets", [])}
    if not current_names <= expected_names:
        raise ReleasePromotionError("GitHub Release contains undeclared assets")
    expected_inventory = [{"name": asset["name"], "size": asset["size"], "sha256": asset["sha256"]} for asset in assets]
    if (
        expected_inventory != promotion["assets"]
        or inventory_sha256(expected_inventory) != promotion["release_assets_sha256"]
    ):
        raise ReleasePromotionError("Rebuilt release assets differ from durable completion")
    output_root = Path(output_dir)
    write_assets(output_root / "assets", assets)
    downloaded = []
    for expected in assets:
        release = api.refresh_release(promotion["release_id"])
        asset = api.asset_by_name(release, expected["name"])
        if asset is not None:
            raw = api.download_asset(asset)
            if len(raw) != expected["size"] or sha256_bytes(raw) != expected["sha256"]:
                api.delete_asset(asset["id"])
                asset = None
        if asset is None:
            api.upload_asset(
                release=api.refresh_release(promotion["release_id"]), name=expected["name"], raw=expected["bytes"]
            )
            release = api.refresh_release(promotion["release_id"])
            asset = api.asset_by_name(release, expected["name"])
        if asset is None:
            raise ReleasePromotionError(f"Republished release asset is missing: {expected['name']}")
        raw = api.download_asset(asset)
        if len(raw) != expected["size"] or sha256_bytes(raw) != expected["sha256"]:
            raise ReleasePromotionError(f"Republished release asset hash mismatch: {expected['name']}")
        downloaded.append({"name": expected["name"], "size": expected["size"], "sha256": expected["sha256"]})
    api.publish_release(promotion["release_id"])
    final_names = {asset.get("name") for asset in api.refresh_release(promotion["release_id"]).get("assets", [])}
    if final_names != expected_names:
        raise ReleasePromotionError("Republished GitHub Release asset set is incomplete")
    result = {
        "schema_version": 1,
        "tag": tag,
        "build_id": completion_record["build_id"],
        "release_id": promotion["release_id"],
        "release_assets_sha256": inventory_sha256(downloaded),
        "assets": downloaded,
    }
    write_canonical_json(output_root / "republish-result.json", result)
    return result
