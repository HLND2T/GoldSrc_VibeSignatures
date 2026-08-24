from __future__ import annotations

import json
import os
from pathlib import Path

from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import canonical_json_bytes, sha256_bytes
from release_workflow_lib.staging import (
    STATE_SEQUENCE,
    build_stage_root,
    load_marker,
    reject_release_path_links,
    release_staging_root,
    release_tag_lock,
    validated_build_id,
    write_diagnostic,
)


class ReleaseRecoveryError(ReleaseWorkflowError):
    pass


def stage_info(*, persisted_root: str | Path, tag: str, build_id: str, required_state: str | None = None) -> dict:
    root = build_stage_root(persisted_root, tag, build_id)
    if required_state is not None:
        if required_state not in STATE_SEQUENCE:
            raise ReleaseRecoveryError(f"Unknown required stage state: {required_state}")
        marker, _raw = load_marker(root, required_state)
        return marker
    for state in reversed(STATE_SEQUENCE):
        if (root / f"{state}.json").is_file():
            marker, _raw = load_marker(root, state)
            return marker
    raise ReleaseRecoveryError("Release stage has no valid state marker")


def verify_retry_authorized(
    *, persisted_root: str | Path, tag: str, build_id: str, new_build_id: str, reason: str
) -> dict:
    root = build_stage_root(persisted_root, tag, build_id)
    ready, _raw = load_marker(root, "READY")
    validated_build_id(new_build_id)
    if not isinstance(reason, str) or not reason.strip():
        raise ReleaseRecoveryError("Retry reason is required")
    if (root / "PROMOTION_STARTED.json").exists():
        raise ReleaseRecoveryError("Retry is forbidden after promotion has started; resume the same build")
    if build_stage_root(persisted_root, tag, new_build_id).exists():
        raise ReleaseRecoveryError("Retry target build ID already exists")
    return {
        "schema_version": 1,
        "tag": tag,
        "old_build_id": build_id,
        "new_build_id": new_build_id,
        "source_sha": ready["bindings"]["source_sha"],
        "content_manifest_sha256": ready["content_manifest_sha256"],
    }


def authorize_retry(*, persisted_root: str | Path, tag: str, build_id: str, new_build_id: str, reason: str) -> dict:
    with release_tag_lock(persisted_root, tag):
        root = build_stage_root(persisted_root, tag, build_id)
        result = verify_retry_authorized(
            persisted_root=persisted_root,
            tag=tag,
            build_id=build_id,
            new_build_id=new_build_id,
            reason=reason,
        )
        write_diagnostic(root, "SUPERSEDED", f"replacement={new_build_id}; {reason}")
        return result


def abandon_build(*, persisted_root: str | Path, tag: str, build_id: str, confirmation: str, reason: str) -> Path:
    if confirmation != f"abandon:{tag}:{build_id}":
        raise ReleaseRecoveryError("Abandon confirmation does not match exact tag/build ID")
    with release_tag_lock(persisted_root, tag):
        root = build_stage_root(persisted_root, tag, build_id)
        if (root / "PROMOTION_STARTED.json").exists():
            raise ReleaseRecoveryError("Cannot abandon a build after promotion has started")
        return write_diagnostic(root, "ABANDONED", reason)


def cleanup_completed_stage(*, persisted_root: str | Path, tag: str, build_id: str, confirmation: str) -> Path:
    if confirmation != f"cleanup:{tag}:{build_id}":
        raise ReleaseRecoveryError("Cleanup confirmation does not match exact tag/build ID")
    staging = release_staging_root(persisted_root)
    root = build_stage_root(persisted_root, tag, build_id)
    target = staging / "cleanup-trash" / tag / build_id
    if target.is_dir() and not root.exists():
        return target
    complete, _raw = load_marker(root, "PROMOTION_COMPLETE")
    completion = staging / "completed" / tag / f"{build_id}.json"
    if not completion.is_file():
        raise ReleaseRecoveryError("Durable completion record is missing")
    record = load_completion_record(persisted_root=persisted_root, tag=tag, build_id=build_id)
    if (
        record.get("bindings") != complete["bindings"]
        or record.get("content_manifest_sha256") != complete["content_manifest_sha256"]
    ):
        raise ReleaseRecoveryError("Durable completion record does not match the completed stage")
    reject_release_path_links(target.parent, "Release cleanup trash")
    target.parent.mkdir(parents=True, exist_ok=True)
    reject_release_path_links(target.parent, "Release cleanup trash")
    if target.exists():
        raise ReleaseRecoveryError("Cleanup trash target already exists while live stage is present")
    os.replace(root, target)
    pr_number = complete["bindings"]["pr_number"]
    index = staging / "pr-index" / f"{pr_number}.json"
    if index.is_file():
        os.replace(index, target / "PR_INDEX.json")
    return target


def reconcile_local_stage(*, persisted_root: str | Path, tag: str, build_id: str) -> dict:
    root = build_stage_root(persisted_root, tag, build_id)
    states = [
        state
        for state in (
            "BUILDING",
            "HEAD_BOUND",
            "PR_CREATED",
            "READY",
            "PROMOTION_STARTED",
            "PROMOTED",
            "PROMOTION_COMPLETE",
        )
        if (root / f"{state}.json").is_file()
    ]
    diagnostics = (
        sorted(path.name for path in (root / "diagnostics").glob("*.json")) if (root / "diagnostics").is_dir() else []
    )
    completion = release_staging_root(persisted_root) / "completed" / tag / f"{build_id}.json"
    document = {
        "schema_version": 1,
        "tag": tag,
        "build_id": build_id,
        "states": states,
        "diagnostics": diagnostics,
        "completion_record": completion.is_file(),
    }
    canonical_json_bytes(document)
    return document


def reconcile_release(*, persisted_root: str | Path, tag: str, build_id: str, api) -> dict:
    local = reconcile_local_stage(persisted_root=persisted_root, tag=tag, build_id=build_id)
    completion = None
    if local["completion_record"]:
        completion = load_completion_record(persisted_root=persisted_root, tag=tag, build_id=build_id)
    remote_tag = api.get_annotated_tag(tag)
    remote_release = api.get_release(tag)
    differences = []
    if completion is None:
        if remote_tag is not None:
            differences.append("remote tag exists without durable completion")
        if remote_release is not None:
            differences.append("remote Release exists without durable completion")
    else:
        promotion = completion.get("promotion", {})
        expected_tag = {
            "object_sha": promotion.get("tag_object_sha"),
            "target_sha": promotion.get("tag_target_sha"),
        }
        if remote_tag != expected_tag:
            differences.append("remote tag identity differs from durable completion")
        if remote_release is None or remote_release.get("id") != promotion.get("release_id"):
            differences.append("remote Release identity differs from durable completion")
        elif remote_release.get("draft", False):
            differences.append("durably completed remote Release is still draft")
        else:
            expected_assets = {
                asset["name"]: asset
                for asset in promotion.get("assets", [])
                if isinstance(asset, dict) and "name" in asset
            }
            remote_assets = remote_release.get("assets", [])
            remote_names = [asset.get("name") for asset in remote_assets]
            if len(remote_names) != len(set(remote_names)):
                differences.append("remote Release contains duplicate asset names")
            missing = sorted(set(expected_assets) - set(remote_names))
            extra = sorted(set(remote_names) - set(expected_assets))
            if missing:
                differences.append(f"remote Release assets are missing: {missing}")
            if extra:
                differences.append(f"remote Release has undeclared assets: {extra}")
            for asset in remote_assets:
                expected = expected_assets.get(asset.get("name"))
                if expected is None:
                    continue
                raw = api.download_asset(asset)
                if len(raw) != expected.get("size") or sha256_bytes(raw) != expected.get("sha256"):
                    differences.append(f"remote Release asset hash differs: {asset.get('name')}")
    return {
        **local,
        "remote_tag": remote_tag,
        "remote_release_id": remote_release.get("id") if remote_release is not None else None,
        "differences": differences,
    }


def load_completion_record(*, persisted_root: str | Path, tag: str, build_id: str) -> dict:
    path = release_staging_root(persisted_root) / "completed" / tag / f"{build_id}.json"
    try:
        raw = path.read_bytes()
        document = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseRecoveryError(f"Unable to read completion record: {exc}") from exc
    if canonical_json_bytes(document) != raw:
        raise ReleaseRecoveryError("Completion record is not canonical JSON")
    return document
