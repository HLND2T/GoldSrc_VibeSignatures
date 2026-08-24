from __future__ import annotations

from pathlib import Path

from analysis_config import validated_tag
from release_workflow_lib.content import build_content_manifest, verify_content_manifest
from release_workflow_lib.errors import ShadowVerificationError
from release_workflow_lib.git_objects import GitObjectRepository
from release_workflow_lib.hashing import canonical_json_bytes, sha256_bytes, write_canonical_json


def run_shadow_verification(
    *,
    repo: GitObjectRepository,
    default_ref: str,
    tags: tuple[str, ...],
    repository_id: int,
    workflow_repository: str,
    workflow_path: str,
    workflow_ref: str,
    output_dir: str | Path,
) -> dict:
    normalized_tags = tuple(validated_tag(tag) for tag in tags)
    if len(normalized_tags) < 3 or len(set(normalized_tags)) != len(normalized_tags):
        raise ShadowVerificationError("Shadow verification requires at least three distinct tags")
    source_sha = repo.resolve_commit(default_ref)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    results = []
    for tag in normalized_tags:
        if repo.entry(source_sha, f"release-manifests/{tag}.json") is not None:
            raise ShadowVerificationError(f"Shadow new-mode input already has a tracked release manifest: {tag}")
        document = build_content_manifest(
            repo=repo,
            source_ref=source_sha,
            tag=tag,
            repository_id=repository_id,
            workflow_repository=workflow_repository,
            workflow_path=workflow_path,
            workflow_ref=workflow_ref,
        )
        raw = canonical_json_bytes(document)
        verify_content_manifest(
            repo=repo,
            default_ref=source_sha,
            manifest_raw=raw,
            repository_id=repository_id,
            workflow_repository=workflow_repository,
            workflow_path=workflow_path,
            workflow_ref=workflow_ref,
        )
        path = output / f"{tag}.content-manifest.json"
        path.write_bytes(raw)
        results.append(
            {
                "game_version": tag,
                "mode_decision": "new",
                "content_manifest_sha256": sha256_bytes(raw),
                "tracked_content_inventory_sha256": document["tracked_content_inventory_sha256"],
            }
        )
    evidence = {
        "schema_version": 1,
        "source_sha": source_sha,
        "bin_gitlink_sha": repo.gitlink(source_sha, "bin"),
        "repository_id": repository_id,
        "workflow_repository": workflow_repository,
        "workflow_path": workflow_path,
        "workflow_ref_sha": repo.resolve_commit(workflow_ref),
        "results": results,
    }
    write_canonical_json(output / "shadow-evidence.json", evidence)
    return evidence
