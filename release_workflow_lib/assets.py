from __future__ import annotations

import io
import zipfile
from pathlib import Path, PurePosixPath

from analysis_config import validated_tag
from release_workflow_lib.errors import ContentMismatchError
from release_workflow_lib.git_objects import GitObjectRepository
from release_workflow_lib.hashing import canonical_json_bytes, sha256_bytes

ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def _asset_record(name: str, raw: bytes) -> dict:
    return {"name": name, "size": len(raw), "sha256": sha256_bytes(raw), "bytes": raw}


def deterministic_gamedata_zip(repo: GitObjectRepository, ref: str, tag: str) -> bytes:
    tag = validated_tag(tag)
    prefix = f"gamedata/{tag}"
    entries = repo.list_tree(ref, prefix)
    if not entries:
        raise ContentMismatchError(f"Tracked gamedata is missing for {tag}")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for entry in entries:
            if entry.mode != "100644" or entry.object_type != "blob" or entry.size is None:
                raise ContentMismatchError(f"Gamedata archive input must be a regular blob: {entry.path}")
            relative = PurePosixPath(entry.path).relative_to(PurePosixPath(prefix)).as_posix()
            information = zipfile.ZipInfo(relative, ZIP_TIMESTAMP)
            information.compress_type = zipfile.ZIP_DEFLATED
            information.create_system = 3
            information.external_attr = 0o100644 << 16
            archive.writestr(
                information, repo.read_blob_oid(entry.oid), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9
            )
    return output.getvalue()


def build_payload_assets(repo: GitObjectRepository, ref: str, tag: str) -> list[dict]:
    tag = validated_tag(tag)
    snapshot = repo.read_blob(ref, f"gamesymbols/{tag}.yaml", required_mode="100644")
    metadata = repo.read_blob(ref, f"gamesymbols/{tag}.metadata.yaml", required_mode="100644")
    gamedata = deterministic_gamedata_zip(repo, ref, tag)
    return [
        _asset_record(f"gamesymbols-{tag}.yaml", snapshot),
        _asset_record(f"gamesymbols-{tag}.metadata.yaml", metadata),
        _asset_record(f"gamedata-{tag}.zip", gamedata),
    ]


def build_provenance_asset(
    *,
    tag: str,
    content_manifest_sha256: str,
    source_sha: str,
    output_head_sha: str,
    merge_sha: str,
    workflow_repository: str,
    workflow_path: str,
    workflow_ref_sha: str,
    run_id: str,
    run_attempt: int,
    pr_number: int,
    tag_object_sha: str,
    tag_target_sha: str,
    release_id: int,
    payload_assets: list[dict],
) -> dict:
    document = {
        "schema_version": 1,
        "release_tag": validated_tag(tag),
        "content_manifest_sha256": content_manifest_sha256,
        "source_sha": source_sha,
        "output_head_sha": output_head_sha,
        "merge_sha": merge_sha,
        "workflow_repository": workflow_repository,
        "workflow_path": workflow_path,
        "workflow_ref_sha": workflow_ref_sha,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "pr_number": pr_number,
        "tag_object_sha": tag_object_sha,
        "tag_target_sha": tag_target_sha,
        "release_id": release_id,
        "payload_assets": [
            {"name": asset["name"], "size": asset["size"], "sha256": asset["sha256"]} for asset in payload_assets
        ],
    }
    raw = canonical_json_bytes(document)
    return _asset_record(f"release-provenance-{tag}.json", raw)


def build_checksum_asset(tag: str, assets: list[dict]) -> dict:
    lines = [f"{asset['sha256']}  {asset['name']}" for asset in sorted(assets, key=lambda item: item["name"])]
    raw = ("\n".join(lines) + "\n").encode("utf-8")
    return _asset_record(f"release-assets-{validated_tag(tag)}.sha256", raw)


def write_assets(output_dir: str | Path, assets: list[dict]) -> None:
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    expected = {asset["name"] for asset in assets}
    existing = {path.name for path in root.iterdir() if path.is_file()}
    if existing - expected:
        raise ContentMismatchError(f"Release asset directory contains undeclared files: {sorted(existing - expected)}")
    for asset in assets:
        path = root / asset["name"]
        if path.exists() and path.read_bytes() != asset["bytes"]:
            raise ContentMismatchError(f"Release asset already exists with different bytes: {asset['name']}")
        path.write_bytes(asset["bytes"])
