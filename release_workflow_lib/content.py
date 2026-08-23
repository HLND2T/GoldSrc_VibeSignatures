from __future__ import annotations

import tempfile
from pathlib import Path, PurePosixPath

from analysis_config import validated_tag
from gamedata_contract import (
    discover_generator_modules,
    generator_contract_sha256,
    parse_gamedata_manifest_bytes,
)
from gamesymbol_snapshot_lib.codec import (
    canonical_snapshot_bytes,
    parse_snapshot_bytes,
    snapshot_analysis_output_contract_version,
    snapshot_config_digest_version,
)
from gamesymbol_snapshot_lib.metadata import parse_metadata_bytes, verify_metadata
from release_workflow_lib.errors import ContentMismatchError
from release_workflow_lib.git_objects import GitObjectRepository, GitTreeEntry, source_bundle_sha256
from release_workflow_lib.hashing import canonical_json_bytes, inventory_sha256, sha256_bytes
from release_workflow_lib.manifest import parse_content_manifest_bytes, validate_content_manifest

CONFIG_CONTRACT_PATHS = (
    "analysis_config.py",
    "analysis_output_contract.py",
    "analysis_planner.py",
    "gamesymbol_snapshot_lib/config.py",
    "trusted_yaml.py",
)
RELEASE_TOOL_CONTRACT_PATHS = (
    "analysis_config.py",
    "analysis_output_contract.py",
    "analysis_planner.py",
    "gamedata_contract.py",
    "gamesymbol_snapshot_lib/codec.py",
    "gamesymbol_snapshot_lib/config.py",
    "gamesymbol_snapshot_lib/errors.py",
    "gamesymbol_snapshot_lib/metadata.py",
    "gamesymbol_snapshot_lib/paths.py",
    "gamesymbol_store.py",
    "release_workflow.py",
    "release_workflow_lib/__init__.py",
    "release_workflow_lib/content.py",
    "release_workflow_lib/errors.py",
    "release_workflow_lib/git_objects.py",
    "release_workflow_lib/hashing.py",
    "release_workflow_lib/manifest.py",
    "release_workflow_lib/shadow.py",
    "trusted_yaml.py",
)


def _required_payload_blob(repo: GitObjectRepository, ref: str, path: str) -> bytes:
    return repo.read_blob(ref, path, required_mode="100644")


def _tracked_content_entries(repo: GitObjectRepository, source_sha: str, tag: str) -> tuple[GitTreeEntry, ...]:
    required = (
        f"gamesymbols/{tag}.yaml",
        f"gamesymbols/{tag}.metadata.yaml",
        f"gamedata/{tag}/gamedata-manifest.json",
    )
    entries = [repo.entry(source_sha, path) for path in required]
    if any(entry is None for entry in entries):
        missing = [path for path, entry in zip(required, entries, strict=True) if entry is None]
        raise ContentMismatchError(f"Tracked release payload is incomplete for {tag}: {missing}")
    gamedata_entries = repo.list_tree(source_sha, f"gamedata/{tag}")
    combined = {
        entry.path: entry
        for entry in (
            entries[0],
            entries[1],
            *gamedata_entries,
        )
        if entry is not None
    }
    result = tuple(sorted(combined.values(), key=lambda item: item.path.encode("utf-8")))
    for entry in result:
        if entry.mode != "100644" or entry.object_type != "blob" or entry.size is None:
            raise ContentMismatchError(f"Tracked release payload must be a regular 100644 blob: {entry.path}")
    return result


def tracked_content_inventory(repo: GitObjectRepository, source_sha: str, tag: str) -> list[dict]:
    inventory = []
    for entry in _tracked_content_entries(repo, source_sha, tag):
        raw = repo.read_blob_oid(entry.oid)
        if len(raw) != entry.size:
            raise ContentMismatchError(f"Tracked release payload size changed while reading: {entry.path}")
        inventory.append(
            {
                "path": entry.path,
                "mode": entry.mode,
                "size": entry.size,
                "sha256": sha256_bytes(raw),
            }
        )
    return inventory


def snapshot_binary_inventory_sha256(document: dict) -> str:
    binaries = []
    for module in sorted(document.get("binaries", {}), key=lambda value: value.encode("utf-8")):
        for platform in ("windows", "linux"):
            metadata = document["binaries"][module].get(platform)
            if metadata is not None:
                binaries.append({"module": module, "platform": platform, **metadata})
    return sha256_bytes(canonical_json_bytes({"schema_version": 1, "binaries": binaries}))


def _materialize_tree(repo: GitObjectRepository, ref: str, prefix: str, destination: Path) -> bool:
    entries = repo.list_tree(ref, prefix)
    for entry in entries:
        if entry.mode != "100644" or entry.object_type != "blob" or entry.size is None:
            raise ContentMismatchError(f"Contract source must be a regular 100644 blob: {entry.path}")
        relative = PurePosixPath(entry.path).relative_to(PurePosixPath(prefix))
        output = destination.joinpath(*relative.parts)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(repo.read_blob_oid(entry.oid))
    return bool(entries)


def _generator_contract_digest(repo: GitObjectRepository, source_sha: str) -> str:
    with tempfile.TemporaryDirectory(prefix="release-generator-contract-") as temporary:
        root = Path(temporary) / "gamedata-generators"
        if _materialize_tree(repo, source_sha, "gamedata-generators", root):
            modules = discover_generator_modules(root)
        else:
            modules = []
        return generator_contract_sha256(modules)


def _verify_metadata_projection(tag: str, snapshot_raw: bytes, metadata_raw: bytes, config_raw: bytes) -> None:
    with tempfile.TemporaryDirectory(prefix="release-metadata-") as temporary:
        root = Path(temporary)
        snapshot = root / f"{tag}.yaml"
        metadata = root / f"{tag}.metadata.yaml"
        config = root / f"{tag}.config.yaml"
        snapshot.write_bytes(snapshot_raw)
        metadata.write_bytes(metadata_raw)
        config.write_bytes(config_raw)
        verify_metadata(metadata_path=metadata, snapshot_path=snapshot, config_path=config, game_version=tag)


def _verify_gamedata(
    *,
    repo: GitObjectRepository,
    source_sha: str,
    tag: str,
    snapshot_sha256: str,
    config_sha256: str,
    generator_digest: str,
) -> tuple[dict, str]:
    path = f"gamedata/{tag}/gamedata-manifest.json"
    raw = _required_payload_blob(repo, source_sha, path)
    document, manifest_sha256 = parse_gamedata_manifest_bytes(raw, f"{source_sha}:{path}")
    expected_bindings = {
        "game_version": tag,
        "candidate_sha256": snapshot_sha256,
        "analysis_config_sha256": config_sha256,
        "generator_contract_sha256": generator_digest,
    }
    for field, expected in expected_bindings.items():
        if document[field] != expected:
            raise ContentMismatchError(f"Gamedata manifest {field} does not match release content")
    actual_payload = []
    for entry in repo.list_tree(source_sha, f"gamedata/{tag}"):
        if entry.path == path:
            continue
        if entry.mode != "100644" or entry.object_type != "blob" or entry.size is None:
            raise ContentMismatchError(f"Gamedata payload must be a regular 100644 blob: {entry.path}")
        raw_payload = repo.read_blob_oid(entry.oid)
        actual_payload.append({"path": entry.path, "size": len(raw_payload), "sha256": sha256_bytes(raw_payload)})
    if actual_payload != document["files"]:
        raise ContentMismatchError("Gamedata Git-tree payload does not match its canonical manifest")
    return document, manifest_sha256


def build_content_manifest(
    *,
    repo: GitObjectRepository,
    source_ref: str,
    tag: str,
    repository_id: int,
    workflow_repository: str,
    workflow_path: str,
    workflow_ref: str,
) -> dict:
    tag = validated_tag(tag)
    source_sha = repo.resolve_commit(source_ref)
    workflow_ref_sha = repo.resolve_commit(workflow_ref)
    _required_payload_blob(repo, workflow_ref_sha, workflow_path)
    snapshot_path = f"gamesymbols/{tag}.yaml"
    metadata_path = f"gamesymbols/{tag}.metadata.yaml"
    config_path = f"configs/{tag}.yaml"
    gamedata_path = f"gamedata/{tag}"
    snapshot_raw = _required_payload_blob(repo, source_sha, snapshot_path)
    metadata_raw = _required_payload_blob(repo, source_sha, metadata_path)
    config_raw = _required_payload_blob(repo, source_sha, config_path)
    snapshot = parse_snapshot_bytes(snapshot_raw, tag)
    if canonical_snapshot_bytes(snapshot) != snapshot_raw:
        raise ContentMismatchError("Snapshot is not canonical")
    metadata = parse_metadata_bytes(metadata_raw, expected_game_version=tag, snapshot_bytes=snapshot_raw)
    _verify_metadata_projection(tag, snapshot_raw, metadata_raw, config_raw)
    snapshot_sha256 = sha256_bytes(snapshot_raw)
    metadata_sha256 = sha256_bytes(metadata_raw)
    config_sha256 = sha256_bytes(config_raw)
    config_digest = snapshot["config_sha256"].removeprefix("sha256:")
    if metadata["config_sha256"] != config_digest:
        raise ContentMismatchError("Metadata config digest does not match snapshot")
    generator_digest = _generator_contract_digest(repo, source_sha)
    gamedata, gamedata_manifest_sha256 = _verify_gamedata(
        repo=repo,
        source_sha=source_sha,
        tag=tag,
        snapshot_sha256=snapshot_sha256,
        config_sha256=config_sha256,
        generator_digest=generator_digest,
    )
    inventory = tracked_content_inventory(repo, source_sha, tag)
    document = {
        "schema_version": 1,
        "game_version": tag,
        "release_tag": tag,
        "repository_id": repository_id,
        "source_sha": source_sha,
        "bin_gitlink_sha": repo.gitlink(source_sha, "bin"),
        "candidate_sha256": snapshot_sha256,
        "snapshot_schema_version": snapshot["schema_version"],
        "analysis_output_contract_version": snapshot_analysis_output_contract_version(snapshot),
        "metadata_sha256": metadata_sha256,
        "tracked_content_inventory_sha256": inventory_sha256(inventory),
        "snapshot_binary_inventory_sha256": snapshot_binary_inventory_sha256(snapshot),
        "analysis_config_path": config_path,
        "analysis_config_sha256": config_sha256,
        "config_digest_version": snapshot_config_digest_version(snapshot),
        "config_contract_sha256": source_bundle_sha256(
            repo,
            source_sha,
            CONFIG_CONTRACT_PATHS,
            domain="goldsrc-config-contract:v1",
        ),
        "gamedata_path": gamedata_path,
        "gamedata_manifest_sha256": gamedata_manifest_sha256,
        "generator_contract_sha256": gamedata["generator_contract_sha256"],
        "workflow_repository": workflow_repository,
        "workflow_path": workflow_path,
        "workflow_ref_sha": workflow_ref_sha,
        "release_tool_contract_sha256": source_bundle_sha256(
            repo,
            workflow_ref_sha,
            RELEASE_TOOL_CONTRACT_PATHS,
            domain="goldsrc-release-tool-contract:v1",
        ),
    }
    return validate_content_manifest(document)


def verify_content_manifest(
    *,
    repo: GitObjectRepository,
    default_ref: str,
    manifest_raw: bytes,
    repository_id: int,
    workflow_repository: str,
    workflow_path: str,
    workflow_ref: str,
) -> dict:
    actual = parse_content_manifest_bytes(manifest_raw)
    source_sha = repo.resolve_commit(default_ref)
    if actual["source_sha"] != source_sha:
        raise ContentMismatchError("Release source SHA is not the exact default-branch commit")
    expected = build_content_manifest(
        repo=repo,
        source_ref=source_sha,
        tag=actual["game_version"],
        repository_id=repository_id,
        workflow_repository=workflow_repository,
        workflow_path=workflow_path,
        workflow_ref=workflow_ref,
    )
    if actual != expected:
        first = next(key for key in sorted(expected) if actual.get(key) != expected[key])
        raise ContentMismatchError(f"Release content manifest mismatch at {first}")
    return actual
