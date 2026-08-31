#!/usr/bin/env python3
"""Build and verify immutable GitHub Release bundles from tracked analysis artifacts."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path

import yaml

from bin_artifact_contract import BinArtifactContractError, validate_repository_artifact_contract
from gamedata_contract import (
    GamedataContractError,
    analysis_config_sha256,
    discover_generator_modules,
    generator_contract_sha256,
    validate_gamedata_tree,
)
from gamesymbol_snapshot_lib.errors import SnapshotError
from gamesymbol_snapshot_lib.metadata import MetadataContractError, verify_metadata
from gamesymbol_snapshot_lib.operations import check_snapshot_contract
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import (
    canonical_json_bytes,
    file_inventory,
    inventory_sha256,
    reject_reparse_points,
    sha256_bytes,
    sha256_file,
    write_canonical_json,
)
from release_workflow_lib.manifests import require_sha, require_version

BUNDLE_SCHEMA_VERSION = 1
MANIFEST_KEYS = {
    "schema_version",
    "release_version",
    "build_id",
    "workflow_run_url",
    "source_sha",
    "source_subject",
    "bin_gitlink_sha",
    "generator_contract_sha256",
    "ida_runtime_sha256",
    "warm_idb_selection_sha256",
    "gamevers",
    "assets",
}


class ReleaseBundleError(ValueError):
    pass


def _git(repo_root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_root), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        raise ReleaseBundleError(result.stderr.strip() or f"git {' '.join(arguments)} failed")
    return result.stdout.strip()


def _gitlink(repo_root: Path) -> str:
    record = _git(repo_root, "ls-tree", "HEAD", "--", "bin")
    metadata, separator, listed_path = record.partition("\t")
    parts = metadata.split()
    if separator != "\t" or listed_path != "bin" or len(parts) != 3 or parts[:2] != ["160000", "commit"]:
        raise ReleaseBundleError("Source checkout must declare bin as a gitlink")
    return require_sha(parts[2], "bin gitlink SHA")


def _configured_gamevers(repo_root: Path) -> tuple[str, ...]:
    try:
        document = yaml.safe_load((repo_root / "configs/config.yaml").read_bytes()) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ReleaseBundleError(f"Unable to read configs/config.yaml: {exc}") from exc
    values = document.get("gamevers")
    if not isinstance(values, list) or not values or any(not isinstance(value, str) or not value for value in values):
        raise ReleaseBundleError("configs/config.yaml must declare a non-empty gamevers list")
    if len({value.casefold() for value in values}) != len(values):
        raise ReleaseBundleError("configs/config.yaml contains duplicate/case-colliding gamevers")
    return tuple(sorted(values))


def _copy_file(source: Path, target: Path) -> None:
    if not source.is_file():
        raise ReleaseBundleError(f"Required bundle input is missing: {source}")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise ReleaseBundleError(f"Bundle target already exists: {target}")
    target.write_bytes(source.read_bytes())


def _copy_tree(source: Path, target: Path) -> None:
    if not source.is_dir():
        raise ReleaseBundleError(f"Required bundle input directory is missing: {source}")
    reject_reparse_points(source)
    if target.exists():
        raise ReleaseBundleError(f"Bundle target already exists: {target}")
    shutil.copytree(source, target)


def _asset_record(bundle_root: Path, relative: str) -> dict:
    path = bundle_root / relative
    return {"path": relative, "size": path.stat().st_size, "sha256": sha256_file(path)}


def _checksum_bytes(records: list[dict]) -> bytes:
    return "".join(f"{record['sha256']}  {record['path']}\n" for record in records).encode("utf-8")


def _parse_manifest(path: Path) -> dict:
    try:
        raw = path.read_bytes()
        document = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseBundleError(f"Unable to parse release manifest {path}: {exc}") from exc
    if not isinstance(document, dict) or set(document) != MANIFEST_KEYS or document.get("schema_version") != 1:
        raise ReleaseBundleError("Release manifest has unexpected fields or schema")
    if canonical_json_bytes(document) != raw:
        raise ReleaseBundleError("Release manifest is not canonical JSON")
    return document


def build_release_bundle(
    *,
    repo_root: str | Path,
    bundle_root: str | Path,
    gamesymbols_root: str | Path,
    gamedata_root: str | Path,
    archives_root: str | Path,
    ida_runtime_path: str | Path,
    cache_selection_path: str | Path,
    version: str,
    build_id: str,
    workflow_run_url: str,
    source_sha: str,
) -> dict:
    repo_root = Path(repo_root).resolve()
    bundle_root = Path(bundle_root).resolve()
    version = require_version(version)
    source_sha = require_sha(source_sha, "SOURCE_SHA")
    if not build_id or not workflow_run_url:
        raise ReleaseBundleError("build_id and workflow_run_url must be non-empty")
    if _git(repo_root, "rev-parse", "HEAD") != source_sha:
        raise ReleaseBundleError("Bundle source SHA does not match checkout HEAD")
    if bundle_root.exists() and any(bundle_root.iterdir()):
        raise ReleaseBundleError(f"Bundle root must be empty: {bundle_root}")
    bundle_root.mkdir(parents=True, exist_ok=True)

    try:
        repository_artifacts = validate_repository_artifact_contract(repo_root)
        modules = discover_generator_modules(repo_root / "gamedata-generators")
        generator_digest = generator_contract_sha256(modules)
    except (BinArtifactContractError, GamedataContractError, ReleaseWorkflowError) as exc:
        raise ReleaseBundleError(str(exc)) from exc

    ida_runtime = Path(ida_runtime_path)
    cache_selection = Path(cache_selection_path)
    _copy_file(ida_runtime, bundle_root / "evidence/ida-runtime.json")
    _copy_file(cache_selection, bundle_root / "evidence/cache-selection.json")

    artifacts_by_tag = {item.game_version: item for item in repository_artifacts.gamevers}
    gamesymbols_root = Path(gamesymbols_root)
    gamedata_root = Path(gamedata_root)
    archives_root = Path(archives_root)
    payload_paths: list[str] = []
    gamever_records: list[dict] = []
    for gamever in _configured_gamevers(repo_root):
        snapshot_source = gamesymbols_root / f"{gamever}.yaml"
        metadata_source = gamesymbols_root / f"{gamever}.metadata.yaml"
        snapshot_target = bundle_root / "gamesymbols" / snapshot_source.name
        metadata_target = bundle_root / "gamesymbols" / metadata_source.name
        _copy_file(snapshot_source, snapshot_target)
        _copy_file(metadata_source, metadata_target)
        _copy_tree(gamedata_root / gamever, bundle_root / "gamedata" / gamever)
        for archive_name in (f"gamedata-{gamever}.7z", f"gamebin-{gamever}.7z"):
            _copy_file(archives_root / archive_name, bundle_root / "archives" / archive_name)
            payload_paths.append(f"archives/{archive_name}")
        payload_paths.extend((f"gamesymbols/{snapshot_source.name}", f"gamesymbols/{metadata_source.name}"))

        config = repo_root / "configs" / f"{gamever}.yaml"
        try:
            check_snapshot_contract(
                gamever,
                bindir=repo_root / "bin",
                artifactdir=repo_root / "bin_artifacts",
                config_path=config,
                snapshot_path=snapshot_target,
            )
            verify_metadata(
                metadata_path=metadata_target,
                snapshot_path=snapshot_target,
                config_path=config,
                game_version=gamever,
            )
            gamedata_inventory, gamedata_manifest_digest = validate_gamedata_tree(
                bundle_root / "gamedata" / gamever,
                gamever,
                modules,
                candidate_sha256=sha256_file(snapshot_target),
                analysis_config_sha256=analysis_config_sha256(config),
                generator_contract_digest=generator_digest,
            )
        except (SnapshotError, MetadataContractError, GamedataContractError, OSError) as exc:
            raise ReleaseBundleError(f"Release payload contract failed for {gamever}: {exc}") from exc
        artifact_inventory = artifacts_by_tag[gamever]
        gamever_records.append(
            {
                "game_version": gamever,
                "artifact_inventory_sha256": artifact_inventory.digest.removeprefix("sha256:"),
                "analysis_config_sha256": analysis_config_sha256(config),
                "snapshot_sha256": sha256_file(snapshot_target),
                "metadata_sha256": sha256_file(metadata_target),
                "gamedata_manifest_sha256": gamedata_manifest_digest,
                "gamedata_inventory_sha256": inventory_sha256(gamedata_inventory),
            }
        )

    assets = [_asset_record(bundle_root, relative) for relative in sorted(payload_paths)]
    manifest = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "release_version": version,
        "build_id": str(build_id),
        "workflow_run_url": str(workflow_run_url),
        "source_sha": source_sha,
        "source_subject": _git(repo_root, "show", "-s", "--format=%s", "HEAD"),
        "bin_gitlink_sha": _gitlink(repo_root),
        "generator_contract_sha256": generator_digest,
        "ida_runtime_sha256": sha256_file(bundle_root / "evidence/ida-runtime.json"),
        "warm_idb_selection_sha256": sha256_file(bundle_root / "evidence/cache-selection.json"),
        "gamevers": gamever_records,
        "assets": assets,
    }
    manifest_relative = f"release-manifest-{version}.json"
    manifest_path = bundle_root / manifest_relative
    write_canonical_json(manifest_path, manifest)
    checksummed = [*assets, _asset_record(bundle_root, manifest_relative)]
    (bundle_root / f"SHA256SUMS-{version}.txt").write_bytes(_checksum_bytes(checksummed))
    return manifest


def verify_release_bundle(*, repo_root: str | Path, bundle_root: str | Path, version: str) -> dict:
    repo_root = Path(repo_root).resolve()
    bundle_root = Path(bundle_root).resolve()
    version = require_version(version)
    manifest_relative = f"release-manifest-{version}.json"
    manifest = _parse_manifest(bundle_root / manifest_relative)
    if manifest["release_version"] != version:
        raise ReleaseBundleError("Release manifest version mismatch")
    if _git(repo_root, "rev-parse", "HEAD") != manifest["source_sha"]:
        raise ReleaseBundleError("Verifier checkout does not match manifest source SHA")
    if _gitlink(repo_root) != manifest["bin_gitlink_sha"]:
        raise ReleaseBundleError("Verifier bin gitlink does not match manifest")

    try:
        repository_artifacts = validate_repository_artifact_contract(repo_root)
        modules = discover_generator_modules(repo_root / "gamedata-generators")
        generator_digest = generator_contract_sha256(modules)
        reject_reparse_points(bundle_root)
    except (BinArtifactContractError, GamedataContractError, ReleaseWorkflowError) as exc:
        raise ReleaseBundleError(str(exc)) from exc
    if generator_digest != manifest["generator_contract_sha256"]:
        raise ReleaseBundleError("Generator contract digest mismatch")
    if sha256_file(bundle_root / "evidence/ida-runtime.json") != manifest["ida_runtime_sha256"]:
        raise ReleaseBundleError("IDA runtime evidence digest mismatch")
    if sha256_file(bundle_root / "evidence/cache-selection.json") != manifest["warm_idb_selection_sha256"]:
        raise ReleaseBundleError("Warm IDB selection evidence digest mismatch")

    gamevers = _configured_gamevers(repo_root)
    expected_paths = {
        manifest_relative,
        f"SHA256SUMS-{version}.txt",
        "evidence/ida-runtime.json",
        "evidence/cache-selection.json",
    }
    for gamever in gamevers:
        expected_paths.update(
            {
                f"gamesymbols/{gamever}.yaml",
                f"gamesymbols/{gamever}.metadata.yaml",
                f"archives/gamedata-{gamever}.7z",
                f"archives/gamebin-{gamever}.7z",
            }
        )
        expected_paths.update(
            f"gamedata/{gamever}/{item['path']}" for item in file_inventory(bundle_root / "gamedata" / gamever)
        )
    actual_paths = {item["path"] for item in file_inventory(bundle_root)}
    if actual_paths != expected_paths:
        raise ReleaseBundleError(
            f"Release bundle allowlist mismatch: missing={sorted(expected_paths - actual_paths)!r}; "
            f"extra={sorted(actual_paths - expected_paths)!r}"
        )

    artifact_by_tag = {item.game_version: item for item in repository_artifacts.gamevers}
    manifest_by_tag = {item["game_version"]: item for item in manifest["gamevers"]}
    if set(manifest_by_tag) != set(gamevers):
        raise ReleaseBundleError("Release manifest gamever inventory mismatch")
    for gamever in gamevers:
        config = repo_root / "configs" / f"{gamever}.yaml"
        snapshot = bundle_root / "gamesymbols" / f"{gamever}.yaml"
        metadata = bundle_root / "gamesymbols" / f"{gamever}.metadata.yaml"
        record = manifest_by_tag[gamever]
        try:
            check_snapshot_contract(
                gamever,
                bindir=repo_root / "bin",
                artifactdir=repo_root / "bin_artifacts",
                config_path=config,
                snapshot_path=snapshot,
            )
            verify_metadata(
                metadata_path=metadata,
                snapshot_path=snapshot,
                config_path=config,
                game_version=gamever,
            )
            gamedata_inventory, gamedata_manifest_digest = validate_gamedata_tree(
                bundle_root / "gamedata" / gamever,
                gamever,
                modules,
                candidate_sha256=sha256_file(snapshot),
                analysis_config_sha256=analysis_config_sha256(config),
                generator_contract_digest=generator_digest,
            )
        except (SnapshotError, MetadataContractError, GamedataContractError, OSError) as exc:
            raise ReleaseBundleError(f"Release bundle contract failed for {gamever}: {exc}") from exc
        expected_record = {
            "game_version": gamever,
            "artifact_inventory_sha256": artifact_by_tag[gamever].digest.removeprefix("sha256:"),
            "analysis_config_sha256": analysis_config_sha256(config),
            "snapshot_sha256": sha256_file(snapshot),
            "metadata_sha256": sha256_file(metadata),
            "gamedata_manifest_sha256": gamedata_manifest_digest,
            "gamedata_inventory_sha256": inventory_sha256(gamedata_inventory),
        }
        if record != expected_record:
            raise ReleaseBundleError(f"Release manifest provenance mismatch for {gamever}")

    actual_assets = [_asset_record(bundle_root, item["path"]) for item in manifest["assets"]]
    if actual_assets != manifest["assets"]:
        raise ReleaseBundleError("Release payload asset digest mismatch")
    manifest_record = _asset_record(bundle_root, manifest_relative)
    expected_checksums = _checksum_bytes([*manifest["assets"], manifest_record])
    if (bundle_root / f"SHA256SUMS-{version}.txt").read_bytes() != expected_checksums:
        raise ReleaseBundleError("SHA256SUMS does not match payload assets and manifest")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("--repo-root", default=".")
    build.add_argument("--bundle-root", required=True)
    build.add_argument("--gamesymbols-root", required=True)
    build.add_argument("--gamedata-root", required=True)
    build.add_argument("--archives-root", required=True)
    build.add_argument("--ida-runtime", required=True)
    build.add_argument("--cache-selection", required=True)
    build.add_argument("--version", required=True)
    build.add_argument("--build-id", required=True)
    build.add_argument("--workflow-run-url", required=True)
    build.add_argument("--source-sha", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--repo-root", default=".")
    verify.add_argument("--bundle-root", required=True)
    verify.add_argument("--version", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            build_release_bundle(
                repo_root=args.repo_root,
                bundle_root=args.bundle_root,
                gamesymbols_root=args.gamesymbols_root,
                gamedata_root=args.gamedata_root,
                archives_root=args.archives_root,
                ida_runtime_path=args.ida_runtime,
                cache_selection_path=args.cache_selection,
                version=args.version,
                build_id=args.build_id,
                workflow_run_url=args.workflow_run_url,
                source_sha=args.source_sha,
            )
        else:
            verify_release_bundle(repo_root=args.repo_root, bundle_root=args.bundle_root, version=args.version)
    except (ReleaseBundleError, ReleaseWorkflowError, OSError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
