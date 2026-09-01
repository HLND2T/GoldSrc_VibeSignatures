#!/usr/bin/env python3
"""Build and verify immutable GitHub Release bundles from tracked analysis artifacts.

The published payload of an immutable release is a single all-in-one
``archives/gamesymbols-<version>.7z`` containing the browser-consumable
game-symbol JSON (schema-4 index plus one content-addressed schema-3 dataset per
game version). The bundle itself carries the canonical snapshot/metadata YAML so
an independent verifier can re-derive those JSON bytes and compare them exactly.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

import yaml

from bin_artifact_contract import BinArtifactContractError, validate_repository_artifact_contract
from gamedata_contract import GamedataContractError, analysis_config_sha256
from gamesymbol_snapshot_lib.config import load_contract
from gamesymbol_snapshot_lib.errors import SnapshotError
from gamesymbol_snapshot_lib.metadata import MetadataContractError, verify_metadata
from gamesymbol_snapshot_lib.operations import check_snapshot_contract
from gamesymbols_json import encode_dataset, encode_index
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import (
    canonical_json_bytes,
    contained_path,
    file_inventory,
    normalized_relative_path,
    normalized_sha256,
    reject_reparse_points,
    sha256_bytes,
    sha256_file,
    write_canonical_json,
)
from release_workflow_lib.manifests import require_gamever, require_sha, require_version

BUNDLE_SCHEMA_VERSION = 2
MANIFEST_KEYS = {
    "schema_version",
    "release_version",
    "build_id",
    "workflow_run_url",
    "source_sha",
    "source_subject",
    "bin_gitlink_sha",
    "ida_runtime_sha256",
    "warm_idb_selection_sha256",
    "gamesymbols_json",
    "gamevers",
    "assets",
}
GAMEVER_RECORD_KEYS = {
    "game_version",
    "artifact_inventory_sha256",
    "analysis_config_sha256",
    "snapshot_sha256",
    "metadata_sha256",
}
JSON_BINDING_KEYS = {"index_sha256", "index_size", "datasets"}
JSON_DATASET_KEYS = {"game_version", "sha256", "size"}
ASSET_RECORD_KEYS = {"path", "size", "sha256"}
IDA_RUNTIME_EVIDENCE_KEYS = {"kernel_version", "idalib_mcp_sha256"}
CACHE_SELECTION_KEYS = {"schema_version", "cache_mode", "source_sha", "bin_commit", "entries"}
CACHE_SELECTION_ENTRY_KEYS = {"tag", "platform", "cache_key", "generation", "manifest_sha256", "binaries"}
CACHE_BINARY_KEYS = {"module", "platform", "path", "size", "sha256"}
GENERATION_RE = re.compile(r"^[A-Za-z0-9._-]{1,240}$", re.ASCII)
SEVEN_ZIP_ITEM_KEYS = {
    "Path",
    "Size",
    "Packed Size",
    "Modified",
    "Created",
    "Accessed",
    "Attributes",
    "CRC",
    "Encrypted",
    "Method",
    "Characteristics",
    "Host OS",
    "Version",
    "Volume Index",
    "Offset",
    "Block",
    "Folder",
    "Symbolic Link",
    "Hard Link",
}
SEVEN_ZIP_CRC_RE = re.compile(r"^[0-9A-F]{8}$")


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


def _expected_cache_pairs(repo_root: Path, gamevers: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    pairs = []
    for gamever in gamevers:
        contract = load_contract(
            repo_root / "configs" / f"{gamever}.yaml",
            gamever,
            repo_root / "bin",
            artifactdir=repo_root / "bin_artifacts",
        )
        pairs.extend(
            (gamever, platform) for platform in sorted({target.platform for target in contract.binary_targets.values()})
        )
    return tuple(sorted(pairs))


def _copy_file(source: Path, target: Path) -> None:
    if not source.is_file():
        raise ReleaseBundleError(f"Required bundle input is missing: {source}")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise ReleaseBundleError(f"Bundle target already exists: {target}")
    target.write_bytes(source.read_bytes())


def _add_archive_source(sources: dict[str, Path], relative: str, source: Path) -> None:
    relative = normalized_relative_path(relative)
    if not source.is_file():
        raise ReleaseBundleError(f"Expected archive source is missing: {source}")
    if relative.casefold() in {path.casefold() for path in sources}:
        raise ReleaseBundleError(f"Expected archive paths case-collide: {relative}")
    sources[relative] = source


def _json_archive_sources(json_dir: Path) -> dict[str, Path]:
    sources: dict[str, Path] = {}
    for path in sorted(json_dir.iterdir(), key=lambda item: item.name):
        if not path.is_file():
            raise ReleaseBundleError(f"JSON dataset staging is not a plain file: {path}")
        _add_archive_source(sources, f"gamesymbols/{path.name}", path)
    if not sources:
        raise ReleaseBundleError("No JSON datasets were staged for the gamesymbols archive")
    return dict(sorted(sources.items()))


def _asset_record(bundle_root: Path, relative: str) -> dict:
    relative = normalized_relative_path(relative)
    path = contained_path(bundle_root, *PurePosixPath(relative).parts)
    if not path.is_file():
        raise ReleaseBundleError(f"Release asset is missing: {relative}")
    return {"path": relative, "size": path.stat().st_size, "sha256": sha256_file(path)}


def _checksum_bytes(records: list[dict]) -> bytes:
    return "".join(f"{record['sha256']}  {record['path']}\n" for record in records).encode("utf-8")


def _seven_zip_records(archive: Path) -> list[dict[str, str]]:
    result = subprocess.run(
        ["7z", "l", "-slt", "-ba", "-sccUTF-8", str(archive)],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
    )
    if result.returncode != 0:
        raise ReleaseBundleError(result.stderr.strip() or f"Unable to list archive: {archive}")
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for raw_line in result.stdout.splitlines():
        if not raw_line:
            if current:
                records.append(current)
                current = {}
            continue
        key, separator, value = raw_line.partition(" = ")
        if not separator or key not in SEVEN_ZIP_ITEM_KEYS or key in current:
            raise ReleaseBundleError(f"Archive listing is ambiguous or unsafe: {archive}")
        current[key] = value
    if current:
        records.append(current)
    if not records:
        raise ReleaseBundleError(f"Archive contains no entries: {archive}")
    return records


def _seven_zip_inventory(
    archive: Path,
    expected_paths: set[str],
    *,
    required_directories: set[str] | None = None,
) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    seen_casefold: set[str] = set()
    required_directories = {
        normalized_relative_path(path) for path in (() if required_directories is None else required_directories)
    }
    if len({path.casefold() for path in required_directories}) != len(required_directories):
        raise ReleaseBundleError("Required archive directories case-collide")
    expected_directories = {
        PurePosixPath(*PurePosixPath(path).parts[:index]).as_posix()
        for path in expected_paths
        for index in range(1, len(PurePosixPath(path).parts))
    }
    expected_directories.update(
        PurePosixPath(*PurePosixPath(path).parts[:index]).as_posix()
        for path in required_directories
        for index in range(1, len(PurePosixPath(path).parts) + 1)
    )
    for record in _seven_zip_records(archive):
        raw_path = record.get("Path")
        if raw_path is None or any(ord(character) < 32 for character in raw_path):
            raise ReleaseBundleError(f"Archive entry path is missing or unsafe: {archive}")
        normalized_input = raw_path.replace("\\", "/")
        if normalized_input == "." and record.get("Folder") == "+":
            continue
        try:
            path = normalized_relative_path(normalized_input)
        except ReleaseWorkflowError as exc:
            raise ReleaseBundleError(f"Archive entry path is unsafe: {raw_path!r}") from exc
        key = path.casefold()
        if key in seen_casefold:
            raise ReleaseBundleError(f"Archive entry paths duplicate or case-collide: {path}")
        seen_casefold.add(key)
        if record.get("Symbolic Link") or record.get("Hard Link"):
            raise ReleaseBundleError(f"Archive links are not allowed: {path}")
        is_directory = record.get("Folder") == "+" or record.get("Attributes", "").startswith("D")
        if is_directory:
            if path not in expected_directories:
                raise ReleaseBundleError(f"Archive contains an unexpected directory: {path}")
            directories.add(path)
            continue
        try:
            size = int(record["Size"])
        except (KeyError, ValueError) as exc:
            raise ReleaseBundleError(f"Archive file has no valid size: {path}") from exc
        if size < 0:
            raise ReleaseBundleError(f"Archive file has a negative size: {path}")
        crc = record.get("CRC")
        if crc is not None and not SEVEN_ZIP_CRC_RE.fullmatch(crc):
            raise ReleaseBundleError(f"Archive file has an invalid CRC: {path}")
        files.add(path)
    if files != expected_paths:
        raise ReleaseBundleError(
            f"Archive file inventory mismatch: missing={sorted(expected_paths - files)!r}; "
            f"extra={sorted(files - expected_paths)!r}"
        )
    if not required_directories.issubset(directories):
        raise ReleaseBundleError(
            f"Archive required directory inventory mismatch: missing={sorted(required_directories - directories)!r}"
        )
    return files, directories


def _verify_archive(
    archive: Path,
    expected_sources: dict[str, Path],
    *,
    required_directories: set[str] | None = None,
) -> None:
    expected_records = [
        {"path": path, "size": source.stat().st_size, "sha256": sha256_file(source)}
        for path, source in expected_sources.items()
    ]
    _seven_zip_inventory(
        archive,
        {record["path"] for record in expected_records},
        required_directories=required_directories,
    )
    with tempfile.TemporaryDirectory(prefix="release-archive-verify-") as temporary:
        extracted = Path(temporary)
        result = subprocess.run(
            ["7z", "x", "-y", f"-o{extracted}", str(archive)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            raise ReleaseBundleError(result.stderr.strip() or f"Unable to extract archive: {archive}")
        actual_records = file_inventory(extracted)
        if actual_records != expected_records:
            raise ReleaseBundleError(f"Archive content differs from trusted sources: {archive.name}")


def _load_canonical_json(path: Path, label: str) -> dict:
    try:
        raw = path.read_bytes()
        document = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseBundleError(f"Unable to parse {label}: {exc}") from exc
    if not isinstance(document, dict) or canonical_json_bytes(document) != raw:
        raise ReleaseBundleError(f"{label} must be a canonical JSON object")
    return document


def _parse_manifest(path: Path) -> dict:
    try:
        raw = path.read_bytes()
        document = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseBundleError(f"Unable to parse release manifest {path}: {exc}") from exc
    if not isinstance(document, dict) or set(document) != MANIFEST_KEYS or document.get("schema_version") != 2:
        raise ReleaseBundleError("Release manifest has unexpected fields or schema")
    if canonical_json_bytes(document) != raw:
        raise ReleaseBundleError("Release manifest is not canonical JSON")
    return document


def _validate_manifest_identity(
    manifest: dict,
    *,
    repo_root: Path,
    version: str,
    source_sha: str,
    build_id: str,
    workflow_run_url: str,
    gamevers: tuple[str, ...],
) -> None:
    if manifest["release_version"] != version:
        raise ReleaseBundleError("Release manifest version mismatch")
    if manifest["source_sha"] != source_sha:
        raise ReleaseBundleError("Release manifest source SHA differs from the bound workflow identity")
    if manifest["build_id"] != build_id or manifest["workflow_run_url"] != workflow_run_url:
        raise ReleaseBundleError("Release manifest workflow identity mismatch")
    if manifest["source_subject"] != _git(repo_root, "show", "-s", "--format=%s", "HEAD"):
        raise ReleaseBundleError("Release manifest source subject mismatch")
    for key in ("ida_runtime_sha256", "warm_idb_selection_sha256"):
        try:
            normalized_sha256(manifest[key], f"release manifest {key}")
        except ReleaseWorkflowError as exc:
            raise ReleaseBundleError(str(exc)) from exc
    records = manifest["gamevers"]
    if (
        not isinstance(records, list)
        or [record.get("game_version") if isinstance(record, dict) else None for record in records] != list(gamevers)
        or any(not isinstance(record, dict) or set(record) != GAMEVER_RECORD_KEYS for record in records)
    ):
        raise ReleaseBundleError("Release manifest gamever inventory must be unique, canonical, and complete")
    for record in records:
        try:
            normalized_sha256(record["snapshot_sha256"], f"release manifest {record['game_version']} snapshot")
            normalized_sha256(record["metadata_sha256"], f"release manifest {record['game_version']} metadata")
            normalized_sha256(
                record["artifact_inventory_sha256"], f"release manifest {record['game_version']} artifact inventory"
            )
            normalized_sha256(record["analysis_config_sha256"], f"release manifest {record['game_version']} config")
        except ReleaseWorkflowError as exc:
            raise ReleaseBundleError(str(exc)) from exc
    binding = manifest["gamesymbols_json"]
    if not isinstance(binding, dict) or set(binding) != JSON_BINDING_KEYS:
        raise ReleaseBundleError("Release manifest JSON binding has an invalid schema")
    try:
        normalized_sha256(binding["index_sha256"], "release manifest JSON index")
    except ReleaseWorkflowError as exc:
        raise ReleaseBundleError(str(exc)) from exc
    if not isinstance(binding["index_size"], int) or binding["index_size"] <= 0:
        raise ReleaseBundleError("Release manifest JSON index size is invalid")
    datasets = binding["datasets"]
    if (
        not isinstance(datasets, list)
        or [record.get("game_version") if isinstance(record, dict) else None for record in datasets] != list(gamevers)
        or any(
            not isinstance(record, dict)
            or set(record) != JSON_DATASET_KEYS
            or not isinstance(record["size"], int)
            or record["size"] <= 0
            for record in datasets
        )
    ):
        raise ReleaseBundleError("Release manifest JSON dataset inventory is invalid")
    for record in datasets:
        try:
            normalized_sha256(record["sha256"], f"release manifest JSON dataset {record['game_version']}")
        except ReleaseWorkflowError as exc:
            raise ReleaseBundleError(str(exc)) from exc
    assets = manifest["assets"]
    if not isinstance(assets, list) or any(
        not isinstance(record, dict)
        or set(record) != ASSET_RECORD_KEYS
        or not isinstance(record["size"], int)
        or record["size"] < 0
        for record in assets
    ):
        raise ReleaseBundleError("Release manifest asset inventory has an invalid schema")


def _validate_evidence(
    *,
    bundle_root: Path,
    manifest: dict,
    source_sha: str,
    bin_gitlink_sha: str,
    cache_selection_sha256: str,
    gamevers: tuple[str, ...],
    expected_cache_pairs: tuple[tuple[str, str], ...],
) -> None:
    runtime_path = bundle_root / "evidence/ida-runtime.json"
    selection_path = bundle_root / "evidence/cache-selection.json"
    runtime = _load_canonical_json(runtime_path, "IDA runtime evidence")
    if set(runtime) != IDA_RUNTIME_EVIDENCE_KEYS:
        raise ReleaseBundleError("IDA runtime evidence has unexpected fields")
    if (
        not isinstance(runtime["kernel_version"], str)
        or not runtime["kernel_version"].strip()
        or runtime["kernel_version"] != runtime["kernel_version"].strip()
    ):
        raise ReleaseBundleError("IDA runtime kernel version must be a trimmed non-empty string")
    try:
        normalized_sha256(runtime["idalib_mcp_sha256"], "IDA runtime idalib-mcp digest")
        expected_selection_digest = normalized_sha256(cache_selection_sha256, "bound warm IDB selection digest")
    except ReleaseWorkflowError as exc:
        raise ReleaseBundleError(str(exc)) from exc
    selection = _load_canonical_json(selection_path, "warm IDB selection evidence")
    if (
        set(selection) != CACHE_SELECTION_KEYS
        or selection.get("schema_version") != 1
        or selection.get("cache_mode") != "warm"
        or selection.get("source_sha") != source_sha
        or selection.get("bin_commit") != bin_gitlink_sha
        or not isinstance(selection.get("entries"), list)
        or not selection["entries"]
    ):
        raise ReleaseBundleError("Warm IDB selection evidence has an unexpected schema or identity")
    entries = selection["entries"]
    pairs: list[tuple[str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != CACHE_SELECTION_ENTRY_KEYS:
            raise ReleaseBundleError("Warm IDB selection entry has unexpected fields")
        try:
            tag = require_gamever(entry["tag"])
            normalized_sha256(entry["cache_key"], "warm IDB cache key")
            normalized_sha256(entry["manifest_sha256"], "warm IDB generation manifest digest")
        except ReleaseWorkflowError as exc:
            raise ReleaseBundleError(str(exc)) from exc
        platform = entry["platform"]
        if tag not in gamevers or platform not in {"windows", "linux"}:
            raise ReleaseBundleError("Warm IDB selection entry has an unknown tag or platform")
        if not isinstance(entry["generation"], str) or not GENERATION_RE.fullmatch(entry["generation"]):
            raise ReleaseBundleError("Warm IDB selection generation is invalid")
        binaries = entry["binaries"]
        if not isinstance(binaries, list) or not binaries:
            raise ReleaseBundleError("Warm IDB selection entry must bind binaries")
        binary_paths = []
        for binary in binaries:
            if not isinstance(binary, dict) or set(binary) != CACHE_BINARY_KEYS:
                raise ReleaseBundleError("Warm IDB selection binary has unexpected fields")
            try:
                binary_path = normalized_relative_path(binary["path"])
                normalized_sha256(binary["sha256"], "warm IDB binary digest")
            except ReleaseWorkflowError as exc:
                raise ReleaseBundleError(str(exc)) from exc
            if (
                binary["platform"] != platform
                or not isinstance(binary["module"], str)
                or not binary["module"]
                or PurePosixPath(binary_path).parts[0] != binary["module"]
                or not isinstance(binary["size"], int)
                or binary["size"] <= 0
            ):
                raise ReleaseBundleError("Warm IDB selection binary identity is invalid")
            binary_paths.append(binary_path)
        if binary_paths != sorted(binary_paths) or len({path.casefold() for path in binary_paths}) != len(binary_paths):
            raise ReleaseBundleError("Warm IDB selection binaries must use canonical unique order")
        pairs.append((tag, platform))
    if tuple(pairs) != expected_cache_pairs:
        raise ReleaseBundleError("Warm IDB selection entries do not cover the configured tag/platform inventory")
    if sha256_file(runtime_path) != manifest["ida_runtime_sha256"]:
        raise ReleaseBundleError("IDA runtime evidence digest mismatch")
    if (
        sha256_file(selection_path) != manifest["warm_idb_selection_sha256"]
        or sha256_file(selection_path) != expected_selection_digest
    ):
        raise ReleaseBundleError("Warm IDB selection evidence digest mismatch")


def _source_time(repo_root: Path) -> float:
    value = _git(repo_root, "show", "-s", "--format=%cI", "HEAD")
    return datetime.fromisoformat(value).astimezone(timezone.utc).timestamp()


def _pack_gamesymbols_archive(bundle_root: Path, version: str, json_dir: Path, source_time: float) -> None:
    target = bundle_root / "archives" / f"gamesymbols-{version}.7z"
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="release-gamesymbols-archive-") as temporary:
        stage_root = Path(temporary)
        stage = stage_root / "gamesymbols"
        stage.mkdir()
        for path in sorted(json_dir.iterdir(), key=lambda item: item.name):
            if not path.is_file():
                raise ReleaseBundleError(f"JSON dataset staging is not a plain file: {path}")
            shutil.copy2(path, stage / path.name)
        for path in stage.rglob("*"):
            if path.is_file():
                os.utime(path, (source_time, source_time))
        result = subprocess.run(
            ["7z", "a", "-t7z", "-mx=9", "-mmt=off", "-mtc=off", "-mta=off", str(target), "."],
            cwd=stage_root,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise ReleaseBundleError(result.stderr.strip() or f"Unable to pack gamesymbols archive: {target}")


def _derive_dataset(bundle_root: Path, gamever: str) -> tuple[dict, bytes, str]:
    snapshot = bundle_root / "gamesymbols" / f"{gamever}.yaml"
    metadata = bundle_root / "gamesymbols" / f"{gamever}.metadata.yaml"
    dataset = encode_dataset(snapshot.read_bytes(), metadata.read_bytes(), gamever)
    raw = canonical_json_bytes(dataset)
    return dataset, raw, sha256_bytes(raw)


def _stage_json_dataset(json_dir: Path, gamever: str, provided_root: Path, raw: bytes) -> str:
    digest = sha256_bytes(raw)
    name = f"{gamever}.{digest}.json"
    provided = provided_root / name
    if not provided.is_file():
        raise ReleaseBundleError(f"Derived JSON dataset is absent from staging for {gamever}: {name}")
    if provided.read_bytes() != raw:
        raise ReleaseBundleError(f"Staged JSON dataset differs from derivation for {gamever}")
    target = json_dir / name
    if target.exists():
        raise ReleaseBundleError(f"Bundle JSON dataset already exists: {target}")
    target.write_bytes(raw)
    return name


def build_release_bundle(
    *,
    repo_root: str | Path,
    bundle_root: str | Path,
    gamesymbols_root: str | Path,
    gamesymbols_json_root: str | Path,
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
    except (BinArtifactContractError, ReleaseWorkflowError) as exc:
        raise ReleaseBundleError(str(exc)) from exc

    ida_runtime = Path(ida_runtime_path)
    cache_selection = Path(cache_selection_path)
    _copy_file(ida_runtime, bundle_root / "evidence/ida-runtime.json")
    _copy_file(cache_selection, bundle_root / "evidence/cache-selection.json")

    artifacts_by_tag = {item.game_version: item for item in repository_artifacts.gamevers}
    gamesymbols_root = Path(gamesymbols_root)
    gamesymbols_json_root = Path(gamesymbols_json_root)
    gamevers = _configured_gamevers(repo_root)
    json_dir = bundle_root / "gamesymbols-json"
    json_dir.mkdir()
    gamever_records: list[dict] = []
    datasets: list[dict] = []
    for gamever in gamevers:
        snapshot_source = gamesymbols_root / f"{gamever}.yaml"
        metadata_source = gamesymbols_root / f"{gamever}.metadata.yaml"
        snapshot_target = bundle_root / "gamesymbols" / snapshot_source.name
        metadata_target = bundle_root / "gamesymbols" / metadata_source.name
        _copy_file(snapshot_source, snapshot_target)
        _copy_file(metadata_source, metadata_target)
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
        except (SnapshotError, MetadataContractError, OSError) as exc:
            raise ReleaseBundleError(f"Release payload contract failed for {gamever}: {exc}") from exc
        dataset, raw, digest = _derive_dataset(bundle_root, gamever)
        _stage_json_dataset(json_dir, gamever, gamesymbols_json_root, raw)
        datasets.append(dataset)
        artifact_inventory = artifacts_by_tag[gamever]
        gamever_records.append(
            {
                "game_version": gamever,
                "artifact_inventory_sha256": artifact_inventory.digest.removeprefix("sha256:"),
                "analysis_config_sha256": analysis_config_sha256(config),
                "snapshot_sha256": sha256_file(snapshot_target),
                "metadata_sha256": sha256_file(metadata_target),
            }
        )

    index = encode_index(datasets)
    index_path = json_dir / "index.json"
    write_canonical_json(index_path, index)
    if index_path.read_bytes() != canonical_json_bytes(index):
        raise ReleaseBundleError("JSON index was not written canonically")
    index_record = _asset_record(bundle_root, "gamesymbols-json/index.json")

    _pack_gamesymbols_archive(bundle_root, version, json_dir, _source_time(repo_root))
    payload = _asset_record(bundle_root, f"archives/gamesymbols-{version}.7z")
    manifest = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "release_version": version,
        "build_id": str(build_id),
        "workflow_run_url": str(workflow_run_url),
        "source_sha": source_sha,
        "source_subject": _git(repo_root, "show", "-s", "--format=%s", "HEAD"),
        "bin_gitlink_sha": _gitlink(repo_root),
        "ida_runtime_sha256": sha256_file(bundle_root / "evidence/ida-runtime.json"),
        "warm_idb_selection_sha256": sha256_file(bundle_root / "evidence/cache-selection.json"),
        "gamesymbols_json": {
            "index_sha256": index_record["sha256"],
            "index_size": index_record["size"],
            "datasets": [
                {
                    "game_version": dataset["source"]["gameVersion"],
                    "sha256": sha256_bytes(canonical_json_bytes(dataset)),
                    "size": len(canonical_json_bytes(dataset)),
                }
                for dataset in datasets
            ],
        },
        "gamevers": gamever_records,
        "assets": [payload],
    }
    manifest_relative = f"release-manifest-{version}.json"
    manifest_path = bundle_root / manifest_relative
    write_canonical_json(manifest_path, manifest)
    checksummed = [*manifest["assets"], _asset_record(bundle_root, manifest_relative)]
    (bundle_root / f"SHA256SUMS-{version}.txt").write_bytes(_checksum_bytes(checksummed))
    return manifest


def verify_release_bundle(
    *,
    repo_root: str | Path,
    bundle_root: str | Path,
    version: str,
    source_sha: str,
    build_id: str,
    workflow_run_url: str,
    cache_selection_sha256: str,
) -> dict:
    repo_root = Path(repo_root).resolve()
    bundle_root = Path(bundle_root).resolve()
    version = require_version(version)
    source_sha = require_sha(source_sha, "bound SOURCE_SHA")
    if not isinstance(build_id, str) or not build_id or not isinstance(workflow_run_url, str) or not workflow_run_url:
        raise ReleaseBundleError("Bound build ID and workflow run URL must be non-empty strings")
    manifest_relative = f"release-manifest-{version}.json"
    manifest = _parse_manifest(bundle_root / manifest_relative)
    gamevers = _configured_gamevers(repo_root)
    _validate_manifest_identity(
        manifest,
        repo_root=repo_root,
        version=version,
        source_sha=source_sha,
        build_id=build_id,
        workflow_run_url=workflow_run_url,
        gamevers=gamevers,
    )
    if _git(repo_root, "rev-parse", "HEAD") != source_sha:
        raise ReleaseBundleError("Verifier checkout does not match the bound source SHA")
    bin_gitlink_sha = _gitlink(repo_root)
    if bin_gitlink_sha != manifest["bin_gitlink_sha"]:
        raise ReleaseBundleError("Verifier bin gitlink does not match manifest")

    try:
        repository_artifacts = validate_repository_artifact_contract(repo_root)
        reject_reparse_points(bundle_root)
    except (BinArtifactContractError, ReleaseWorkflowError) as exc:
        raise ReleaseBundleError(str(exc)) from exc
    _validate_evidence(
        bundle_root=bundle_root,
        manifest=manifest,
        source_sha=source_sha,
        bin_gitlink_sha=bin_gitlink_sha,
        cache_selection_sha256=cache_selection_sha256,
        gamevers=gamevers,
        expected_cache_pairs=_expected_cache_pairs(repo_root, gamevers),
    )

    expected_paths = {
        manifest_relative,
        f"SHA256SUMS-{version}.txt",
        "evidence/ida-runtime.json",
        "evidence/cache-selection.json",
        "gamesymbols-json/index.json",
        f"archives/gamesymbols-{version}.7z",
    }
    artifact_by_tag = {item.game_version: item for item in repository_artifacts.gamevers}
    manifest_by_tag = {item["game_version"]: item for item in manifest["gamevers"]}
    json_dir = bundle_root / "gamesymbols-json"
    datasets: list[dict] = []
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
        except (SnapshotError, MetadataContractError, OSError) as exc:
            raise ReleaseBundleError(f"Release bundle contract failed for {gamever}: {exc}") from exc
        dataset, raw, digest = _derive_dataset(bundle_root, gamever)
        dataset_name = f"{gamever}.{digest}.json"
        dataset_path = json_dir / dataset_name
        if not dataset_path.is_file():
            raise ReleaseBundleError(f"Derived JSON dataset is absent from the bundle for {gamever}: {dataset_name}")
        if dataset_path.read_bytes() != raw:
            raise ReleaseBundleError(f"Bundle JSON dataset differs from derivation for {gamever}")
        expected_paths.update({f"gamesymbols/{gamever}.yaml", f"gamesymbols/{gamever}.metadata.yaml"})
        expected_paths.add(f"gamesymbols-json/{dataset_name}")
        datasets.append(dataset)
        expected_record = {
            "game_version": gamever,
            "artifact_inventory_sha256": artifact_by_tag[gamever].digest.removeprefix("sha256:"),
            "analysis_config_sha256": analysis_config_sha256(config),
            "snapshot_sha256": sha256_file(snapshot),
            "metadata_sha256": sha256_file(metadata),
        }
        if record != expected_record:
            raise ReleaseBundleError(f"Release manifest provenance mismatch for {gamever}")

    index_bytes = canonical_json_bytes(encode_index(datasets))
    index_path = json_dir / "index.json"
    if index_path.read_bytes() != index_bytes:
        raise ReleaseBundleError("Bundle JSON index differs from independent derivation")
    _verify_archive(
        bundle_root / "archives" / f"gamesymbols-{version}.7z",
        _json_archive_sources(json_dir),
        required_directories={"gamesymbols"},
    )
    actual_paths = {item["path"] for item in file_inventory(bundle_root)}
    if actual_paths != expected_paths:
        raise ReleaseBundleError(
            f"Release bundle allowlist mismatch: missing={sorted(expected_paths - actual_paths)!r}; "
            f"extra={sorted(actual_paths - expected_paths)!r}"
        )

    expected_json_binding = {
        "index_sha256": sha256_bytes(index_bytes),
        "index_size": len(index_bytes),
        "datasets": [
            {
                "game_version": dataset["source"]["gameVersion"],
                "sha256": sha256_bytes(canonical_json_bytes(dataset)),
                "size": len(canonical_json_bytes(dataset)),
            }
            for dataset in datasets
        ],
    }
    if manifest["gamesymbols_json"] != expected_json_binding:
        raise ReleaseBundleError("Release manifest JSON binding mismatch")
    expected_assets = [_asset_record(bundle_root, f"archives/gamesymbols-{version}.7z")]
    if manifest["assets"] != expected_assets:
        raise ReleaseBundleError("Release payload asset inventory or digest mismatch")
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
    build.add_argument("--gamesymbols-json-root", required=True)
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
    verify.add_argument("--source-sha", required=True)
    verify.add_argument("--build-id", required=True)
    verify.add_argument("--workflow-run-url", required=True)
    verify.add_argument("--cache-selection-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            build_release_bundle(
                repo_root=args.repo_root,
                bundle_root=args.bundle_root,
                gamesymbols_root=args.gamesymbols_root,
                gamesymbols_json_root=args.gamesymbols_json_root,
                ida_runtime_path=args.ida_runtime,
                cache_selection_path=args.cache_selection,
                version=args.version,
                build_id=args.build_id,
                workflow_run_url=args.workflow_run_url,
                source_sha=args.source_sha,
            )
        else:
            verify_release_bundle(
                repo_root=args.repo_root,
                bundle_root=args.bundle_root,
                version=args.version,
                source_sha=args.source_sha,
                build_id=args.build_id,
                workflow_run_url=args.workflow_run_url,
                cache_selection_sha256=args.cache_selection_sha256,
            )
    except (ReleaseBundleError, ReleaseWorkflowError, GamedataContractError, OSError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
