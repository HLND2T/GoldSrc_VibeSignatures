#!/usr/bin/env python3
"""Derive canonical game-symbol JSON datasets and index from snapshot YAML.

The release bundle ships a single all-in-one ``gamesymbols-<version>.7z`` whose
contents are the browser-consumable JSON bytes that the Pages application
serves: one schema-3 dataset per game version (content-addressed filename) plus
a schema-4 index. The canonical snapshot/metadata YAML remain the trusted
source; this module deterministically derives those JSON bytes from them.
"""

from __future__ import annotations

import argparse
import json
import re
from functools import cmp_to_key
from pathlib import Path

from gamesymbol_snapshot_lib.candidate_session import CandidateContractError, absolute_path, ensure_real_path
from gamesymbol_snapshot_lib.codec import parse_snapshot_bytes
from gamesymbol_snapshot_lib.metadata import parse_metadata_bytes
from release_workflow_lib.hashing import canonical_json_bytes, sha256_bytes, sha256_file, write_canonical_json

GAME_VERSION_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*-[0-9]+$")
SYMBOL_PATH_PATTERN = re.compile(r"^([^/]+)/([^/]+)\.(windows|linux)\.yaml$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
PLATFORMS = ("windows", "linux")
DATASET_SCHEMA_VERSION = 3
INDEX_SCHEMA_VERSION = 4
SESSION_SCHEMA_VERSION = 1
SESSION_KEYS = {
    "schema_version",
    "gamever",
    "snapshot_sha256",
    "snapshot_schema_version",
    "config_digest_version",
    "config_sha256",
    "file_count",
    "last_publish_time",
    "dataset_path",
    "dataset_sha256",
    "dataset_size",
}


class GamesymbolsJsonError(ValueError):
    pass


def _symbol_kind(payload: dict) -> str:
    if isinstance(payload.get("patch_name"), str):
        return "patch"
    if isinstance(payload.get("vtable_class"), str):
        return "vtable"
    if isinstance(payload.get("struct_name"), str) and isinstance(payload.get("member_name"), str):
        return "structMember"
    if isinstance(payload.get("gv_name"), str):
        return "global"
    if isinstance(payload.get("vfunc_index"), int) and not isinstance(payload.get("vfunc_index"), bool):
        return "virtualFunction"
    if isinstance(payload.get("func_name"), str):
        return "function"
    return "unknown"


def _symbol_name(payload: dict, artifact: str) -> str:
    for key in ("func_name", "gv_name", "patch_name"):
        if isinstance(payload.get(key), str):
            return payload[key]
    if isinstance(payload.get("struct_name"), str) and isinstance(payload.get("member_name"), str):
        return f"{payload['struct_name']}.{payload['member_name']}"
    if isinstance(payload.get("vtable_class"), str):
        return payload["vtable_class"]
    return artifact


def _normalize_binaries(binaries: dict, schema: int) -> dict:
    result: dict = {}
    for module, platforms in binaries.items():
        if not isinstance(module, str) or not module or module in {".", ".."} or "/" in module or "\\" in module:
            raise GamesymbolsJsonError(f"Invalid binary module: {module!r}")
        normalized: dict = {}
        for platform, metadata in platforms.items():
            if platform not in PLATFORMS:
                raise GamesymbolsJsonError(f"Unsupported binary platform: {module}.{platform}")
            entry = {
                "sha256": metadata["sha256"],
                "md5": metadata["md5"],
                "crc32": metadata["crc32"],
                "crc64": metadata["crc64"],
                "size": metadata["size"],
            }
            if schema == 5:
                entry["path"] = metadata["path"]
            elif "path" in metadata:
                raise GamesymbolsJsonError(f"binaries.{module}.{platform}.path is not allowed in schema 6")
            normalized[platform] = entry
        result[module] = normalized
    return result


def _build_dataset(document: dict, metadata: dict, expected_game_version: str) -> dict:
    schema = document["schema_version"]
    if schema not in (5, 6):
        raise GamesymbolsJsonError(f"snapshot schema_version must be 5 or 6, got {schema}")
    game_version = document["game_version"]
    if game_version != expected_game_version:
        raise GamesymbolsJsonError(f"snapshot game_version {game_version} does not match {expected_game_version}")

    source = {
        "gameVersion": game_version,
        "snapshotSchemaVersion": schema,
        "configDigestVersion": document.get("config_digest_version", 1),
        "analysisOutputContractVersion": document.get("analysis_output_contract_version", 1),
        "configSha256": document["config_sha256"],
        "fileCount": document["file_count"],
        "lastPublishTime": document["last_publish_time"],
    }
    records = []
    module_counts: dict[str, dict[str, int]] = {}
    for path in sorted(document["files"]):
        match = SYMBOL_PATH_PATTERN.fullmatch(path)
        if match is None:
            raise GamesymbolsJsonError(f"invalid symbol path {path}")
        module, artifact, platform = match.group(1), match.group(2), match.group(3)
        if not module or not artifact or module in {".", ".."} or artifact in {".", ".."}:
            raise GamesymbolsJsonError(f"invalid symbol path {path}")
        payload = document["files"][path]
        counts = module_counts.setdefault(module, {"count": 0, "windowsCount": 0, "linuxCount": 0})
        counts["count"] += 1
        if platform == "windows":
            counts["windowsCount"] += 1
        else:
            counts["linuxCount"] += 1
        records.append(
            {
                "id": path,
                "module": module,
                "artifact": artifact,
                "symbolName": _symbol_name(payload, artifact),
                "platform": platform,
                "kind": _symbol_kind(payload),
                "payload": payload,
            }
        )
    modules = [
        {"name": name, **module_counts[name]} for name in sorted(module_counts, key=lambda item: item.casefold())
    ]
    dataset = {
        "schemaVersion": DATASET_SCHEMA_VERSION,
        "source": source,
        "binaries": _normalize_binaries(document["binaries"], schema),
        "modules": modules,
        "records": records,
    }
    return _attach_aliases(dataset, metadata, expected_game_version)


def _attach_aliases(dataset: dict, metadata: dict, expected_game_version: str) -> dict:
    if metadata["game_version"] != expected_game_version:
        raise GamesymbolsJsonError("metadata game_version does not match snapshot")
    record_keys = {f"{record['module']}/{record['platform']}/{record['artifact']}" for record in dataset["records"]}
    aliases: dict[str, list[str]] = {}
    for module in metadata["modules"]:
        for symbol in module["symbols"]:
            for artifact in symbol["artifacts"]:
                key = f"{module['name']}/{artifact['platform']}/{artifact['artifact']}"
                if key not in record_keys:
                    raise GamesymbolsJsonError(f"alias owner {key} is absent from snapshot")
                if key in aliases:
                    raise GamesymbolsJsonError(f"duplicate alias owner {key}")
                aliases[key] = symbol["alias"]
    if not aliases:
        return dataset
    records = [
        {**record, "aliases": aliases[key]}
        if (key := f"{record['module']}/{record['platform']}/{record['artifact']}") in aliases
        else record
        for record in dataset["records"]
    ]
    return {**dataset, "records": records}


def _parse_builds(value: str) -> tuple[str, str]:
    if not GAME_VERSION_PATTERN.fullmatch(value):
        raise GamesymbolsJsonError(f"Invalid GoldSrc game version: {value}")
    separator = value.rindex("-")
    return value[:separator], value[separator + 1 :]


def _compare_builds_descending(left: str, right: str) -> int:
    normalized_left = re.sub(r"^0+(?=\d)", "", left)
    normalized_right = re.sub(r"^0+(?=\d)", "", right)
    if len(normalized_left) != len(normalized_right):
        return len(normalized_right) - len(normalized_left)
    return (normalized_right > normalized_left) - (normalized_right < normalized_left)


def _compare_game_versions(left: str, right: str) -> int:
    left_family, left_build = _parse_builds(left)
    right_family, right_build = _parse_builds(right)
    family_difference = (left_family > right_family) - (left_family < right_family)
    if family_difference:
        return family_difference
    return _compare_builds_descending(left_build, right_build)


def encode_dataset(snapshot_bytes: bytes, metadata_bytes: bytes, expected_game_version: str) -> dict:
    document = parse_snapshot_bytes(snapshot_bytes, str(expected_game_version))
    metadata = parse_metadata_bytes(
        metadata_bytes,
        expected_game_version=str(expected_game_version),
        snapshot_bytes=snapshot_bytes,
    )
    return _build_dataset(document, metadata, str(expected_game_version))


def encode_index(datasets: list[dict]) -> dict:
    versions = []
    for dataset in datasets:
        game_version = dataset["source"]["gameVersion"]
        raw = canonical_json_bytes(dataset)
        digest = sha256_bytes(raw)
        versions.append(
            {
                "gameVersion": game_version,
                "url": f"{game_version}.{digest}.json",
                "sha256": digest,
                "size": len(raw),
                "snapshotSchemaVersion": dataset["source"]["snapshotSchemaVersion"],
                "fileCount": dataset["source"]["fileCount"],
                "lastPublishTime": dataset["source"]["lastPublishTime"],
            }
        )
    versions.sort(key=cmp_to_key(lambda left, right: _compare_game_versions(left["gameVersion"], right["gameVersion"])))
    return {"schemaVersion": INDEX_SCHEMA_VERSION, "versions": versions}


def guard_dataset_session(session_path: Path) -> dict:
    session = absolute_path(str(session_path))
    ensure_real_path(session, require_file=True)
    try:
        document = json.loads(session.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GamesymbolsJsonError(f"Unable to parse JSON dataset session {session}: {exc}") from exc
    if not isinstance(document, dict) or set(document) != SESSION_KEYS or document.get("schema_version") != 1:
        raise GamesymbolsJsonError("JSON dataset session has an unexpected schema or identity")
    dataset_path = document.get("dataset_path")
    if not isinstance(dataset_path, str) or not dataset_path:
        raise GamesymbolsJsonError("JSON dataset session has no dataset path")
    dataset = absolute_path(dataset_path)
    ensure_real_path(dataset, require_file=True)
    if not isinstance(document.get("dataset_sha256"), str) or not SHA256_PATTERN.fullmatch(document["dataset_sha256"]):
        raise GamesymbolsJsonError("JSON dataset session has an invalid dataset digest")
    if sha256_file(dataset) != document["dataset_sha256"]:
        raise GamesymbolsJsonError("JSON dataset session digest does not match dataset bytes")
    if not isinstance(document.get("dataset_size"), int) or document["dataset_size"] != dataset.stat().st_size:
        raise GamesymbolsJsonError("JSON dataset session size does not match dataset bytes")
    return document


def build_dataset_cli(*, snapshot_path, metadata_path, game_version, output_dir, session_path) -> dict:
    snapshot = Path(snapshot_path)
    metadata = Path(metadata_path)
    snapshot_raw = snapshot.read_bytes()
    metadata_raw = metadata.read_bytes()
    dataset = encode_dataset(snapshot_raw, metadata_raw, game_version)
    raw = canonical_json_bytes(dataset)
    digest = sha256_bytes(raw)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"{game_version}.{digest}.json"
    if output.exists():
        if output.read_bytes() != raw:
            raise GamesymbolsJsonError(f"Dataset output already exists with different bytes: {output}")
    else:
        write_canonical_json(output, dataset)
    session = absolute_path(str(session_path))
    session.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "schema_version": SESSION_SCHEMA_VERSION,
        "gamever": dataset["source"]["gameVersion"],
        "snapshot_sha256": sha256_bytes(snapshot_raw),
        "snapshot_schema_version": dataset["source"]["snapshotSchemaVersion"],
        "config_digest_version": dataset["source"]["configDigestVersion"],
        "config_sha256": dataset["source"]["configSha256"],
        "file_count": dataset["source"]["fileCount"],
        "last_publish_time": dataset["source"]["lastPublishTime"],
        "dataset_path": str(output),
        "dataset_sha256": digest,
        "dataset_size": len(raw),
    }
    write_canonical_json(session, document)
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("-snapshot", required=True)
    build.add_argument("-metadata", required=True)
    build.add_argument("-gamever", required=True)
    build.add_argument("-output-dir", required=True)
    build.add_argument("-session", required=True)
    guard = commands.add_parser("guard")
    guard.add_argument("-session", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            build_dataset_cli(
                snapshot_path=args.snapshot,
                metadata_path=args.metadata,
                game_version=args.gamever,
                output_dir=args.output_dir,
                session_path=args.session,
            )
        else:
            guard_dataset_session(args.session)
    except (GamesymbolsJsonError, CandidateContractError, OSError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
