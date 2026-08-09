"""Canonical YAML codec with snapshot schema 1-5 reader compatibility."""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import PurePosixPath, PureWindowsPath

import yaml

from analysis_output_contract import ANALYSIS_OUTPUT_CONTRACT_VERSION
from gamesymbol_snapshot_lib.errors import SnapshotSchemaError
from gamesymbol_snapshot_lib.paths import validate_snapshot_key
from trusted_yaml import load_yaml

LEGACY_SCHEMA_VERSION = 1
SCHEMA_2_VERSION = 2
SCHEMA_3_VERSION = 3
SCHEMA_4_VERSION = 4
SCHEMA_VERSION = 5
SCHEMA_KEYS = {
    1: ("schema_version", "game_version", "config_sha256", "file_count", "files"),
    2: ("schema_version", "config_digest_version", "game_version", "config_sha256", "file_count", "files"),
    3: (
        "schema_version",
        "analysis_output_contract_version",
        "config_digest_version",
        "game_version",
        "config_sha256",
        "file_count",
        "files",
    ),
    4: (
        "schema_version",
        "last_publish_time",
        "binaries",
        "analysis_output_contract_version",
        "config_digest_version",
        "game_version",
        "config_sha256",
        "file_count",
        "files",
    ),
    5: (
        "schema_version",
        "last_publish_time",
        "binaries",
        "analysis_output_contract_version",
        "config_digest_version",
        "game_version",
        "config_sha256",
        "file_count",
        "files",
    ),
}
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
MD5_PATTERN = re.compile(r"^[0-9a-f]{32}$")
CRC32_PATTERN = re.compile(r"^[0-9a-f]{8}$")
CRC64_PATTERN = re.compile(r"^[0-9a-f]{16}$")
PUBLISH_TIME_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class CanonicalDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


class _QuotedString(str):
    pass


def _represent_quoted_string(dumper, value):
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="'")


CanonicalDumper.add_representer(_QuotedString, _represent_quoted_string)


def _sort_key(key):
    return type(key).__name__, str(key)


def canonicalize(value):
    if isinstance(value, Mapping):
        return {key: canonicalize(value[key]) for key in sorted(value, key=_sort_key)}
    if isinstance(value, list):
        return [canonicalize(item) for item in value]
    if isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]+", value):
        return _QuotedString(value.lower())
    return value


def canonical_yaml_bytes(value) -> bytes:
    text = yaml.dump(
        canonicalize(value),
        Dumper=CanonicalDumper,
        allow_unicode=True,
        default_flow_style=False,
        explicit_end=False,
        explicit_start=False,
        indent=2,
        line_break="\n",
        sort_keys=False,
        width=1_000_000,
    )
    return text.rstrip("\r\n").encode("utf-8") + b"\n"


def snapshot_config_digest_version(document: Mapping) -> int:
    schema = document.get("schema_version")
    if schema == 1:
        return 1
    if schema in {2, 3, 4, 5} and document.get("config_digest_version") == 2:
        return 2
    if schema not in SCHEMA_KEYS:
        raise SnapshotSchemaError(
            f"Unsupported snapshot schema_version: {schema!r}", reason="unsupported_snapshot_schema"
        )
    raise SnapshotSchemaError(
        f"Unsupported snapshot config_digest_version: {document.get('config_digest_version')!r}",
        reason="unsupported_config_digest_version",
    )


def snapshot_analysis_output_contract_version(document: Mapping) -> int:
    schema = document.get("schema_version")
    if schema in {1, 2}:
        return 1
    value = document.get("analysis_output_contract_version")
    if schema in {3, 4, 5} and isinstance(value, int) and not isinstance(value, bool) and value >= 1:
        return value
    if schema not in SCHEMA_KEYS:
        raise SnapshotSchemaError(
            f"Unsupported snapshot schema_version: {schema!r}", reason="unsupported_snapshot_schema"
        )
    raise SnapshotSchemaError("Invalid analysis_output_contract_version")


def _canonical_binaries(binaries: Mapping, schema: int) -> dict:
    result = canonicalize(binaries)
    for platforms in result.values():
        if not isinstance(platforms, dict):
            continue
        for metadata in platforms.values():
            if not isinstance(metadata, dict):
                continue
            for key in ("sha256", "md5", "crc32", "crc64"):
                if isinstance(metadata.get(key), str):
                    metadata[key] = _QuotedString(metadata[key])
    return result


def build_snapshot_document(
    game_version: str,
    config_sha256: str,
    files: Mapping,
    *,
    schema_version: int = SCHEMA_VERSION,
    config_digest_version: int | None = None,
    analysis_output_contract_version: int | None = None,
    last_publish_time: str | None = None,
    binaries: Mapping | None = None,
) -> dict:
    if schema_version not in SCHEMA_KEYS:
        raise SnapshotSchemaError(f"Unsupported snapshot schema_version: {schema_version!r}")
    ordered_files = {path: canonicalize(files[path]) for path in sorted(files)}
    common = {
        "game_version": str(game_version),
        "config_sha256": config_sha256,
        "file_count": len(ordered_files),
        "files": ordered_files,
    }
    if schema_version == 1:
        if config_digest_version not in {None, 1}:
            raise SnapshotSchemaError("Schema 1 requires config digest version 1")
        return {"schema_version": 1, **common}
    config_digest_version = 2 if config_digest_version is None else config_digest_version
    if config_digest_version != 2:
        raise SnapshotSchemaError("Schemas 2-5 require config digest version 2")
    if schema_version == 2:
        return {"schema_version": 2, "config_digest_version": 2, **common}
    output_version = (
        ANALYSIS_OUTPUT_CONTRACT_VERSION
        if analysis_output_contract_version is None
        else analysis_output_contract_version
    )
    if not isinstance(output_version, int) or isinstance(output_version, bool) or output_version < 1:
        raise SnapshotSchemaError("Invalid analysis output contract version")
    rest = {
        "analysis_output_contract_version": output_version,
        "config_digest_version": 2,
        **common,
    }
    if schema_version == 3:
        return {"schema_version": 3, **rest}
    if last_publish_time is None or binaries is None:
        raise SnapshotSchemaError("Published snapshots require last_publish_time and binaries")
    return {
        "schema_version": schema_version,
        "last_publish_time": last_publish_time,
        "binaries": _canonical_binaries(binaries, schema_version),
        **rest,
    }


def canonical_snapshot_bytes(document: Mapping) -> bytes:
    return canonical_yaml_bytes(
        build_snapshot_document(
            str(document["game_version"]),
            document["config_sha256"],
            document["files"],
            schema_version=document["schema_version"],
            config_digest_version=snapshot_config_digest_version(document),
            analysis_output_contract_version=snapshot_analysis_output_contract_version(document),
            last_publish_time=document.get("last_publish_time"),
            binaries=document.get("binaries"),
        )
    )


def _validate_relative_binary_path(value: object, context: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or PureWindowsPath(value).is_absolute():
        raise SnapshotSchemaError(f"{context} must be a relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or "//" in value or any(part in {"", ".", ".."} for part in path.parts):
        raise SnapshotSchemaError(f"{context} is unsafe: {value!r}")
    return path.as_posix()


def _validate_binaries(document: dict) -> None:
    schema = document["schema_version"]
    binaries = document.get("binaries")
    if not isinstance(binaries, dict):
        raise SnapshotSchemaError("Snapshot binaries must be a mapping")
    module_spellings: dict[str, str] = {}
    expected_keys = {"path", "sha256", "md5"} if schema == 4 else {"path", "sha256", "md5", "crc32", "crc64", "size"}
    for module, platforms in binaries.items():
        if not isinstance(module, str) or not module or module in {".", ".."} or "/" in module or "\\" in module:
            raise SnapshotSchemaError(f"Invalid binary module: {module!r}")
        prior = module_spellings.setdefault(module.casefold(), module)
        if prior != module:
            raise SnapshotSchemaError(f"Case-insensitive binary module collision: {prior!r} and {module!r}")
        if not isinstance(platforms, dict) or not platforms or not set(platforms).issubset({"windows", "linux"}):
            raise SnapshotSchemaError(f"Invalid platforms for binary module {module}")
        for platform, metadata in platforms.items():
            context = f"binaries.{module}.{platform}"
            if not isinstance(metadata, dict) or set(metadata) != expected_keys:
                raise SnapshotSchemaError(f"{context} has unexpected metadata fields")
            metadata["path"] = _validate_relative_binary_path(metadata["path"], f"{context}.path")
            if not isinstance(metadata["sha256"], str) or not SHA256_PATTERN.fullmatch(metadata["sha256"]):
                raise SnapshotSchemaError(f"{context}.sha256 is invalid")
            if not isinstance(metadata["md5"], str) or not MD5_PATTERN.fullmatch(metadata["md5"]):
                raise SnapshotSchemaError(f"{context}.md5 is invalid")
            if schema == 5:
                if not isinstance(metadata["crc32"], str) or not CRC32_PATTERN.fullmatch(metadata["crc32"]):
                    raise SnapshotSchemaError(f"{context}.crc32 is invalid")
                if not isinstance(metadata["crc64"], str) or not CRC64_PATTERN.fullmatch(metadata["crc64"]):
                    raise SnapshotSchemaError(f"{context}.crc64 is invalid")
                if not isinstance(metadata["size"], int) or isinstance(metadata["size"], bool) or metadata["size"] < 0:
                    raise SnapshotSchemaError(f"{context}.size is invalid")


def parse_snapshot_bytes(data: bytes, expected_game_version: str | None = None) -> dict:
    try:
        document = load_yaml(data)
    except yaml.YAMLError as exc:
        raise SnapshotSchemaError(f"Unable to parse snapshot YAML: {exc}") from exc
    if not isinstance(document, dict) or document.get("schema_version") not in SCHEMA_KEYS:
        raise SnapshotSchemaError("Unsupported snapshot schema", reason="unsupported_snapshot_schema")
    schema = document["schema_version"]
    if set(document) != set(SCHEMA_KEYS[schema]):
        raise SnapshotSchemaError(f"Snapshot schema {schema} has unexpected fields")
    snapshot_config_digest_version(document)
    snapshot_analysis_output_contract_version(document)
    game_version = document.get("game_version")
    if not isinstance(game_version, str) or (
        expected_game_version is not None and game_version != str(expected_game_version)
    ):
        raise SnapshotSchemaError("Snapshot game_version is invalid or mismatched")
    if not isinstance(document.get("config_sha256"), str) or not DIGEST_PATTERN.fullmatch(document["config_sha256"]):
        raise SnapshotSchemaError("Snapshot config_sha256 is invalid")
    files = document.get("files")
    if not isinstance(files, dict):
        raise SnapshotSchemaError("Snapshot files must be a mapping")
    count = document.get("file_count")
    if not isinstance(count, int) or isinstance(count, bool) or count != len(files):
        raise SnapshotSchemaError("Snapshot file_count does not match files")
    normalized = {}
    spellings = {}
    for raw_path, payload in files.items():
        path = validate_snapshot_key(raw_path)
        prior = spellings.setdefault(path.casefold(), path)
        if prior != path:
            raise SnapshotSchemaError(f"Case-insensitive snapshot path collision: {prior!r} and {path!r}")
        if not isinstance(payload, dict):
            raise SnapshotSchemaError(f"Snapshot payload must be a mapping: {path}")
        normalized[path] = payload
    document["files"] = normalized
    if schema in {4, 5}:
        publish_time = document.get("last_publish_time")
        if not isinstance(publish_time, str) or not PUBLISH_TIME_PATTERN.fullmatch(publish_time):
            raise SnapshotSchemaError("Snapshot publish time must use UTC second precision")
        try:
            datetime.strptime(publish_time, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise SnapshotSchemaError("Snapshot publish time is invalid") from exc
        _validate_binaries(document)
    return document
