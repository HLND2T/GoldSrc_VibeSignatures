"""Immutable alias metadata companion for canonical game-symbol snapshots."""

from __future__ import annotations

import hashlib
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path

import yaml

from analysis_planner import PLATFORMS, load_config, module_declares_platform, symbol_artifact_filename
from gamesymbol_snapshot_lib.codec import CanonicalDumper, DIGEST_PATTERN, SHA256_PATTERN, parse_snapshot_bytes
from gamesymbol_snapshot_lib.paths import metadata_path_for_snapshot, snapshot_tag_from_filename
from gamesymbol_store import SnapshotSymbolStore
from trusted_yaml import load_yaml

METADATA_SCHEMA_VERSION = 1
METADATA_KEYS = (
    "schema_version",
    "game_version",
    "snapshot_sha256",
    "config_digest_version",
    "config_sha256",
    "modules",
)


class MetadataContractError(ValueError):
    pass


def raw_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _aliases(value: object, context: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise MetadataContractError(f"{context} must be a non-empty string list")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip() or item != item.strip():
            raise MetadataContractError(f"{context} contains an empty or invalid alias")
        if item in result:
            raise MetadataContractError(f"{context} contains duplicate alias {item!r}")
        result.append(item)
    return result


def _component(value: object, context: str) -> str:
    if not isinstance(value, str) or not value or value in {".", ".."} or "/" in value or "\\" in value:
        raise MetadataContractError(f"{context} must be one safe non-empty component")
    return value


def _snapshot_owner_keys(snapshot_document: Mapping) -> set[tuple[str, str, str]]:
    owners: set[tuple[str, str, str]] = set()
    for path in snapshot_document["files"]:
        module, filename = path.split("/", 1)
        matched = None
        for platform in PLATFORMS:
            suffix = f".{platform}.yaml"
            if filename.endswith(suffix):
                matched = (module, platform, filename[: -len(suffix)])
                break
        if matched is None or not matched[2]:
            raise MetadataContractError(f"Snapshot record has no platform owner identity: {path}")
        if matched in owners:
            raise MetadataContractError(f"Duplicate snapshot owner identity: {matched}")
        owners.add(matched)
    return owners


def build_metadata_document(*, snapshot_path: str | Path, config_path: str | Path, expected_game_version: str) -> dict:
    snapshot = Path(snapshot_path)
    filename_tag = snapshot_tag_from_filename(snapshot.name)
    if filename_tag != str(expected_game_version):
        raise MetadataContractError(f"Snapshot filename does not match game version {expected_game_version!r}")
    store = SnapshotSymbolStore.open(
        snapshot,
        expected_game_version=str(expected_game_version),
        config_path=config_path,
    )
    snapshot_raw = snapshot.read_bytes()
    snapshot_document = parse_snapshot_bytes(snapshot_raw, str(expected_game_version))
    _document, modules = load_config(config_path)
    projected_modules = []
    owner_keys: set[tuple[str, str, str]] = set()
    snapshot_owners = _snapshot_owner_keys(snapshot_document)
    for module in modules:
        projected_symbols = []
        for symbol in module["symbols"]:
            raw_aliases = symbol.get("alias", [])
            if not raw_aliases:
                continue
            aliases = _aliases(raw_aliases, f"{module['name']}.{symbol['name']}.alias")
            artifacts = []
            for platform in PLATFORMS:
                if not module_declares_platform(module, platform) or symbol.get("platform") not in {None, platform}:
                    continue
                filename = symbol_artifact_filename(symbol, platform)
                suffix = f".{platform}.yaml"
                artifact = filename[: -len(suffix)]
                owner = (module["name"], platform, artifact)
                if owner not in snapshot_owners or not store.contains(module["name"], filename):
                    raise MetadataContractError(f"Alias owner does not uniquely match a snapshot record: {owner}")
                if owner in owner_keys:
                    raise MetadataContractError(f"Duplicate alias owner identity: {owner}")
                owner_keys.add(owner)
                artifacts.append({"platform": platform, "artifact": artifact})
            if not artifacts:
                raise MetadataContractError(f"Alias symbol has no snapshot owner: {module['name']}.{symbol['name']}")
            projected_symbols.append({"name": symbol["name"], "artifacts": artifacts, "alias": aliases})
        if projected_symbols:
            projected_modules.append({"name": module["name"], "symbols": projected_symbols})
    if not DIGEST_PATTERN.fullmatch(store.config_sha256):
        raise MetadataContractError("Snapshot config digest is not sha256")
    return {
        "schema_version": METADATA_SCHEMA_VERSION,
        "game_version": str(expected_game_version),
        "snapshot_sha256": raw_sha256(snapshot_raw),
        "config_digest_version": store.config_digest_version,
        "config_sha256": store.config_sha256.removeprefix("sha256:"),
        "modules": projected_modules,
    }


def canonical_metadata_bytes(document: Mapping) -> bytes:
    text = yaml.dump(
        {key: document[key] for key in METADATA_KEYS},
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


def parse_metadata_bytes(
    data: bytes,
    *,
    expected_game_version: str | None = None,
    snapshot_bytes: bytes | None = None,
) -> dict:
    try:
        document = load_yaml(data)
    except yaml.YAMLError as exc:
        raise MetadataContractError(f"Unable to parse metadata YAML: {exc}") from exc
    if not isinstance(document, dict) or tuple(document) != METADATA_KEYS:
        raise MetadataContractError("Metadata schema has unexpected fields or key order")
    if document["schema_version"] != METADATA_SCHEMA_VERSION:
        raise MetadataContractError("Unsupported metadata schema_version")
    game_version = document["game_version"]
    if not isinstance(game_version, str) or expected_game_version is not None and game_version != expected_game_version:
        raise MetadataContractError("Metadata game_version is invalid or mismatched")
    if not isinstance(document["snapshot_sha256"], str) or not SHA256_PATTERN.fullmatch(document["snapshot_sha256"]):
        raise MetadataContractError("Metadata snapshot_sha256 is invalid")
    if snapshot_bytes is not None and document["snapshot_sha256"] != raw_sha256(snapshot_bytes):
        raise MetadataContractError("Metadata snapshot_sha256 does not match snapshot bytes")
    if document["config_digest_version"] != 2:
        raise MetadataContractError("Metadata config_digest_version must be 2")
    if not isinstance(document["config_sha256"], str) or not SHA256_PATTERN.fullmatch(document["config_sha256"]):
        raise MetadataContractError("Metadata config_sha256 is invalid")
    modules = document["modules"]
    if not isinstance(modules, list):
        raise MetadataContractError("Metadata modules must be a list")
    snapshot_owners = (
        _snapshot_owner_keys(parse_snapshot_bytes(snapshot_bytes, game_version)) if snapshot_bytes is not None else None
    )
    seen_modules: set[str] = set()
    seen_owners: set[tuple[str, str, str]] = set()
    for module_index, module in enumerate(modules):
        if not isinstance(module, dict) or tuple(module) != ("name", "symbols"):
            raise MetadataContractError(f"modules[{module_index}] has unexpected fields")
        module_name = _component(module["name"], f"modules[{module_index}].name")
        if module_name.casefold() in seen_modules:
            raise MetadataContractError(f"Duplicate metadata module: {module_name}")
        seen_modules.add(module_name.casefold())
        symbols = module["symbols"]
        if not isinstance(symbols, list) or not symbols:
            raise MetadataContractError(f"modules[{module_index}].symbols must be non-empty")
        seen_symbols: set[str] = set()
        for symbol_index, symbol in enumerate(symbols):
            context = f"modules[{module_index}].symbols[{symbol_index}]"
            if not isinstance(symbol, dict) or tuple(symbol) != ("name", "artifacts", "alias"):
                raise MetadataContractError(f"{context} has unexpected fields")
            symbol_name = _component(symbol["name"], f"{context}.name")
            if symbol_name.casefold() in seen_symbols:
                raise MetadataContractError(f"Duplicate metadata symbol: {module_name}.{symbol_name}")
            seen_symbols.add(symbol_name.casefold())
            aliases = _aliases(symbol["alias"], f"{context}.alias")
            symbol["alias"] = aliases
            artifacts = symbol["artifacts"]
            if not isinstance(artifacts, list) or not artifacts:
                raise MetadataContractError(f"{context}.artifacts must be non-empty")
            last_platform_index = -1
            for artifact_index, artifact in enumerate(artifacts):
                artifact_context = f"{context}.artifacts[{artifact_index}]"
                if not isinstance(artifact, dict) or tuple(artifact) != ("platform", "artifact"):
                    raise MetadataContractError(f"{artifact_context} has unexpected fields")
                platform = artifact["platform"]
                if platform not in PLATFORMS:
                    raise MetadataContractError(f"{artifact_context}.platform is invalid")
                platform_index = PLATFORMS.index(platform)
                if platform_index <= last_platform_index:
                    raise MetadataContractError(f"{context}.artifacts are not in canonical platform order")
                last_platform_index = platform_index
                artifact_name = _component(artifact["artifact"], f"{artifact_context}.artifact")
                owner = (module_name, platform, artifact_name)
                if owner in seen_owners:
                    raise MetadataContractError(f"Duplicate metadata owner identity: {owner}")
                if snapshot_owners is not None and owner not in snapshot_owners:
                    raise MetadataContractError(f"Metadata owner is absent from snapshot: {owner}")
                seen_owners.add(owner)
    if canonical_metadata_bytes(document) != data:
        raise MetadataContractError("Metadata bytes are not canonical")
    return document


def verify_metadata(
    *, metadata_path: str | Path, snapshot_path: str | Path, config_path: str | Path, game_version: str
) -> dict:
    metadata = Path(metadata_path)
    snapshot_raw = Path(snapshot_path).read_bytes()
    actual_raw = metadata.read_bytes()
    actual = parse_metadata_bytes(actual_raw, expected_game_version=str(game_version), snapshot_bytes=snapshot_raw)
    expected = build_metadata_document(
        snapshot_path=snapshot_path,
        config_path=config_path,
        expected_game_version=str(game_version),
    )
    if actual != expected:
        raise MetadataContractError(
            f"Metadata projection does not match snapshot/config: {_first_difference(expected, actual)}"
        )
    return actual


def _first_difference(expected: object, actual: object, path: str = "$") -> str:
    if type(expected) is not type(actual):
        return path
    if isinstance(expected, dict):
        for key in tuple(dict.fromkeys((*expected, *actual))):
            if key not in expected or key not in actual:
                return f"{path}.{key}"
            difference = _first_difference(expected[key], actual[key], f"{path}.{key}")
            if difference:
                return difference
        return ""
    if isinstance(expected, list):
        if len(expected) != len(actual):
            return f"{path}.length"
        for index, (expected_item, actual_item) in enumerate(zip(expected, actual, strict=True)):
            difference = _first_difference(expected_item, actual_item, f"{path}[{index}]")
            if difference:
                return difference
        return ""
    return "" if expected == actual else path


def compare_metadata(
    *,
    actual_path: str | Path,
    expected_path: str | Path,
    snapshot_path: str | Path,
    config_path: str | Path,
    game_version: str,
) -> None:
    actual = verify_metadata(
        metadata_path=actual_path,
        snapshot_path=snapshot_path,
        config_path=config_path,
        game_version=game_version,
    )
    expected_raw = Path(expected_path).read_bytes()
    expected = parse_metadata_bytes(
        expected_raw,
        expected_game_version=str(game_version),
        snapshot_bytes=Path(snapshot_path).read_bytes(),
    )
    if actual != expected:
        raise MetadataContractError(f"Metadata mismatch for {game_version}: {_first_difference(expected, actual)}")


def write_metadata(
    *, snapshot_path: str | Path, config_path: str | Path, game_version: str, output_path: str | Path
) -> dict:
    document = build_metadata_document(
        snapshot_path=snapshot_path,
        config_path=config_path,
        expected_game_version=str(game_version),
    )
    raw = canonical_metadata_bytes(document)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix=f".{output.name}.", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    verify_metadata(
        metadata_path=output,
        snapshot_path=snapshot_path,
        config_path=config_path,
        game_version=str(game_version),
    )
    return document


def companion_path(snapshot_path: str | Path) -> Path:
    return metadata_path_for_snapshot(snapshot_path)
