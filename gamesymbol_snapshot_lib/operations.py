"""Pack, restore, verify, and contract-check canonical snapshots."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

from analysis_config import resolve_analysis_config
from analysis_output_contract import ANALYSIS_OUTPUT_CONTRACT_MISMATCH_REASON
from binary_format import validate_binary
from binary_hashing import hash_file
from decrypt_blob import BlobFormatError, build_pe, parse_blob, verify_pe
from gamesymbol_snapshot_lib.codec import (
    SCHEMA_4_VERSION,
    SCHEMA_VERSION,
    build_snapshot_document,
    canonical_snapshot_bytes,
    canonical_yaml_bytes,
    parse_snapshot_bytes,
    snapshot_analysis_output_contract_version,
    snapshot_config_digest_version,
)
from gamesymbol_snapshot_lib.config import LATEST_CONFIG_DIGEST_VERSION, load_contract
from gamesymbol_snapshot_lib.diff import format_snapshot_mismatch
from gamesymbol_snapshot_lib.errors import SnapshotMismatchError, SnapshotSchemaError, SnapshotUntrustedError
from gamesymbol_snapshot_lib.model import SnapshotContext
from gamesymbol_snapshot_lib.paths import (
    canonical_key,
    ensure_real_tree,
    is_reparse_point,
    iter_yaml_paths,
    path_from_key,
)
from ida_analyze_util import SymbolArtifactError, normalize_signature, normalize_symbol_artifact
from trusted_yaml import load_yaml_file


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def _load_yaml_mapping(path: Path) -> dict:
    try:
        payload = load_yaml_file(path)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise SnapshotMismatchError(f"Unable to read symbol YAML {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SnapshotMismatchError(f"Symbol YAML top level must be a mapping: {path}")
    try:
        normalized = normalize_symbol_artifact(payload)
        if normalized != payload:
            raise SymbolArtifactError("symbol fields are not normalized")
        for key, value in normalized.items():
            if key.endswith("_sig") and normalize_signature(value) != value:
                raise SymbolArtifactError(f"{key} is not normalized")
    except SymbolArtifactError as exc:
        raise SnapshotMismatchError(f"Non-canonical symbol YAML {path}: {exc}") from exc
    return payload


def collect_actual_files(contract, *, strict: bool = True) -> dict[str, dict]:
    missing = [key for key in sorted(contract.required_paths) if not path_from_key(contract.game_root, key).is_file()]
    if missing:
        raise SnapshotMismatchError("Missing required symbol YAML:\n" + "\n".join(f"  {key}" for key in missing))
    actual = {canonical_key(contract.game_root, path) for path in iter_yaml_paths(contract.game_root)}
    undeclared = sorted(actual - contract.formal_paths)
    if strict and undeclared:
        raise SnapshotMismatchError("Undeclared symbol YAML:\n" + "\n".join(f"  {key}" for key in undeclared))
    selected = sorted(contract.required_paths | (contract.optional_paths & actual))
    return {key: _load_yaml_mapping(path_from_key(contract.game_root, key)) for key in selected}


def _binary_path(contract, target) -> Path:
    return contract.game_root / target.module_name / target.binary_name


def _ensure_plain_binary(path: Path, game_root: Path) -> None:
    if not path.is_file():
        raise SnapshotMismatchError(f"Binary file is missing: {path}")
    current = path
    while current != game_root:
        if is_reparse_point(current):
            raise SnapshotMismatchError(f"Binary path traverses a link/reparse point: {current}")
        if game_root not in current.parents:
            raise SnapshotMismatchError(f"Binary escapes game root: {path}")
        current = current.parent


def _validate_binary_identity(path: Path, platform: str) -> None:
    try:
        validate_binary(path, platform)
        return
    except ValueError as binary_error:
        if platform != "windows":
            raise binary_error

    try:
        parsed = parse_blob(path.read_bytes())
        rebuilt = build_pe(parsed)
        verify_pe(rebuilt, parsed)
    except (OSError, BlobFormatError) as blob_error:
        raise ValueError(f"{binary_error}; not a valid Metahook PE32 blob: {blob_error}") from blob_error


def collect_binary_metadata(contract, schema_version: int = SCHEMA_VERSION) -> dict:
    if schema_version not in {SCHEMA_4_VERSION, SCHEMA_VERSION}:
        raise SnapshotSchemaError(f"Binary metadata is unsupported for schema {schema_version}")
    binaries = {}
    for key in sorted(contract.binary_targets):
        target = contract.binary_targets[key]
        binary = _binary_path(contract, target)
        _ensure_plain_binary(binary, contract.game_root)
        try:
            _validate_binary_identity(binary, target.platform)
        except ValueError as exc:
            raise SnapshotMismatchError(f"Invalid binary for {target.module_name}/{target.platform}: {exc}") from exc
        hashes = hash_file(binary)
        metadata = {"path": target.source_path, "sha256": hashes["sha256"], "md5": hashes["md5"]}
        if schema_version == SCHEMA_VERSION:
            metadata.update({"crc32": hashes["crc32"], "crc64": hashes["crc64"], "size": hashes["size"]})
        binaries.setdefault(target.module_name, {})[target.platform] = metadata
    return binaries


def _publish_time() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_actual_document(
    contract,
    *,
    strict: bool = True,
    schema_version: int = SCHEMA_VERSION,
    last_publish_time: str | None = None,
    binaries: dict | None = None,
) -> dict:
    if schema_version in {SCHEMA_4_VERSION, SCHEMA_VERSION}:
        last_publish_time = last_publish_time or _publish_time()
        binaries = collect_binary_metadata(contract, schema_version) if binaries is None else binaries
    return build_snapshot_document(
        contract.game_version,
        contract.config_sha256,
        collect_actual_files(contract, strict=strict),
        schema_version=schema_version,
        config_digest_version=contract.config_digest_version,
        analysis_output_contract_version=contract.analysis_output_contract_version,
        last_publish_time=last_publish_time,
        binaries=binaries,
    )


def validate_snapshot_contract(document: dict, contract) -> None:
    if snapshot_config_digest_version(document) != contract.config_digest_version:
        raise SnapshotMismatchError("Snapshot config digest version mismatch", reason="config_digest_mismatch")
    if document["config_sha256"] != contract.config_sha256:
        raise SnapshotMismatchError("Snapshot config digest mismatch", reason="config_digest_mismatch")
    if snapshot_analysis_output_contract_version(document) != contract.analysis_output_contract_version:
        raise SnapshotMismatchError(
            "Snapshot analysis output contract version mismatch", reason=ANALYSIS_OUTPUT_CONTRACT_MISMATCH_REASON
        )
    paths = set(document["files"])
    if paths - contract.formal_paths or contract.required_paths - paths:
        raise SnapshotMismatchError(
            "Snapshot files do not match the analysis contract", reason="snapshot_contract_mismatch"
        )
    if document["schema_version"] in {SCHEMA_4_VERSION, SCHEMA_VERSION}:
        expected = {
            (target.module_name, target.platform): target.source_path for target in contract.binary_targets.values()
        }
        actual = {
            (module, platform): metadata["path"]
            for module, platforms in document["binaries"].items()
            for platform, metadata in platforms.items()
        }
        if actual != expected:
            raise SnapshotMismatchError("Snapshot binaries do not match config", reason="snapshot_contract_mismatch")


def load_snapshot_for_contract(snapshot_path, contract, *, require_canonical: bool = True):
    try:
        raw = Path(snapshot_path).read_bytes()
    except OSError as exc:
        raise SnapshotMismatchError(f"Unable to read snapshot {snapshot_path}: {exc}") from exc
    document = parse_snapshot_bytes(raw, contract.game_version)
    validate_snapshot_contract(document, contract)
    if require_canonical and raw != canonical_snapshot_bytes(document):
        raise SnapshotMismatchError("Snapshot is not canonical", reason="noncanonical_snapshot")
    return document, raw


def load_snapshot_context(snapshot_path, config_path, game_version, bindir, *, require_canonical=True):
    try:
        raw = Path(snapshot_path).read_bytes()
    except OSError as exc:
        raise SnapshotMismatchError(f"Unable to read snapshot {snapshot_path}: {exc}") from exc
    document = parse_snapshot_bytes(raw, str(game_version))
    contract = load_contract(config_path, game_version, bindir, snapshot_config_digest_version(document))
    validate_snapshot_contract(document, contract)
    if require_canonical and raw != canonical_snapshot_bytes(document):
        raise SnapshotMismatchError("Snapshot is not canonical", reason="noncanonical_snapshot")
    return SnapshotContext(document, raw, contract)


def pack_snapshot(
    game_version,
    bindir="bin",
    config_path=None,
    snapshot_path=None,
    *,
    last_publish_time: str | None = None,
    strict: bool = True,
) -> bytes:
    output = Path(snapshot_path or f"gamesymbols/{game_version}.yaml")
    config = resolve_analysis_config(game_version, config_path)
    contract = load_contract(config, game_version, bindir, LATEST_CONFIG_DIGEST_VERSION)
    ensure_real_tree(Path(bindir), contract.game_root)
    document = build_actual_document(contract, strict=strict, last_publish_time=last_publish_time)
    data = canonical_snapshot_bytes(document)
    reparsed = parse_snapshot_bytes(data, str(game_version))
    validate_snapshot_contract(reparsed, contract)
    if canonical_snapshot_bytes(reparsed) != data:
        raise SnapshotSchemaError("Generated snapshot failed canonical self-check")
    _atomic_write(output, data)
    return data


def _write_files(contract, document, *, overwrite: bool) -> None:
    for key, payload in document["files"].items():
        target = path_from_key(contract.game_root, key)
        if target.exists() and not overwrite:
            continue
        _atomic_write(target, canonical_yaml_bytes(payload))


def _delete_yaml_tree(game_root: Path) -> None:
    for path in list(iter_yaml_paths(game_root)):
        path.unlink()


def restore_snapshot(game_version, bindir="bin", config_path=None, snapshot_path=None, *, replace=False) -> bytes:
    snapshot = Path(snapshot_path or f"gamesymbols/{game_version}.yaml")
    config = resolve_analysis_config(game_version, config_path)
    context = load_snapshot_context(snapshot, config, game_version, bindir)
    ensure_real_tree(Path(bindir), context.contract.game_root)
    if not replace:
        conflicts = [
            key
            for key, expected in context.document["files"].items()
            if path_from_key(context.contract.game_root, key).exists()
            and _load_yaml_mapping(path_from_key(context.contract.game_root, key)) != expected
        ]
        if conflicts:
            raise SnapshotMismatchError("Refusing to overwrite different symbol YAML: " + ", ".join(conflicts))
    else:
        _delete_yaml_tree(context.contract.game_root)
    _write_files(context.contract, context.document, overwrite=replace)
    restored = build_actual_document(
        context.contract,
        strict=True,
        schema_version=context.document["schema_version"],
        last_publish_time=context.document.get("last_publish_time"),
        binaries=context.document.get("binaries"),
    )
    if canonical_snapshot_bytes(restored) != context.raw_bytes:
        raise SnapshotMismatchError("Restore round-trip did not reproduce the snapshot")
    return context.raw_bytes


def verify_snapshot(game_version, bindir="bin", config_path=None, snapshot_path=None) -> bytes:
    snapshot = Path(snapshot_path or f"gamesymbols/{game_version}.yaml")
    config = resolve_analysis_config(game_version, config_path)
    context = load_snapshot_context(snapshot, config, game_version, bindir)
    actual = build_actual_document(
        context.contract,
        strict=True,
        schema_version=context.document["schema_version"],
        last_publish_time=context.document.get("last_publish_time"),
    )
    data = canonical_snapshot_bytes(actual)
    if data != context.raw_bytes:
        raise SnapshotMismatchError(format_snapshot_mismatch(context.document, actual))
    return data


def check_snapshot_contract(game_version, bindir="bin", config_path=None, snapshot_path=None) -> SnapshotContext:
    snapshot = Path(snapshot_path or f"gamesymbols/{game_version}.yaml")
    config = resolve_analysis_config(game_version, config_path)
    try:
        context = load_snapshot_context(snapshot, config, game_version, bindir)
        with tempfile.TemporaryDirectory(prefix="gamesymbol-contract-") as temp:
            temporary_contract = load_contract(
                config, game_version, Path(temp) / "bin", context.contract.config_digest_version
            )
            _write_files(temporary_contract, context.document, overwrite=True)
            rebuilt = build_actual_document(
                temporary_contract,
                strict=True,
                schema_version=context.document["schema_version"],
                last_publish_time=context.document.get("last_publish_time"),
                binaries=context.document.get("binaries"),
            )
            if canonical_snapshot_bytes(rebuilt) != context.raw_bytes:
                raise SnapshotUntrustedError("snapshot_round_trip_mismatch", "Snapshot is not byte-stable")
        return context
    except SnapshotSchemaError as exc:
        raise SnapshotUntrustedError(exc.reason, str(exc)) from exc
    except SnapshotMismatchError as exc:
        if exc.reason:
            raise SnapshotUntrustedError(exc.reason, str(exc)) from exc
        raise
