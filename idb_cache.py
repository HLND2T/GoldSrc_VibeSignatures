#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath

from analysis_config import validated_tag
from binary_format import validate_binary
from ida_database_paths import (
    database_file_role,
    database_paths,
    existing_database_lock,
    is_reparse_point,
    validate_database_file_set,
    validate_plain_file,
)
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import (
    canonical_json_bytes,
    inventory_sha256,
    load_json_object,
    normalized_relative_path,
    normalized_sha256,
    reject_reparse_points,
    sha256_bytes,
    sha256_file,
    write_canonical_json,
)

CACHE_SCHEMA_VERSION = 1
WARMUP_CONTRACT_VERSION = 1
WARM_WORKER_CONTRACT_FILES = (
    "binary_format.py",
    "ida_analyze_bin.py",
    "ida_database_paths.py",
    "ida_mcp_session.py",
    "idb_cache.py",
    "idb_warm_worker.py",
    "release_workflow_lib/errors.py",
    "release_workflow_lib/hashing.py",
)
CACHE_IDENTITY_KEYS = {
    "schema_version",
    "tag",
    "ida_runtime",
    "warmup_contract_version",
    "warm_worker_sha256",
    "normalized_ida_args",
    "binaries",
}
RUNTIME_KEYS = {
    "kernel_version",
    "processor",
    "bitness",
    "file_type",
    "loader_name",
    "loader_module_sha256",
    "plugins",
}
GENERATION_MANIFEST_KEYS = {
    "schema_version",
    "tag",
    "cache_key",
    "generation",
    "published_at",
    "identity",
    "binaries",
    "payload_inventory_sha256",
    "files",
}
READY_KEYS = {"schema_version", "tag", "cache_key", "generation", "manifest_sha256"}
SAFE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$", re.ASCII)
UTC_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class IdbCacheError(ValueError):
    pass


def _component(value: object, context: str) -> str:
    if not isinstance(value, str) or not SAFE_COMPONENT_RE.fullmatch(value):
        raise IdbCacheError(f"{context} must be a safe non-empty component")
    return value


def _positive_int(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise IdbCacheError(f"{context} must be a positive integer")
    return value


def _plain_root(path: str | Path, *, create: bool = False) -> Path:
    root = Path(path)
    if create:
        root.mkdir(parents=True, exist_ok=True)
    if not root.is_dir() or is_reparse_point(root):
        raise IdbCacheError(f"Cache/workspace root must be a plain directory: {root}")
    return root.resolve()


def _contained_path(root: Path, relative: str, *, require_file: bool = False) -> Path:
    try:
        normalized = normalized_relative_path(relative)
    except ReleaseWorkflowError as exc:
        raise IdbCacheError(str(exc)) from exc
    candidate = root.joinpath(*PurePosixPath(normalized).parts)
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise IdbCacheError(f"Path escapes its root: {relative}") from exc
    current = root
    for part in PurePosixPath(normalized).parts:
        current = current / part
        if current.exists() and is_reparse_point(current):
            raise IdbCacheError(f"Links/reparse points are not allowed: {current}")
    if require_file:
        validate_plain_file(candidate, context="Cache input")
    return candidate


def _runtime_identity(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != RUNTIME_KEYS:
        raise IdbCacheError("IDA runtime identity has unexpected or missing fields")
    for field in ("kernel_version", "processor", "file_type", "loader_name"):
        if not isinstance(value[field], str) or not value[field].strip() or value[field] != value[field].strip():
            raise IdbCacheError(f"ida_runtime.{field} must be a trimmed non-empty string")
    if value["processor"] != "metapc" or value["bitness"] != 32 or value["file_type"] not in {"PE", "ELF"}:
        raise IdbCacheError("Initial warm cache supports only metapc PE32/ELF32 runtimes")
    normalized_sha256(value["loader_module_sha256"], "ida_runtime.loader_module_sha256")
    plugins = value["plugins"]
    if not isinstance(plugins, list):
        raise IdbCacheError("ida_runtime.plugins must be a list")
    normalized_plugins = []
    seen = set()
    for index, plugin in enumerate(plugins):
        if not isinstance(plugin, dict) or set(plugin) != {"name", "sha256"}:
            raise IdbCacheError(f"ida_runtime.plugins[{index}] has unexpected fields")
        name = _component(plugin["name"], f"ida_runtime.plugins[{index}].name")
        if name.casefold() in seen:
            raise IdbCacheError(f"Duplicate IDA plugin identity: {name}")
        seen.add(name.casefold())
        normalized_sha256(plugin["sha256"], f"ida_runtime.plugins[{index}].sha256")
        normalized_plugins.append({"name": name, "sha256": plugin["sha256"]})
    if normalized_plugins != sorted(normalized_plugins, key=lambda item: item["name"].encode("utf-8")):
        raise IdbCacheError("ida_runtime.plugins must use canonical name order")
    return {**value, "plugins": normalized_plugins}


def _binary_identities(value: object) -> list[dict]:
    if not isinstance(value, list) or not value:
        raise IdbCacheError("Cache identity binaries must be a non-empty list")
    result = []
    seen_paths = set()
    seen_pairs = set()
    for index, binary in enumerate(value):
        if not isinstance(binary, dict) or set(binary) != {"module", "platform", "path", "size", "sha256"}:
            raise IdbCacheError(f"binaries[{index}] has unexpected fields")
        module = _component(binary["module"], f"binaries[{index}].module")
        platform = binary["platform"]
        if platform not in {"windows", "linux"}:
            raise IdbCacheError(f"binaries[{index}].platform is invalid")
        try:
            path = normalized_relative_path(binary["path"])
        except ReleaseWorkflowError as exc:
            raise IdbCacheError(str(exc)) from exc
        if PurePosixPath(path).parts[0] != module:
            raise IdbCacheError(f"binaries[{index}].path must begin with its module")
        _positive_int(binary["size"], f"binaries[{index}].size")
        normalized_sha256(binary["sha256"], f"binaries[{index}].sha256")
        pair = (module.casefold(), platform)
        if pair in seen_pairs or path.casefold() in seen_paths:
            raise IdbCacheError("Cache identity contains duplicate binary pair/path")
        seen_pairs.add(pair)
        seen_paths.add(path.casefold())
        result.append(dict(binary))
    canonical = sorted(result, key=lambda item: (item["module"].encode("utf-8"), item["platform"], item["path"]))
    if result != canonical:
        raise IdbCacheError("Cache identity binaries are not in canonical order")
    return result


def validate_cache_identity(value: object) -> dict:
    if (
        not isinstance(value, dict)
        or set(value) != CACHE_IDENTITY_KEYS
        or value["schema_version"] != CACHE_SCHEMA_VERSION
    ):
        raise IdbCacheError("Cache identity has unexpected fields or schema")
    try:
        tag = validated_tag(value["tag"])
    except (TypeError, ValueError) as exc:
        raise IdbCacheError(f"Invalid cache tag: {exc}") from exc
    runtime = _runtime_identity(value["ida_runtime"])
    if value["warmup_contract_version"] != WARMUP_CONTRACT_VERSION:
        raise IdbCacheError("Unsupported warmup contract version")
    normalized_sha256(value["warm_worker_sha256"], "warm_worker_sha256")
    args = value["normalized_ida_args"]
    if not isinstance(args, list) or any(
        not isinstance(item, str) or not item or item != item.strip() or "\0" in item for item in args
    ):
        raise IdbCacheError("normalized_ida_args must be a list of trimmed non-empty strings")
    binaries = _binary_identities(value["binaries"])
    expected_platform = "windows" if runtime["file_type"] == "PE" else "linux"
    if any(binary["platform"] != expected_platform for binary in binaries):
        raise IdbCacheError("Every binary in one cache identity must use the runtime loader platform")
    return {
        "schema_version": CACHE_SCHEMA_VERSION,
        "tag": tag,
        "ida_runtime": runtime,
        "warmup_contract_version": WARMUP_CONTRACT_VERSION,
        "warm_worker_sha256": value["warm_worker_sha256"],
        "normalized_ida_args": list(args),
        "binaries": binaries,
    }


def parse_cache_identity_bytes(raw: bytes) -> dict:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IdbCacheError(f"Unable to parse cache identity: {exc}") from exc
    identity = validate_cache_identity(value)
    if canonical_json_bytes(identity) != raw:
        raise IdbCacheError("Cache identity is not canonical JSON")
    return identity


def load_cache_identity(path: str | Path) -> dict:
    try:
        return parse_cache_identity_bytes(Path(path).read_bytes())
    except OSError as exc:
        raise IdbCacheError(f"Unable to read cache identity {path}: {exc}") from exc


def cache_key(identity: object) -> str:
    return sha256_bytes(canonical_json_bytes(validate_cache_identity(identity)))


def build_binary_identity(*, workspace_root: str | Path, module: str, platform: str, relative_path: str) -> dict:
    root = _plain_root(workspace_root)
    path = normalized_relative_path(relative_path)
    binary = _contained_path(root, path, require_file=True)
    validate_binary(binary, platform)
    return {
        "module": _component(module, "module"),
        "platform": platform,
        "path": path,
        "size": binary.stat().st_size,
        "sha256": sha256_file(binary),
    }


def build_cache_identity(
    *, tag: str, ida_runtime: dict, normalized_ida_args: list[str], binaries: list[dict], warm_worker_path: str | Path
) -> dict:
    document = {
        "schema_version": CACHE_SCHEMA_VERSION,
        "tag": validated_tag(tag),
        "ida_runtime": ida_runtime,
        "warmup_contract_version": WARMUP_CONTRACT_VERSION,
        "warm_worker_sha256": warm_worker_contract_sha256(warm_worker_path),
        "normalized_ida_args": normalized_ida_args,
        "binaries": sorted(
            binaries,
            key=lambda item: (item["module"].encode("utf-8"), item["platform"], item["path"]),
        ),
    }
    return validate_cache_identity(document)


def warm_worker_contract_sha256(warm_worker_path: str | Path) -> str:
    worker = validate_plain_file(warm_worker_path, context="Warm worker")
    if worker.name != "idb_warm_worker.py":
        return sha256_file(worker)
    root = worker.parent
    files = []
    for relative in WARM_WORKER_CONTRACT_FILES:
        path = _contained_path(root, relative, require_file=True)
        files.append({"path": relative, "size": path.stat().st_size, "sha256": sha256_file(path)})
    return sha256_bytes(canonical_json_bytes({"domain": "goldsrc-idb-warm-worker:v1", "files": files}))


def _tag_root(persisted_root: str | Path, tag: str, *, create: bool = False) -> Path:
    root = _plain_root(persisted_root, create=create)
    cache_root = root / "idb-cache"
    if cache_root.exists() and (not cache_root.is_dir() or is_reparse_point(cache_root)):
        raise IdbCacheError(f"IDB cache root must be a plain directory: {cache_root}")
    if create:
        cache_root.mkdir(exist_ok=True)
    tag_root = cache_root / validated_tag(tag)
    if create:
        tag_root.mkdir(parents=True, exist_ok=True)
    return _plain_root(tag_root) if tag_root.exists() else tag_root


def _generation_name(key: str, run_id: str, attempt: int) -> str:
    normalized_sha256(key, "cache_key")
    return f"{key}-{_component(run_id, 'run_id')}-{_positive_int(attempt, 'attempt')}"


def _published_at(value: str | None = None) -> str:
    if value is None:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not isinstance(value, str) or not UTC_TIME_RE.fullmatch(value):
        raise IdbCacheError("published_at must use UTC second precision")
    datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return value


def _database_records(workspace_root: Path, binary_identity: dict) -> list[dict]:
    binary = _contained_path(workspace_root, binary_identity["path"], require_file=True)
    records = []
    for path in validate_database_file_set(binary):
        relative = path.relative_to(workspace_root).as_posix()
        records.append(
            {
                "relative_path": normalized_relative_path(relative),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
                "role": database_file_role(binary, path),
            }
        )
    return sorted(records, key=lambda item: item["relative_path"].encode("utf-8"))


def _payload_file(path: Path, relative_path: str) -> dict:
    return {"path": relative_path, "size": path.stat().st_size, "sha256": sha256_file(path)}


def _validate_manifest(document: object, raw: bytes | None = None) -> dict:
    if (
        not isinstance(document, dict)
        or set(document) != GENERATION_MANIFEST_KEYS
        or document["schema_version"] != CACHE_SCHEMA_VERSION
    ):
        raise IdbCacheError("Generation manifest has unexpected fields or schema")
    identity = validate_cache_identity(document["identity"])
    if document["tag"] != identity["tag"]:
        raise IdbCacheError("Generation tag does not match cache identity")
    normalized_sha256(document["cache_key"], "cache_key")
    if document["cache_key"] != cache_key(identity):
        raise IdbCacheError("Generation cache key does not match identity")
    _component(document["generation"], "generation")
    _published_at(document["published_at"])
    binaries = document["binaries"]
    if not isinstance(binaries, list) or len(binaries) != len(identity["binaries"]):
        raise IdbCacheError("Generation binary records do not match identity cardinality")
    expected_files = []
    for index, (record, expected_identity) in enumerate(zip(binaries, identity["binaries"], strict=True)):
        if not isinstance(record, dict) or set(record) != {"module", "platform", "path", "database_files"}:
            raise IdbCacheError(f"Generation binaries[{index}] has unexpected fields")
        if {key: record[key] for key in ("module", "platform", "path")} != {
            key: expected_identity[key] for key in ("module", "platform", "path")
        }:
            raise IdbCacheError(f"Generation binaries[{index}] identity mismatch")
        binary_cache_path = f"payload/binaries/{expected_identity['path']}"
        expected_files.append(
            {
                "path": binary_cache_path,
                "size": expected_identity["size"],
                "sha256": expected_identity["sha256"],
            }
        )
        database_files = record["database_files"]
        if not isinstance(database_files, list) or not database_files:
            raise IdbCacheError(f"Generation binaries[{index}] has no database files")
        primary_count = 0
        seen = set()
        for database_index, database in enumerate(database_files):
            if not isinstance(database, dict) or set(database) != {"relative_path", "size", "sha256", "role"}:
                raise IdbCacheError(f"Generation database file {index}:{database_index} has unexpected fields")
            relative = normalized_relative_path(database["relative_path"])
            if relative.casefold() in seen or relative not in {
                path.as_posix() for path in database_paths(PurePosixPath(expected_identity["path"]))
            }:
                raise IdbCacheError(f"Generation database path is duplicate or invalid: {relative}")
            seen.add(relative.casefold())
            _positive_int(database["size"], f"database_files[{database_index}].size")
            normalized_sha256(database["sha256"], f"database_files[{database_index}].sha256")
            if database["role"] not in {"primary", "side"}:
                raise IdbCacheError(f"Generation database role is invalid: {database['role']!r}")
            primary_count += database["role"] == "primary"
            expected_files.append(
                {
                    "path": f"payload/databases/{relative}",
                    "size": database["size"],
                    "sha256": database["sha256"],
                }
            )
        if primary_count != 1:
            raise IdbCacheError(f"Generation binaries[{index}] must have exactly one primary database")
    files = document["files"]
    expected_files.sort(key=lambda item: item["path"].encode("utf-8"))
    if files != expected_files or inventory_sha256(files) != document["payload_inventory_sha256"]:
        raise IdbCacheError("Generation payload inventory is invalid")
    if raw is not None and canonical_json_bytes(document) != raw:
        raise IdbCacheError("Generation manifest is not canonical JSON")
    return document


def _read_manifest(generation_root: Path) -> tuple[dict, bytes, str]:
    manifest_path = generation_root / "manifest.json"
    try:
        raw = manifest_path.read_bytes()
        document = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IdbCacheError(f"Unable to read generation manifest {manifest_path}: {exc}") from exc
    return _validate_manifest(document, raw), raw, sha256_bytes(raw)


def _verify_generation_root(generation_root: Path, *, expected_generation: str | None = None) -> tuple[dict, str]:
    if not generation_root.is_dir() or is_reparse_point(generation_root):
        raise IdbCacheError(f"Generation is not a plain directory: {generation_root}")
    try:
        reject_reparse_points(generation_root)
    except ReleaseWorkflowError as exc:
        raise IdbCacheError(str(exc)) from exc
    document, _raw, manifest_sha256 = _read_manifest(generation_root)
    if expected_generation is not None and document["generation"] != expected_generation:
        raise IdbCacheError("Generation manifest name binding mismatch")
    actual = []
    payload = generation_root / "payload"
    if not payload.is_dir():
        raise IdbCacheError("Generation payload directory is missing")
    for path in sorted((item for item in payload.rglob("*") if item.is_file()), key=lambda item: item.as_posix()):
        relative = path.relative_to(generation_root).as_posix()
        actual.append(_payload_file(path, normalized_relative_path(relative)))
    if actual != document["files"]:
        raise IdbCacheError("Generation payload bytes do not match manifest")
    allowed = {"manifest.json", *(item["path"] for item in document["files"])}
    actual_paths = {
        path.relative_to(generation_root).as_posix() for path in generation_root.rglob("*") if path.is_file()
    }
    if actual_paths != allowed:
        raise IdbCacheError("Generation contains undeclared files")
    return document, manifest_sha256


def publish_generation(
    *,
    persisted_root: str | Path,
    identity: dict,
    workspace_root: str | Path,
    run_id: str,
    attempt: int,
    published_at: str | None = None,
) -> dict:
    identity = validate_cache_identity(identity)
    key = cache_key(identity)
    generation = _generation_name(key, run_id, attempt)
    tag_root = _tag_root(persisted_root, identity["tag"], create=True)
    generations = tag_root / "generations"
    generations.mkdir(exist_ok=True)
    if is_reparse_point(generations):
        raise IdbCacheError("Generations directory must not be a reparse point")
    workspace = _plain_root(workspace_root)
    incoming = generations / f".incoming-{uuid.uuid4().hex}"
    incoming.mkdir()
    try:
        records = []
        files = []
        for binary_identity in identity["binaries"]:
            binary = _contained_path(workspace, binary_identity["path"], require_file=True)
            validate_binary(binary, binary_identity["platform"])
            if binary.stat().st_size != binary_identity["size"] or sha256_file(binary) != binary_identity["sha256"]:
                raise IdbCacheError(f"Workspace binary identity mismatch: {binary_identity['path']}")
            database_records = _database_records(workspace, binary_identity)
            cached_binary = _contained_path(incoming, f"payload/binaries/{binary_identity['path']}")
            cached_binary.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(binary, cached_binary)
            files.append(_payload_file(cached_binary, f"payload/binaries/{binary_identity['path']}"))
            for database in database_records:
                source = _contained_path(workspace, database["relative_path"], require_file=True)
                cached = _contained_path(incoming, f"payload/databases/{database['relative_path']}")
                cached.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, cached)
                files.append(_payload_file(cached, f"payload/databases/{database['relative_path']}"))
            records.append(
                {
                    "module": binary_identity["module"],
                    "platform": binary_identity["platform"],
                    "path": binary_identity["path"],
                    "database_files": database_records,
                }
            )
        files.sort(key=lambda item: item["path"].encode("utf-8"))
        manifest = {
            "schema_version": CACHE_SCHEMA_VERSION,
            "tag": identity["tag"],
            "cache_key": key,
            "generation": generation,
            "published_at": _published_at(published_at),
            "identity": identity,
            "binaries": records,
            "payload_inventory_sha256": inventory_sha256(files),
            "files": files,
        }
        _validate_manifest(manifest)
        write_canonical_json(incoming / "manifest.json", manifest)
        _verify_generation_root(incoming, expected_generation=generation)
        target = generations / generation
        if target.exists():
            existing, existing_sha = _verify_generation_root(target, expected_generation=generation)
            if existing != manifest:
                raise IdbCacheError(f"Immutable generation already exists with different bytes: {generation}")
            shutil.rmtree(incoming)
            manifest_sha256 = existing_sha
        else:
            os.replace(incoming, target)
            _verified, manifest_sha256 = _verify_generation_root(target, expected_generation=generation)
        selection = {
            "schema_version": CACHE_SCHEMA_VERSION,
            "tag": identity["tag"],
            "cache_key": key,
            "generation": generation,
            "manifest_sha256": manifest_sha256,
        }
        write_canonical_json(tag_root / "READY.json", selection)
        return selection
    finally:
        if incoming.exists():
            shutil.rmtree(incoming)


def _parse_selection(raw: bytes) -> dict:
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IdbCacheError(f"Unable to parse cache selection: {exc}") from exc
    if (
        not isinstance(document, dict)
        or set(document) != READY_KEYS
        or document["schema_version"] != CACHE_SCHEMA_VERSION
    ):
        raise IdbCacheError("Cache selection has unexpected fields or schema")
    try:
        document["tag"] = validated_tag(document["tag"])
    except (TypeError, ValueError) as exc:
        raise IdbCacheError(f"Invalid cache selection tag: {exc}") from exc
    normalized_sha256(document["cache_key"], "cache selection key")
    normalized_sha256(document["manifest_sha256"], "cache selection manifest_sha256")
    _component(document["generation"], "cache selection generation")
    if canonical_json_bytes(document) != raw:
        raise IdbCacheError("Cache selection is not canonical JSON")
    return document


def verify_selection(*, persisted_root: str | Path, selection: dict) -> dict:
    selection = _parse_selection(canonical_json_bytes(selection))
    tag_root = _tag_root(persisted_root, selection["tag"])
    generation_root = _contained_path(tag_root, f"generations/{selection['generation']}")
    manifest, manifest_sha256 = _verify_generation_root(
        generation_root,
        expected_generation=selection["generation"],
    )
    if manifest["cache_key"] != selection["cache_key"] or manifest_sha256 != selection["manifest_sha256"]:
        raise IdbCacheError("Exact cache selection does not match its generation")
    return manifest


def probe_generation(*, persisted_root: str | Path, identity: dict) -> dict | None:
    identity = validate_cache_identity(identity)
    key = cache_key(identity)
    tag_root = _tag_root(persisted_root, identity["tag"])
    if not tag_root.is_dir():
        return None
    ready_path = tag_root / "READY.json"
    if ready_path.is_file():
        try:
            ready = _parse_selection(ready_path.read_bytes())
            if ready["cache_key"] == key:
                manifest = verify_selection(persisted_root=persisted_root, selection=ready)
                if manifest["identity"] == identity:
                    return ready
        except (OSError, IdbCacheError):
            pass
    generations = tag_root / "generations"
    if not generations.is_dir() or is_reparse_point(generations):
        return None
    candidates = []
    for path in sorted(generations.iterdir(), key=lambda item: item.name):
        if not path.name.startswith(f"{key}-") or not path.is_dir():
            continue
        try:
            manifest, manifest_sha256 = _verify_generation_root(path, expected_generation=path.name)
        except IdbCacheError:
            continue
        if manifest["identity"] == identity:
            candidates.append(
                {
                    "schema_version": CACHE_SCHEMA_VERSION,
                    "tag": identity["tag"],
                    "cache_key": key,
                    "generation": path.name,
                    "manifest_sha256": manifest_sha256,
                }
            )
    if not candidates:
        return None
    selection = candidates[-1]
    write_canonical_json(ready_path, selection)
    return selection


def _atomic_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    try:
        shutil.copyfile(source, temporary)
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()


def restore_generation(*, persisted_root: str | Path, selection: dict, workspace_root: str | Path) -> dict:
    manifest = verify_selection(persisted_root=persisted_root, selection=selection)
    workspace = _plain_root(workspace_root)
    generation_root = _contained_path(
        _tag_root(persisted_root, manifest["tag"]),
        f"generations/{manifest['generation']}",
    )
    restored = []
    try:
        for identity, record in zip(manifest["identity"]["binaries"], manifest["binaries"], strict=True):
            binary = _contained_path(workspace, identity["path"], require_file=True)
            cached_binary = _contained_path(
                generation_root,
                f"payload/binaries/{identity['path']}",
                require_file=True,
            )
            if (
                binary.stat().st_size != identity["size"]
                or sha256_file(binary) != identity["sha256"]
                or sha256_file(cached_binary) != identity["sha256"]
            ):
                raise IdbCacheError(f"Workspace/cache binary identity mismatch before restore: {identity['path']}")
            lock = existing_database_lock(binary)
            if lock is not None:
                raise IdbCacheError(f"Active IDA database lock prevents restore: {lock}")
            for existing in database_paths(binary):
                if existing.exists():
                    validate_plain_file(existing, context="Existing IDA database")
                    existing.unlink()
            for database in record["database_files"]:
                source = _contained_path(
                    generation_root,
                    f"payload/databases/{database['relative_path']}",
                    require_file=True,
                )
                destination = _contained_path(workspace, database["relative_path"])
                _atomic_copy(source, destination)
                restored.append(destination)
            actual = _database_records(workspace, identity)
            if actual != record["database_files"]:
                raise IdbCacheError(f"Restored IDA database inventory mismatch: {identity['path']}")
            if binary.stat().st_size != identity["size"] or sha256_file(binary) != identity["sha256"]:
                raise IdbCacheError(f"Workspace binary identity changed during restore: {identity['path']}")
        return manifest
    except Exception:
        for path in restored:
            if path.is_file() and not is_reparse_point(path):
                path.unlink()
        raise


def _remove_database_files(workspace: Path, identity: dict) -> None:
    for binary_identity in identity["binaries"]:
        binary = _contained_path(workspace, binary_identity["path"], require_file=True)
        if existing_database_lock(binary) is not None:
            raise IdbCacheError(f"Active IDA database lock prevents cleanup: {binary}")
        for path in database_paths(binary):
            if path.exists():
                validate_plain_file(path, context="IDA database cleanup target")
                path.unlink()


def warm_and_publish(
    *,
    persisted_root: str | Path,
    identity_path: str | Path,
    workspace_root: str | Path,
    run_id: str,
    attempt: int,
    port_lock: str | Path,
    timeout_seconds: float,
) -> dict:
    identity = load_cache_identity(identity_path)
    workspace = _plain_root(workspace_root)
    _remove_database_files(workspace, identity)
    observed_fd, observed_name = tempfile.mkstemp(prefix="idb-warm-observed-", suffix=".json")
    os.close(observed_fd)
    observed_path = Path(observed_name)
    try:
        command = [
            sys.executable,
            str(Path(__file__).with_name("idb_warm_worker.py")),
            "run",
            "-identity",
            str(Path(identity_path).resolve()),
            "-workspace-root",
            str(workspace),
            "-port-lock",
            str(Path(port_lock).resolve()),
            "-output",
            str(observed_path),
        ]
        try:
            result = subprocess.run(command, check=False, timeout=timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            _remove_database_files(workspace, identity)
            raise IdbCacheError(f"Restricted IDB warm worker timed out after {timeout_seconds:g}s") from exc
        if result.returncode != 0:
            _remove_database_files(workspace, identity)
            raise IdbCacheError(f"Restricted IDB warm worker failed with exit code {result.returncode}")
        observed = load_json_object(observed_path)
        if observed != identity["ida_runtime"]:
            _remove_database_files(workspace, identity)
            raise IdbCacheError("Warm worker observed runtime identity does not match expected identity")
        return publish_generation(
            persisted_root=persisted_root,
            identity=identity,
            workspace_root=workspace,
            run_id=run_id,
            attempt=attempt,
        )
    finally:
        if observed_path.exists():
            observed_path.unlink()


def prune_tag(
    *,
    persisted_root: str | Path,
    tag: str,
    now: datetime | None = None,
    keep_latest: int = 3,
    minimum_age: timedelta = timedelta(days=7),
    incoming_age: timedelta = timedelta(hours=24),
) -> list[str]:
    tag_root = _tag_root(persisted_root, tag)
    if not tag_root.is_dir():
        return []
    now = datetime.now(timezone.utc) if now is None else now.astimezone(timezone.utc)
    ready_generation = None
    ready_path = tag_root / "READY.json"
    if ready_path.is_file():
        try:
            ready_generation = _parse_selection(ready_path.read_bytes())["generation"]
        except IdbCacheError:
            ready_generation = None
    generations = tag_root / "generations"
    if not generations.is_dir() or is_reparse_point(generations):
        return []
    removed = []
    valid = []
    for path in generations.iterdir():
        if path.name.startswith(".incoming-"):
            age = now - datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
            if age >= incoming_age and path.is_dir() and not is_reparse_point(path):
                shutil.rmtree(path)
                removed.append(path.name)
            continue
        if not path.is_dir() or is_reparse_point(path):
            continue
        try:
            manifest, _digest = _verify_generation_root(path, expected_generation=path.name)
            published = datetime.strptime(manifest["published_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            valid.append((published, path))
        except IdbCacheError:
            continue
    valid.sort(key=lambda item: (item[0], item[1].name), reverse=True)
    keep = {path.name for _published, path in valid[:keep_latest]}
    if ready_generation is not None:
        keep.add(ready_generation)
    for published, path in valid:
        if path.name not in keep and now - published >= minimum_age:
            shutil.rmtree(path)
            removed.append(path.name)
    return removed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Content-addressed immutable GoldSrc IDB cache")
    commands = parser.add_subparsers(dest="command", required=True)
    probe = commands.add_parser("probe")
    probe.add_argument("-persisted-root", required=True)
    probe.add_argument("-identity", required=True)
    probe.add_argument("-output", required=True)
    warm = commands.add_parser("warm")
    warm.add_argument("-persisted-root", required=True)
    warm.add_argument("-identity", required=True)
    warm.add_argument("-workspace-root", required=True)
    warm.add_argument("-run-id", required=True)
    warm.add_argument("-attempt", required=True, type=int)
    warm.add_argument("-port-lock", required=True)
    warm.add_argument("-timeout-seconds", type=float, default=3600.0)
    publish = commands.add_parser("publish")
    publish.add_argument("-persisted-root", required=True)
    publish.add_argument("-identity", required=True)
    publish.add_argument("-workspace-root", required=True)
    publish.add_argument("-run-id", required=True)
    publish.add_argument("-attempt", required=True, type=int)
    restore = commands.add_parser("restore")
    restore.add_argument("-persisted-root", required=True)
    restore.add_argument("-selection", required=True)
    restore.add_argument("-workspace-root", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("-persisted-root", required=True)
    verify.add_argument("-selection", required=True)
    prune = commands.add_parser("prune")
    prune.add_argument("-persisted-root", required=True)
    prune.add_argument("-tag", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "probe":
            selection = probe_generation(
                persisted_root=args.persisted_root,
                identity=load_cache_identity(args.identity),
            )
            if selection is None:
                return 3
            write_canonical_json(args.output, selection)
        elif args.command == "warm":
            selection = warm_and_publish(
                persisted_root=args.persisted_root,
                identity_path=args.identity,
                workspace_root=args.workspace_root,
                run_id=args.run_id,
                attempt=args.attempt,
                port_lock=args.port_lock,
                timeout_seconds=args.timeout_seconds,
            )
            print(json.dumps(selection, sort_keys=True))
        elif args.command == "publish":
            selection = publish_generation(
                persisted_root=args.persisted_root,
                identity=load_cache_identity(args.identity),
                workspace_root=args.workspace_root,
                run_id=args.run_id,
                attempt=args.attempt,
            )
            print(json.dumps(selection, sort_keys=True))
        elif args.command == "restore":
            selection = _parse_selection(Path(args.selection).read_bytes())
            restore_generation(
                persisted_root=args.persisted_root,
                selection=selection,
                workspace_root=args.workspace_root,
            )
        elif args.command == "verify":
            verify_selection(
                persisted_root=args.persisted_root,
                selection=_parse_selection(Path(args.selection).read_bytes()),
            )
        else:
            for removed in prune_tag(persisted_root=args.persisted_root, tag=args.tag):
                print(removed)
    except (IdbCacheError, OSError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
