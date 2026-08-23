"""Strict, contained contract for downstream gamedata generators."""

from __future__ import annotations

import importlib.util
import inspect
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType, ModuleType
from typing import Any

from release_workflow_lib.hashing import (
    canonical_json_bytes,
    file_inventory,
    inventory_sha256,
    reject_reparse_points,
    sha256_bytes,
    sha256_file,
    write_canonical_json,
)

MODULE_DIRECTORY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", re.ASCII)
ALLOWED_OUTPUT_SUFFIXES = {".json", ".jsonc", ".txt", ".cfg", ".ini", ".yaml", ".yml"}
SUPPORTED_GENERATOR_API_VERSIONS = {1, 2}
GAMEDATA_MANIFEST_FILENAME = "gamedata-manifest.json"
GAMEDATA_MANIFEST_KEYS = {
    "schema_version",
    "game_version",
    "candidate_sha256",
    "analysis_config_sha256",
    "generator_contract_sha256",
    "payload_inventory_sha256",
    "files",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class GamedataContractError(ValueError):
    pass


def analysis_config_sha256(path: str | Path) -> str:
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise GamedataContractError(f"Unable to read analysis config {path}: {exc}") from exc
    normalized = raw.replace(b"\r\n", b"\n")
    if b"\r" in normalized:
        raise GamedataContractError(f"Analysis config contains unsupported bare CR bytes: {path}")
    return sha256_bytes(normalized)


def _freeze(value):
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


@dataclass(frozen=True)
class GeneratorContext:
    game_version: str
    binaries: Mapping[str, Any]

    def __post_init__(self):
        object.__setattr__(self, "game_version", str(self.game_version))
        object.__setattr__(self, "binaries", _freeze(self.binaries))


@dataclass(frozen=True)
class GeneratorModule:
    directory: str
    name: str
    api_version: int
    source_dir: Path
    module: ModuleType
    output_paths: tuple[str, ...]
    source_files: tuple[dict, ...]

    def record(self):
        return {
            "directory": self.directory,
            "name": self.name,
            "api_version": self.api_version,
            "output_paths": list(self.output_paths),
            "source_files": list(self.source_files),
        }


def normalized_output_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise GamedataContractError(f"Invalid declared output path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise GamedataContractError(f"Output path is not contained: {value!r}")
    if path.suffix.lower() not in ALLOWED_OUTPUT_SUFFIXES:
        raise GamedataContractError(f"Output has a forbidden extension: {value}")
    return path.as_posix()


def _load_module(directory: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"goldsrc_gamedata_{directory}", path)
    if spec is None or spec.loader is None:
        raise GamedataContractError(f"Unable to load generator: {path}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise GamedataContractError(f"Failed to import generator {directory}: {exc}") from exc
    return module


def _contract(directory: str, source_dir: Path, module: ModuleType) -> GeneratorModule:
    if not MODULE_DIRECTORY_RE.fullmatch(directory):
        raise GamedataContractError(f"Invalid generator directory: {directory!r}")
    name = getattr(module, "MODULE_NAME", None)
    update = getattr(module, "update", None)
    api = getattr(module, "GENERATOR_API_VERSION", 1)
    if not isinstance(name, str) or not name.strip() or not callable(update):
        raise GamedataContractError(f"Generator {directory} must declare MODULE_NAME and callable update")
    if isinstance(api, bool) or api not in SUPPORTED_GENERATOR_API_VERSIONS:
        raise GamedataContractError(f"Generator {directory} has unsupported API version: {api!r}")
    if api == 2:
        try:
            parameter = inspect.signature(update).parameters.get("context")
        except (TypeError, ValueError) as exc:
            raise GamedataContractError(f"Generator {directory} has an unreadable update signature") from exc
        if parameter is None:
            raise GamedataContractError(f"Generator {directory} API v2 update must accept context")
    declared = getattr(module, "OUTPUT_PATHS", None)
    if not isinstance(declared, (list, tuple)) or not declared:
        raise GamedataContractError(f"Generator {directory} must declare non-empty OUTPUT_PATHS")
    outputs = tuple(normalized_output_path(value) for value in declared)
    if len({value.casefold() for value in outputs}) != len(outputs):
        raise GamedataContractError(f"Generator {directory} declares duplicate/case-colliding outputs")
    reject_reparse_points(source_dir)
    sources = tuple(
        item
        for item in file_inventory(source_dir)
        if "__pycache__" not in PurePosixPath(item["path"]).parts and not item["path"].endswith(".pyc")
    )
    return GeneratorModule(directory, name.strip(), api, source_dir, module, outputs, sources)


def discover_generator_modules(modules_dir: str | Path) -> list[GeneratorModule]:
    root = Path(modules_dir)
    if not root.exists():
        return []
    if not root.is_dir():
        raise GamedataContractError(f"Generator root is not a directory: {root}")
    reject_reparse_points(root)
    modules = []
    names: set[str] = set()
    directories: set[str] = set()
    for source_dir in sorted((path for path in root.iterdir() if path.is_dir()), key=lambda path: path.name):
        module_path = source_dir / "gamedata.py"
        if not module_path.is_file():
            continue
        loaded = _load_module(source_dir.name, module_path)
        if not getattr(loaded, "MODULE_ENABLED", True):
            continue
        contract = _contract(source_dir.name, source_dir, loaded)
        if contract.directory.casefold() in directories:
            raise GamedataContractError(f"Case-insensitive generator directory collision: {contract.directory}")
        if contract.name.casefold() in names:
            raise GamedataContractError(f"Duplicate generator MODULE_NAME: {contract.name}")
        directories.add(contract.directory.casefold())
        names.add(contract.name.casefold())
        modules.append(contract)
    return modules


def generator_contract_sha256(modules: list[GeneratorModule]) -> str:
    return sha256_bytes(canonical_json_bytes({"schema_version": 1, "modules": [module.record() for module in modules]}))


def prefixed_output_inventory(output_root: str | Path, gamever: str) -> list[dict]:
    prefix = f"gamedata/{gamever}/"
    return [{**item, "path": prefix + item["path"]} for item in file_inventory(output_root)]


def validate_output_tree(output_root: str | Path, gamever: str, modules: list[GeneratorModule]) -> list[dict]:
    root = Path(output_root)
    if not root.is_dir():
        raise GamedataContractError(f"Versioned output is missing: {root}")
    expected = sorted(f"{module.directory}/{path}" for module in modules for path in module.output_paths)
    actual = [item for item in file_inventory(root) if item["path"] != GAMEDATA_MANIFEST_FILENAME]
    actual_paths = [item["path"] for item in actual]
    if actual_paths != expected:
        missing = sorted(set(expected) - set(actual_paths))
        extra = sorted(set(actual_paths) - set(expected))
        raise GamedataContractError(f"Output tree violates OUTPUT_PATHS: missing={missing}, undeclared={extra}")
    prefix = f"gamedata/{gamever}/"
    return [{**item, "path": prefix + item["path"]} for item in actual]


def gamedata_manifest_sha256(inventory: list[dict]) -> str:
    return inventory_sha256(inventory)


def build_gamedata_manifest(
    *,
    gamever: str,
    candidate_sha256: str,
    analysis_config_sha256: str,
    generator_contract_digest: str,
    payload_files: list[dict],
) -> dict:
    tag = str(gamever)
    for label, digest in (
        ("candidate_sha256", candidate_sha256),
        ("analysis_config_sha256", analysis_config_sha256),
        ("generator_contract_sha256", generator_contract_digest),
    ):
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise GamedataContractError(f"{label} is invalid")
    return {
        "schema_version": 1,
        "game_version": tag,
        "candidate_sha256": candidate_sha256,
        "analysis_config_sha256": analysis_config_sha256,
        "generator_contract_sha256": generator_contract_digest,
        "payload_inventory_sha256": inventory_sha256(payload_files),
        "files": payload_files,
    }


def write_gamedata_manifest(output_root: str | Path, document: dict) -> str:
    path = Path(output_root) / GAMEDATA_MANIFEST_FILENAME
    write_canonical_json(path, document)
    return sha256_file(path)


def parse_gamedata_manifest_bytes(raw: bytes, source: str = "<bytes>") -> tuple[dict, str]:
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GamedataContractError(f"Unable to read gamedata manifest {source}: {exc}") from exc
    if not isinstance(document, dict) or set(document) != GAMEDATA_MANIFEST_KEYS or document.get("schema_version") != 1:
        raise GamedataContractError("Gamedata manifest has unexpected fields or schema")
    if canonical_json_bytes(document) != raw:
        raise GamedataContractError("Gamedata manifest is not canonical JSON")
    if not isinstance(document["game_version"], str) or not document["game_version"]:
        raise GamedataContractError("Gamedata manifest game_version is invalid")
    for field in (
        "candidate_sha256",
        "analysis_config_sha256",
        "generator_contract_sha256",
        "payload_inventory_sha256",
    ):
        if not isinstance(document[field], str) or not SHA256_RE.fullmatch(document[field]):
            raise GamedataContractError(f"Gamedata manifest {field} is invalid")
    if (
        not isinstance(document["files"], list)
        or inventory_sha256(document["files"]) != document["payload_inventory_sha256"]
    ):
        raise GamedataContractError("Gamedata manifest payload inventory is invalid")
    return document, sha256_bytes(raw)


def parse_gamedata_manifest(path: str | Path) -> tuple[dict, str]:
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise GamedataContractError(f"Unable to read gamedata manifest {path}: {exc}") from exc
    return parse_gamedata_manifest_bytes(raw, str(path))


def validate_gamedata_tree(
    output_root: str | Path,
    gamever: str,
    modules: list[GeneratorModule],
    *,
    candidate_sha256: str,
    analysis_config_sha256: str,
    generator_contract_digest: str,
) -> tuple[list[dict], str]:
    payload_files = validate_output_tree(output_root, gamever, modules)
    manifest, manifest_sha256 = parse_gamedata_manifest(Path(output_root) / GAMEDATA_MANIFEST_FILENAME)
    expected = build_gamedata_manifest(
        gamever=gamever,
        candidate_sha256=candidate_sha256,
        analysis_config_sha256=analysis_config_sha256,
        generator_contract_digest=generator_contract_digest,
        payload_files=payload_files,
    )
    if manifest != expected:
        raise GamedataContractError("Gamedata manifest bindings do not match generated payload")
    return prefixed_output_inventory(output_root, gamever), manifest_sha256
