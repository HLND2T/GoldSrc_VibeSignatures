"""Strict, contained contract for downstream gamedata generators."""

from __future__ import annotations

import importlib.util
import inspect
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
)

MODULE_DIRECTORY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", re.ASCII)
ALLOWED_OUTPUT_SUFFIXES = {".json", ".jsonc", ".txt", ".cfg", ".ini", ".yaml", ".yml"}
SUPPORTED_GENERATOR_API_VERSIONS = {1, 2}


class GamedataContractError(ValueError):
    pass


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
    actual = file_inventory(root)
    actual_paths = [item["path"] for item in actual]
    if actual_paths != expected:
        missing = sorted(set(expected) - set(actual_paths))
        extra = sorted(set(actual_paths) - set(expected))
        raise GamedataContractError(f"Output tree violates OUTPUT_PATHS: missing={missing}, undeclared={extra}")
    return prefixed_output_inventory(root, gamever)


def gamedata_manifest_sha256(inventory: list[dict]) -> str:
    return inventory_sha256(inventory)
