"""Read-only SymbolStore implementations for snapshots and migration tests."""

from __future__ import annotations

import copy
import fnmatch
import hashlib
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

import yaml

from analysis_config import AnalysisConfigError, resolve_analysis_config
from gamesymbol_snapshot_lib.codec import (
    SCHEMA_VERSION,
    canonical_snapshot_bytes,
    canonical_yaml_bytes,
    parse_snapshot_bytes,
    snapshot_config_digest_version,
)
from gamesymbol_snapshot_lib.config import LATEST_CONFIG_DIGEST_VERSION, load_contract
from gamesymbol_snapshot_lib.errors import SnapshotConfigError, SnapshotMismatchError, SnapshotSchemaError
from gamesymbol_snapshot_lib.operations import validate_snapshot_contract
from gamesymbol_snapshot_lib.paths import canonical_key, is_reparse_point, iter_yaml_paths


class SymbolStoreError(Exception):
    pass


class SnapshotFormatError(SymbolStoreError):
    pass


class SnapshotCanonicalError(SymbolStoreError):
    pass


class SnapshotConfigMismatchError(SymbolStoreError):
    pass


class SnapshotGameVersionMismatchError(SymbolStoreError):
    pass


class InvalidSymbolPathError(SymbolStoreError):
    pass


class SymbolNotFoundError(SymbolStoreError):
    pass


class CandidateChangedError(SymbolStoreError):
    pass


@dataclass(frozen=True)
class SymbolEntry:
    path: str
    module: str
    filename: str
    payload: Mapping[str, Any]


class SymbolStore(Protocol):
    @property
    def game_version(self) -> str: ...

    @property
    def schema_version(self) -> int: ...

    @property
    def config_digest_version(self) -> int: ...

    @property
    def config_sha256(self) -> str: ...

    @property
    def candidate_sha256(self) -> str: ...

    @property
    def file_count(self) -> int: ...

    @property
    def binaries(self) -> Mapping[str, Any]: ...

    @property
    def modules(self) -> Sequence[str]: ...

    def contains(self, module: str, filename: str) -> bool: ...

    def get(self, module: str, filename: str) -> Mapping[str, Any] | None: ...

    def require(self, module: str, filename: str) -> Mapping[str, Any]: ...

    def glob_module(self, module: str, filename_pattern: str) -> Sequence[SymbolEntry]: ...

    def iter_module(self, module: str) -> Sequence[SymbolEntry]: ...


def _component(value: str, label: str) -> str:
    if not isinstance(value, str) or not value or value in {".", ".."} or "/" in value or "\\" in value:
        raise InvalidSymbolPathError(f"{label} must be one safe path component")
    return value


def _filename(value: str) -> str:
    result = _component(value, "filename")
    if not result.endswith(".yaml"):
        raise InvalidSymbolPathError("Symbol filename must end with .yaml")
    return result


def _pattern(value: str) -> str:
    result = _component(value, "filename pattern")
    if "**" in result or "[" in result or "]" in result:
        raise InvalidSymbolPathError(f"Unsupported filename glob: {value!r}")
    return result


class _MemorySymbolStore:
    def __init__(
        self,
        game_version,
        *,
        schema_version,
        config_digest_version,
        config_sha256,
        source_sha256,
        files,
        binaries=None,
    ):
        self._game_version = str(game_version)
        self._schema_version = schema_version
        self._config_digest_version = config_digest_version
        self._config_sha256 = config_sha256
        self._candidate_sha256 = source_sha256
        self._files = {path: copy.deepcopy(payload) for path, payload in files.items()}
        self._binaries = copy.deepcopy(binaries or {})
        self._modules = {}
        for path in sorted(self._files):
            parts = PurePosixPath(path).parts
            if len(parts) != 2:
                raise SnapshotFormatError(f"Symbol store path must be <module>/<filename>: {path}")
            module, filename = _component(parts[0], "module"), _filename(parts[1])
            self._modules.setdefault(module, []).append(f"{module}/{filename}")

    game_version = property(lambda self: self._game_version)
    schema_version = property(lambda self: self._schema_version)
    config_digest_version = property(lambda self: self._config_digest_version)
    config_sha256 = property(lambda self: self._config_sha256)
    candidate_sha256 = property(lambda self: self._candidate_sha256)
    file_count = property(lambda self: len(self._files))
    binaries = property(lambda self: copy.deepcopy(self._binaries))
    modules = property(lambda self: tuple(self._modules))

    @staticmethod
    def _key(module, filename):
        return f"{_component(module, 'module')}/{_filename(filename)}"

    def contains(self, module, filename):
        return self._key(module, filename) in self._files

    def get(self, module, filename):
        value = self._files.get(self._key(module, filename))
        return copy.deepcopy(value) if value is not None else None

    def require(self, module, filename):
        value = self.get(module, filename)
        if value is None:
            raise SymbolNotFoundError(f"Symbol not found: {self._key(module, filename)}")
        return value

    def _entry(self, path):
        module, filename = path.split("/", 1)
        return SymbolEntry(path, module, filename, copy.deepcopy(self._files[path]))

    def glob_module(self, module, filename_pattern):
        module = _component(module, "module")
        pattern = _pattern(filename_pattern)
        return tuple(
            self._entry(path)
            for path in self._modules.get(module, ())
            if fnmatch.fnmatchcase(path.split("/", 1)[1], pattern)
        )

    def iter_module(self, module):
        module = _component(module, "module")
        return tuple(self._entry(path) for path in self._modules.get(module, ()))


class SnapshotSymbolStore(_MemorySymbolStore):
    @classmethod
    def open(cls, snapshot_path, *, expected_game_version: str, config_path=None):
        path = Path(os.path.abspath(snapshot_path))
        if not path.is_file() or any(
            candidate.exists() and is_reparse_point(candidate) for candidate in (path, *path.parents)
        ):
            raise SnapshotFormatError(f"Snapshot is not a regular plain file: {path}")
        try:
            raw = path.read_bytes()
            document = parse_snapshot_bytes(raw)
        except (OSError, SnapshotSchemaError) as exc:
            raise SnapshotFormatError(f"Unable to open snapshot {path}: {exc}") from exc
        if document["game_version"] != str(expected_game_version):
            raise SnapshotGameVersionMismatchError(
                f"Snapshot game version {document['game_version']} does not match {expected_game_version}"
            )
        try:
            config = resolve_analysis_config(expected_game_version, config_path)
            digest_version = snapshot_config_digest_version(document)
            contract = load_contract(
                config,
                expected_game_version,
                "bin",
                digest_version,
                artifactdir="bin_artifacts",
            )
            validate_snapshot_contract(document, contract)
        except (AnalysisConfigError, SnapshotConfigError, SnapshotMismatchError) as exc:
            raise SnapshotConfigMismatchError(str(exc)) from exc
        if canonical_snapshot_bytes(document) != raw:
            raise SnapshotCanonicalError(f"Snapshot is not canonical: {path}")
        return cls(
            document["game_version"],
            schema_version=document["schema_version"],
            config_digest_version=digest_version,
            config_sha256=document["config_sha256"],
            source_sha256=f"sha256:{hashlib.sha256(raw).hexdigest()}",
            files=document["files"],
            binaries=document.get("binaries", {}),
        )


class DirectorySymbolStore(_MemorySymbolStore):
    def __init__(
        self,
        artifact_root,
        game_version: str,
        *,
        config_sha256: str | None = None,
        config_digest_version: int = LATEST_CONFIG_DIGEST_VERSION,
    ):
        game_root = Path(artifact_root) / str(game_version)
        files = {}
        for path in iter_yaml_paths(game_root):
            key = canonical_key(game_root, path)
            try:
                payload = yaml.safe_load(path.read_bytes())
            except (OSError, yaml.YAMLError) as exc:
                raise SnapshotFormatError(f"Unable to read directory symbol {path}: {exc}") from exc
            if not isinstance(payload, dict):
                raise SnapshotFormatError(f"Directory symbol payload must be a mapping: {path}")
            files[key] = payload
        digest = f"sha256:{hashlib.sha256(canonical_yaml_bytes(files)).hexdigest()}"
        super().__init__(
            game_version,
            schema_version=SCHEMA_VERSION,
            config_digest_version=config_digest_version,
            config_sha256=config_sha256 or f"sha256:{'0' * 64}",
            source_sha256=digest,
            files=files,
        )


def open_snapshot_store(*, snapshot_path, config_path, expected_game_version):
    return SnapshotSymbolStore.open(snapshot_path, config_path=config_path, expected_game_version=expected_game_version)
