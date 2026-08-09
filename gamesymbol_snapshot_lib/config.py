"""Build the versioned snapshot contract from an analysis config."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from analysis_output_contract import ANALYSIS_OUTPUT_CONTRACT_VERSION
from analysis_planner import build_execution_plan, expected_symbol_artifacts, load_config
from gamesymbol_snapshot_lib.errors import SnapshotConfigError
from gamesymbol_snapshot_lib.model import BinaryTarget, SnapshotContract

LATEST_CONFIG_DIGEST_VERSION = 2
SUPPORTED_CONFIG_DIGEST_VERSIONS = (1, 2)
V2_DOMAIN_SEPARATOR = b"gamesymbol-config-contract:v2\n"


def _canonical_value(value):
    if isinstance(value, dict):
        return {key: _canonical_value(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


def config_digest(document: dict, version: int = LATEST_CONFIG_DIGEST_VERSION) -> str:
    if version not in SUPPORTED_CONFIG_DIGEST_VERSIONS:
        raise SnapshotConfigError(f"Unsupported config digest version: {version!r}")
    encoded = json.dumps(_canonical_value(document), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    if version == 2:
        encoded = V2_DOMAIN_SEPARATOR + encoded
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def load_contract(
    config_path: str | Path,
    game_version: str,
    bindir: str | Path,
    config_digest_version: int = LATEST_CONFIG_DIGEST_VERSION,
) -> SnapshotContract:
    try:
        document, modules = load_config(config_path)
        build_execution_plan(
            modules,
            platforms=("windows", "linux"),
            bin_dir=bindir,
            tag=str(game_version),
        )
        required, optional = expected_symbol_artifacts(modules)
    except (OSError, TypeError, ValueError) as exc:
        raise SnapshotConfigError(f"Invalid analysis contract: {exc}") from exc
    targets = {}
    for module in modules:
        for platform in ("windows", "linux"):
            source_path = module.get(f"path_{platform}")
            if source_path:
                targets[(module["name"], platform)] = BinaryTarget(module["name"], platform, source_path)
    return SnapshotContract(
        str(game_version),
        Path(bindir) / str(game_version),
        config_digest_version,
        config_digest(document, config_digest_version),
        ANALYSIS_OUTPUT_CONTRACT_VERSION,
        frozenset(required),
        frozenset(optional),
        targets,
    )
