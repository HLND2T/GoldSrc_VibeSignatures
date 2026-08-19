"""Build the versioned snapshot contract from an analysis config."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from analysis_output_contract import ANALYSIS_OUTPUT_CONTRACT_VERSION
from analysis_planner import (
    build_artifact_ownership_index,
    build_execution_plan,
    expected_symbol_artifacts,
    load_config,
    symbol_artifact_filename,
)
from gamesymbol_snapshot_lib.errors import SnapshotConfigError
from gamesymbol_snapshot_lib.model import BinaryTarget, SkillNode, SnapshotContract

LATEST_CONFIG_DIGEST_VERSION = 2
SUPPORTED_CONFIG_DIGEST_VERSIONS = (1, 2)
V2_DOMAIN_SEPARATOR = b"gamesymbol-config-contract:v2\n"
SKILL_NODE_DOMAIN_SEPARATOR = b"gamesymbol-skill-node:v1\n"


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


def _node_symbol_contract(module: dict, platform: str, outputs: frozenset[str]) -> list[dict]:
    records = []
    for symbol in module["symbols"]:
        if symbol["category"] == "struct" or symbol.get("platform") not in {None, platform}:
            continue
        artifact = f"{module['name']}/{symbol_artifact_filename(symbol, platform)}"
        if artifact not in outputs:
            continue
        record = {
            "name": symbol["name"],
            "artifact": artifact,
            "category": symbol["category"],
            "platform": symbol.get("platform"),
            "aliases": sorted(symbol.get("alias", ())),
            "source_aliases": sorted(symbol.get("source_alias", ())),
        }
        for field in ("struct", "member"):
            if field in symbol:
                record[field] = symbol[field]
        records.append(record)
    return sorted(records, key=lambda item: (item["artifact"].casefold(), item["name"]))


def _skill_node(node, module: dict, target: BinaryTarget) -> SkillNode:
    required_inputs = frozenset(node.required_inputs)
    optional_inputs = frozenset(node.optional_inputs)
    required_outputs = frozenset(node.required_outputs)
    optional_outputs = frozenset(node.optional_outputs)
    symbols = _node_symbol_contract(module, node.platform, required_outputs | optional_outputs)
    payload = {
        "logical_key": [node.module, node.skill, node.platform],
        "binary_target": {"source_path": target.source_path, "binary_name": target.binary_name},
        "required_inputs": sorted(required_inputs),
        "optional_inputs": sorted(optional_inputs),
        "required_outputs": sorted(required_outputs),
        "optional_outputs": sorted(optional_outputs),
        "prerequisites": sorted(node.prerequisites),
        "skip_if_exists": sorted(node.skip_if_exists),
        "aliases": sorted(node.aliases),
        "symbols": symbols,
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    fingerprint = f"sha256:{hashlib.sha256(SKILL_NODE_DOMAIN_SEPARATOR + encoded).hexdigest()}"
    return SkillNode(
        node_id=node.id,
        logical_key=(node.module, node.skill, node.platform),
        module_name=node.module,
        skill_name=node.skill,
        platform=node.platform,
        required_inputs=required_inputs,
        optional_inputs=optional_inputs,
        required_outputs=required_outputs,
        optional_outputs=optional_outputs,
        prerequisites=tuple(node.prerequisites),
        skip_if_exists=frozenset(node.skip_if_exists),
        aliases=tuple(node.aliases),
        categories=frozenset(symbol["category"] for symbol in symbols),
        fingerprint=fingerprint,
    )


def load_contract(
    config_path: str | Path,
    game_version: str,
    bindir: str | Path,
    config_digest_version: int = LATEST_CONFIG_DIGEST_VERSION,
) -> SnapshotContract:
    try:
        document, modules = load_config(config_path)
        analysis_plan = build_execution_plan(
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
                targets[(module["name"], platform)] = BinaryTarget(
                    module["name"], platform, source_path, module[f"module_{platform}"]
                )
    modules_by_name = {module["name"]: module for module in modules}
    try:
        nodes = {}
        for node in analysis_plan.nodes:
            target = targets.get((node.module, node.platform))
            if target is None:
                raise ValueError(f"Analysis node has no binary identity target: {node.id}")
            nodes[node.id] = _skill_node(node, modules_by_name[node.module], target)
        owners = build_artifact_ownership_index(analysis_plan, required | optional)
    except (TypeError, ValueError) as exc:
        raise SnapshotConfigError(f"Invalid analysis contract: {exc}") from exc
    return SnapshotContract(
        game_version=str(game_version),
        game_root=Path(bindir) / str(game_version),
        config_digest_version=config_digest_version,
        config_sha256=config_digest(document, config_digest_version),
        analysis_output_contract_version=ANALYSIS_OUTPUT_CONTRACT_VERSION,
        required_paths=frozenset(required),
        optional_paths=frozenset(optional),
        binary_targets=targets,
        analysis_plan=analysis_plan,
        nodes=nodes,
        owners_by_path=owners,
    )
