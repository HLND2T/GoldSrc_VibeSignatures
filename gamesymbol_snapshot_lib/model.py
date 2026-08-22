from dataclasses import dataclass
from pathlib import Path

from analysis_planner import ExecutionPlan


@dataclass(frozen=True)
class BinaryTarget:
    module_name: str
    platform: str
    source_path: str | None
    binary_name: str


@dataclass(frozen=True)
class SkillNode:
    node_id: str
    logical_key: tuple[str, str, str]
    module_name: str
    skill_name: str
    platform: str
    required_inputs: frozenset[str]
    optional_inputs: frozenset[str]
    required_outputs: frozenset[str]
    optional_outputs: frozenset[str]
    prerequisites: tuple[str, ...]
    skip_if_exists: frozenset[str]
    aliases: tuple[str, ...]
    categories: frozenset[str]
    fingerprint: str

    @property
    def inputs(self) -> frozenset[str]:
        return self.required_inputs | self.optional_inputs

    @property
    def outputs(self) -> frozenset[str]:
        return self.required_outputs | self.optional_outputs


@dataclass(frozen=True)
class SnapshotContract:
    game_version: str
    game_root: Path
    config_digest_version: int
    config_sha256: str
    analysis_output_contract_version: int
    required_paths: frozenset[str]
    optional_paths: frozenset[str]
    binary_targets: dict[tuple[str, str], BinaryTarget]
    analysis_plan: ExecutionPlan
    nodes: dict[str, SkillNode]
    owners_by_path: dict[str, frozenset[str]]

    @property
    def formal_paths(self) -> frozenset[str]:
        return self.required_paths | self.optional_paths


@dataclass(frozen=True)
class SnapshotContext:
    document: dict
    raw_bytes: bytes
    contract: SnapshotContract
