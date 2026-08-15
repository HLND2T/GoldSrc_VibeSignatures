from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BinaryTarget:
    module_name: str
    platform: str
    source_path: str
    binary_name: str


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

    @property
    def formal_paths(self) -> frozenset[str]:
        return self.required_paths | self.optional_paths


@dataclass(frozen=True)
class SnapshotContext:
    document: dict
    raw_bytes: bytes
    contract: SnapshotContract
