"""Canonical game-symbol snapshot package."""

from gamesymbol_snapshot_lib.codec import SCHEMA_VERSION
from gamesymbol_snapshot_lib.errors import SnapshotError

__all__ = ["SCHEMA_VERSION", "SnapshotError"]
