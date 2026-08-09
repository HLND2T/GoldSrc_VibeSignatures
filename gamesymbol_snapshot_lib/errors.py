class SnapshotError(Exception):
    """Base error for snapshot operations."""


class SnapshotConfigError(SnapshotError):
    """Configuration or CLI contract error."""


class SnapshotSchemaError(SnapshotConfigError):
    def __init__(self, message: str, *, reason: str = "snapshot_contract_mismatch"):
        super().__init__(message)
        self.reason = reason


class SnapshotMismatchError(SnapshotError):
    def __init__(self, message: str, *, reason: str | None = None):
        super().__init__(message)
        self.reason = reason


class SnapshotUntrustedError(SnapshotError):
    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason
