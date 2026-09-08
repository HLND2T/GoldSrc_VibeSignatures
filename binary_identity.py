"""Shared binary identity classification: plain PE/ELF versus Metahook blob.

The snapshot metadata writer and the IDA analysis preparation both need the
same answer: is this game binary a regular Windows PE / Linux ELF, or a
Metahook blob container that only becomes a PE after decrypt/rebuild/verify?
This module owns that decision so the published ``is_blob`` flag and the
analysis binary choice can never diverge.
"""

from __future__ import annotations

from pathlib import Path

from binary_format import validate_binary
from decrypt_blob import BlobFormatError, build_pe, parse_blob, verify_pe


def validate_binary_is_blob(path: str | Path, platform: str) -> bool:
    """Validate a game binary and report whether it is a Metahook blob.

    Returns ``False`` when the file is a valid plain Windows PE32 or Linux
    ELF32 binary. Returns ``True`` only when a Windows file fails plain-binary
    validation but passes the full blob ``parse_blob -> build_pe -> verify_pe``
    pipeline; a bare algorithm marker is never enough. Any other input (invalid
    or truncated binary, non-Windows validation failure, unreadable file)
    raises ``ValueError`` or ``OSError``, so callers never see an unknown state.
    """
    try:
        validate_binary(path, platform)
        return False
    except ValueError as binary_error:
        if platform != "windows":
            raise binary_error
        # Python clears the except-bound name at the end of the block, so keep
        # the message alive for the combined blob failure below.
        plain_failure = str(binary_error)

    try:
        parsed = parse_blob(Path(path).read_bytes())
        rebuilt = build_pe(parsed)
        verify_pe(rebuilt, parsed)
    except (OSError, BlobFormatError) as blob_error:
        raise ValueError(f"{plain_failure}; not a valid Metahook PE32 blob: {blob_error}") from blob_error
    return True
