"""Accept anchor-only drift between a rebuilt artifact and the committed blob.

An LLM_DECOMPILE finder may report any of several rule-conformant reference
instructions for one global, so its anchor fields legitimately vary between
runs. The resolved address stays authoritative: a payload may differ only in
its anchor group, and only while the symbol identity and its address are
unchanged.
"""

from __future__ import annotations

import yaml

# Fields describing which instruction anchors a global. The pipeline may pick a
# different reference instruction, or a reference in another function, for the
# same address; the address itself is compared separately and may never drift.
GLOBAL_ANCHOR_FIELDS = frozenset(
    {
        "gv_sig_va",
        "gv_sig",
        "gv_inst_offset",
        "gv_inst_length",
        "gv_inst_disp",
        "gv_pic_addend",
    }
)

IDENTITY_KEY = "gv_name"
ADDRESS_KEYS = ("gv_va", "gv_rva")


def _payload(raw: bytes) -> dict | None:
    try:
        document = yaml.safe_load(raw.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError):
        return None
    if not isinstance(document, dict) or not all(isinstance(key, str) for key in document):
        return None
    return document


def _parse_offset(value) -> int | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = int(value, 0)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def anchor_is_coherent(payload: dict) -> bool:
    """Check that one payload still describes a well-formed anchored instruction.

    ``gv_inst_offset`` is measured from ``gv_sig_va``, while ``gv_sig`` only
    holds a function prefix, so the offset is deliberately not bounded by the
    signature width here.
    """
    offset = _parse_offset(payload.get("gv_inst_offset"))
    length = _parse_offset(payload.get("gv_inst_length"))
    if offset is None or length is None or length == 0:
        return False
    if _parse_offset(payload.get("gv_sig_va")) is None:
        return False
    signature = payload.get("gv_sig")
    if not isinstance(signature, str) or not signature.strip():
        return False
    disp_raw = payload.get("gv_inst_disp")
    if disp_raw is None:
        return True
    disp = _parse_offset(disp_raw)
    return disp is not None and disp < length


def anchor_only_drift(expected_raw: bytes, actual_raw: bytes) -> dict | None:
    """Return the changed anchor fields when two payloads differ only there."""
    expected = _payload(expected_raw)
    actual = _payload(actual_raw)
    if expected is None or actual is None or set(expected) != set(actual):
        return None
    if IDENTITY_KEY not in expected:
        return None
    changed = {key for key in expected if expected[key] != actual[key]}
    if not changed or not changed <= GLOBAL_ANCHOR_FIELDS:
        return None
    if any(expected.get(key) != actual.get(key) for key in ADDRESS_KEYS):
        return None
    if not anchor_is_coherent(actual):
        return None
    return {key: (expected[key], actual[key]) for key in sorted(changed)}
