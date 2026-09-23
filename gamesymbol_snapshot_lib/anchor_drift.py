"""Accept anchor-only drift between a rebuilt artifact and the committed blob.

A finder may report any of several rule-conformant reference instructions for one
symbol, so the fields that describe *how* it was located legitimately vary
between runs. The resolved facts stay authoritative: a payload may differ only
inside its anchor group, and only while the symbol identity, the resolved
address/offset and the anchor shape are unchanged.

Search-policy switches (``*_max_match``, ``*_allow_across_function_boundary``)
belong to no anchor group on purpose: tolerating them would accept a different
search rather than an equivalent sampling of the same one.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

import yaml


@dataclass(frozen=True)
class AnchorSpec:
    """How one artifact category describes the symbol it locates.

    ``select_keys`` must all be present for the spec to apply, ``fixed_keys``
    are the resolved facts a rebuilt payload has to reproduce byte-exactly, and
    ``anchor_fields`` is the only set allowed to drift. ``coherent`` carries the
    cross-field invariants that symbol normalization does not already enforce.
    """

    select_keys: tuple[str, ...]
    fixed_keys: tuple[str, ...]
    anchor_fields: frozenset[str]
    coherent: Callable[[dict], bool] | None = None


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
    """Check that one payload still describes a well-formed anchored global.

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


# Every other field a spec does not list keeps the byte-exact gate, which is how
# the policy switches and each category's primary signature stay pinned.
ANCHOR_SPECS: tuple[AnchorSpec, ...] = (
    AnchorSpec(
        select_keys=("gv_name",),
        fixed_keys=("gv_va", "gv_rva"),
        anchor_fields=frozenset(
            {
                "gv_sig",
                "gv_sig_va",
                "gv_inst_offset",
                "gv_inst_length",
                "gv_inst_disp",
                "gv_pic_addend",
                "gv_address_offset",
            }
        ),
        coherent=anchor_is_coherent,
    ),
    AnchorSpec(
        select_keys=("struct_name", "member_name"),
        fixed_keys=("offset", "size"),
        anchor_fields=frozenset(
            {
                "offset_sig",
                "offset_sig_disp",
                "offset_sig_addend",
                "offset_sig_ref_kind",
            }
        ),
    ),
    AnchorSpec(
        select_keys=("func_name", "vfunc_offset"),
        fixed_keys=("func_va", "func_rva", "vfunc_offset", "vfunc_index"),
        anchor_fields=frozenset({"vfunc_sig", "vfunc_sig_disp"}),
    ),
)


def _spec_for(payload: dict) -> AnchorSpec | None:
    for spec in ANCHOR_SPECS:
        if all(key in payload for key in spec.select_keys):
            return spec
    return None


def anchor_only_drift(expected_raw: bytes, actual_raw: bytes) -> dict | None:
    """Return the changed anchor fields when two payloads differ only there."""
    expected = _payload(expected_raw)
    actual = _payload(actual_raw)
    if expected is None or actual is None or set(expected) != set(actual):
        return None
    spec = _spec_for(expected)
    if spec is None:
        return None
    changed = {key for key in expected if expected[key] != actual[key]}
    if not changed or not changed <= spec.anchor_fields:
        return None
    if any(expected.get(key) != actual.get(key) for key in spec.fixed_keys):
        return None
    if spec.coherent is not None and not spec.coherent(actual):
        return None
    return {key: (expected[key], actual[key]) for key in sorted(changed)}


def accepted_anchor_drift(
    expected: Mapping[str, tuple[int, str]],
    actual: Mapping[str, tuple[int, str]],
    *,
    read_expected: Callable[[str], bytes | None],
    read_actual: Callable[[str], bytes | None],
) -> dict[str, dict] | None:
    """Map every drifting artifact to its changed anchor fields, or fail closed.

    ``expected`` and ``actual`` map an artifact key to its ``(size, sha256)``
    fingerprint. Missing, extra and non-anchor payload changes keep the
    byte-exact gate: any of them makes the whole comparison return ``None``.
    """
    if expected.keys() != actual.keys():
        return None
    drift: dict[str, dict] = {}
    for key, expected_fingerprint in expected.items():
        if expected_fingerprint == actual[key]:
            continue
        expected_raw = read_expected(key)
        actual_raw = read_actual(key)
        if expected_raw is None or actual_raw is None:
            return None
        changed = anchor_only_drift(expected_raw, actual_raw)
        if changed is None:
            return None
        drift[key] = changed
    return drift or None
