"""Architecture-neutral artifact helpers and x86 global-reference resolution."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path

import yaml

SYMBOL_TYPES = frozenset({"func", "gv", "vfunc", "vtable", "patch", "struct", "structmember"})
SIGNATURE_RE = re.compile(r"^(?:[0-9A-F]{2}|\?\?)(?: (?:[0-9A-F]{2}|\?\?))*$")


class SymbolArtifactError(ValueError):
    pass


def quoted_hex(value: int) -> str:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SymbolArtifactError(f"Expected a non-negative integer, got {value!r}")
    return f"0x{value:x}"


def normalize_signature(value: str | bytes | Iterable[int | None]) -> str:
    if isinstance(value, bytes):
        tokens = [f"{byte:02X}" for byte in value]
    elif isinstance(value, str):
        raw = value.strip().replace("\\x", " ").replace(",", " ").replace("*", "?")
        tokens = raw.split()
        normalized = []
        for token in tokens:
            token = token.upper()
            if token in {"?", "??"} or "?" in token:
                normalized.append("??")
            elif re.fullmatch(r"[0-9A-F]{2}", token):
                normalized.append(token)
            else:
                raise SymbolArtifactError(f"Invalid signature token: {token!r}")
        tokens = normalized
    else:
        tokens = ["??" if byte is None else f"{byte:02X}" for byte in value]
    signature = " ".join(tokens)
    if not signature or not SIGNATURE_RE.fullmatch(signature):
        raise SymbolArtifactError(f"Invalid signature: {value!r}")
    return signature


def signature_matches(data: bytes, signature: str) -> list[int]:
    tokens = normalize_signature(signature).split()
    pattern = [None if token == "??" else int(token, 16) for token in tokens]
    if len(pattern) > len(data):
        return []
    return [
        offset
        for offset in range(len(data) - len(pattern) + 1)
        if all(expected is None or data[offset + index] == expected for index, expected in enumerate(pattern))
    ]


def _parse_int(value: object, field: str) -> int:
    if isinstance(value, bool):
        raise SymbolArtifactError(f"{field} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise SymbolArtifactError(f"{field} must be an integer") from exc
    raise SymbolArtifactError(f"{field} must be an integer")


def resolve_x86_global_reference(
    *,
    operands: Iterable[int | Mapping[str, object]] = (),
    data_xrefs: Iterable[int] = (),
    gv_ref_kind: str = "operand",
    gv_ref_index: int = 0,
    gv_ref_deref_count: int = 0,
    read_u32: Callable[[int], int | bytes] | None = None,
) -> int:
    if gv_ref_kind not in {"operand", "data_xref"}:
        raise SymbolArtifactError("gv_ref_kind must be operand or data_xref")
    if isinstance(gv_ref_index, bool) or not isinstance(gv_ref_index, int) or gv_ref_index < 0:
        raise SymbolArtifactError("gv_ref_index must be a non-negative integer")
    if gv_ref_deref_count not in {0, 1, 2}:
        raise SymbolArtifactError("gv_ref_deref_count must be between 0 and 2")
    if gv_ref_kind == "operand":
        candidates = list(operands)
        if gv_ref_index >= len(candidates):
            raise SymbolArtifactError("gv_ref_index is outside the instruction operands")
        selected = candidates[gv_ref_index]
        if isinstance(selected, Mapping):
            selected = selected.get("address", selected.get("value"))
        address = _parse_int(selected, "operand reference")
    else:
        candidates = sorted({_parse_int(value, "data xref") for value in data_xrefs})
        if gv_ref_index >= len(candidates):
            raise SymbolArtifactError("gv_ref_index is outside the sorted data xrefs")
        address = candidates[gv_ref_index]
    for _ in range(gv_ref_deref_count):
        if read_u32 is None:
            raise SymbolArtifactError("read_u32 is required when gv_ref_deref_count is non-zero")
        value = read_u32(address)
        if isinstance(value, bytes):
            if len(value) != 4:
                raise SymbolArtifactError("read_u32 returned a byte string whose length is not 4")
            address = int.from_bytes(value, "little")
        else:
            address = _parse_int(value, "dereferenced value")
    return address


def normalize_symbol_artifact(payload: Mapping[str, object]) -> dict:
    if not isinstance(payload, Mapping):
        raise SymbolArtifactError("Symbol artifact must be a mapping")
    kind = payload.get("type", payload.get("kind"))
    if kind not in SYMBOL_TYPES:
        raise SymbolArtifactError(f"Unsupported symbol type: {kind!r}")
    name = payload.get("name")
    if not isinstance(name, str) or not name:
        raise SymbolArtifactError("Symbol artifact requires a non-empty name")
    normalized = dict(payload)
    normalized["type"] = kind
    normalized.pop("kind", None)
    for field, value in tuple(normalized.items()):
        if field.endswith("_sig") and value is not None:
            normalized[field] = normalize_signature(value)
        if field.endswith(("_addr", "_size", "_offset", "_length", "_disp")) and value is not None:
            normalized[field] = quoted_hex(_parse_int(value, field))
    if kind == "gv":
        normalized.setdefault("gv_ref_kind", "operand")
        normalized.setdefault("gv_ref_index", 0)
        normalized.setdefault("gv_ref_deref_count", 0)
        if normalized["gv_ref_kind"] not in {"operand", "data_xref"}:
            raise SymbolArtifactError("gv_ref_kind must be operand or data_xref")
        if (
            isinstance(normalized["gv_ref_index"], bool)
            or not isinstance(normalized["gv_ref_index"], int)
            or normalized["gv_ref_index"] < 0
        ):
            raise SymbolArtifactError("gv_ref_index must be a non-negative integer")
        if normalized["gv_ref_deref_count"] not in {0, 1, 2}:
            raise SymbolArtifactError("gv_ref_deref_count must be between 0 and 2")
    if (
        kind == "vfunc"
        and "vfunc_slot_size" in normalized
        and _parse_int(normalized["vfunc_slot_size"], "vfunc_slot_size") != 4
    ):
        raise SymbolArtifactError("GoldSrc x86 vfunc slots are exactly 4 bytes")
    if kind == "vfunc":
        normalized["vfunc_slot_size"] = quoted_hex(4)
    if kind == "structmember" and not all(isinstance(normalized.get(field), str) for field in ("struct", "member")):
        raise SymbolArtifactError("structmember artifacts require struct and member metadata")
    return normalized


def write_symbol_yaml(path: str | Path, payload: Mapping[str, object]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        yaml.safe_dump(normalize_symbol_artifact(payload), allow_unicode=True, sort_keys=False, width=120),
        encoding="utf-8",
        newline="\n",
    )
