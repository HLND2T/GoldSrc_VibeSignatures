"""Discover and emit constant SetBounds CALL sites in the current GameUI."""

import inspect
from pathlib import Path

from ida_analyze_util import _find_unique_bytes, _load_yaml_mapping, write_patch_yaml
from ida_preprocessor_scripts._func_to_func_callsites_common import (
    expected_callsite_outputs,
    generate_callsite_signatures,
)
from ida_preprocessor_scripts._panel_bounds_collect import COLLECT, IDENTIFY_BOUNDS
from ida_preprocessor_scripts._panel_bounds_identity import (
    bounds_body_matches,
    bounds_constants,
    bounds_forwarder,
    bounds_scaled_constants,
    calls_reached_after,
    constructor_receivers,
    constructor_vtable,
)
from ida_preprocessor_scripts._panel_size_callsites_common import IDENTITY_SOURCE
from ida_preprocessor_scripts._panel_size_collect import IDENTIFY
from ida_preprocessor_scripts._vgui_paint_common import walk
from ida_preprocessor_scripts._vgui_private_method_identity import stack_check_preserves_registers


def bounds_identity_source(tail):
    """Worker source that proves the current Panel::SetBounds as `target`, then runs `tail`."""
    return "\n".join(
        (
            inspect.getsource(stack_check_preserves_registers),
            IDENTITY_SOURCE,
            inspect.getsource(bounds_constants),
            inspect.getsource(bounds_forwarder),
            inspect.getsource(bounds_scaled_constants),
            inspect.getsource(bounds_body_matches),
            inspect.getsource(constructor_receivers),
            inspect.getsource(constructor_vtable),
            inspect.getsource(calls_reached_after),
            IDENTIFY,
            IDENTIFY_BOUNDS,
            tail,
        )
    )


async def discover_bounds_callsites(session, platform, init):
    source = bounds_identity_source(COLLECT)
    result = await walk(session, source, dict(platform=platform, init=init, scaled=False))
    if not isinstance(result, dict) or result.get("error") or "sites" not in result:
        raise ValueError(f"Panel bounds discovery failed: {result}")
    if result.get("rejects"):
        raise ValueError(f"Could not analyze every SetBounds caller: {result['rejects']}")
    return result


async def preprocess_bounds_callsites(session, expected_outputs, new_binary_dir, platform, image_base, debug=False):
    if platform not in ("windows", "linux"):
        return False
    outputs = list(expected_outputs)
    expected = {}
    for mode in ("Const", "ScaledConst"):
        prefix = f"vgui2_Panel_SetBounds_{mode}_callsite_"
        subset = [p for p in outputs if Path(p).name.startswith(prefix)]
        expected[mode] = expected_callsite_outputs(subset, prefix) if subset else []
        if expected[mode] is None:
            raise ValueError(f"Invalid numbered SetBounds outputs: {mode}")
    if not outputs or sum(map(len, expected.values())) != len(outputs):
        raise ValueError("Expected contiguous numbered SetBounds callsite outputs")
    record = _load_yaml_mapping(Path(new_binary_dir) / f"vgui2_Panel_Init.{platform}.yaml")
    if not record or record.get("func_name") != "vgui2::Panel::Init(int, int, int, int)":
        raise ValueError("Missing current Panel::Init input")
    found = await discover_bounds_callsites(session, platform, int(record["func_va"], 0))
    rows = {}
    for mode, declared in expected.items():
        sites = sorted((s for s in found["sites"] if s["mode"] == mode), key=lambda site: int(site["ea"], 0))
        if len(sites) != len(declared):
            raise ValueError(f"SetBounds {mode}: found {len(sites)} sites, declared {len(declared)}")
        for (name, output), site in zip(declared, sites):
            ea = int(site["ea"], 0)
            if ea < image_base or ea in rows:
                raise ValueError("Invalid/duplicate current SetBounds callsite address")
            rows[ea] = name, output
    signatures = await generate_callsite_signatures(session, rows)
    if not signatures or {s["ea"] for s in signatures["sites"]} != set(rows):
        raise ValueError("Could not sign every SetBounds callsite")
    payloads = []
    for site in signatures["sites"]:
        ea = site["ea"]
        if await _find_unique_bytes(session, site["patch_sig"]) != ea:
            raise ValueError(f"Non-unique SetBounds callsite signature at {ea:x}")
        name, output = rows[ea]
        payloads.append(
            (
                output,
                dict(
                    patch_name=name,
                    patch_va=hex(ea),
                    patch_rva=hex(ea - image_base),
                    patch_sig=site["patch_sig"],
                    patch_sig_disp=site["patch_sig_disp"],
                ),
            )
        )
    for output, payload in payloads:
        write_patch_yaml(output, payload)
    if debug:
        print(f"Panel SetBounds: method={found['method']}, {len(payloads)} verified callsites")
    return True
