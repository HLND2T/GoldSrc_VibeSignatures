"""Discover and emit strict constant-size callsites for any embedded VGUI module."""

import inspect
from pathlib import Path

from ida_analyze_util import _find_unique_bytes, _load_yaml_mapping, write_patch_yaml
from ida_preprocessor_scripts import _panel_size_identity
from ida_preprocessor_scripts._func_to_func_callsites_common import (
    expected_callsite_outputs,
    generate_callsite_signatures,
)
from ida_preprocessor_scripts._panel_size_collect import COLLECT
from ida_preprocessor_scripts._vgui_paint_common import walk
from ida_preprocessor_scripts._vgui_private_method_identity import stack_check_preserves_registers

IDENTITY_SOURCE = Path(_panel_size_identity.__file__).read_text(encoding="utf-8")


async def discover_size_callsites(session, platform, init, *, scaled):
    source = inspect.getsource(stack_check_preserves_registers) + "\n" + IDENTITY_SOURCE + "\n" + COLLECT
    result = await walk(session, source, dict(platform=platform, init=init, scaled=scaled))
    if not isinstance(result, dict) or result.get("error") or "sites" not in result:
        raise ValueError(f"Panel size discovery failed: {result}")
    if result.get("rejects"):
        raise ValueError(f"Could not analyze every size caller: {result['rejects']}")
    return result


async def preprocess_size_callsites(session, expected_outputs, new_binary_dir, platform, image_base, debug=False):
    if platform not in ("windows", "linux"):
        return False
    outputs = list(expected_outputs)
    modes = {mode for mode in ("ScaledConst", "Const") if any(f"_{mode}_callsite_" in Path(p).name for p in outputs)}
    if len(modes) != 1:
        raise ValueError("Expected exactly one explicit sizing mode in output identities")
    mode = modes.pop()
    expected = {}
    for kind in ("SetSize", "SetMinimumSize"):
        prefix = f"vgui2_Panel_{kind}_{mode}_callsite_"
        subset = [p for p in outputs if Path(p).name.startswith(prefix)]
        expected[kind] = expected_callsite_outputs(subset, prefix) if subset else []
        if expected[kind] is None:
            raise ValueError(f"Invalid numbered callsite outputs: {prefix}")
    if sum(map(len, expected.values())) != len(outputs):
        raise ValueError("Unexpected Panel size output")
    directory = Path(new_binary_dir)
    stem = "ClientVGUI_Panel_Init" if directory.name == "client" else "vgui2_Panel_Init"
    record = _load_yaml_mapping(directory / f"{stem}.{platform}.yaml")
    if not record or record.get("func_name") != "vgui2::Panel::Init(int, int, int, int)":
        raise ValueError("Missing current Panel::Init input")
    found = await discover_size_callsites(session, platform, int(record["func_va"], 0), scaled=mode == "ScaledConst")
    rows = {}
    for kind, declared in expected.items():
        sites = sorted(found["sites"][kind], key=lambda site: int(site["ea"], 0))
        if len(sites) != len(declared):
            raise ValueError(f"{kind}: found {len(sites)} sites, declared {len(declared)}")
        for (name, output), site in zip(declared, sites):
            ea = int(site["ea"], 0)
            if ea < image_base or ea in rows:
                raise ValueError("Invalid/duplicate current callsite address")
            rows[ea] = (name, output)
    signatures = await generate_callsite_signatures(session, rows)
    if not signatures or {s["ea"] for s in signatures["sites"]} != set(rows):
        raise ValueError("Could not sign every current callsite")
    payloads = []
    for site in signatures["sites"]:
        ea = site["ea"]
        if await _find_unique_bytes(session, site["patch_sig"]) != ea:
            raise ValueError(f"Non-unique callsite signature at {ea:x}")
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
        print(f"Panel sizes ({mode}): methods={found['methods']}, {len(payloads)} verified callsites")
    return True
