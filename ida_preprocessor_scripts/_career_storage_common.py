"""Recover and atomically prepare Career storage records from current x86 evidence."""

from pathlib import Path

from ida_analyze_util import (
    _load_yaml_mapping,
    write_func_yaml,
    write_patch_yaml,
    write_scalar_yaml,
    write_struct_offset_yaml,
)
from ida_preprocessor_scripts._career_bot_cost_common import COMMON, IDENTITY_SOURCE
from ida_preprocessor_scripts._career_player_name_common import COLLECT_COMMON, collect
from ida_preprocessor_scripts._career_storage_collect import COLLECT
from ida_preprocessor_scripts import _career_storage_identity as identity
from ida_preprocessor_scripts._func_to_func_callsites_common import CALLSITE_SUPPORT_PY
from ida_preprocessor_scripts._vgui_paint_common import walk
from ida_preprocessor_scripts._vgui_private_symbols_common import function_payload


IDENTITY = Path(identity.__file__).read_text(encoding="utf-8")


async def discover_storage(session, platform):
    roots = await walk(
        session,
        COMMON + "\nresult={t:literal_evidence(t) for t in ('%s/CZProfile-*.czp','%s/CZProfile-%s.czp')}",
        {},
    )
    if roots.get("error"):
        raise ValueError(roots["error"])
    if not any(row["addresses"] for row in roots.values()):
        return dict(absent=True, literals=roots)
    tables = await collect(session, platform, ["CCareerProfileFrame", "CCareerNewProfileBox"])
    found = await walk(
        session,
        IDENTITY_SOURCE + COMMON + COLLECT_COMMON + IDENTITY + COLLECT,
        dict(platform=platform, tables=tables),
    )
    if found.get("error"):
        raise ValueError(found["error"])
    return found


async def storage_payloads(session, found, image_base):
    if found.get("absent"):
        raise ValueError("This image has no Career storage implementation")
    payloads = {}
    for name, function in found["functions"].items():
        payload = await function_payload(
            session,
            function["ea"],
            image_base,
            function["display"],
            table=function.get("table"),
            index=function.get("index"),
        )
        if not payload:
            raise ValueError(f"No unique entry signature: {name}")
        payloads[name] = payload
    for group, sites in found["groups"].items():
        for index, site in enumerate(sites):
            name = f"{group}_{index}"
            # The generic signature builder accepts any decoded instruction.
            # Do not use the direct-CALL-only discovery helper on observation points.
            signed = await walk(
                session,
                CALLSITE_SUPPORT_PY + "\nrow,error=generate_patch_sig(values['ea'])\n"
                "if error:raise ValueError(error)\nresult=row",
                dict(ea=site["ea"]),
            )
            if signed.get("error") or not signed.get("patch_sig"):
                raise ValueError(f"Cannot sign {name}: {signed}")
            if signed["original_bytes"].lower() != site["original_bytes"]:
                raise ValueError("Callsite bytes changed during collection")
            payloads[name] = dict(
                patch_name=name,
                patch_va=hex(site["ea"]),
                patch_rva=hex(site["ea"] - image_base),
                patch_sig=signed["patch_sig"],
                patch_sig_disp=signed["patch_sig_disp"],
            )
            for suffix, value in (
                ("instruction_length", site["length"]),
                ("hook_strategy", site["strategy"]),
                ("abi", site["abi"]),
            ):
                scalar = name + "_" + suffix
                payloads[scalar] = dict(scalar_name=scalar, scalar_value=value)
    for name, value in found["scalars"].items():
        payloads[name] = dict(scalar_name=name, scalar_value=value)
    for name, member in found["members"].items():
        payloads[name] = dict(
            struct_name=member["struct"],
            member_name=member["member"],
            offset=hex(member["offset"]),
            size=hex(member["size"]),
        )
    return payloads


async def preprocess_storage(session, expected_outputs, directory, platform, image_base, debug=False):
    try:
        found = await discover_storage(session, platform)
        difficulty = _load_yaml_mapping(Path(directory) / f"CCareerDifficultyBox_ctor.{platform}.yaml")
        if (
            not difficulty
            or difficulty.get("func_name") != "CCareerDifficultyBox::CCareerDifficultyBox(char const*, vgui2::Panel*)"
        ):
            raise ValueError("Missing the existing complete difficulty constructor")
        if {c["owner"] for c in found.get("query_callers", [])} != {int(difficulty["func_va"], 0)}:
            raise ValueError("Profile lookup callers differ from the verified difficulty constructor")
        payloads = await storage_payloads(session, found, image_base)
        outputs = {Path(p).name.removesuffix(f".{platform}.yaml"): p for p in expected_outputs}
        if len(outputs) != len(expected_outputs) or set(outputs) != set(payloads):
            raise ValueError(f"Declared storage inventory differs: {set(outputs) ^ set(payloads)}")
        declared = {
            group: sorted(
                int(name[len(group) + 1 :])
                for name in outputs
                if name.startswith(group + "_") and name[len(group) + 1 :].isdigit()
            )
            for group in found["groups"]
        }
        identity.validate_groups(found["groups"], declared)
        for name, payload in payloads.items():
            writer = (
                write_patch_yaml
                if "patch_name" in payload
                else write_scalar_yaml
                if "scalar_name" in payload
                else write_struct_offset_yaml
                if "member_name" in payload
                else write_func_yaml
            )
            writer(outputs[name], payload)
        if debug:
            print(
                f"Career storage: {len(found['functions'])} entries, "
                f"{sum(map(len, found['groups'].values()))} callsites, {len(payloads)} records"
            )
        return True
    except (ValueError, KeyError, TypeError) as exc:
        if debug:
            print(f"Career storage rejected: {exc}")
        return False
