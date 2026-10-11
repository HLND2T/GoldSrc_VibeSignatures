#!/usr/bin/env python3
"""Locate asGetActiveContext through its tail-index body statement.

asGetActiveContext() is a C-linkage AngelScript SDK accessor with an empty
argument list and no owning string or floating-point constant, so it has no
direct string/constant anchor. Its entire body is one source statement:

    asCThreadLocalData *tld = asCThreadManager::GetLocalData();
    if( tld == 0 || tld->activeContexts.GetLength() == 0 )
        return 0;
    return tld->activeContexts[tld->activeContexts.GetLength()-1];

The tail read `tld->activeContexts[GetLength()-1]` is the discriminating body
statement. asCThreadLocalData stores the active-context array pointer at +0 and
its element count at +4 (fixed by the AngelScript SDK and identical across both
Sven builds), so the tail read compiles to: load the count from +4, test it,
load the array pointer from +0, and index the last element at [array+count*4-4].
The two sketches below encode exactly that statement, starting at the count
load and ending on the final indexed load; they are not the function header.

Only the scratch register the compiler picks for the count differs, and it is
stable per compiler family across both Sven builds: the PE32 (MSVC) builds use
ecx for this chain, the ELF32 (gcc/Itanium) builds use edx. Each 13-byte sketch
resolves to exactly one owning function across the whole image on every
configured 5.15/5.16 binary, so two signatures cover all four targets -- well
within the code-signature budget. A finder governed by find-anchor-to-goldsrc-
symbol must pass old_yaml_map=None; output signatures are generated after
discovery and are never used as anchors.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["asGetActiveContext"]
BODY_SIGNATURES = {
    # mov ecx,[eax+4]; test ecx,ecx; jz; mov eax,[eax]; mov eax,[eax+ecx*4-4]
    "windows": "8B 48 04 85 C9 74 ?? 8B 00 8B 44 88 FC",
    # mov edx,[eax+4]; test edx,edx; jz; mov eax,[eax]; mov eax,[eax+edx*4-4]
    "linux": "8B 50 04 85 D2 74 ?? 8B 00 8B 44 90 FC",
}
FUNC_XREFS = {
    platform: [{"func_name": "asGetActiveContext", "xref_signatures": [signature]}]
    for platform, signature in BODY_SIGNATURES.items()
}
GENERATE_YAML_DESIRED_FIELDS = [
    ("asGetActiveContext", ["func_name", "func_va", "func_rva", "func_size", "func_sig"]),
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS[platform],
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
