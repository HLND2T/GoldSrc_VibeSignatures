---
title: Sven CString CScriptBuilder server locator
type: note
permalink: goldsrc-vibesignatures/locators/sven-cstring-cscript-builder-server-locator
tags:
- svencoop
- server
- angelscript
- locator
---

# CString / CScriptBuilder server locator

## Overview
Issue #349 Part E covers CString::Assign(const char*, unsigned int), CString::~CString(), and CScriptBuilder::DefineWord(const char*) on Sven 5.15 (svencoop-8948) and 5.16 (svencoop-10257), PE32/I386 and ELF32/I386. All three have standalone native callable bodies on all four supplied inputs.

## Responsibilities
- Discover by exact strings, registration descriptors and verified current-target calls. No byte signature, fixed address, call ordinal or old artifact discovers a target.
- Publish 12 target function artifacts and 16 supporting registration/constructor/adapter artifacts; distinguish wrappers and native methods.

## Involved Files & Symbols
- ida_preprocessor_scripts/find-CString-CScriptBuilder-predecessors.py: exact owned registration declarations and module-builder diagnostic.
- ida_preprocessor_scripts/find-RegisterSCScriptASString-decompiles.py: grouped found_funcptr mapping for CString_opAssign and DestructASString.
- ida_preprocessor_scripts/find-CString_opAssign-decompiles.py: native CString_Assign call.
- ida_preprocessor_scripts/find-DestructASString-decompiles.py: native CString_dtor call/tail jump, resolving PLT/GOT.
- ida_preprocessor_scripts/find-CASModuleBuilder_CASModuleBuilder-decompiles.py: CScriptBuilder_DefineWord call with SERVER.
- cstring_builder_artifacts.py: real source identities and output-only body-covering signatures.
- configs/svencoop-8948.yaml and configs/svencoop-10257.yaml: module server, category func, explicit DAG.
- Eight generated/annotated references under ida_preprocessor_scripts/references/svencoop-10257/server; family fallback lets 8948 reuse the same source-role references.

## Architecture
Registration is uniquely owned by the intersection of FULLMATCH:void Destructstring() and FULLMATCH:string& opAssign(const string& in szString). Select object string, exact CString-reference opAssign, convention asCALL_THISCALL=3, member-pointer discriminator 3. Select destructor behaviour 2 / void Destructstring() / convention asCALL_CDECL_OBJLAST=4 / global-pointer discriminator 2 for the destruction adapter. Its cdecl ABI is separate from the native destructor ABI.

CString_opAssign reads source buffer +20 and length +24, then calls Assign on this. DestructASString tail-jumps on Windows; Linux calls the native destructor (5.15 PLT/GOT). Module-builder constructor uniquely owns FULLMATCH:CASModuleBuilder::CASModuleBuilder: null module info! followed by a newline. Its SERVER definition passes the script-builder object to DefineWord. The callee constructs a temporary string, finds it in definedWords, and inserts only when absent.

| Native function VA (Linux VA=RVA; Windows base=0x10000000) | 8948 Windows | 8948 Linux | 10257 Windows | 10257 Linux |
|---|---|---|---|---|
| CString::Assign(const char*, unsigned int) | 0x100da8b0 | 0x228f7a | 0x100dc3a0 | 0x177e40 |
| CString::~CString() | 0x100d85a0 | 0x228e4a | 0x100da100 | 0x177780 |
| CScriptBuilder::DefineWord(const char*) | 0x10330ee0 | 0x1acaa0 | 0x1034ccc0 | 0xee470 |

## Dependencies
- [[idalib-mcp]]: shared-supervisor idb_open sessions were verified against original hashes, restored with minimal source metadata, exported through generate_reference_yaml.py, and explicitly closed with save=True. Analyzer consumers used strict warm/no-save sessions.
- [[Sven CScriptDictionary server locator]]: established registration descriptor ABI and executable GOT-pointee validation.
- Retained 5.15 ELF symbols confirm native identities: _ZN7CString6AssignEPKcj, _ZN7CStringD2Ev (D1 same entry), _ZN14CScriptBuilder10DefineWordEPKc. Consumer source D:/metamod-fallguys and its SDK are reference revisions; full private server source and usable DWARF were unavailable. Target instructions remain authoritative.

## Notes
- Trigger: the consumer's 5.16 Linux CString_dtor signature uniquely matches 0x1787a2. Root cause: this is a ClearMemory-style function which deallocates then resets fields; uniqueness does not establish destructor identity. Correct approach: follow the registered DestructASString callback's call at 0x156a90 to 0x177780, which only conditionally deallocates. Verify through the native registration and current-target call, not consumer field naming. Scope: these four supplied server inputs; do not propagate the old 0x1787a2 identification.
- The consumer's Linux Assign caller signature also matches two integer-formatting functions. Recover the CString-reference assignment method from its exact registration instead.
- Windows native members use ECX=this; the consumer fastcall dummy EDX is an adapter. Linux native members use cdecl with this first on the stack. Buffer +20, length +24 and capacity/ownership +28 are corroborating partial layout, not emitted globals or struct-member artifacts.
- Output signature byte budgets reach body statements beyond SEH/PIC prologues. Tiny destruction adapters require explicit across-function-boundary uniqueness. Such signatures only validate already-discovered output and cannot bypass the anchor chain (old_yaml_map=None).
- Validation: all five new stages executed on all four inputs using real LLM mapping where declared. An independent raw executable-segment audit verified all 28 identities/VA/RVA/input hashes and exactly one signature hit at each native/adapter entry. Unit suite: 1494 tests OK, 12 skipped. Repository-contract suite: 15 tests OK after staging task artifacts; format and git diff --check passed. Both complete server config runs exited zero with existing outputs (47/46 stages skipped); target finders were actually executed in the earlier staged runs and the 16-node exact batch.
- SHA256: 8948 DLL 61c5955cc3bcb1d4a23f8d65b5c19dd042c026e776ded937439bcdcd21973849; 8948 SO 18ba7ee4e7ccd109dd43172446f463d9a12d9154dfa1f1230cb8345aadd43643; 10257 DLL f8be8b7ba8af2a5006127c3c36ced3717d94aec1120ef8b5678e28b23f0b07c0; 10257 SO 7a980bbd4b03f7380092e45d0a7515085ffb5142e62589d87e2596e90d89d2ca.

## Callers
- Registered CString::operator=(const CString&) calls CString::Assign on each supplied input.
- Registered DestructASString forwards to the native destructor on each supplied input.
- CASModuleBuilder::CASModuleBuilder(ModuleType::Type, const char*) calls CScriptBuilder::DefineWord with SERVER on each supplied input.
