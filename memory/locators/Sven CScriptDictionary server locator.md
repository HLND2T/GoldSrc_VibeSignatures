---
title: Sven CScriptDictionary server locator
type: note
permalink: goldsrc-vibesignatures/locators/sven-cscript-dictionary-server-locator
tags:
- svencoop
- server
- angelscript
- dictionary
- locator
---

# CScriptDictionary server locator

## Overview
Issue #349 Part G covers ten server/private functions on svencoop-8948 (5.15) and svencoop-10257 (5.16), Windows PE32/I386 and Linux ELF32/I386. All ten have independent callable bodies in all four inputs. This note records binary evidence, not hook implementation.

## Responsibilities
- Locate real native dictionary methods, excluding generic wrappers and numeric Set/Get overloads.
- Publish 40 target function artifacts plus six supporting registration/factory functions.
- Keep functions, pointer-materialization instructions, GOT storage, and derived layout offsets distinct.

## Involved Files & Symbols
- ida_preprocessor_scripts/find-CScriptDictionary-registration.py: exact string intersection.
- ida_preprocessor_scripts/find-CScriptDictionary-registration-decompiles.py: nine native members and Linux supporting generic factory.
- ida_preprocessor_scripts/find-CScriptDictionary_Create.py: Windows body anchor / Linux factory call.
- script_dictionary_artifacts.py: real identities and body-covering output validation signatures.
- ida_analyze_util.py: found_funcptr consumes verified code_address_targets, requiring an exact callable entry.
- configs/svencoop-8948.yaml and configs/svencoop-10257.yaml: server DAG and func declarations.
- Six references under ida_preprocessor_scripts/references/svencoop-*/server/: generated through generate_reference_yaml.py after IDB metadata reconstruction.

## Architecture
Intersect FULLMATCH:dictionary@ f() with FULLMATCH:void erase(const string &in). The common native registration owner is unique; 5.16 Linux's separate generic registration does not contain the STL erase alias.
Windows registration entry: 5.15 0x10334780 / 5.16 0x10350640. Linux native registration: 5.15 0x1afcae / 5.16 0xf205c.

Select dictionary native asCALL_THISCALL=3 pointers; AddRef/Release behaviours are 5/6, with void f(). Set and Get use the exact ? declarations, excluding int64/double overloads. IsEmpty/GetSize are recovered from registered pointers instead of adjacency scans.

Linux factory behaviour 3 / dictionary@ f() / convention 6 identifies ScriptDictionaryFactory_Generic: 5.15 0x1b2b36, 5.16 0xf5a8a. Calls at 0x1b2b5d (PLT) / 0xf5aa7 (direct) resolve the engine-taking Create. Windows generic factory inlines construction and cannot substitute for Create.

Windows Create uses one approved unique body signature starting entry+0x24: allocate 48 bytes, initialize vptr/container, refCount=1/gcFlag=false, retain engine, read cache 1003. Call/vptr addresses are wildcarded. Independently verified returned object and GC notification distinguish the engine overload and inline wrapper.

| Function (all module=server, category=func) | 8948 Windows | 8948 Linux | 10257 Windows | 10257 Linux |
|---|---|---|---|---|
| Create(asIScriptEngine*) | 0x10333890 | 0x1b2afa | 0x1034f780 | 0xf5a4e |
| AddRef() const | 0x10333940 | 0x1af0be | 0x1034f830 | 0xf13d6 |
| Release() const | 0x10333950 | 0x1af1b4 | 0x1034f840 | 0xf14d6 |
| Set(const CString&, void*, int) | 0x103339d0 | 0x1b3270 | 0x1034f8c0 | 0xf60be |
| Get(const CString&, void*, int) const | 0x10333c40 | 0x1b2c74 | 0x1034fb30 | 0xf5bda |
| Exists(const CString&) const | 0x10333f10 | 0x1b2e96 | 0x1034fe00 | 0xf5e20 |
| IsEmpty() const | 0x10333f30 | 0x1aee72 | 0x1034fe20 | 0xf119c |
| GetSize() const | 0x10333f40 | 0x1aee80 | 0x1034fe30 | 0xf11aa |
| Delete(const CString&) | 0x10333f50 | 0x1b2f58 | 0x1034fe40 | 0xf5ee8 |
| DeleteAll() | 0x10334090 | 0x1b29b2 | 0x1034ff80 | 0xf594c |

## Dependencies
- Current target instructions/registration arguments and retained 5.15 Linux symbols are authoritative. Consumer sources in D:/metamod-fallguys/asext and the AngelScript SDK are reference revisions; full private server source and usable DWARF were unavailable.
- [[idalib-mcp]]: shared 13337 supervisor was unavailable; owned IdaMcpLifecycle sessions bound exact binaries, saved metadata in place, closed workers, and released ports.
- [[Sven AngelScript callable lifetime]]: adjacent server ABI/reference work.

## Notes
- Create is static cdecl. Windows native members use ECX=this and fixed stack argument cleanup; consumer fastcall dummy EDX is only an adapter. Linux uses cdecl with this first on the stack.
- Delete returns bool although the consumer declares void. Get/Exists/IsEmpty return bool, GetSize unsigned int, AddRef/Release/Set/DeleteAll void. Keys are CString references.
- Confirmed partial layout: vptr+0, engine+4, refCount+8, gcFlag+12, container+16; element count Windows+24/Linux+28; allocated size Windows48/Linux44. These offsets were not emitted as independent globals/fields.
- asSFuncPtr size Windows36/Linux32, discriminator Windows+32/Linux+28. Native member pointers use flag3, global cdecl flag2, generic callback flag1; do not confuse discriminator with call convention.
- Trigger: ELF callback load has no direct address operand. Root cause: PIC GOT instructions expose a data slot while the decoder separately validates its executable pointee. Correct approach: use code_address_targets; explicit empty/ambiguous/malformed lists must not fall back to data operands. Require exact target entry and preserve predecessor boundaries. Verified by synthetic shared behavior tests and all current Linux registrations.
- IsEmpty/GetSize Windows bodies are 8/4 bytes. Output-only uniqueness signatures may extend across a function boundary with an explicit flag; this is separate from discovery.
- All three finder stages were executed on all four inputs with old-artifact discovery disabled and real LLM mapping where declared. Independent raw executable-segment scanning found exactly one hit for each of the 46 new signatures and confirmed all 40 target entries.
- Reproducible checks: ida_analyze_bin.py -gamever <tag> -modules server -skill <stage> -platform windows,linux -oldgamever none -debug; format_repo_files.py --check; tests/run_test_suite.py unit and repository-contract. No tests assert concrete finder/config/generated-text inventories.
- Supported scope is precisely the four supplied inputs; there are no uncovered Part G methods. Part H iterator methods and all other issue sections remain separate.

## Callers
- Both Linux ScriptDictionaryFactory_Generic bodies call CScriptDictionary::Create(asIScriptEngine*) and store the object at GetAddressOfReturnLocation.
- Native registration materializes the member pointers as descriptors passed to AngelScript RegisterObjectBehaviour/RegisterObjectMethod; these are pointer references, not direct calls to the members.
