---
title: Sven CScriptDictionary iterator server locator
type: note
permalink: goldsrc-vibesignatures/locators/sven-cscriptdictionary-iterator-server-locator
tags:
  - sven
  - server
  - angelscript
  - abi
---

# CScriptDictionary iterator server locator

## Scope and approval

Issue #349 Part H: six ordinary `server / func` methods, Sven Co-op 5.15
(`svencoop-8948`) and 5.16 (`svencoop-10257`), PE32/I386 and ELF32/I386.
All six have independent callable bodies on all four inputs. The user approved
the six anchors in this session before finder/config implementation.
This covers symbol location and artifacts; consumer hook implementation is outside scope.

## How it is located

- `find-CScriptDictionary-CIterator.py` uses approved body patterns, with no
  old-artifact discovery. The tiny bodies have no string/float anchor. begin/end
  initialize `{node, dictionary}`; GetKey returns the node's CString; `!=`
  compares node pointers; GetValue delegates to `CScriptDictValue::Get` with
  engine, output and integer typeId. Windows prefix ++ follows the next node.
- Budgets across all four inputs: begin/end three patterns each, GetKey/`!=`
  two each, GetValue four, Windows ++ one. Call displacements are wildcarded;
  the 5.15 Linux PIC prologues are excluded. Each applicable pattern has one
  raw-binary match. Alternatives advance only on zero hits, never ambiguity.
- The complete matched statement must lie inside the current executable IDA
  function. Inspection then binds its exact callable entry. Generic xref-owner
  backtracking rejects short entry matches when other callable methods are
  nearby; this local owner check avoids that ambiguity without changing the
  shared recovery heuristic.
- Linux prefix/postfix ++ are byte-identical: there are two matches in each
  ELF. They cannot be distinguished by body bytes. The Linux-only
  `find-CScriptDictionary-CIterator-pp-decompiles.py` uses a verified call inside
  `InitializeEntity`, not an address ordering or neighboring-function guess.
  Shared `found_call` validation checks the current instruction and resolves
  5.15 PLT; body verification requires the resolved entry to advance the node.
- Supporting `find-CASEntityFuncs_InitializeEntity.py` requires both exact
  diagnostic literals to independently identify the same unique owner:
  `CASEntityFuncs::CreateCustomEntity: failed to retrieve value for key '%s' from dictionary!\n`
  and `CASEntityFuncs::CreateCustomEntity: failed to get string type!\n`.
  Each occurs once per image. The diagnostic names CreateCustomEntity, but the
  retained 5.15 ELF symbol identifies `InitializeEntity(const CString&,
  CBaseEntity*, CScriptDictionary*)`, a static member with three stack arguments.
  5.15 ELF has no direct string xref; the existing
  `_sven_client_pic_common` helper recovers its decoded GOTOFF operands.

## Verified addresses

All addresses below are VAs. PE image base is `0x10000000`; ELF image base is zero.

| Function | 8948 Windows | 8948 Linux | 10257 Windows | 10257 Linux |
| --- | --- | --- | --- | --- |
| InitializeEntity (supporting) | 0x102cda90 | 0x338b18 | 0x102dd720 | 0x2a9e5a |
| begin() const | 0x103342f0 | 0x1b284a | 0x103501b0 | 0xf5808 |
| end() const | 0x10334310 | 0x1b2878 | 0x103501d0 | 0xf581c |
| CIterator::GetKey() const | 0x10334230 | 0x1b28e2 | 0x103500f0 | 0xf5880 |
| CIterator::operator!=(const CIterator&) const | 0x10334220 | 0x1b28d2 | 0x103500e0 | 0xf5870 |
| CIterator::GetValue(void*, int) const | 0x10334290 | 0x1b295a | 0x10350150 | 0xf58f8 |
| CIterator::operator++() | 0x103341e0 | 0x1b28a4 | 0x103500a0 | 0xf5842 |

Linux ++ callsites independently recovered by real LLM requests:
5.15 `0x338ca7 -> PLT 0x18d120 -> 0x1b28a4`;
5.16 `0x2a9fb9 -> 0xf5842`. Both calls pass only iterator this, not postfix int.
The unused postfix entries are `0x1b28b0` and `0xf584e`.

## ABI and partial layouts

- `CIterator` is eight bytes: `{node pointer +0, dictionary pointer +4}`.
  It does not contain `{CString key; value; typeId}` as the issue originally suggested.
  Key/value/typeId live in the pointed-to container node.
- Windows native members use ECX=this; the consumer's fastcall EDX is an
  adapter dummy. begin/end put dictionary in ECX and result on the stack;
  EAX returns the result address and `ret 4` consumes the result argument.
  `!=` consumes four stack bytes; GetValue consumes eight; GetKey/++ use none.
- Linux begin/end put hidden result first and dictionary second on the stack;
  EAX returns result. `ret 4` consumes only the hidden pointer; the caller
  cleans the remaining stack arguments. This is not a normal two-argument
  stdcall. References use explicit argument locations to prevent Hex-Rays
  from dropping/reversing the dictionary argument.
- Other Linux members use i386 cdecl with iterator this first. GetKey returns
  `const CString&` (address); `!=` and GetValue return bool; prefix ++ returns
  void. Hex-Rays's original Linux EAX-based reference-return guess for ++ is
  unsupported: the SDK declares void and Windows does not return iterator this.
- Current nodes: next pointer +0; key Windows +8 / Linux +4;
  dictionary value Windows +48 / Linux +40. Both dictionaries hold engine at
  +4. Windows begin uses dictionary +20's header node then its next pointer;
  Windows end returns that header. Linux begin uses dictionary +24's node;
  Linux end uses null. These are evidence, not published global/member artifacts.

## Reference and provenance

One reference gamever: `svencoop-10257`, both configured platforms. References
were generated through `generate_reference_yaml.py` after source-like metadata
reconstruction, then the ++ target was annotated in both disassembly and
procedure. 8948 uses the existing Sven family reference fallback.

Current machine code and 5.15 retained ELF names are authoritative. Consumer
sources and the modified AngelScript SDK under `~/metamod-fallguys` are
reference revisions, not matching private server source. No usable DWARF was
present. Partial views recover entity->vars->edict, CString data, iterator,
dictionary engine, and key/value dispatch. Linux compiler stack reuse is
represented by a std::string/CString union view, not a consumer ABI declaration.

Shared supervisor acquisition: initial `idb_list` had no active sessions;
each exact input was opened through `idb_open`, checked with survey/health,
and finalized with successful `idb_close(save=True)`. Reference metadata was
saved in the 10257 `.i64` files; raw binary hashes remained unchanged.
Formal analyzer runs use strict existing IDBs and do not save finder mutations.

| Binary | SHA-256 |
| --- | --- |
| 8948 server.dll | 61c5955cc3bcb1d4a23f8d65b5c19dd042c026e776ded937439bcdcd21973849 |
| 8948 server.so | 18ba7ee4e7ccd109dd43172446f463d9a12d9154dfa1f1230cb8345aadd43643 |
| 10257 server.dll | f8be8b7ba8af2a5006127c3c36ced3717d94aec1120ef8b5678e28b23f0b07c0 |
| 10257 server.so | 7a980bbd4b03f7380092e45d0a7515085ffb5142e62589d87e2596e90d89d2ca |

## Verification and remaining scope

Run each tag's five new config nodes with `ida_analyze_bin.py -gamever <tag>
-node server:<platform>:<skill> -oldgamever none -debug`. Both Linux ++ calls
require a real LLM response; generated signatures never discover the overload.
Output-only extended signatures may cross function boundaries for identical
Linux prefix/postfix bodies, with the explicit artifact flag.

All 24 requested method entries and four supporting entries were independently
compared to current binary evidence and scanned for unique executable-region
signatures. Format/source tests are separate from commercial IDA evidence.
The five new nodes succeeded on each tag (zero failures/skips); the final 10257
method nodes were rerun after the local owner/shared publisher extraction.
`tests/run_test_suite.py all -b --durations 30` ran 1513 tests in 136.042 seconds,
exit 0, 13 skips (Windows-only, opt-in CLI/IDA, and unavailable Redis groups).
Repository format, changed-file Ruff excluding existing finder N999/EXE001
conventions, and diff whitespace checks passed. The initial inventory-only test
error was resolved by staging all generated artifacts before the final suite.
No Part H method is missing or inlined away in the four supported inputs.
Other #349 sections remain separate; this delivery must not close the whole issue.

## Reusable lesson

- Trigger: iterator buffer corruption or a wrong ++ overload despite a byte match.
- Constraint: hidden structure return changes argument order/cleanup by compiler;
  prefix/postfix may have identical bodies; decompiler prototypes are hypotheses.
- Correct practice: derive the eight-byte state and call ABI from instructions,
  use a semantic caller to distinguish overloads, and validate the resolved body.
- Verification: both platform peers, actual caller argument setup/return cleanup,
  current-IDB call validation, and unique output signatures.
- Scope: Sven server CScriptDictionary iterator methods on these x86 builds.
