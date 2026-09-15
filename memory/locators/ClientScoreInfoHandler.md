---
title: ClientScoreInfoHandler locator
type: note
permalink: goldsrc-vibesignatures/locators/clientscoreinfohandler
tags:
  - locator
  - client
  - func
---

# ClientScoreInfoHandler

## Symbol

- **Name**: `ClientScoreInfoHandler`
- **Category**: `func`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-client-ScoreInfo-handler.py`

## Availability

- Declared in 10 configs: cstrike-10210, cstrike-3248, cstrike-3647, cstrike-4554, cstrike-6153, cstrike-8684, czero-10210, czero-8684, czeror-10210, czeror-8684.
- Platforms: Windows + Linux.
- Inlined / absent: none observed. The CS/CZ handler shares `CounterStrikeViewport`, CZDS uses the distinct `TeamFortressViewport` body; HL/cof/Sven have no ScoreInfo registration and are not configured for this symbol.

## Predecessors

- None. `find-client-ScoreInfo-handler` has no `expected_input`; it is the root of the client ScoreInfo chain.

## How it is located

1. `_client_registration_common.REGISTRATION_QUERY` recovers cdecl registration arguments for the message name `ScoreInfo`. Candidate strings are those whose NUL-terminated bytes end with exactly the label (a GCC pool may keep the label as a suffix); owners come from `DataRefsTo` of that string. Each owner is scanned per basic block with symbolic register/stack tracking: a `call` consuming `(name, callback)` from `[esp+0]`/`[esp+4]` or from the top two pushed values registers the callback. The callback must be unique (`len(callbacks) != 1` fails).
2. Inside the callback, only `mov reg, [mem]` (-> `object`), `mov reg, reg`, and `call/jmp [reg+offset]` are tracked. A dispatch is a `call/jmp` through `[vtable_object + offset]` where `offset % 4 == 0` and the base came from an in-memory object pointer. Exactly one dispatch is required; it yields `(interface_pointer, slot)`.
3. Writers of `interface_pointer` are the functions that contain a `mov [interface_pointer], ...` store. Each is walked as a symbolic constructor: branch states are kept separate (conditional `jmp` forked into pending states, unconditional `jmp` followed, `call` clobbers eax/ecx/edx and memory, `ret` ends), with an 8192-instruction budget. `lea` prefers a single writable data ref, else the composed `address()`. A `mov [esp+...]` source is captured as a symbolic `stack_value` so a cdecl constructor's `this` survives a base-constructor call in a callee-saved register.
4. When a non-zero value is stored into `interface_pointer`, the stored value must itself be a proven constant naming a data address (the interface vtable); otherwise the finder fails with `unproven non-null interface assignment`. Collected vtables must yield exactly one concrete handler: `target = dword(table + slot)` must be an executable function start (an `add_func` is attempted only for code/unknown bytes).
5. A 1-to-3-instruction target consisting of `ecx` / `[esp+4]` `add|sub imm` adjustments followed by `jmp near func` is treated as a this-adjusting jump thunk and the jump destination is used instead.
6. The final target is emitted as a function YAML (`func_name`/`func_va`/`func_rva`/`func_size`/`func_sig`). If signature generation fails at the exact entry, the finder retries with `allow_across_function_boundary` and records `func_sig_allow_across_function_boundary`.

## Pitfalls

- CS assigns `gCSViewPortMsgs` to a *secondary subobject* of its static viewport; CZDS assigns `gViewPortMsgs` in the viewport constructor. Neither the interface slot nor the object layout may be copied across builds — only the current constructor's explicit pointer/vptr stores are evidence.
- The `register`/`dispatch` split matters: the wrapper can dispatch through a different interface global than the one it null-checks. Resolve the actual call interface and the constructor-assigned subobject vptr before naming the handler.
- Corrected cstrike-4554 root cause: the viewport writes secondary vptrs, then branches on `this != nullptr` before assigning the global interface pointer. The old linear walk stopped at the conditional jump and found no table; branch states must stay separate while requiring one concrete handler across them.
- Null-guarded subobject conversions still carry the same vptr evidence on the non-null path, so they do not disqualify a table.
- Fails closed on: cyclic/over-budget control flow, `loop` instructions, unresolved (indirect) branches, unknown non-null interface assignments, multiple ScoreInfo callbacks, multiple dispatches, or multiple concrete handlers.
- Reference-family layouts and slot numbers are never copied into the target. Addresses recorded in notes (e.g. the 4554 constructor and interface pointer) are binary evidence only.
