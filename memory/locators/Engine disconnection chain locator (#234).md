---
title: Engine disconnection chain locator (#234)
type: note
permalink: goldsrc-vibesignatures/locators/engine-disconnection-chain-locator-234
tags:
- locator
- engine
- disconnection
- issue-234
---

# Engine disconnection chain (#234)

## Trigger signal
A finder needs `CL_Parse_Disconnect`, `COM_ExplainDisconnection`, `COM_ExtendedExplainDisconnection`, `gszDisconnectReason`, `gszExtendedDisconnectReason`, `gfExtendedError`, or `Host_EndGame` in `hw.dll`/`hw.so`.

## Constraint and cause
The two explanation functions have no unique owned diagnostic string. `CL_Parse_Disconnect` is the `svc_disconnect` (opcode 2) callback in the already validated `cl_parsefuncs` table. Its nonempty-message branch references `#GameUI_DisconnectedFromServerExtended` and calls the basic then extended setter; its empty branch calls the same basic setter. Old Windows BLOB `hw.dll` is encrypted and must be analyzed through `hw.decrypt.dll`. SvEngine Linux can route calls through PLT and access globals through PIC/GOT.

The current target binaries put the `gfExtendedError = true` store in `COM_ExplainDisconnection`; `COM_ExtendedExplainDisconnection` does not make that store in checked builds, although the HLND2T source reference does. CoF 5936 reads the reason's leading byte with `movsx` then compares the register to `'#'`; other checked builds compare memory directly.

## Correct locator
1. Consume `cl_parsefuncs` and validate the `svc_disconnect` table entry to emit `CL_Parse_Disconnect`.
2. From the verified handler, use the exact Extended GameUI token's data reference and the next two direct call targets. Resolve ELF PLT and require the empty branch's basic-token call to agree with the first target.
3. In each setter, find the unique 256-byte public reason by the 255-byte copy limit, explicit `reason[255] = 0`, and `'#'` print guard. Recover the base from a current-IDB operand; use GOT/GOTOFF decoding on Linux. In the basic setter, recover `gfExtendedError` from the unique true store.
4. Locate `Host_EndGame` from its own `Host_EndGame: %s\n` string; old Windows builds have two string objects whose xrefs collapse to the same function.

## Verification
The issue #234 batch selection ran all five finders on 15 configured engine binary/platform pairs: 75/75 successful nodes, producing 105 function/GV YAML artifacts. The 7 Linux artifact VAs on each of `hl-8684`, `hl-10210`, and `svencoop-8948` matched independent ELF `nm` symbols exactly. The `hl-3248` BLOB, CoF Windows, `hl-8684` relocation ELF, and both Sven Linux PIC families were included. Run the selected-node analyzer batch and validate category fields/signatures for future builds; do not copy the historical addresses.

## Scope
Engine module across hl-3248..hl-10210, svencoop-8948/10257, and cof-5936 as configured. Client-only cstrike/czero/czeror configs have no engine module.