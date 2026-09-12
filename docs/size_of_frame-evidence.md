# size_of_frame engine evidence (issue #106)

## Quality checks

- `uv run python format_repo_files.py --check`: passed.
- `uv run python tests/run_test_suite.py unit -b --durations 10`: 766 tests, OK (2 opt-in CLI tests skipped).
- `uv run python tests/run_test_suite.py repository-contract -b --durations 10`: 14 tests, OK.
- `uv run python tests/run_test_suite.py all -b --durations 10`: 784 tests, OK (6 skips: 2 opt-in CLI tests, 3 Redis integration classes without a server, 1 opt-in IDA environment test). The real owned IDA finder checks below were executed separately for all 13 binaries.
- Pages: `npm test -- --reporter=dot` (50/50), `npm run lint`, and `npm run build` passed.
- All 10 engine-version snapshots were rebuilt from the real tracked artifacts with `pack_snapshot`, read through `SnapshotSymbolStore`, and exported through `encode_dataset`/`encode_index`. All 13 scalar payloads survived unchanged. These validation snapshots are local scratch, not a release publication.
- Pages rebuilt with `GSVIBE_GAMESYMBOLS_DIR=D:/gsvibe-scalar-validation/datasets`; `node pages/verifyGameSymbolAssets.mjs --directory pages/dist/gamesymbols` verified all 10 real datasets.
- `git diff --cached --check`: passed.

## Engine validation

Current-binary validation on 2026-09-11: 10 configured engine versions, 13/13 Windows/Linux targets succeeded. Each target ran the grouped finder with old_yaml_map=None and the current predecessor artifact; existing scalar files did not skip discovery.

Contract: scalar_name and uint32 scalar_value only. Consumers use the number for the matching binary identity. No scalar signature or instruction offset exists. The instruction traces below are offline evidence, including optimized arithmetic; they are not discovery constants.

Root: FULLMATCH:Non-sprite set to glow!\n. Each analyzed binary contains one exact NUL-terminated literal and one file match for the validated predecessor function signature. Both player paths independently agree on the byte stride; entity-state indexing is excluded. Linux second-argument stack offsets were decoded from the live IDA instructions, not inferred from stack-variable names.

Lifecycle: isolated copies under D:/gsvibe-scalar-validation, exact binary identity, IDA 9.3, owned IdaMcpLifecycle, restored_strict, save_on_success=False. All workers completed normal owned cleanup. Reference reconstruction used the same owned no-save policy and the unchanged generate_reference_yaml.py CLI, sequentially for Sven Windows/Linux; unknown Sven types/helpers remain explicitly partial. No binary/IDB scratch is delivered.

Source intent: D:/HLND2T_official/engine/r_trans.c:219-343, particularly lines 291 and 305. The source revision is not assumed identical to Sven or CoF; target machine code determines each byte stride.

Reproduction after exact cache warm/restore:

```powershell
uv run python ida_analyze_bin.py -allgamever -modules engine -skill find-R_DrawTEntitiesOnList-decompiles -platform windows,linux -debug
```

The recorded run used -batch_selection D:/gsvibe-scalar-validation/selection.json (all 13 engine nodes), -bindir D:/gsvibe-scalar-validation/bin, -artifactdir D:/gsvibe-scalar-validation/artifacts and -batch_diagnostics D:/gsvibe-scalar-validation/verified-analysis. GSVIBE_ANALYSIS_MAX_CONCURRENCY=3; GSVIBE_ANALYSIS_MAX_MEMORY_MIB=16384.

| Engine | Platform | Value | Owner VA | Literal / owner signature matches |
|---|---|---:|---|---|
| hl-3248 | windows | 17080 / 0x42b8 | 0x1d93200 | 1 / 1 |
| hl-3266 | windows | 17080 / 0x42b8 | 0x1d931e0 | 1 / 1 |
| hl-3329 | windows | 17080 / 0x42b8 | 0x1d930c0 | 1 / 1 |
| hl-3647 | windows | 17080 / 0x42b8 | 0x1d93230 | 1 / 1 |
| hl-4554 | windows | 17080 / 0x42b8 | 0x1d9f1a0 | 1 / 1 |
| hl-6153 | windows | 17080 / 0x42b8 | 0x1d87170 | 1 / 1 |
| hl-8684 | windows | 17080 / 0x42b8 | 0x1d88af0 | 1 / 1 |
| hl-8684 | linux | 17080 / 0x42b8 | 0x200a30 | 1 / 1 |
| hl-10210 | windows | 17176 / 0x4318 | 0x101fa870 | 1 / 1 |
| hl-10210 | linux | 17176 / 0x4318 | 0x1b0c90 | 1 / 1 |
| svencoop-10257 | windows | 34072 / 0x8518 | 0x1d932a0 | 1 / 1 |
| svencoop-10257 | linux | 34072 / 0x8518 | 0x17e2a0 | 1 / 1 |
| cof-5936 | windows | 17088 / 0x42c0 | 0x1dc4539 | 1 / 1 |

## Binary hashes and instruction evidence

### hl-3248 / windows

Original SHA-256: `525bdbddf2f180824944ee2576702e040c2f5554ca4290f40faec842e2cf02bb`

Analyzed `engine/hw.decrypt.dll` SHA-256: `7311ec923c5644a4c81fb1c887d1062f7732c3b7152ad0469ff367bc0094feb0`

Player path 1:

```asm
0x1d933d6: and     eax, ecx
0x1d933d8: mov     edx, [edx]
0x1d933da: lea     ecx, [eax+eax*8]
0x1d933dd: shl     ecx, 3
0x1d933e0: sub     ecx, eax
0x1d933e2: lea     ecx, [ecx+ecx*2]
0x1d933e5: lea     eax, [eax+ecx*2]
0x1d933e8: lea     ecx, [eax+eax*4]
0x1d933eb: mov     eax, edx
0x1d933ed: shl     eax, 4
0x1d933f0: add     eax, edx
0x1d933f2: lea     edx, [eax+eax*4]
0x1d933f5: shl     edx, 2
0x1d933f8: lea     eax, unk_2DE134C[edx+ecx*8]
0x1d933ff: mov     ecx, off_1ED35E4
0x1d93405: push    eax
0x1d93406: push    edi
0x1d93407: call    dword ptr [ecx+8]
```

Player path 2:

```asm
0x1d9346e: and     eax, ecx
0x1d93470: lea     ecx, [eax+eax*8]
0x1d93473: shl     ecx, 3
0x1d93476: sub     ecx, eax
0x1d93478: lea     ecx, [ecx+ecx*2]
0x1d9347b: lea     eax, [eax+ecx*2]
0x1d9347e: mov     ecx, [edx]
0x1d93480: lea     ebp, [eax+eax*4]
0x1d93483: mov     eax, ecx
0x1d93485: shl     eax, 4
0x1d93488: add     eax, ecx
0x1d9348a: mov     ecx, off_1ED35E4
0x1d93490: lea     edx, [eax+eax*4]
0x1d93493: shl     edx, 2
0x1d93496: lea     eax, unk_2DE134C[edx+ebp*8]
0x1d9349d: push    eax
0x1d9349e: push    0
0x1d934a0: call    dword ptr [ecx+8]
```

### hl-3266 / windows

Original SHA-256: `e3faf0b5f1f694b02208ee905148d7febcde9eb8ea093c1251ce6a3dda1bb65e`

Analyzed `engine/hw.decrypt.dll` SHA-256: `d00aed229438f2b3dbe0c77f37657b903e6c35893ee1d39e4695afbfffefee21`

Player path 1:

```asm
0x1d933b6: and     eax, ecx
0x1d933b8: mov     edx, [edx]
0x1d933ba: lea     ecx, [eax+eax*8]
0x1d933bd: shl     ecx, 3
0x1d933c0: sub     ecx, eax
0x1d933c2: lea     ecx, [ecx+ecx*2]
0x1d933c5: lea     eax, [eax+ecx*2]
0x1d933c8: lea     ecx, [eax+eax*4]
0x1d933cb: mov     eax, edx
0x1d933cd: shl     eax, 4
0x1d933d0: add     eax, edx
0x1d933d2: lea     edx, [eax+eax*4]
0x1d933d5: shl     edx, 2
0x1d933d8: lea     eax, unk_2DE134C[edx+ecx*8]
0x1d933df: mov     ecx, off_1ED35E4
0x1d933e5: push    eax
0x1d933e6: push    edi
0x1d933e7: call    dword ptr [ecx+8]
```

Player path 2:

```asm
0x1d9344e: and     eax, ecx
0x1d93450: lea     ecx, [eax+eax*8]
0x1d93453: shl     ecx, 3
0x1d93456: sub     ecx, eax
0x1d93458: lea     ecx, [ecx+ecx*2]
0x1d9345b: lea     eax, [eax+ecx*2]
0x1d9345e: mov     ecx, [edx]
0x1d93460: lea     ebp, [eax+eax*4]
0x1d93463: mov     eax, ecx
0x1d93465: shl     eax, 4
0x1d93468: add     eax, ecx
0x1d9346a: mov     ecx, off_1ED35E4
0x1d93470: lea     edx, [eax+eax*4]
0x1d93473: shl     edx, 2
0x1d93476: lea     eax, unk_2DE134C[edx+ebp*8]
0x1d9347d: push    eax
0x1d9347e: push    0
0x1d93480: call    dword ptr [ecx+8]
```

### hl-3329 / windows

Original SHA-256: `ef59e9f2001baf08185d3482684a56a8faad1b31f2fe6e5ba97048fe23f696ff`

Analyzed `engine/hw.decrypt.dll` SHA-256: `4b42b89992cda6ef5b84c1bb56556f5b15b1e0c2a3a7b9f04fe053dcf24c4480`

Player path 1:

```asm
0x1d93296: and     eax, ecx
0x1d93298: mov     edx, [edx]
0x1d9329a: lea     ecx, [eax+eax*8]
0x1d9329d: shl     ecx, 3
0x1d932a0: sub     ecx, eax
0x1d932a2: lea     ecx, [ecx+ecx*2]
0x1d932a5: lea     eax, [eax+ecx*2]
0x1d932a8: lea     ecx, [eax+eax*4]
0x1d932ab: mov     eax, edx
0x1d932ad: shl     eax, 4
0x1d932b0: add     eax, edx
0x1d932b2: lea     edx, [eax+eax*4]
0x1d932b5: shl     edx, 2
0x1d932b8: lea     eax, unk_2DADC6C[edx+ecx*8]
0x1d932bf: mov     ecx, off_1EA517C
0x1d932c5: push    eax
0x1d932c6: push    edi
0x1d932c7: call    dword ptr [ecx+8]
```

Player path 2:

```asm
0x1d9332e: and     eax, ecx
0x1d93330: lea     ecx, [eax+eax*8]
0x1d93333: shl     ecx, 3
0x1d93336: sub     ecx, eax
0x1d93338: lea     ecx, [ecx+ecx*2]
0x1d9333b: lea     eax, [eax+ecx*2]
0x1d9333e: mov     ecx, [edx]
0x1d93340: lea     ebp, [eax+eax*4]
0x1d93343: mov     eax, ecx
0x1d93345: shl     eax, 4
0x1d93348: add     eax, ecx
0x1d9334a: mov     ecx, off_1EA517C
0x1d93350: lea     edx, [eax+eax*4]
0x1d93353: shl     edx, 2
0x1d93356: lea     eax, unk_2DADC6C[edx+ebp*8]
0x1d9335d: push    eax
0x1d9335e: push    0
0x1d93360: call    dword ptr [ecx+8]
```

### hl-3647 / windows

Original SHA-256: `f80c01c3c8f0800c89102343d58c4295bb62872f654cbd04a524788aa10f901f`

Analyzed `engine/hw.decrypt.dll` SHA-256: `7d4bee5d199c40d738c0bc2ed668c0fd8830278e2fed1f320b07832fda993110`

Player path 1:

```asm
0x1d93406: and     eax, ecx
0x1d93408: mov     edx, [edx]
0x1d9340a: lea     ecx, [eax+eax*8]
0x1d9340d: shl     ecx, 3
0x1d93410: sub     ecx, eax
0x1d93412: lea     ecx, [ecx+ecx*2]
0x1d93415: lea     eax, [eax+ecx*2]
0x1d93418: lea     ecx, [eax+eax*4]
0x1d9341b: mov     eax, edx
0x1d9341d: shl     eax, 4
0x1d93420: add     eax, edx
0x1d93422: lea     edx, [eax+eax*4]
0x1d93425: shl     edx, 2
0x1d93428: lea     eax, unk_2DACB0C[edx+ecx*8]
0x1d9342f: mov     ecx, off_1EA42A4
0x1d93435: push    eax
0x1d93436: push    edi
0x1d93437: call    dword ptr [ecx+8]
```

Player path 2:

```asm
0x1d9349e: and     eax, ecx
0x1d934a0: lea     ecx, [eax+eax*8]
0x1d934a3: shl     ecx, 3
0x1d934a6: sub     ecx, eax
0x1d934a8: lea     ecx, [ecx+ecx*2]
0x1d934ab: lea     eax, [eax+ecx*2]
0x1d934ae: mov     ecx, [edx]
0x1d934b0: lea     ebp, [eax+eax*4]
0x1d934b3: mov     eax, ecx
0x1d934b5: shl     eax, 4
0x1d934b8: add     eax, ecx
0x1d934ba: mov     ecx, off_1EA42A4
0x1d934c0: lea     edx, [eax+eax*4]
0x1d934c3: shl     edx, 2
0x1d934c6: lea     eax, unk_2DACB0C[edx+ebp*8]
0x1d934cd: push    eax
0x1d934ce: push    0
0x1d934d0: call    dword ptr [ecx+8]
```

### hl-4554 / windows

Original SHA-256: `482871315f4a713a8aa72c5e2a73092d261bacb618890a4523630e9e168eb2a3`

Analyzed `engine/hw.dll` SHA-256: `482871315f4a713a8aa72c5e2a73092d261bacb618890a4523630e9e168eb2a3`

Player path 1:

```asm
0x1d9f37b: and     eax, ebp
0x1d9f37d: mov     edx, [edx]
0x1d9f37f: lea     ecx, [eax+eax*8]
0x1d9f382: shl     ecx, 3
0x1d9f385: sub     ecx, eax
0x1d9f387: lea     ecx, [ecx+ecx*2]
0x1d9f38a: lea     eax, [eax+ecx*2]
0x1d9f38d: lea     ecx, [eax+eax*4]
0x1d9f390: mov     eax, edx
0x1d9f392: shl     eax, 4
0x1d9f395: add     eax, edx
0x1d9f397: lea     edx, [eax+eax*4]
0x1d9f39a: shl     edx, 2
0x1d9f39d: lea     eax, unk_2D56C2C[edx+ecx*8]
0x1d9f3a4: mov     ecx, off_1E82A7C
0x1d9f3aa: push    eax
0x1d9f3ab: push    ebx
0x1d9f3ac: call    dword ptr [ecx+8]
```

Player path 2:

```asm
0x1d9f417: and     eax, ecx
0x1d9f419: lea     ecx, [eax+eax*8]
0x1d9f41c: shl     ecx, 3
0x1d9f41f: sub     ecx, eax
0x1d9f421: lea     ecx, [ecx+ecx*2]
0x1d9f424: lea     eax, [eax+ecx*2]
0x1d9f427: mov     ecx, [edx]
0x1d9f429: lea     esi, [eax+eax*4]
0x1d9f42c: mov     eax, ecx
0x1d9f42e: shl     eax, 4
0x1d9f431: add     eax, ecx
0x1d9f433: mov     ecx, off_1E82A7C
0x1d9f439: lea     edx, [eax+eax*4]
0x1d9f43c: shl     edx, 2
0x1d9f43f: lea     eax, unk_2D56C2C[edx+esi*8]
0x1d9f446: push    eax
0x1d9f447: push    0
0x1d9f449: call    dword ptr [ecx+8]
```

### hl-6153 / windows

Original SHA-256: `5d9958f8111197f5fb22cc2a44f05239f4d5c9a48b8795f2bc287d507258a257`

Analyzed `engine/hw.dll` SHA-256: `5d9958f8111197f5fb22cc2a44f05239f4d5c9a48b8795f2bc287d507258a257`

Player path 1:

```asm
0x1d87346: and     eax, ecx
0x1d87348: mov     edx, [edx]
0x1d8734a: lea     ecx, [eax+eax*8]
0x1d8734d: shl     ecx, 3
0x1d87350: sub     ecx, eax
0x1d87352: lea     ecx, [ecx+ecx*2]
0x1d87355: lea     eax, [eax+ecx*2]
0x1d87358: lea     ecx, [eax+eax*4]
0x1d8735b: mov     eax, edx
0x1d8735d: shl     eax, 4
0x1d87360: add     eax, edx
0x1d87362: lea     edx, [eax+eax*4]
0x1d87365: shl     edx, 2
0x1d87368: lea     eax, unk_2D87C2C[edx+ecx*8]
0x1d8736f: mov     ecx, off_1E503B4
0x1d87375: push    eax
0x1d87376: push    edi
0x1d87377: call    dword ptr [ecx+8]
```

Player path 2:

```asm
0x1d873dd: and     eax, ecx
0x1d873df: lea     ecx, [eax+eax*8]
0x1d873e2: shl     ecx, 3
0x1d873e5: sub     ecx, eax
0x1d873e7: lea     ecx, [ecx+ecx*2]
0x1d873ea: lea     eax, [eax+ecx*2]
0x1d873ed: mov     ecx, [edx]
0x1d873ef: lea     ebx, [eax+eax*4]
0x1d873f2: mov     eax, ecx
0x1d873f4: shl     eax, 4
0x1d873f7: add     eax, ecx
0x1d873f9: mov     ecx, off_1E503B4
0x1d873ff: lea     edx, [eax+eax*4]
0x1d87402: shl     edx, 2
0x1d87405: lea     eax, unk_2D87C2C[edx+ebx*8]
0x1d8740c: push    eax
0x1d8740d: push    0
0x1d8740f: call    dword ptr [ecx+8]
```

### hl-8684 / windows

Original SHA-256: `be45f76049a133392423679d334c69c8e1e7e82dc873eebdd229ea0341ba1b10`

Analyzed `engine/hw.dll` SHA-256: `be45f76049a133392423679d334c69c8e1e7e82dc873eebdd229ea0341ba1b10`

Player path 1:

```asm
0x1d88cc6: and     eax, ecx
0x1d88cc8: mov     edx, [edx]
0x1d88cca: lea     ecx, [eax+eax*8]
0x1d88ccd: shl     ecx, 3
0x1d88cd0: sub     ecx, eax
0x1d88cd2: lea     ecx, [ecx+ecx*2]
0x1d88cd5: lea     eax, [eax+ecx*2]
0x1d88cd8: lea     ecx, [eax+eax*4]
0x1d88cdb: mov     eax, edx
0x1d88cdd: shl     eax, 4
0x1d88ce0: add     eax, edx
0x1d88ce2: lea     edx, [eax+eax*4]
0x1d88ce5: shl     edx, 2
0x1d88ce8: lea     eax, unk_2D8B14C[edx+ecx*8]
0x1d88cef: mov     ecx, off_1E5330C
0x1d88cf5: push    eax
0x1d88cf6: push    edi
0x1d88cf7: call    dword ptr [ecx+8]
```

Player path 2:

```asm
0x1d88d5d: and     eax, ecx
0x1d88d5f: lea     ecx, [eax+eax*8]
0x1d88d62: shl     ecx, 3
0x1d88d65: sub     ecx, eax
0x1d88d67: lea     ecx, [ecx+ecx*2]
0x1d88d6a: lea     eax, [eax+ecx*2]
0x1d88d6d: mov     ecx, [edx]
0x1d88d6f: lea     ebx, [eax+eax*4]
0x1d88d72: mov     eax, ecx
0x1d88d74: shl     eax, 4
0x1d88d77: add     eax, ecx
0x1d88d79: mov     ecx, off_1E5330C
0x1d88d7f: lea     edx, [eax+eax*4]
0x1d88d82: shl     edx, 2
0x1d88d85: lea     eax, unk_2D8B14C[edx+ebx*8]
0x1d88d8c: push    eax
0x1d88d8d: push    0
0x1d88d8f: call    dword ptr [ecx+8]
```

### hl-8684 / linux

Original SHA-256: `1e775773292407106ac17c98bc19f0444e8f1525d46e592de5cc53afad2b89e1`

Analyzed `engine/hw.so` SHA-256: `1e775773292407106ac17c98bc19f0444e8f1525d46e592de5cc53afad2b89e1`

Player path 1:

```asm
0x200d10: and     eax, ecx
0x200d12: imul    eax, 42B8h
0x200d18: lea     eax, (m1.max_edicts+2AFBCh)[eax+edx*4]
0x200d1f: mov     [esp+3Ch+var_38], eax
0x200d23: mov     eax, pStudioAPI
0x200d28: call    dword ptr [eax+8]
```

Player path 2:

```asm
0x200e27: and     eax, ebp
0x200e29: imul    eax, 42B8h
0x200e2f: lea     eax, (m1.max_edicts+2AFBCh)[eax+edx*4]
0x200e36: mov     [esp+3Ch+var_38], eax
0x200e3a: mov     eax, pStudioAPI
0x200e3f: call    dword ptr [eax+8]
```

### hl-10210 / windows

Original SHA-256: `9ba9a2db5e07598fd59afa35507a98c86162e4e15b3835177b78c11842cd2295`

Analyzed `engine/hw.dll` SHA-256: `9ba9a2db5e07598fd59afa35507a98c86162e4e15b3835177b78c11842cd2295`

Player path 1:

```asm
0x101fab9d: and     eax, dword_11282A84
0x101faba3: imul    ecx, eax, 4318h
0x101faba9: imul    eax, [esi], 154h
0x101fabaf: lea     eax, unk_11282DCC[eax]
0x101fabb5: add     eax, ecx
0x101fabb7: push    eax
0x101fabb8: mov     eax, off_1031C0F0
0x101fabbd: push    3
0x101fabbf: mov     eax, [eax+8]
0x101fabc2: call    eax
```

Player path 2:

```asm
0x101fac16: and     eax, dword_11282A84
0x101fac1c: imul    ecx, eax, 4318h
0x101fac22: imul    eax, [edx], 154h
0x101fac28: lea     eax, unk_11282DCC[eax]
0x101fac2e: add     eax, ecx
0x101fac30: push    eax
0x101fac31: mov     eax, off_1031C0F0
0x101fac36: push    0
0x101fac38: mov     eax, [eax+8]
0x101fac3b: call    eax
```

### hl-10210 / linux

Original SHA-256: `fca6628b5a4d76a945e11b9796f327004edc65420d9f9cc23f883143508edd78`

Analyzed `engine/hw.so` SHA-256: `fca6628b5a4d76a945e11b9796f327004edc65420d9f9cc23f883143508edd78`

Player path 1:

```asm
0x1b0df0: and     eax, ecx
0x1b0df2: imul    eax, 4318h
0x1b0df8: lea     eax, nMax.frames.playerstate.entityType[eax+edx*4]
0x1b0dff: mov     [esp+3Ch+var_38], eax
0x1b0e03: mov     eax, pStudioAPI
0x1b0e08: call    dword ptr [eax+8]
```

Player path 2:

```asm
0x1b1047: and     eax, ebp
0x1b1049: imul    eax, 4318h
0x1b104f: lea     eax, nMax.frames.playerstate.entityType[eax+edx*4]
0x1b1056: mov     [esp+3Ch+var_38], eax
0x1b105a: mov     eax, pStudioAPI
0x1b105f: call    dword ptr [eax+8]
```

### svencoop-10257 / windows

Original SHA-256: `e3c7f374b70845fb6f45c05906e4b5fe3dc9f394ab37bb653501d3b6a3282596`

Analyzed `engine/hw.dll` SHA-256: `e3c7f374b70845fb6f45c05906e4b5fe3dc9f394ab37bb653501d3b6a3282596`

Player path 1:

```asm
0x1d933ae: and     eax, cl_parsecount
0x1d933b4: imul    ecx, eax, 8518h
0x1d933ba: imul    eax, [ebx], 154h
0x1d933c0: lea     eax, unk_234B93C[eax]
0x1d933c6: add     eax, ecx
0x1d933c8: push    eax
0x1d933c9: mov     eax, off_1EE297C
0x1d933ce: push    3
0x1d933d0: mov     eax, [eax+8]
0x1d933d3: call    eax
```

Player path 2:

```asm
0x1d9343c: and     eax, cl_parsecount
0x1d93442: imul    ecx, eax, 8518h
0x1d93448: imul    eax, [edx], 154h
0x1d9344e: lea     eax, unk_234B93C[eax]
0x1d93454: add     eax, ecx
0x1d93456: push    eax
0x1d93457: mov     eax, off_1EE297C
0x1d9345c: push    0
0x1d9345e: mov     eax, [eax+8]
0x1d93461: call    eax
```

### svencoop-10257 / linux

Original SHA-256: `8cead76a51204a4ba1036c85cc2099b7c3542950d924846a9aa2ccf619df7dfd`

Analyzed `engine/hw.so` SHA-256: `8cead76a51204a4ba1036c85cc2099b7c3542950d924846a9aa2ccf619df7dfd`

Player path 1:

```asm
0x17e5e7: and     edx, [esi]
0x17e5e9: mov     [esp+5Ch+cap], 3
0x17e5f0: imul    esi, edx, 8518h
0x17e5f6: mov     edx, [esp+5Ch+var_44]
0x17e5fa: lea     eax, [esi+eax+2427BCh]
0x17e601: add     edx, eax
0x17e603: mov     [esp+5Ch+pname], edx
0x17e607: call    dword ptr [ecx+8]
```

Player path 2:

```asm
0x17e6e5: and     ecx, [eax]
0x17e6e7: imul    eax, ecx, 8518h
0x17e6ed: mov     ecx, [esp+5Ch+var_2C]
0x17e6f1: mov     ecx, [ecx]
0x17e6f3: mov     [esp+5Ch+cap], 0
0x17e6fa: dec     ecx
0x17e6fb: imul    ecx, 154h
0x17e701: lea     eax, [eax+ecx+2427BCh]
0x17e708: mov     ecx, [esp+5Ch+var_44]
0x17e70c: mov     [esp+5Ch+var_44], edx
0x17e710: add     eax, ecx
0x17e712: mov     [esp+5Ch+pname], eax
0x17e716: mov     eax, [edx]
0x17e718: call    dword ptr [eax+8]
```

### cof-5936 / windows

Original SHA-256: `9dd34e536c4bb7cda3bc1bc4f0f5f6163687566a16f35c0ea0be59f93da62875`

Analyzed `engine/hw.dll` SHA-256: `9dd34e536c4bb7cda3bc1bc4f0f5f6163687566a16f35c0ea0be59f93da62875`

Player path 1:

```asm
0x1dc4786: and     eax, dword_1EAE664
0x1dc478c: imul    eax, 42C0h
0x1dc4792: mov     ecx, dword_2C0E4BC
0x1dc4798: mov     edx, [ecx]
0x1dc479a: sub     edx, 1
0x1dc479d: imul    edx, 154h
0x1dc47a3: lea     eax, unk_2E11A48[eax+edx]
0x1dc47aa: push    eax
0x1dc47ab: push    3
0x1dc47ad: mov     ecx, off_1EC5BFC
0x1dc47b3: call    dword ptr [ecx+8]
```

Player path 2:

```asm
0x1dc4834: and     edx, dword_1EAE664
0x1dc483a: imul    edx, 42C0h
0x1dc4840: mov     eax, dword_2C0E4BC
0x1dc4845: mov     ecx, [eax]
0x1dc4847: sub     ecx, 1
0x1dc484a: imul    ecx, 154h
0x1dc4850: lea     edx, unk_2E11A48[edx+ecx]
0x1dc4857: push    edx
0x1dc4858: push    0
0x1dc485a: mov     eax, off_1EC5BFC
0x1dc485f: call    dword ptr [eax+8]
```

## Existing-output comparison

All pre-existing materialized YAML files were compared byte-for-byte. The sole difference is the user-approved Sven Linux cl_parsecount correction: old 0x2F1654 is CL_UPDATE_MASK (initialized to 63); current client base 0x15D7D60 plus member 0x242324 gives 0x181A084. Loads 0x17E5D4 and 0x17E6DF feed the masked index; parser store 0xFEEB5 confirms the mutable member.

The new GV artifact selects instruction 0x17E5D4 (length 6, disp 2), with gv_pic_addend=0x15D7D60. Its existing function-root signature is unique. No new GV schema was introduced. All other cl_parsecount artifacts are byte-identical.
