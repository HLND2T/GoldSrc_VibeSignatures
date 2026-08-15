---
name: decrypt-blob-gamebin
description: Decrypt all Non-PE Metahook "blob" game binaries under bin/ into PE32 DLLs via decrypt_blob.py. Triggered only by explicit user slash command; never auto-invoked by the model.
disable-model-invocation: true
---

# Decrypt Blob Game Binaries

Invoke `decrypt_blob.py` to convert every Metahook "blob" game binary under
`bin/` into a regular PE32 DLL. This skill is triggered **only** by an explicit
user slash command (`/decrypt-blob-gamebin`). Do not run it as an implicit step
of another task.

## Scope

- Scan `bin/` recursively across every game-version root
  (`bin/hl-3266/`, `bin/hl-3329/`, `bin/hl-3647/`, ...).
- Process **only** Non-PE Metahook blob game binaries: files that are not valid
  PE/ELF and carry the blob `0x12345678` algorithm marker.
- Skip valid PE/ELF binaries, `.i64` IDA databases, `.yaml` artifacts, any
  other non-blob file, and already-decrypted outputs (`*.decrypt.*`, e.g.
  `hw.decrypt.dll`).

## Output naming

Write the decrypted PE next to its blob source, inserting `.decrypt` before the
final extension:

- `bin/hl-3266/engine/hw.dll` → `bin/hl-3266/engine/hw.decrypt.dll`
- General rule: `<stem>.<ext>` → `<stem>.decrypt.<ext>`

## Steps

### 1. Discover the blob files

Classify candidates with the repo's own parser so only true blobs are processed.
From the repository root:

```powershell
uv run python -c "
import sys; sys.path.insert(0, '.')
from pathlib import Path
import decrypt_blob
for p in sorted(Path('bin').rglob('*')):
    if not p.is_file():
        continue
    if '.decrypt.' in p.name:
        continue  # already-decrypted output, not a blob
    try:
        decrypt_blob.parse_blob(p.read_bytes())
    except Exception:
        continue
    print(p)
"
```

Every printed path is a confirmed blob.

### 2. Decrypt each blob

For each confirmed blob `<input>` under `bin/`, derive the output path with the
naming rule above and invoke `decrypt_blob.py` directly:

```powershell
uv run python decrypt_blob.py <input> <output>
```

Example:

```powershell
uv run python decrypt_blob.py bin/hl-3266/engine/hw.dll bin/hl-3266/engine/hw.decrypt.dll
```

### 3. Verify

- Each invocation must print `wrote <output>` and exit 0.
- A non-zero exit with `error: not a Metahook blob` means the file was
  misclassified; re-check the discovery step for that path.
- Spot-check one output with the repo's PE validator:

```powershell
uv run python -c "from binary_format import inspect_binary; print(inspect_binary('<output>'))"
```

Expect `platform='windows', container='PE', bits=32, machine='I386'`.

## Notes

- `bin/` is gitignored; decrypted outputs there are analysis artifacts and must
  not be staged.
- Never overwrite the source blob in place; always use the `.decrypt` output name.
