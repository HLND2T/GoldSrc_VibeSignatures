---
name: init-gamebin
description: Download all Steam game depots declared in download.yaml via download_depot.py, copy the depot binaries into bin/<tag>/<module> via copy_depot_bin.py, and optionally warm their IDA databases with warmup_idb.py. Triggered only by explicit user slash command; never auto-invoked by the model.
disable-model-invocation: true
---

# Init Game Binaries

Bootstrap the `depots/` and `bin/` trees for every release tag declared in
`download.yaml`. Two stages, in order:

1. **Download** every depot manifest with `download_depot.py -all`.
2. **Copy** the configured binaries from `depots/` into `bin/<tag>/<module>`
   with `copy_depot_bin.py -gamever <tag>` for each downloaded tag.
3. **Warm** (optional, opt-in) the IDA databases of the copied binaries with
   `warmup_idb.py -gamever <tag>`.

This skill is triggered **only** by an explicit user slash command
(`/init-gamebin`). Do not run it as an implicit step of another task.

## Prerequisites

- `DepotDownloader` must be on `PATH`; `download_depot.py` invokes it as a
  subprocess.
- Steam credentials are loaded from the repo's `.env`
  (`DEPOTDOWNLOADER_STEAM_USERNAME` / `DEPOTDOWNLOADER_STEAM_PASSWORD`). If
  either is absent, DepotDownloader prompts interactively — keep the terminal
  attached. Account ownership of the target apps is not required; these depots
  are public.
- `depots/` are gitignored. Never stage downloaded or copied
  binaries.

## Steps

### 1. Download all depots

From the repository root:

```powershell
uv run python download_depot.py -all
```

This downloads every tag in `download.yaml` into `depots/<basepath>/` using the
declared `appid`/`depot`/`manifest` ids and the module `depot_{platform}`
filelists from the matching `configs/<tag>.yaml`. Each depot path is relative
to that tag's `download.yaml` `basepath`. The default `-os all-platform`
passes `-all-platforms` to DepotDownloader, fetching both Windows and Linux
binaries.

On success the script prints `Downloaded all N tags into depots.` and exits 0.
If a tag fails, it prints `Failed to download N of M tags.` and exits 1 — the
remaining copy stage must not proceed until every tag downloaded cleanly.

### 2. Copy binaries into bin/

For every `tag` listed under `downloads` in `download.yaml`, invoke
`copy_depot_bin.py` once:

```powershell
uv run python copy_depot_bin.py -gamever <TAG>
```

`copy_depot_bin.py` resolves `depot_<platform>` below the tag's declared
`basepath`, validates each source binary
(PE32 I386 for `windows`, ELF32 80386 for `linux`), and copies it to
`bin/<TAG>/<module>/<module_<platform>>` — for example
`bin/hl-8684/engine/hw.dll` or `bin/svencoop-10257/server/server.so`. Existing
targets that already validate are left untouched. The script prints
`Completed: N successful, N failed` and exits 1 if any binary failed.

If `configs/<TAG>.yaml` does not exist for a downloaded tag, report the gap and
stop — do not create or edit configs on the fly.

### 3. Verify

Re-run the copy step in check-only mode for every tag and require zero missing:

```powershell
uv run python copy_depot_bin.py -gamever <TAG> -checkonly
```

`-checkonly` exits 0 only when every configured binary for that tag is present
in `bin/<tag>/` and passes binary-format validation.

### 4. Warm IDA databases (optional)

After the copy stage is verified, **ask** the user whether to warm the IDA
databases for the tags and wait for an explicit yes/no. Warmup runs full IDA
auto-analysis on every configured binary via `warmup_idb.py` and leaves the
database beside the binary so later analysis runs under the strict
restored-database policy. It is slow and resource-heavy, so it is opt-in and
must never run implicitly.

Before asking, resolve a Python interpreter with idalib — the same probe the
warm IDB cache workflow uses:

```powershell
$pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
& $pythonExe idb_warm_worker.py --print-ida-version
```

If the probe fails or prints no version, tell the user IDB warmup is skipped and
why (no Python with idalib available), then finish without warming.

If the interpreter is available and the user agrees, run the producer once per
tag from the repository root:

```powershell
uv run python warmup_idb.py -gamever <TAG> -python "$pythonExe"
```

`warmup_idb.py` resolves `configs/<TAG>.yaml`, prepares every declared binary
exactly as analysis does (a blob-backed binary is decrypted to its sibling
`<stem>.decrypt<ext>` first), and warms each binary with a separate bare-idalib
worker process. It prints `Warmup complete: N warmed, M already warm` and exits
0; a database that already validates is skipped, so re-running is cheap and
`-force` invalidates and re-warms everything. Exit code 1 means at least one
database was not warmed — report the failing platform and do not continue to
analysis.

Do not warm a tag whose copy stage failed, and only ever pass the interpreter
probed above.

## Completion checklist

- [ ] `download_depot.py -all` printed `Downloaded all N tags` and exited 0.
- [ ] Every `downloads[].tag` in `download.yaml` has a matching `bin/<tag>/` tree.
- [ ] `copy_depot_bin.py -gamever <TAG> -checkonly` exits 0 for every tag.
- [ ] Warmup was offered with the idalib probe result stated, and run only for tags the user approved.
- [ ] `warmup_idb.py -gamever <TAG>` printed `Warmup complete:` or `nothing to do` and exited 0 for every warmed tag.
- [ ] No `depots/` or `bin/` files were staged.
