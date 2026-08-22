---
name: init-gamebin
description: Download all Steam game depots declared in download.yaml via download_depot.py, then copy the depot binaries into bin/<tag>/<module> via copy_depot_bin.py. Triggered only by explicit user slash command; never auto-invoked by the model.
disable-model-invocation: true
---

# Init Game Binaries

Bootstrap the `depots/` and `bin/` trees for every release tag declared in
`download.yaml`. Two stages, in order:

1. **Download** every depot manifest with `download_depot.py -all`.
2. **Copy** the configured binaries from `depots/` into `bin/<tag>/<module>`
   with `copy_depot_bin.py -gamever <tag>` for each downloaded tag.

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

## Completion checklist

- [ ] `download_depot.py -all` printed `Downloaded all N tags` and exited 0.
- [ ] Every `downloads[].tag` in `download.yaml` has a matching `bin/<tag>/` tree.
- [ ] `copy_depot_bin.py -gamever <TAG> -checkonly` exits 0 for every tag.
- [ ] No `depots/` or `bin/` files were staged.
