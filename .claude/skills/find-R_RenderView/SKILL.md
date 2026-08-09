---
name: find-r-renderview
description: |
  Locate the ordinary GoldSrc engine function R_RenderView in Sven Co-op 10257 Windows and Linux
  binaries by the string xref "R_RenderView: NULL worldmodel" and emit its canonical function artifact.
---

# Find R_RenderView

Run the registered `find-R_RenderView` preprocessor for the `engine` module in game version
`svencoop-10257`. The finder uses shared Pattern A and writes
`R_RenderView.{platform}.yaml` with `func_name`, `func_sig`, `func_va`, `func_rva`, and
`func_size`.

The target is an ordinary function in both `hw.dll` and `hw.so`; do not classify it as a
vfunc or require a vtable artifact.

```powershell
uv run python ida_analyze_bin.py -gamever svencoop-10257 -modules engine -skill find-R_RenderView -platform windows,linux -debug
```

Success requires one function candidate on each platform and canonical artifacts whose identity
field is `func_name: R_RenderView`.
