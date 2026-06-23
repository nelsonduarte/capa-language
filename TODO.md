# Capa, TODO (pending work)

> **Convention.** When an item here is completed, it moves to the top of
> the matching section of [`DONE.md`](DONE.md) with its completion date
> (`YYYY-MM-DD`). `DONE.md` is the internal task record (distinct from
> [`CHANGELOG.md`](CHANGELOG.md), which records user-facing releases).
> This file holds only what is still open; everything already shipped
> lives in [`DONE.md`](DONE.md).

Compiler at **v1.10.0** (released 2026-06-22). Suite green (3127 tests),
CI green. Items are grouped by time horizon, not by an internal priority
code.

---

## Short term (consolidation)

## Medium term (prove the value)

- **Make Python/Wasm parity universal.** Lift it beyond the
  `_PARITY_PROGRAMS` subset (every program runs identically on both
  backends, not just the registered set). GAP-2b (dynamic-prefix
  `.allows()` attenuation) closed in v1.6.0.
- **Paper -> LaTeX.** Draft v1.9 is local-only; LaTeX conversion targets
  a 2027 venue submission.
- **Debugger: DAP adapter + per-expression source maps.** Statement-level
  source maps + caret snippets already ship; the stepping adapter and
  sub-expression granularity remain open.

## Long term (gated, do NOT start without a concrete driver)

- **Native backend (declared future direction).** Evolving Capa toward a
  native backend with Rust/Go-level performance is the declared future
  direction, not merely an optional gated item. The honesty of the
  feasibility doc stands: a from-scratch native backend is an arc of many
  months, and the gate to start the backend proper remains a concrete
  driver (a perf-bound consumer the Wasm-AOT path provably cannot serve,
  a hard native-FFI requirement, or a target with no acceptable Wasm
  runtime). The phased execution plan (the "how", as opposed to the
  feasibility doc's "if / when / how much") lives in
  `docs/design/native-backend-plan.md`, which marks **Phase 0
  (prerequisites) and Phase 1 (spike) as AUTHORISED to start**, decides
  Phase 2 after their results, and keeps Phases 3+ gated on a driver.
  What is actionable in the near future are the low-risk prerequisites
  the feasibility doc section 5.3 already flags as "do independently
  first, benefits Wasm too" (Phase 0 of the plan):
  - Refactor `_layout.py` to be parameterised by pointer width and
    alignment (32 vs 64 bit). The Wasm backend consumes it too, and
    doing it in isolation de-risks the largest regression surface.
  - Tighten CIR type resolution so the native ABI no longer depends on
    the `_layout.py` "default unknown to Int" fallback.
  - Decide the memory-management strategy (bump-on-mmap first, then
    refcounting, the honest staged answer).
  These three are the near-future actionable steps; the backend proper
  stays gated on a driver. The Map O(N^2) and the bump-allocator
  doubling leak in "Known technical residuals" below are the Wasm-runtime
  limitations whose structural cure this backend (a real allocator / GC)
  is meant to deliver. See `docs/design/llvm-backend-feasibility.md`
  (sections 5.3 and 6 for the prerequisites and the gate; the doc weighs
  llvmlite vs textual `.ll` vs Cranelift-direct without deciding, and
  that toolchain choice is left open here too) and
  `docs/design/native-backend-plan.md` (the phased "how", with Phase 0+1
  authorised and the rest gated).
- **Async/await.** Triple gate: a real I/O-bound workload, GC, and the
  appetite to reopen the noninterference proof. See
  `docs/design/async-feasibility.md`.
- **Parked.** GC beyond CPython's, self-hosting, macros / syntax
  extensions, quantitative capabilities, refinement types, turbofish.

## Known technical residuals (documented limitations, low priority)

- **Wasm `Map<K,V>` is a linear array of pairs.** On the Wasm backend a
  Map is stored as a flat array of key/value pairs with a linear scan,
  so `get` / `set` / `contains_key` are O(N) and building a Map of N
  keys is O(N^2). The Python backend uses a native dict (O(1)). It is
  imperceptible for Maps with tens to hundreds of keys and only matters
  for a single Map holding thousands of keys; the semantics (insertion
  order, overwrite in place) are identical on both backends. Documented
  for the user in `docs/stdlib.md`. The structural cure (an O(1) hash
  map backed by a real allocator) belongs to the future native backend,
  not a hand-written WAT hash table in a backend that is not the
  performance destination.
- **Wasm bump allocator leaks on doubling.** The Wasm runtime uses a
  bump allocator with no `free`, so any array that grows by doubling
  (List / Map / Set, and the concat fallback) leaks the previous buffer
  at each doubling. This is harmless for short CLI runs (the wasm
  instance is torn down and linear memory vanishes) and is the same
  no-free limitation the layout/GC discussion in
  `docs/design/llvm-backend-feasibility.md` (sections 2.4, 5.3) tracks.
  The structural fix (a real allocator with reclamation, refcounting,
  or GC) belongs to the future native backend, linked from the native
  backend entry above.
- **Selective import is not scoped to the importing module.** A
  selective `import foo (a, b)` is implemented by mangling `foo`'s
  unselected `pub` symbols *in place* on the parsed-and-cached module
  AST, in a single flat global scope. The mangled AST is then shared by
  every other module that imports the same `foo` (whole, or with a
  different selection), so one importer's selection leaks into the
  others and the visible surface would be order-dependent. The loader
  guard that *rejects* mixing selective and whole-module (or two
  divergent selective) imports of the same module is the correct
  stopgap: it refuses the divergence outright (`module 'foo' imported
  twice with different selection`) rather than silently dropping a view.
  This cross-module shape (not same-root) is what `capa_claimdesk` hit
  in v1.5.2: the app selectively imported `capa_csv.model` while the
  vendored `capa_csv` lib whole-imported it; the downstream fix was to
  align on the whole-module import. The real cure is to make import
  visibility per-importer (each importer sees its own view of the
  shared module) rather than a single mutated global namespace, which
  is non-trivial module-system work. Locus: `capa/loader.py`
  (`_apply_selective_import`, the `_mangle_private_items` rename, and
  the `seen_paths` / `_cache` / `_import_sig` dedup at the top of
  `_link`). Test gap: `TestDivergentReimport` in `tests/test_loader.py`
  only covers the same-root case (both imports in one file); it does
  not exercise the cross-module shape (module A selective, module B
  whole) the claimdesk surfaced.
- **Fs hardlink `st_nlink`.** A hard link created in-prefix to an
  out-of-prefix file passes the checks.
- **Db post-open TOCTOU.** Narrow residual window; `sqlite3` does not
  accept a pre-opened file descriptor.
- **IFC C-2 residual.** A `@secret` closure bound to a `let`/field and
  then passed by name cross-function is a documented false negative.
- **IFC flow-insensitivity on reassignment.** Conservative, never
  unsound.
- **Security M3.** `install.sh` same-channel SHA pinning, deferred by
  design.
