# Capa, TODO (pending work)

> **Convention.** When an item here is completed, it moves to the top of
> the matching section of [`DONE.md`](DONE.md) with its completion date
> (`YYYY-MM-DD`). `DONE.md` is the internal task record (distinct from
> [`CHANGELOG.md`](CHANGELOG.md), which records user-facing releases).
> This file holds only what is still open; everything already shipped
> lives in [`DONE.md`](DONE.md).

Compiler at **v1.10.0** (released 2026-06-22). Suite green (3109 tests),
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
- **Wasm performance.** The bump allocator is O(n^2) on string concat in a
  loop; `parse_json` costs O(n) handles per document. Only material with
  large payloads.

## Long term (gated, do NOT start without a concrete driver)

- **Native LLVM backend.** Gate: a perf-bound consumer the Wasm-AOT path
  provably cannot serve, or native FFI. See
  `docs/design/llvm-backend-feasibility.md`.
- **Async/await.** Triple gate: a real I/O-bound workload, GC, and the
  appetite to reopen the noninterference proof. See
  `docs/design/async-feasibility.md`.
- **Parked.** GC beyond CPython's, self-hosting, macros / syntax
  extensions, quantitative capabilities, refinement types, turbofish.

## Known technical residuals (documented limitations, low priority)

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
