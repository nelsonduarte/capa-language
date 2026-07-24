# Capa, TODO (pending work)

> **Convention.** When an item here is completed, it moves to the top of
> the matching section of [`DONE.md`](DONE.md) with its completion date
> (`YYYY-MM-DD`). `DONE.md` is the internal task record (distinct from
> [`CHANGELOG.md`](CHANGELOG.md), which records user-facing releases).
> This file holds only what is still open; everything already shipped
> lives in [`DONE.md`](DONE.md).

Compiler at **v1.21.0** (released 2026-07-24). Suite green (~4796 tests),
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

- **Native backend (additive future axis, gated).** A native backend
  with Rust/Go-level performance is an additive future axis: it sits
  underneath the security mission (capabilities + IFC + SBOM stay the
  priority) and removes an adoption objection rather than redefining the
  project. It stays future work, conditioned on a concrete driver. The
  honesty of the feasibility doc stands: a from-scratch native backend is
  an arc of many months, and the gate to start the backend proper remains
  a concrete driver (a perf-bound consumer the Wasm-AOT path provably
  cannot serve, a hard native-FFI requirement, or a target with no
  acceptable Wasm runtime). The phased execution plan (the "how", as
  opposed to the feasibility doc's "if / when / how much") lives in
  `docs/design/native-backend-plan.md`, which marks **Phase 0
  (prerequisites) and Phase 1 (spike) as AUTHORISED to start as
  background work that also benefits the Wasm backend**, decides Phase 2
  after their results, and keeps Phases 3+ gated on a driver.
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
  authorised as Wasm-benefiting background work and the rest gated).
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
- **Root-manifest refusal is an outcome, not a single seam.** The build
  path reads the root `capa.toml` through `capa.pkg.read_root_manifest`,
  which refuses a manifest it cannot parse (v1.19.0,
  [advisory](docs/advisories/2026-07-20-capa-floor.md)). Three
  package-management reads stay outside it (`capa/pkg/_add.py`,
  `capa/pkg/_install.py`, `capa/testrunner.py`) and each refuses through
  its own `except ManifestError`. Nothing fails open today, and a
  structural test stops the old `except Exception` returning, but a
  future read added without a handler would not be caught by the seam.
  The cure is to route the three through the seam, or to assert
  structurally that every root-manifest read has a handler.
- **The loader's manifest read is cwd-scoped while the floor gate is
  root-scoped.** `_capa_search_paths` and `_capa_dependency_roots` in
  `capa/cli.py` both read `Path.cwd() / "capa.toml"`, so the root
  manifest is authoritative for module resolution only when the build
  runs FROM the project root. The floor / broken-manifest gate resolves
  its root with `find_package_root`, an ancestor walk, precisely because
  `Path.cwd()` was wrong there (v1.19.0). Building from a subdirectory
  therefore still resolves imports with no declared `path` mapping and
  no `./vendor` root, which is the same defect class the
  [advisory](docs/advisories/2026-07-20-capa-floor.md) is named for: a
  declared dependency stops being authoritative and a same-named
  directory on the search path can satisfy the import instead.
  Pre-existing rather than a v1.19.0 regression, and not a floor bypass
  (the floor is enforced from a subdirectory, verified). The cure is to
  give both functions the same ancestor walk the gate uses, which also
  removes the last disagreement about what "the project root" means.
- **Fs hardlink `st_nlink`.** A hard link created in-prefix to an
  out-of-prefix file passes the checks.
- **Db post-open TOCTOU.** Narrow residual window; `sqlite3` does not
  accept a pre-opened file descriptor.
- **IFC C-2 residual.** The two-hop closure-by-name laundering is now
  caught for a closure bound to a single-assignment `let` / `var` that
  denotes one lambda literal (closed in v1.15.0). The remaining documented
  false negatives are a `@secret` closure borne in a STRUCT FIELD, a `Fun`
  PARAMETER re-passed onward, a binding whose RHS is not a lambda literal
  (e.g. a call result), or ANY `var` that is ever reassigned, then passed
  by name cross-function.
- **IFC flow-insensitivity on reassignment.** Conservative, never
  unsound.
- **Security M3.** `install.sh` same-channel SHA pinning, deferred by
  design.
