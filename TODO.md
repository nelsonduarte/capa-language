# Capa, TODO (pending work)

> **Convention.** When an item here is completed, it moves to the top of
> the matching section of [`DONE.md`](DONE.md) with its completion date
> (`YYYY-MM-DD`). `DONE.md` is the internal task record (distinct from
> [`CHANGELOG.md`](CHANGELOG.md), which records user-facing releases).
> This file holds only what is still open; everything already shipped
> lives in [`DONE.md`](DONE.md).

Compiler at **v1.5.1** (released 2026-06-18). Suite green (3080 tests),
CI green. Items are grouped by time horizon, not by an internal priority
code.

---

## Short term (consolidation)

## Medium term (prove the value)

- **NLnet empirical study.** Analyse 10-20 real libraries and measure the
  false-negative SBOM findings avoided by construction versus heuristic
  tools. Highest-return NLnet deliverable.
- **Make Python/Wasm parity universal.** Lift it beyond the
  `_PARITY_PROGRAMS` subset: close GAP-2b (a dynamic-prefix `restrict_to`
  attenuation is not inline-enforced on Wasm).
- **M4: `verify_provenance="required"` as an option/default**, closing
  the SLSA L2 fail-open layer.
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
