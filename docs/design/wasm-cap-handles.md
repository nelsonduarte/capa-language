# Wasm capability handle tables, architecture (slice 25, 2026-05-30)

> **STATUS: RESOLVED (historical record).** The cap-attenuation bug
> described below has been fixed: handle tables shipped, and
> capability attenuation is now sound on the Wasm backend (restriction
> state travels with the handle across function boundaries, matching
> the Python backend). This document is kept as the design record for
> how the fix was reasoned out; it does not describe a live defect.

## Problem (audit slice 25 F1)

Capa's regulator-facing pitch, "the manifest's `provably_excluded_capabilities`
is a hard claim by construction", is **broken on the Wasm backend** whenever a
restricted capability crosses any function boundary. The current Wasm emitter
inlines `restrict_to(...)` checks as `$str_contains` / path-prefix WAT at the
**literal call site** in the **same function**. The moment the cap is passed as
an argument to another `fun`, the receiving function sees a "plain" cap, the
emitter has no information about prior attenuations, and the host bridge
executes the syscall unconditionally.

Five caps confirmed exploitable from real Capa source (Fs, Db, Proc, Env,
Clock) with one-function-hop reproducers; Net is exploitable in principle but
needs a controlled DNS responder to demonstrate end-to-end. Component Model
host has the same bug.

The Python backend is sound, caps are first-class objects, restriction state
travels with the value through every call.

## Reach

Every downstream demo using `restrict_to(...)` then passing the cap to a
helper is affected on `--wasm`:

- `audit-trail-reporter/reporter.capa:257-262` (read_fs, write_fs → `run(...)`)
- `policy-eval/policy_eval.capa:180-185` (same pattern)
- `sbom-watch/watch.capa:207-212` (same pattern)

The gov pack happens to do its single attenuation inline (one function), so it
is not exploited today.

## Architecture: capability handle tables

Adopt the only design that preserves soundness without restricting program
shape:

1. **Cap values on Wasm become i32 handles** (currently erased entirely).
2. **Host-side handle table** maps each handle to a Python-side
   `CapRestriction` object holding the actual allowed set / prefix / etc.
3. **Allocation imports** (`capa:host/<cap>.restrict-to`, etc.) take an input
   handle + the restriction argument, allocate a new restriction (intersection
   with the parent), and return a new handle.
4. **Privileged op imports** (`fs.read`, `net.get`, ...) take the cap handle
   as their first argument, look up the restriction, enforce it, then perform
   the syscall.
5. **`main`'s cap params** are root handles, allocated by the host at instance
   init and passed to `main` along with the user args.
6. **Cap-typed function params + struct fields + closure captures** become
   `i32` slots throughout the CIR → Wasm pipeline (un-erase them).

### Handle lifecycle

- Handles are immutable. `restrict_to(...)` never mutates the source handle;
  it returns a fresh one bound to a new restriction object.
- Handle table grows monotonically per instance. Sticky handles are fine,
  Wasm program lifetime is short (one CLI invocation in the common case);
  long-running deployments will need GC, tracked as a future P3.
- Handle `0` is reserved (sentinel for "no cap"); root handles start at `1`.

### Per-cap restriction classes (Python-side)

These already exist in `capa/runtime/_capabilities.py`: the existing `Fs`,
`Net`, `Db`, `Proc`, `Env`, `Clock` classes hold exactly the restriction state
the table needs. The handle table reuses those classes verbatim; the table is
just `dict[int, Fs | Net | Db | ...]`. No new restriction logic to write.

### What the inline attenuation emitter does after the migration

The inline `restrict_to → $str_contains / path-prefix` machinery in
`capa/ir/_emit_wasm/_caps.py` becomes obsolete for soundness. It can be:

- Removed entirely (preferred, less code, single enforcement point).
- Kept as a fast-path optimisation that skips the host round-trip when the
  attenuation chain is fully literal and in the same function (a measurable
  win for tight loops, defer to a later perf slice).

For the rollout we **remove** the inline machinery. Programs that previously
relied on it now get the same enforcement via the host bridge. Measured
overhead per call: one Python-side dict lookup + the existing restriction
check. Negligible relative to the syscall itself.

### Side benefit: fixes F2 too

The Wasm Net inline check today uses `$str_contains(url, host)`: a substring
match anywhere in the URL, not a parsed-hostname equality check. F2 is a
direct consequence of the inline approach (the emitter can only do
byte-level scans). Routing through the host bridge means `Net.allows(url)`
runs the existing `urlparse(url).hostname` Python logic, which already does
the right thing. F1 and F2 both close in the same rollout.

## File impact map

The migration touches ~10 files. Phased rollout, one cap at a time:

### Foundation (slice 25.1, this slice)

- `capa/runtime/_cap_handles.py` (NEW, ~150 LOC), `CapHandleTable` class,
  per-cap allocation helpers, root-handle bootstrap.
- Tests for the table itself (handle allocation, lookup, intersection).

### Fs rollout (slice 25.2)

- `capa/runtime/_wasm_host.py`: add Fs handle imports, modify privileged Fs
  ops to take handle.
- `capa/ir/_emit_wasm/_caps.py`: Fs method lowering passes handle, removes
  inline path-prefix check.
- `capa/ir/_emit_wasm/_locals.py`, `_closures.py`, `_dispatch.py`,
  `_traits.py`, `_discovery.py`: Fs param/capture/field becomes i32.
- `capa/ir/_emit_wit.py`: Fs WIT signatures grow a `handle: u32` first
  param.
- Cross-function reproducer becomes a parity test that DENIES on both
  backends.

### Net rollout (slice 25.3)

- Same shape as Fs.
- F2 closes incidentally (host bridge uses parsed hostname).

### Db / Proc / Env / Clock rollouts (slices 25.4 – 25.7)

- Same shape per cap.

### Component Model parity (slice 25.8)

- `capa/runtime/_wasm_component_host.py`: mirror the core-host changes.
- Verify component-model parity tests still pass.

### Cleanup (slice 25.9)

- Remove inline-attenuation emitter machinery once all caps are migrated.
- Update positioning docs to reflect that Wasm now matches Python on
  cap-discipline soundness.
- Add an explicit `tests/test_cap_handles_cross_function.py` parity suite
  exercising every cap × every cross-function pattern.

## Stopgap before the rollout completes

Until slices 25.2–25.8 land:

- The bug is documented honestly in `TODO.md` under slice 25.
- `docs/regulatory.md` gains a paragraph: "Wasm cap discipline is sound
  intra-function only; cross-function attenuation enforcement is in
  progress (issue tracker link)".
- A new lint warning (slice 25.1) fires when `capa --wasm` compiles a
  program that crosses an attenuated cap across a function boundary,
  doesn't reject, just warns, so existing programs still compile and
  the warning surfaces the issue to operators evaluating Wasm-mode SBOMs.
