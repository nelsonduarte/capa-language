# Wasm capability handle tables, architecture (slice 25, 2026-05-30)

> **STATUS: RESOLVED (historical record).** The cap-attenuation bug
> described below has been fixed: handle tables shipped, and
> capability attenuation is now sound on the Wasm backend (restriction
> state travels with the handle across function boundaries, matching
> the Python backend). This document is kept as the design record for
> how the fix was reasoned out; it does not describe a live defect.
> The follow-up section immediately below records a SECOND defect, in
> how a root handle reached a `main` slot, found and closed on
> 2026-07-23.

## Follow-up: how a root handle reaches a `main` slot (2026-07-23)

Point 5 above ("`main`'s cap params are root handles, allocated by the
host at instance init") left one question open, and slices 25.2-25.8
answered it the cheap way: the host matched the parameter's NAME,
lowercased, against `{fs, net, db, proc, env, clock}`, and used the
`Fs` root for anything that missed.

That is a strictly weaker guarantee than the handle table it feeds.
The handle table makes attenuation travel with the value; the binding
decided which value a slot started from by reading an identifier out
of the WebAssembly debug `name` custom section. Three consequences,
all reproduced, all exiting 0:

- `fun main(conn: Net, stdio: Stdio)` got the `Fs` root, so
  `conn.allows("example.com")` answered `true` on Python and `false`
  on `--wasm`.
- `fun main(net: Fs, ...)` got the `Net` root because of how the
  parameter was spelled.
- `wasm-tools strip --all` deletes the `name` section, after which
  every slot fell to `Fs`.

Capa's claim is that the type is the contract and the capability is in
the signature. That does not survive a binding decided by a strippable
string.

The binding is now derived from the DECLARED capability type, in
declaration order, and is carried where two separate classes of
tampering cannot reach it:

| path | carrier | section |
| --- | --- | --- |
| core module (`WasmHost`) | export NAME of an immutable global, `capa:main-cap-types=net,fs` | export section (id 7) |
| component (`WasmComponentHost`) | slot labels `cap<N>-<kind>` in the exported world | component type |
| AOT container | `main_cap_types` in the header, copied from the `.wasm` at build time | container header |

Two criteria drove that choice, not one:

1. **It must survive normal tooling.** A custom section does not: a
   strip removes it, which is how the third consequence above arose.
2. **The running program must not be able to reach it.** Lehmann,
   Kinder and Pradel ("Everything Old is New Again: Binary Security of
   WebAssembly", USENIX Security 2020, section 4.2.3) show that data a
   compiler treats as constant is routinely writable once it lives in
   linear memory. So the binding is in no data segment: an export name
   is not addressable by any Wasm instruction, and the global it hangs
   off is immutable and never read. Capa is memory-safe, so this is
   not a threat from Capa code; it matters at the foreign-component
   boundary, where a module Capa did not compile shares the address
   space.

There is **no fallback and no compatibility mode**. A slot whose
capability the host cannot determine grants nothing, and the artifact
is refused before it is instantiated, so a module with a `start`
function does not get to run first. An artifact that predates the
binding is refused for the same reason: accepting it would mean
reinstating the name matching, which is the vulnerability. The
encoding and its inverse live in
[`capa/ir/_cap_binding.py`](../../capa/ir/_cap_binding.py) so the two
emitters and the two hosts cannot drift; the tests are
[`tests/test_wasm_cap_binding.py`](../../tests/test_wasm_cap_binding.py).

### What contains a binding that IS forged

Rewriting the binding in an artifact you already control is not an
escalation on its own: every kind it can name hands the slot a root of
the wrong TYPE, and `CapHandleTable.lookup(handle, Fs)` then refuses
every op on it. The typed lookup, not the binding, is the wall.

That only holds where the bridges consult it. Three did not
(`now_secs`, `now_monotonic`, `env_args`, on both hosts): they
performed the lookup and discarded the result, each under a comment
claiming a bad handle failed loudly there. With the binding rewritten
so an `Env` slot held the `Fs` root, `env.args()` returned the real
process argv, exit 0, no diagnostic, while `fs.allows` on the same run
correctly answered `false`. They now use `_require_receiver`, which
raises, and `TestEveryBridgeRequiresItsReceiver` fails if a fourth
appears.

### What this does NOT give you

This work delivers three properties and no more: the binding follows
the declared TYPE, it is not carried anywhere ordinary tooling strips
or the guest can write, and it cannot be silently defaulted.

It does **not** deliver WASI's "handles are unforgeable, no ambient
authorities", and an earlier draft of this section wrongly implied it
did. Handles remain small sequential integers a guest can name by
writing the integer down. Two consequences pre-dated this change and
were out of its scope; they are in different states today.

- **Cross-capability forgery is now closed (2026-07-31).** Until then,
  `WasmHost`'s linker defined every `capa:host/*` import regardless of
  what the artifact declared AND the per-instance handle table was
  bootstrapped with a root for every handle-bearing cap, so a
  hand-written module declaring only `net` could call
  `capa:host/fs.exists(2, ".")` with the integer the Fs root was
  deterministically assigned and read the filesystem. Confirmed against
  `6321246` as well, so it is not a regression from this work.
  `b5d3514` closes it by bootstrapping the table with ONLY the declared
  caps' roots (`bootstrap_root_handles(..., declared=cap_types)` in
  [`capa/runtime/_cap_handles.py`](../../capa/runtime/_cap_handles.py)).
  The linker is deliberately unchanged: the imports are still all
  defined, but a forged integer for an UNDECLARED cap now resolves to
  no entry, or to the wrong-type entry a declared cap occupies, and
  fails the typed handle-table lookup, so the privileged op denies at
  the call. The declared capability set is therefore a runtime-enforced
  UPPER BOUND on the authority the artifact can exercise, on all three
  hosts: the core `--run --wasm` host, the AOT `capa run-aot` path, and
  the Component host. Mechanized on all three in
  `TestUndeclaredCapabilityHasNoRoot` in
  [`tests/test_wasm_cap_binding.py`](../../tests/test_wasm_cap_binding.py),
  with the bootstrap-omission unit in
  [`tests/test_cap_handles.py`](../../tests/test_cap_handles.py).

- **Intra-capability widening is still open.** Root handles and their
  `restrict_to` children are still predictable integers, so within a
  cap it DECLARED a guest can name the unrestricted root of that cap
  instead of an attenuated child. This is not a cross-cap escalation:
  it is authority the artifact already holds by declaring the cap, and
  on the single-artifact core path there is no in-instance trust
  boundary to escalate across. Full handle UNFORGEABILITY (unguessable
  tokens, or a Component-Model resource-type migration) remains
  separate, deferred, tracked work.

Two honest caveats on the cross-cap fix. It restores the HONESTY of the
declared / SBOM cap set (the imports an artifact can exercise can no
longer exceed its declaration); it does not turn `capa run-aot` into a
sandbox for untrusted artifacts. The `capa:main-cap-types` binding is
the artifact's own, freely editable self-declaration, and there is no
operator-supplied cap allowlist on `run-aot`, so a malicious artifact
may simply declare all six caps and receive all six roots. Operator
cap-allowlisting is a separate, open, undecided question. The executed
`.wasm` / `.cwasm` therefore stays in the TCB: its declared cap set is
trusted as its authority ceiling, and the fix makes that ceiling
ENFORCED rather than advisory, it does not remove the artifact from the
TCB.

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

- The bug is documented honestly under slice 25 (now closed; see
  `DONE.md`).
- `docs/regulatory.md` gains a paragraph: "Wasm cap discipline is sound
  intra-function only; cross-function attenuation enforcement is in
  progress (issue tracker link)".
- A new lint warning (slice 25.1) fires when `capa --wasm` compiles a
  program that crosses an attenuated cap across a function boundary,
  doesn't reject, just warns, so existing programs still compile and
  the warning surfaces the issue to operators evaluating Wasm-mode SBOMs.
