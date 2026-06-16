# Capa security advisory, 2026-06-16: IFC, linear-affinity, and manifest soundness fixes

> **Status.** Published with the `1.3.0` release. All five findings below
> were remediated in the hardening window between `v1.2.0` (2026-06-15)
> and `v1.3.0` (2026-06-16). Each fix tightens the static analysis so a
> program that previously compiled now produces an error (or a manifest
> that previously over-claimed an exclusion now declines to); every such
> change is claimed here under the [`STABILITY.md`](../../STABILITY.md)
> **security exception** (the same soundness-fix carve-out Rust and
> Python follow), and is therefore shipped as a **MINOR** bump, not a
> MAJOR one. The rationale is stated per finding below.

This advisory satisfies the `STABILITY.md` requirement that a security
fix changing observable behaviour without a major bump "ships with a
security advisory ... [that] states explicitly what changed and why the
change is not subject to the major-bump rule."

Affected versions: `1.2.0` and earlier on the `1.x` line.
Fixed in: `1.3.0`.
Reporter / process: internal hardening pass for the `1.3.0` release.
Channel: this advisory; cross-referenced from
[`SECURITY.md`](../../SECURITY.md) and the `1.3.0` `CHANGELOG.md` entry.

## Why these are security fixes, not breaking changes

Every finding below is a case where the analyzer (or the manifest
builder reading the analyzer) **accepted** or **affirmed** something
that violates a first-class, machine-checked Capa security property:
either information-flow control over `@secret` data, the linear /
typestate use-once discipline, or the manifest's
`provably_excluded_capabilities` claim. All three are in scope per
[`SECURITY.md`](../../SECURITY.md) ("Compilation accepts a program where
a `@secret` value reaches a public sink that the analyzer should
reject", "The `consume` qualifier is bypassed (a value is used after
consumption)", and the capability-discipline guarantees the manifest
publishes). The prior behaviour was a soundness bug, so tightening it
falls squarely under the `STABILITY.md` security exception and does not
force a major bump. No previously-rejected program is now accepted; the
direction of every change is reject-more (or claim-less), and only
programs that were already unsound, or manifests that already
over-claimed, are affected.

## Information-flow control over `@secret` (2 findings)

Capa's information-flow control is a first-class, machine-checked
security property: a `@secret` value must not reach a public sink
without an explicit `declassify`. The following two gaps let the
`@secret` label be dropped, allowing silent laundering of secret data to
public sinks even under `@strict_ifc`.

### I1. The value of a `match` / `if` expression and of a capturing closure came out public

**What changed.** The value produced by a `match`-expression or an
`if`-expression, and the result of calling a closure that captured a
`@secret` binding, came out `@public`. A `@secret` could therefore be
laundered to a public sink with no `declassify` and no warning, even
under `@strict_ifc`: routing it through a `match` / `if` value, or
through a closure that captured it, stripped the label. (A `@secret`
index laundered this way also slipped past a `@constant_time` function.)
The value of a `match` / `if` now carries the join of its branch / arm
labels and, under `@strict_ifc`, the selector's label as an implicit
flow; calling a closure that captures a `@secret` binding now yields a
`@secret` result. All-public branches and non-capturing closures stay
public (no over-tainting).

**Security impact.** Silent laundering of `@secret` data (PII, secret
indices) to public sinks, directly undermining the core guarantee that
the compiler proves `@secret` data does not reach public sinks. No
diagnostic fired, including under `@strict_ifc`.

**Exception rationale.** Exactly the in-scope IFC class `SECURITY.md`
names ("Compilation accepts a program where a `@secret` value reaches a
public sink that the analyzer should reject"). The accepted programs
were already unsound; rejecting more restores the documented discipline.
Security exception, MINOR. (Fix in commit `0b86e1f`.)

### I2. A captured-`@secret` closure passed to a HOF that invokes it and sinks the result leaked cross-function

**What changed.** A closure that captured a `@secret` binding, passed to
a higher-order function which **invoked** the closure and sent its result
to a public sink, leaked with no warning. The cross-function summary did
not mark an invoked `Fun` parameter as sink-reaching, so the flow was
invisible across the call boundary. The summary now marks an invoked
`Fun` parameter sink-reaching, and the call site flags an inline closure
argument whose result label is `@secret` (a warning by default, a hard
error under `@strict_ifc`). A closure whose body `declassify`s its
captured secret, a non-capturing closure, and a `Fun` parameter that is
stored or returned but never invoked-and-sunk are all clean (no false
positive).

**Known residual.** A closure bound to a name and then passed by
reference (rather than as an inline argument) is left for a future
iteration: a documented false **negative**, never a false positive. It
is recorded here so the boundary of the fix is explicit.

**Security impact.** The same silent `@secret`-laundering class as I1,
reached across a function boundary through a higher-order callee instead
of intra-procedurally.

**Exception rationale.** Same in-scope IFC class as I1. The accepted
programs were already unsound; closing the cross-function leak is a
soundness fix under the security exception. MINOR. (Fix in commit
`909959c`.)

## Linear / typestate affinity (1 finding)

The linear / typestate discipline gives a value an **affine, use-once**
obligation: a `linear type` value (and every typestate value, which is
linear by nature) must be consumed exactly once, and must not be used
after it is consumed. This is what makes a non-duplicable token, for
example a payment authorization that may settle only once, actually
non-duplicable.

### A1. Double-consume of a linear / typestate value via alias or captured closure

**What changed.** A linear / typestate value could be consumed twice by
**aliasing** it (`let h2 = h`, then consuming both `h` and `h2`) or by
**capturing** it in a closure that is invoked more than once (each
invocation re-consuming the captured value). Both type-checked and ran.
An aliasing `let` / `var` now **moves** the must-consume obligation onto
the new name (the source binding is poisoned, so any later use of it is a
compile error), and consuming a captured linear value is rejected exactly
as consuming a captured capability already is. A single consume through
an alias (`let h2 = h; close(h2)`) stays valid.

**Security impact.** Double-spend / use-after-consume. The use-once
guarantee was not enforced through aliasing or closure capture: the same
authorization token could be settled twice. The compiler advertised
non-duplicability it did not deliver.

**Exception rationale.** The accepted programs were exactly the class
`SECURITY.md` lists as in scope ("the `consume` qualifier is bypassed").
Rejecting them restores the documented discipline; security exception,
MINOR. (Fix in commit `0895de4`.)

## Manifest `provably_excluded_capabilities` (2 findings)

`provably_excluded_capabilities` is the manifest's machine-checkable
claim that a function provably **cannot** reach a given capability. A
false exclusion is a supply-chain soundness bug: a consumer relying on
the manifest would believe a capability is unreachable when it is not.
The reachability walk missed two ways a capability can be reached through
a hidden closure.

### M1. False exclusion via a closure stored in a struct field

**What changed.** `provably_excluded_capabilities` falsely affirmed that
a function excludes a capability when the function can in fact reach it
through a closure stored in a field of a plain (non-cap-bearing) data
struct. The reachability walk did not descend into struct fields holding
a `Fun(...)` type. A struct whose fields transitively hold a `Fun(...)`
type is now treated as unprovable, so any function whose signature
touches it downgrades its exclusion list. A struct with no `Fun` in its
fields still permits exclusion (no over-approximation).

**Security impact.** A manifest that over-claims: a capability advertised
as provably excluded was actually reachable through a closure smuggled in
a struct field. A downstream consumer trusting the SBOM's exclusion claim
would be misled about the function's authority.

**Exception rationale.** The manifest is a published, machine-checked
security artefact; a false exclusion is a soundness bug in the
capability-discipline guarantees it makes. Declining the false claim is a
soundness fix under the security exception. MINOR. (Fix in commit
`4b960b5`.)

### M2. False exclusion via a closure in a sum-type variant payload

**What changed.** The same false exclusion fired when the `Fun(...)` is
hidden inside a **sum type's variant payload**
(`type Action = Run(Fun() -> Unit) | Noop`): the reachability walk
expanded struct fields only, so `runner(a: Action)` falsely excluded
every capability while `Run(f) -> f()` reached whatever the caller
captured. Sums and structs are now folded into one fixpoint, so a `Fun`
in a variant payload, a Fun-bearing sum nested in a struct field, and a
Fun-bearing struct nested in a variant payload all downgrade. A sum whose
variants carry no `Fun` (a plain enum) still permits exclusion.

**Security impact.** The same manifest over-claim class as M1, reached
through a sum-type variant payload instead of a struct field; an
attacker-equivalent bypass of the M1 fix had it shipped alone.

**Exception rationale.** Same in-scope manifest-soundness class as M1;
completes the closure of the false-exclusion hole. Security exception,
MINOR. (Fix in commit `c37e0a4`.)

## Precision (no over-tainting, no false rejection, no over-approximation)

For the IFC fixes, precision is preserved: all-public branches of a
`match` / `if` stay public, a non-capturing closure stays public, and a
closure that `declassify`s its captured secret is clean. For the linear
fix, a single consume through an alias keeps compiling. For the manifest
fixes, a struct or sum with no `Fun` in its fields / payloads still
permits exclusion. The changes reject (or decline to claim) only the
programs that were already unsound or the manifests that already
over-claimed.

## Credit

Found and fixed during the internal hardening pass for the `1.3.0`
release.
