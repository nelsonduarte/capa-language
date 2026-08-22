# Capa security advisory, 2026-08-22: a borrowed linear / typestate value and a consumed cap-bearing struct could be discharged twice with no diagnostic

> **Status.** Published with the `1.32.0` release. The findings below are silent
> resource-discipline false negatives in the analyzer: a borrowed (non-`consume`)
> linear or typestate parameter could be discharged a second time while the caller
> still owned it (finding B-F1, a double-consume / double-free), a cap-bearing
> struct could be used after `consume` (finding B-F2), a linear / typestate value
> selected through an `if` / `match` expression escaped every move seam (the
> conditional-selection route), and a single-owner linear / typestate value packed
> into a `List` / `Map` / `Set` / tuple escaped name threading and handed out
> unbounded aliases (the container-of-linear route). Each is a soundness fix and
> ships as a **MINOR** bump under the [`STABILITY.md`](../../STABILITY.md) security
> exception.

This advisory satisfies the `STABILITY.md` requirement that a security fix
changing observable behaviour without a major bump "ships with a security
advisory ... [that] states explicitly what changed and why the change is not
subject to the major-bump rule."

**Severity:** Moderate. The impact is a double discharge of a linear resource: a
capability or a typestate-tracked value released, closed, or otherwise consumed
twice while another owner still holds it. The consequence is program-dependent
(a double-close, a double-free of a host resource, or a double-effect); it was
measured concretely as a double-disbursement in a downstream program. There is no
memory-unsafety in the Wasm sandbox itself, no host escape, and no bypass of the
capability grant; the flaw is that Capa's linear / typestate DISCIPLINE (each
value discharged exactly once) was not enforced on these routes. The gaps were
silent on all backends (legacy transpiler, CIR Python, and Wasm).

**CVSS-style vector (illustrative):**
`CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:L` (~5.8). CVSS is an imperfect fit:
the flaw is a soundness gap in a static verifier. The primary impact is on
integrity (a resource discharged twice); `AC:H` reflects that a specific
borrow-then-escape, consume-then-use, or conditional-selection shape must be
present.

**CWE:** CWE-415 (double free) as the representative instance, more generally
CWE-1341 (multiple releases of the same resource); the linear / typestate value
may be a capability, a file / database / process handle, or any
`consume`-disciplined value.

**Affected versions:** `< 1.32.0` on the `1.x` line. Each route was reproduced on
the current `main` before the fix; the exact earliest affected release was not
bisected by executing each historical binary.

**Fixed in:** `1.32.0`.

**GHSA:** GHSA-XXXX-XXXX-XXXX (to be assigned at publication).

**Reporter / process:** internal hardening pass for the `1.32.0` release,
following the audit of the whole compiler (audit criticals B-F1 and B-F2). The
concrete fix landed in `c73c0ad`, which seals the concrete route set and builds
on the incremental work in `8b2f995` (recognise a cap-bearing struct on the
argument-consume path, B-F2), `c9ddb69` (track borrowed linear / typestate params
so they cannot escape, B-F1), the struct-field move-path series (`69c69f6`,
`ff7d517`, `3ab1fe1`, `425be41`), `79c9d92` (bar a linear / typestate value
selected through a conditional), and `f2570b6` / `84e089c` (bar a linear /
typestate value from entering a container, and seal the container-of-linear class
via a type-formation invariant). The generic type-variable passthrough seal was
**shelved** for a future sound-by-construction rebuild because its route-by-route
over-approximation did not converge; that is disclosed below.

**Channel:** this advisory; cross-referenced from the `1.32.0` `CHANGELOG.md`
entry.

## Why these are security fixes, not breaking changes

The analyzer treated a borrowed linear / typestate value as owned, and a
`consume`d cap-bearing struct as still-live, so it accepted programs that violate
the linear / typestate discipline the type system publishes. That discipline is a
first-class Capa property. The prior behaviour was a soundness bug, so tightening
it falls under the `STABILITY.md` security exception. Every change is reject-only
in the safe direction (a borrowed value stays readable and forwardable, a
`consume` param remains a terminal owner, and factory / passthrough shapes still
compile), and only a program that already double-discharged a value is affected.
They ship as a **MINOR** bump.

## B-F1. A borrowed linear / typestate parameter could escape and be discharged twice

A non-`consume` (borrowed) linear or typestate parameter was untracked, so the
analyzer treated it as owned: it could be consumed in the callee, returned,
aliased-then-consumed, transitioned with `become`, released via a `consume self`
method, or packed into an aggregate, all with no diagnostic, giving a
double-consume / double-free while the caller still owned the value.

The concrete surface closed by `1.32.0` is: direct return of a borrowed
linear / typestate param, container escape (list, tuple, struct, set, map),
struct-field move-paths in all orderings, and `if` / `match` conditional
selection.

`c9ddb69` adds a per-function `_borrowed_linear` set, seeded at function entry
from every non-`consume` parameter (including `self`) whose type is linear or a
typestate, saved and restored alongside `_live_linear`. A single guard in
`_linear_discharge` (`capa/analyzer/_linear.py:416`, the borrowed-name check at
`capa/analyzer/_linear.py:438`) rejects a discharge of a borrowed name, which
covers the consume-arg, return, `consume self`, and `become` paths that all funnel
through it. Alias propagation marks the target of `let b = h` borrowed when the
source is borrowed and skips opening a fresh owned obligation, keeping the value
single-owner; packing a borrowed identifier into a struct / list / tuple literal
gets an explicit check at literal construction. The struct-field move-path series
(`69c69f6`, `ff7d517`, `3ab1fe1`, `425be41`) extends the borrow facet over field
move-paths so a linear value consumed through a struct-field path is tracked.

## B-F2. A cap-bearing struct used after `consume`

A cap-bearing struct was not treated as a consumable capability source when passed
to a `consume` parameter, so `dispose(m); m.send(..)` on a struct cap `m` was
use-after-consume with no diagnostic, whereas a directly-typed cap was caught.

`8b2f995` adds a dedicated `_consumable_cap_path` helper
(`capa/analyzer/_discipline.py:183`, a bare cap OR a cap-bearing struct via the
existing capability walk) and calls it from `_mark_consumed_args`
(`capa/analyzer/_discipline.py:27`) in place of the narrower
`_is_capability_ident`, so the consumed path is recorded and the existing
use-after-consume detectors at the `Ident` and `FieldAccess` use sites fire
unchanged. This covers the bare-`Ident` and the `Ident`-rooted `FieldAccess`
(`box.mailer`) argument shapes. It is confined to the consume path: the aliasing
and structural checks are untouched, so a struct cap stays droppable (a multi-use
with no consume still compiles).

## The conditional-selection route

An `if` / `match` EXPRESSION whose value is an existing linear / typestate place
(a bare `Ident` or an `Ident`-rooted `FieldAccess` of linear / typestate type)
was invisible to the move / consume / return / receiver seams, which recognise
only bare `Ident` / `FieldAccess` nodes. Binding, consuming, or returning such a
wrapper (`let t = if c then s else s; close(s); close(t)`) opened a SECOND
obligation on the same runtime value, a double-free measured on all backends.

`79c9d92` closes it with one precise syntactic bar, `_check_linear_conditional_alias`
(`capa/analyzer/_linear.py:211`), run beside the container use-gate and deduped
per node. It fires when the wrapper's result type is linear / typestate or
linear-carrying AND at least one arm yields a place (recursing through nested
`if` / `match` wrappers). Because every producing context routes through
`_check_expr`, this single site covers bind-RHS, consume-argument, consume-self
receiver, return, `become`, and struct-literal element. All-fresh arms (calls /
literals / `become`) yield a value that cannot alias an existing obligation, so
the legitimate factory `let t = if c then open(1) else open(2)` still compiles.

## The container-of-linear route

A single-owner linear / typestate value (owned, borrowed, fresh, or a
linear-carrying carrier struct) packed into a `List` / `Map` / `Set` or a tuple
escapes name threading: a later read of the container hands out an unbounded number
of aliases to a value that must be discharged exactly once, a double-free / leak
the earlier move-path work did not cover.

`f2570b6` bars the value at the insertion site: `_check_no_linear_into_container`
in `capa/analyzer/_ifc.py` (mirroring the capability check
`_check_no_cap_into_container`) rejects an element / key / value position of
`List.push` / `Set.add` / `Map.set` whose type is linear or linear-carrying, and
`_reject_linear_list_element` rejects a fresh linear packed straight into a list
literal that never passes through a mutator. `84e089c` then seals the class as a
**type-formation invariant** with the same four mechanisms the capability
discipline already uses (driven by `_container_carries_linear`): a per-expression
use-gate, a deferred end-of-function recheck for late-inferred element types, a
signature entry-gate at the parameter, return, struct field, typestate field,
sum-variant payload, and const positions, and a generic-substitution gate that
fires only when substitution turns a non-container-of-linear into one. A bare
linear value at top level stays legal; only its containment in a `List` / `Map` /
`Set` / tuple at any nesting depth is refused. Analyzer-only and reject-only.

## Scope and known residuals

- **Generic type-variable passthrough (shelved, disclosed-open).** A borrowed
  linear / typestate value laundered through a generic type parameter is not
  sealed: the route-by-route over-approximation of a generic seal did not
  converge, so it was shelved for a future sound-by-construction rebuild rather
  than shipped as an over-rejecting approximation.
- **A conservative over-reject on a fresh-via-bound-name arm.** An `if` / `match`
  arm that yields a FRESH linear value via a bound name (a payload moved out of a
  sum, an inline `let ...; x`) is treated as a place and barred; this is
  reject-valid, never accept-invalid, and is deferred pending scope-aware place
  resolution.
- **A separate leak surface (deferred).** A non-linear carrier dropped without
  consuming its linear field (a LEAK, not a double-free) is a separate deferred
  surface, disclosed-open.

## Remediation

**Upgrade to `1.32.0`.** On affected versions there was no analyzer-configuration
workaround: these routes were silent at compile time on all backends. After
upgrading, each is a compile error.

## Verification

Analyzer-only, reject-only, no codegen change; the three-backend output is
byte-identical for previously-accepted programs and the full suite is green
(5340 passed at the landing commit). Pinned in
[`tests/test_analyzer.py`](../../tests/test_analyzer.py) (the reject shapes and
the must-compile over-reject controls) and
[`tests/test_ir_wasm_parity.py`](../../tests/test_ir_wasm_parity.py) (the
cross-backend behaviour).

## Credit

Found and fixed during the internal hardening pass for the `1.32.0` release
(audit criticals B-F1 and B-F2).
