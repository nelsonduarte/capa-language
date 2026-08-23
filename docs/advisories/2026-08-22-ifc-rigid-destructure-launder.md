# Capa security advisory, 2026-08-22: a struct-destructuring pattern could launder a `@secret` through a public twin

> **Status.** Published with the `1.32.0` release. The finding below is a class of
> silent information-flow false negatives: a nominal struct-destructuring pattern
> (a `let` / `for` binding or a `match` arm) binds each named field with the type
> it has in the PATTERN's struct, never the scrutinee's, and until `1.32.0` the
> pattern's struct name was never checked against the value's type. A public-twin
> pattern over a `@secret` value therefore rebound the secret field under the
> twin's public label, laundering it. The class has four progressively-closed
> faces, culminating in a rigid same-name-collision launder through a generic
> constructor. It is claimed under the [`STABILITY.md`](../../STABILITY.md)
> **security exception** and is therefore shipped as a **MINOR** bump, not a MAJOR
> one.

This advisory satisfies the `STABILITY.md` requirement that a security fix
changing observable behaviour without a major bump "ships with a security
advisory ... [that] states explicitly what changed and why the change is not
subject to the major-bump rule."

**Severity:** Moderate. Confidentiality impact only (a silent information-flow /
noninterference false negative). The severe faces were silent at BOTH tiers (no
warning by default and no error under `@strict_ifc`) and leaked on all backends;
one face is instead a Python-only leak with a loud Wasm fault, and one is a
runtime fault rather than a leak (each stated per face below). No integrity,
availability, code-execution, or memory-safety impact, and no bypass of the
capability discipline itself.

**CVSS-style vector (illustrative):**
`CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` (~5.3). CVSS is an imperfect fit:
the flaw is a soundness gap in a static verifier. `AC:H` reflects that a
public-twin destructure over a matching secret-carrying value, and (for the last
face) the generic same-name-collision shape, must be present.

**CWE:** CWE-200 (exposure of sensitive information), the same information-flow
laundering class as the prior IFC advisories
([`2026-08-08-ifc-param-carried-readback.md`](2026-08-08-ifc-param-carried-readback.md)
and the other 2026-08 advisories).

**Affected versions:** `< 1.32.0` on the `1.x` line. The leaking shapes were
reproduced on the current `main` before the fix; the exact earliest affected
release was not bisected by executing each historical binary.

**Fixed in:** `1.32.0`.

**GHSA:** GHSA-7pf3-h2cq-52wm.

**Reporter / process:** internal hardening pass for the `1.32.0` release. The
class was closed by a sequence of commits, each face building on the last:
`6cb827d` (type-check struct-destructuring patterns against the scrutinee, closing
the concrete-struct-mismatch public twin), `445eea2` (substitute the scrutinee's
generic arguments into the destructured field types, closing the generic-field
`TyVar` face), `0c684ef` (reject destructuring a rigid type-parameter scrutinee),
and `43f75aa` (the shared `_constructor_result_args` helper that restores a rigid
marker erased at a generic construction seam, so the rigid reject fires at the
same-name-collision face).

**Channel:** this advisory; cross-referenced from the `1.32.0` `CHANGELOG.md`
entry.

## Why this is a security fix, not a breaking change

The analyzer bound a destructured field at the pattern's declared type without
checking or substituting the scrutinee's type, so it failed to follow a `@secret`
value through a destructure, in scope per [`SECURITY.md`](../../SECURITY.md)
("Compilation accepts a program where a `@secret` value reaches a public sink that
the analyzer should reject"). The prior behaviour was a soundness bug, so
tightening it falls under the `STABILITY.md` security exception. The direction of
the change is reject-more (or, for `445eea2`, type-precisely-more, which also
repaired two pre-existing false positives), and only a program that was already
unsound (or already faulting at runtime) is affected. It ships as a **MINOR** bump.

## The four faces

1. **Concrete-struct-name mismatch public twin (`6cb827d`).** A pattern naming a
   different struct than the scrutinee's concrete type rebound the secret field
   under the twin's public label: a silent launder at both IFC tiers and on both
   backends. A `match` twin additionally added a silent Python-drops / Wasm-leaks
   divergence, and a pattern naming a field the value lacks passed `--check` and
   then faulted at runtime. One reject in the `StructPat` binder, resolving
   struct-ness through the global type registry (not the value scope, so a
   local binder named like the type cannot shadow the guard away), closes all
   three.

2. **Generic-field `TyVar` face (`445eea2`).** A destructuring binder assigned each
   name the struct's RAW declared field type without substituting the scrutinee's
   generic arguments, so a generic-typed field bound as a bare `TyVar`. A
   public-twin destructure of that `TyVar` slipped the concrete-struct mismatch
   guard and laundered a `@secret` silently even under `@strict_ifc`, leaking on
   Python (`let Box { v } = b; let Other { a } = v` for `b: Box<ASecret>`).
   Building the field substitution from the struct's type params to the scrutinee's
   arguments binds the field at its instantiated concrete type, so the guard fires;
   this also repaired two pre-existing false positives (a field access or method
   call on such a bound field).

3. **Rigid type-parameter scrutinee (`0c684ef`).** Destructuring a value whose
   static type is a RIGID type variable (a bare `T` from `fun f<T>`, or an
   intermediate that substitutes to itself) is an unsound downcast the compiler
   cannot justify by parametricity, so the binder now rejects it on both pattern
   arms. The two arms differ in severity, stated accurately: the STRUCT-destructure
   channel was a SILENT both-backends `@secret` leak (the severe channel), while
   the VARIANT-MATCH arm was NOT a silent leak (Python structurally no-ops, Wasm
   faults loud), so rejecting it is fail-closed rather than a leak closure. A
   FLEXIBLE `?` inference placeholder is excluded so the empty-list for-destructure
   stays legal.

4. **Rigid same-name-collision through a generic constructor (`43f75aa`).** A rigid
   value constructed through a generic struct literal or variant call whose type
   parameter shares the caller's rigid parameter NAME (`Wrap<T>` used inside
   `fun leak<T>`) erased the rigid `T` to `TyUnknown` at the construction seam:
   unification's reflexive same-name short-circuit returns without binding, and each
   seam read `mapping.get(p, TyUnknown)`. A downstream public-twin destructure then
   resolved nothing, the rigid reject of face 3 did not fire, and the `@secret`
   laundered silently on all backends (a nested `List<T>` field being the same root
   one level deeper). A shared `_constructor_result_args` helper
   (`capa/analyzer/_typing.py:264`), routed through the struct-literal seam in
   `capa/analyzer/_expressions.py` and the variant-call seam in
   `capa/analyzer/_dispatch.py`, restores `TyVar(p)` when a field or payload still
   carries it, so the value stays rigid and the face-3 reject fires at the twin
   destructure. Unification is untouched.

All four rejects live in the `StructPat` / `VariantPat` binder
(`capa/analyzer/_bind_pattern` and the destructuring guard at
`capa/analyzer/_patterns.py` around line 732); a rejected program never reaches the
IFC summary or codegen. The changes are type-inference and reject only, and the
three-backend output is byte-identical for previously-accepted programs.

## Scope and known residuals

The other same-name erasure sites (closure-return, `?`-on-`Result`, `map` /
`filter`) and the trait / sum destructure residuals stay disclosed-open. In
particular, a **trait-typed scrutinee** downcast (`s: Shape` then
`let Circle { r } = s`) resolves `ty.name` to a trait rather than a struct or a
type variable, so the legitimate downcast stays accepted and a public-twin
downcast is not caught (a Python-backend leak). That residual is disclosed in
source at [`capa/analyzer/_patterns.py:722-731`](../../capa/analyzer/_patterns.py)
and pinned by a test; it also ships as a disclosed known issue with `1.32.0`.

## Remediation

**Upgrade to `1.32.0`.** On affected versions the severe faces were silent at both
tiers, so no analyzer configuration would have caught them. After upgrading, a
public-twin or rigid destructure is a compile error.

## Verification

Type-inference and reject only, no codegen change. Pinned in
[`tests/test_ifc_destructure_pattern_typecheck.py`](../../tests/test_ifc_destructure_pattern_typecheck.py),
which flips each face from accept-and-leaks (or accept-and-faults) into the reject
class, adds the struct-literal-direct and nested-`List` shapes, keeps the rewrap
and concrete-payload over-reject controls compiling, and cross-checks that both
construction seams route through the one helper.

## Credit

Found and fixed during the internal hardening pass for the `1.32.0` release.
