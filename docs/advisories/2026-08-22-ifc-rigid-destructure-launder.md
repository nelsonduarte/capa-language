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

### Update (post-1.32.0, unreleased on main, commit `c6fb7f9`)

The **trait-typed scrutinee** downcast residual disclosed just above is now
CLOSED on `main` for every scrutinee hop the cross-function summary pass's
name-only type representation can CARRY. This is a plain commit on `main` under
the project's Python-style release cadence: **no new GHSA, no version bump**, and
none of the `1.32.0` history above (the four faces, GHSA-7pf3-h2cq-52wm, the
`Fixed in: 1.32.0` facts) is changed. It extends the fix, it does not restate it.

The mechanism is analyzer-only, no codegen change. A `StructPat` destructuring a
scrutinee whose static type is a TRAIT raises each bound field to the JOIN, over
every concrete implementor of that trait, of the implementor's same-named DECLARED
field label (`trait_destructure_field_label` over `build_impl_reverse_index`,
[`capa/analyzer/_ifc_tables.py`](../../capa/analyzer/_ifc_tables.py)). The runtime
value must be one of the trait's implementors, so the join is a sound upper bound
on the true runtime field label and needs no runtime tag. The one helper is called
from BOTH seams: the intra-procedural pass (`_raise_trait_destructure_binds`,
[`capa/analyzer/_ifc.py`](../../capa/analyzer/_ifc.py)), which types the scrutinee
from the type-checker and so covers every `let` / `for` / `match` form, and the
cross-function summary pass (`_raise_trait_destructure_taint`,
[`capa/analyzer/_ifc_summary.py`](../../capa/analyzer/_ifc_summary.py)), which
re-derives the scrutinee's static type COMPOSITIONALLY in `_scrutinee_static_type`
/ `_resolve_static_type` (typing a receiver by recursion and reading each next
hop's declared type from an existing signature / field table). The join only
RAISES labels; it emits no reject and consumes none, so the concrete-twin and
rigid-`TyVar` rejects of the four faces are untouched. Two supporting changes
widen the summary resolver: a trait-block method return is registered as a callable
keyed by the trait name so a trait-typed-receiver method call (`s.clone()` where
`s: Shape`) types its return (RC2, `_register_callable` / `_TraitMethodCallable`),
and a hoisted call/method/index result is recorded through a provenance-gated
recorder (`_cur_call_derived` / `_struct_prov_type` / `_struct_prov_elem`, RC1) so
a later bare-`Ident` or `Index` scrutinee off it resolves without perturbing the
deep-read path (the pre-existing `RESTORE_BITES` residual is preserved). As with
the whole class, the trait join emits a warning at the default tier and a hard
error under `@strict_ifc`, and its soundness rests on whole-program visibility of
every implementor at the certifying analysis (true today; unsound only under a
future separate-compilation / trusted-precompiled-library path).

Closed shapes, each pinned in
[`tests/test_ifc_destructure_pattern_typecheck.py`](../../tests/test_ifc_destructure_pattern_typecheck.py):
a public-twin trait downcast in `let` / `for` / `match`; cross-function through a
parameter, a return, a call result, a single-level index (`xs[0]` of a
`List<Shape>`), a field chain (`get().s`, `xs[0].s`), a hoisted local
(`let s = get(); ... s`), a trait-typed-receiver method (`s.clone()`), and an `if`
/ `match`-EXPRESSION scrutinee whose branches agree on the trait type. A behavioural
cross-check drives every compositional spelling through both seams so the two
resolvers cannot drift.

**Two residuals stay open**, each disclosed by ROOT CAUSE (not by spelling) and
each pinned still-silent:

1. **Nested-container element erasure.** A hop like `xss[0][0]` where
   `xss: List<List<Trait>>` (and its hoisted, field-rooted, and call-rooted twins)
   still launders SILENTLY across a function boundary on the Python interpreter and
   `--ir`. Root cause: the summary stores element types NAME-ONLY
   (`_param_elem_type_names` / `_cur_elem_types` keep `args[0].name`), so
   `List<List<Shape>>` collapses to the bare name `"List"` and the inner `<Shape>`
   is erased before the resolver runs; recursion cannot recover an erased type. This
   is the same representational ceiling pinned at
   [`tests/test_ifc_forloop_destructure_deep_return.py`](../../tests/test_ifc_forloop_destructure_deep_return.py).
   Pinned by `RES_TRAIT_NESTED_CONTAINER_ELEM_LAUNDER`.
2. **Non-nameable hop (the inference ceiling).** A call to a GENERIC callee whose
   declared return type is a type PARAMETER (`fun idish<T>(x: T) -> T`), a receiver
   of dynamic / unknown static type, or an untracked / foreign callee. The
   pre-Phase-2 summary reads the declared return NAME (`"T"`, not a trait), so the
   join does not fire and the secret crosses SILENTLY on Python / `--ir`. This is
   the pre-pass's inherent inference ceiling: it runs before the type-checker's
   per-expression type map exists and cannot instantiate `T` to a trait. Pinned by
   `RES_TRAIT_GENERIC_RETURN_LAUNDER`.

Both residuals are **Python / `--ir`-only** and **caught intra-procedurally** (an
in-function sink of the same value still warns / errors); the Wasm Component Model
backend **refuses the whole trait-downcast class loud** at codegen (measured: a
`--wasm` compile of the `List<List<Shape>>` case fails with `FieldAccess on
receiver of type 'Shape': no struct layout known`). Both are scheduled to be closed
together by a future **design item B**: a structured-type resolver that
single-sources the type-checker's resolved type map rather than adding a third
independent re-derivation. That is a design / research item, not an imminent patch.

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
