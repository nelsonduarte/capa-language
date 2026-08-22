# Capa security advisory, 2026-08-22: a rigid same-name-collision destructure laundered a `@secret` through a generic constructor

> **Status.** Published with the `1.32.0` release. The finding below is a silent
> information-flow false negative: a `@secret` value carried by a rigid type
> parameter could be laundered to a public twin by constructing it through a
> generic struct literal or variant call whose type parameter shared the caller's
> rigid parameter NAME, then destructuring it. It is claimed under the
> [`STABILITY.md`](../../STABILITY.md) **security exception** and is therefore
> shipped as a **MINOR** bump, not a MAJOR one. The rationale is stated below.

This advisory satisfies the `STABILITY.md` requirement that a security fix
changing observable behaviour without a major bump "ships with a security
advisory ... [that] states explicitly what changed and why the change is not
subject to the major-bump rule."

**Severity:** Moderate. Confidentiality impact only (a silent information-flow /
noninterference false negative). It is the "worst kind" of hole in that the leak
was silent at BOTH tiers (no warning by default and no error under `@strict_ifc`)
and ran on all backends, but it is scoped down by the specific program shape that
must be present: the caller is generic over a rigid parameter `T`, and it
constructs the secret-carrying value through a generic type (`Wrap<T>`) whose own
type parameter is spelled with the SAME name `T`, then destructures the wrapper
to a public binding. No integrity, availability, code-execution, or
memory-safety impact, and no bypass of the capability discipline itself.

**CVSS-style vector (illustrative):**
`CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` (~5.3). CVSS is an imperfect fit:
the flaw is a soundness gap in a static verifier. `AC:H` reflects the specific
same-name generic-collision shape that must be present.

**CWE:** CWE-200 (exposure of sensitive information), the same information-flow
laundering class as the prior IFC advisories
([`2026-08-08-ifc-param-carried-readback.md`](2026-08-08-ifc-param-carried-readback.md)
and the six other 2026-08 advisories).

**Affected versions:** `< 1.32.0` on the `1.x` line. The leaking shape was
reproduced on the current `main` before the fix; the exact earliest affected
release was not bisected by executing each historical binary.

**Fixed in:** `1.32.0`.

**GHSA:** GHSA-XXXX-XXXX-XXXX (to be assigned at publication).

**Reporter / process:** internal hardening pass for the `1.32.0` release,
extending the destructure-pattern type-checking work landed earlier in the same
cycle. The named fix commit is `43f75aa` (the shared `_constructor_result_args`
helper that restores the erased rigid marker at both construction seams). It sits
atop three foundation commits from the same cycle: `6cb827d` (type-check
struct-destructuring patterns against the scrutinee), `445eea2` (substitute
generic args into struct-destructuring field types), and `0c684ef` (reject
destructuring a rigid type-parameter scrutinee) which established the reject that
this fix routes the previously-erased case into.

**Channel:** this advisory; cross-referenced from the `1.32.0` `CHANGELOG.md`
entry.

## Why this is a security fix, not a breaking change

The analyzer **erased** a rigid type parameter at a generic construction seam and
so failed to follow a `@secret` value through the wrap-and-destructure path, in
scope per [`SECURITY.md`](../../SECURITY.md) ("Compilation accepts a program
where a `@secret` value reaches a public sink that the analyzer should reject").
The prior behaviour was a soundness bug, so tightening it falls under the
`STABILITY.md` security exception. The direction of the change is reject-more, and
only a program that was already unsound (a `@secret` laundered to a public twin)
is affected. It ships as a **MINOR** bump.

## Details

A rigid value constructed through a generic STRUCT literal or VARIANT call whose
type parameter shares the caller's rigid parameter NAME (a `type Wrap<T>` used
inside `fun leak<T>`) had its rigid `T` erased to `TyUnknown` at the construction
seam. Unification's reflexive same-name short-circuit returns without binding, and
each seam read `mapping.get(p, TyUnknown)`, collapsing the type argument. A
downstream public-twin destructure then resolved nothing, so the rigid-scrutinee
reject (landed in `0c684ef`) did not fire, and the `@secret` was laundered
silently on all backends. A nested `List<T>` field was the same root one level
deeper.

## The fix

`43f75aa` adds a single shared construction-site helper,
`_constructor_result_args` on the typing mixin
(`capa/analyzer/_typing.py:264`), and routes both seams through it: the
struct-literal seam in `capa/analyzer/_expressions.py` and the variant-call seam
in `capa/analyzer/_dispatch.py`. For each declared type parameter it uses the
unification binding when present; otherwise, when a field or payload still carries
the same rigid `TyVar(p)` via a parallel walk of the expected signature and the
resolved actual (the reflexive-collision witness, which also closes the nested
container sibling), it restores `TyVar(p)` instead of `TyUnknown`; otherwise
`TyUnknown`. This only restores the rigid marker the seam was dropping, so the
value behaves as if the rigid `T` were held directly and the existing
rigid-scrutinee reject fires at the twin destructure (`capa/analyzer/_patterns.py`
around the destructuring guard). No new reject logic, no codegen change,
unification untouched.

The change is type-inference only. The differently-named (`Wrap<E>`) and concrete
paths are unchanged, and the three-backend output is byte-identical for
previously-accepted programs.

## Scope and known residuals

The fix closes the struct-literal-direct, the variant-call, and the nested
`List<T>` same-name-collision shapes. The other same-name erasure sites
(closure-return, `?`-on-`Result`, `map` / `filter`) and the trait / sum
destructure residuals stay disclosed-open. In particular, a **trait-typed
scrutinee** downcast (`s: Shape` then `let Circle { r } = s`) resolves `ty.name`
to a trait rather than a struct or a type variable, so the legitimate downcast
stays accepted and a public-twin downcast is not caught (a Python-backend leak).
That residual is disclosed in source at
[`capa/analyzer/_patterns.py:722-731`](../../capa/analyzer/_patterns.py) and
pinned by a test; it also ships as a disclosed known issue with `1.32.0`.

## Remediation

**Upgrade to `1.32.0`.** On affected versions the launder was silent at both
tiers, so no analyzer configuration would have caught it. After upgrading, the
downstream destructure of the now-rigid scrutinee is a compile error.

## Verification

Analyzer-only, reject-only, no codegen change. Pinned in
[`tests/test_ifc_destructure_pattern_typecheck.py`](../../tests/test_ifc_destructure_pattern_typecheck.py),
which flips the same-name-constructor residual from accept-and-leaks into the
reject class, adds the struct-literal-direct and nested-`List` shapes, keeps the
rewrap and concrete-payload over-reject controls compiling, and cross-checks that
both seams route through the one helper.

## Credit

Found and fixed during the internal hardening pass for the `1.32.0` release.
