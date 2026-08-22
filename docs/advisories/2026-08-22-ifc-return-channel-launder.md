# Capa security advisory, 2026-08-22: a `@secret` could be laundered through a function's return-value channel

> **Status.** Published with the `1.32.0` release. The finding below is a silent
> information-flow false negative in the cross-function return channel: a `@secret`
> introduced inside a callee and returned to the caller (through a field store into
> a local, a deep field-access chain, a for-loop or destructuring binder, or a
> locally-resolved lambda's result) was not tracked at the field precision the sink
> check needs, so it laundered to a public sink `--check`-clean at both tiers and
> on both backends. It is claimed under the [`STABILITY.md`](../../STABILITY.md)
> **security exception** and is therefore shipped as a **MINOR** bump, not a MAJOR
> one.

This advisory satisfies the `STABILITY.md` requirement that a security fix
changing observable behaviour without a major bump "ships with a security
advisory ... [that] states explicitly what changed and why the change is not
subject to the major-bump rule."

**Severity:** Moderate. Confidentiality impact only (a silent information-flow
false negative). It is the "worst kind" of hole in that every sub-shape below was
silent at BOTH tiers (no warning by default and no error under `@strict_ifc`) and
ran on all backends, but it is scoped down by requiring that the `@secret`
originate inside the callee (a declared-`@secret` field, or an opaque call that
returns one) and reach the caller's sink through the specific return route. No
integrity, availability, code-execution, or memory-safety impact, and no bypass of
the capability discipline itself.

**CVSS-style vector (illustrative):**
`CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (~6.2). CVSS is an imperfect fit:
the flaw is a soundness gap in a static verifier. The score reflects a
confidentiality-only break, observable at run time; `AC:L` reflects that returning
a value that carries an internally-introduced secret is an ordinary, idiomatic
shape.

**CWE:** CWE-200 (exposure of sensitive information), the same information-flow
laundering class as the prior IFC advisories
([`2026-08-08-ifc-param-carried-readback.md`](2026-08-08-ifc-param-carried-readback.md)
and the other 2026-08 advisories).

**Affected versions:** `< 1.32.0` on the `1.x` line. Each sub-shape was reproduced
on the current `main` before the fix; the exact earliest affected release was not
bisected by executing each historical binary.

**Fixed in:** `1.32.0`.

**GHSA:** GHSA-XXXX-XXXX-XXXX (to be assigned at publication).

**Reporter / process:** internal hardening pass following the `1.31.0` release,
extending the field-store access-path channel built in `1.30.1`. Fix commits (a
tight sequence building the field-qualified return channel, with the design record
in `37d1c76`): `d28ab67` (field-qualify the pass-to-callee sink gate, the
prerequisite guard), `b26aefd` (migrate `return_effects` to a per-path field map,
behaviour-preserving schema change), `ffee175` (close the local field-store return
laundering, field-precisely), `89bbcd7` (close the cross-function deep field-access
return leak), `055f699` (close the for-loop and destructuring binder deep-field
return channel), `353d98e` (close the locally-resolved lambda result-face return
leak), and `4f4a7d9` (gate the fail-closed result-label raise past
pending-inference lambdas, a precision correction that prevents a benign miss from
becoming a traceback).

**Channel:** this advisory; cross-referenced from the `1.32.0` `CHANGELOG.md`
entry.

## Why this is a security fix, not a breaking change

The analyzer's cross-function summary failed to carry a `@secret` through the
return-value channel at the field precision the sink check needs, so it accepted
programs that launder a secret, in scope per [`SECURITY.md`](../../SECURITY.md)
("Compilation accepts a program where a `@secret` value reaches a public sink that
the analyzer should reject"). The prior behaviour was a soundness bug, so
tightening it falls under the `STABILITY.md` security exception. The direction of
every change is flag-more, and only a program that was already unsound is affected.
It ships as a **MINOR** bump.

## Details

The cross-function summary tracks what a callee's return value can carry so the
caller can label the call result. Four return routes were under-tracked, each a
silent both-backends leak:

1. **Local field-store return laundering.** A `@secret` introduced inside a callee
   and field-stored into a fresh LOCAL struct that is then returned recorded only a
   cross-function mutation effect (which needs a parameter-rooted target, so a
   fresh local recorded nothing), and never raised the local's return content.
2. **Cross-function deep field-access return.** A callee returning a nested
   declared-`@secret` field (`return t.f2.f3.v`) was recognised only when the
   receiver was an `Ident` (depth 1); a deeper chain attributed no internal-secret
   and the return effect carried only the harmless parameter index.
3. **For-loop and destructuring binder deep-field return.** The deep-field walk
   resolved the root type via a per-callable value-type map, but a `for`-loop
   element binder and a struct-destructuring field binder were never seeded, so a
   return of a nested secret field reached through such a binder fell back to the
   whole-value carrier and dropped the taint.
4. **Locally-resolved lambda result face.** A locally-resolved lambda (a `let` /
   `var` bound to a lambda literal invoked in the same scope, or an IIFE) whose
   RESULT carried a `@secret` (a declared-secret field read, or a call that returns
   a secret) was not consulted at the invocation.

## The fix

The schema and infrastructure land first, then each leak:

- `b26aefd` makes `return_effects` a per-path field map
  (`{callable_key: {field_path -> frozenset(sources)}}`,
  `capa/analyzer/_ifc_summary.py:441`), carried on the same monotone fixpoint;
  behaviour-preserving in isolation. `d28ab67` field-qualifies the pass-to-callee
  sink gate so a later field-store content taint on a disjoint sibling does not
  reach a callee that sinks only a clean path.
- `ffee175` makes a direct field store content-write the root at the stored
  field's path, so a same-body read-back or a return of a local observes it while a
  disjoint public sibling stays clean; the return of a local records its content
  per path.
- `89bbcd7` walks the field-access chain type-precisely in `_field_read_is_secret`
  (`capa/analyzer/_ifc_summary.py:1735`) from its root through a
  `struct_field_type_names` map to the leaf's owning struct, resolving a
  local-rooted chain via a per-callable `_cur_value_types` map, so a deep return of
  a declared-secret field is recognised. Each hop follows the declared field type,
  never a field-name match, so an unrelated same-named public field is not flagged.
- `055f699` seeds the `for`-loop element binder (`_iter_element_struct_type`,
  `capa/analyzer/_ifc_summary.py:1915`) and the struct-destructuring field binder
  (`_record_pattern_value_types`, `capa/analyzer/_ifc_summary.py:1884`)
  type-precisely, by declared type never bound-name spelling.
- `353d98e` joins the closure's cached def-time result label
  (`_lambda_result_labels`, return-effect-aware, method-return-precise,
  declassify-aware) into the call-result label at the two locally-resolved sites in
  `_callee_label` (`capa/analyzer/_ifc.py:1268`). The lookup is fail-closed. The
  ceiling is exact: as strong as the direct-call verdict through a one-certain
  lambda, never weaker, never stronger.
- `4f4a7d9` narrows that fail-closed raise (`_lambda_static_result_label`,
  `capa/analyzer/_ifc.py:1333`) so a lambda still in `_pending_inferred_lambdas` (a
  benign, already-a-type-error miss) is treated as public-for-now rather than
  raising an uncaught traceback; the raise stays only for a genuinely-unexpected
  miss. This cannot hide a leak because such a program does not compile.

Every change is analyzer-only: both backends stay byte-identical and only the
`--check` verdict changes.

## Scope and known residuals

The return channel stays whole-value for a returned struct that received an
inside-callee secret (an accepted, disclosed OVER-approximation: a sink of any
field of such a struct flags; the per-field precision is delivered intra-body).
A chain rooted at a call or index result (`id(t).f2.f3.v`,
`get_items(bag)[0].v`) stays a whole-value false negative, the same different-root
points-to family disclosed in
[`2026-08-10-ifc-cross-function-whole-struct-read.md`](2026-08-10-ifc-cross-function-whole-struct-read.md).
The escaping-alias, higher-order-invoked, and nested-local-lambda result-face
residuals stay open, inherited from the lambda-flow advisories.

## Remediation

**Upgrade to `1.32.0`.** On affected versions the launder was silent at both
tiers, so no analyzer configuration would have caught it. After upgrading, each
route is a warning by default and a hard error under `@strict_ifc`.

## Verification

Analyzer-only, output byte-identical. Pinned across
[`tests/test_ifc_param_carried_readback.py`](../../tests/test_ifc_param_carried_readback.py)
and the dedicated local-field-store, deep-field-return, for-loop / destructuring,
and locally-resolved-lambda-result return test modules, each asserting the closed
leak shapes flag at both tiers, the field-precision anti-false-positive controls
stay clean, and the disclosed over-approximation and points-to residuals are pinned
as currently-accepted.

## Credit

Found and fixed during the internal hardening pass following the `1.31.0`
release.
