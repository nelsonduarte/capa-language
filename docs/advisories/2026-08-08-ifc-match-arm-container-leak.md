# Capa security advisory, 2026-08-08: information-flow match-arm container-mutation false negative

> **Status.** Published with the `1.27.0` release. The finding below is a
> silent information-flow false negative closed in the cross-function
> information-flow summary. It is claimed under the
> [`STABILITY.md`](../../STABILITY.md) **security exception** (the same
> soundness-fix carve-out Rust and Python follow) and is therefore shipped
> as a **MINOR** bump, not a MAJOR one. The rationale is stated below. This
> is a second advisory dated 2026-08-08; it follows on from
> [`2026-08-08-ifc-param-carried-readback.md`](2026-08-08-ifc-param-carried-readback.md)
> (shipped with `1.26.0`), which closed the sibling read-back shape.

This advisory satisfies the `STABILITY.md` requirement that a security
fix changing observable behaviour without a major bump "ships with a
security advisory ... [that] states explicitly what changed and why the
change is not subject to the major-bump rule."

**Severity:** Moderate. Confidentiality impact only (a silent
information-flow / noninterference false negative). It requires the
developer to have annotated the data `@secret` and to rely on the
analyzer's information-flow check, which is a **warning by default** and
a **hard error only under `@strict_ifc`**; the false negative removed
both signals, so a build that gates noninterference on `@strict_ifc`
passed while laundering the secret. No integrity or availability impact,
and no bypass of the capability discipline itself. Consistent with how
the prior IFC laundering advisories
([`2026-06-16-soundness.md`](2026-06-16-soundness.md),
[`2026-07-03-soundness.md`](2026-07-03-soundness.md),
[`2026-08-08-ifc-param-carried-readback.md`](2026-08-08-ifc-param-carried-readback.md))
framed the class: "the worst kind of hole" (a silent false negative),
because the author writes `@secret`, believes they are protected, and are
not.

**CVSS-style vector (illustrative):**
`CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (~6.2). CVSS is an
imperfect fit here: the flaw is a soundness gap in a static verifier. The
score reflects a confidentiality-only break of the information-flow
noninterference guarantee, observable at run time, with no integrity,
availability, code-execution, or memory-safety impact.

**Affected versions:** `1.26.0` and earlier on the `1.x` line. This
false negative lives in the cross-function information-flow summary, whose
match-arm handling copies each arm's environment in isolation. The
summary shipped in the `1.1` line (`feat: add cross-function
information-flow inference`, 2026-06-08); before that line there was no
cross-function summary at all, so a `@secret` parameter laundered through
an inline container mutation in a `match` arm to a public sink was equally
undetected on the `1.0.x` releases. The false negative was concretely
**reproduced on the released `1.26.0` binary** (see Reproduction); the
exact earliest affected release below `1.26.0` was **not bisected** by
executing each historical binary. This is the same
information-flow-laundering class as the 2026-06-16 (`1.3.0`), 2026-07-03
(`1.15.0`), and 2026-08-08 (`1.26.0`,
[param-carried read-back](2026-08-08-ifc-param-carried-readback.md))
advisories, which stated their range as the release before the fix "and
earlier on the `1.x` line"; this advisory follows that convention.

**Fixed in:** `1.27.0`.

**Reporter / process:** internal hardening pass following the `1.26.0`
release, driven by adversarial dogfooding of the information-flow control.
The fix was validated by a diff review, an adjudication, an independent
focused review (ship), and a pentester pass over the leak-shape corpus (no
new laundering, no regression, both backends); the full suite grew from
5086 to 5099 tests with zero regressions.

**Channel:** this advisory; cross-referenced from
[`SECURITY.md`](../../SECURITY.md) and the `1.27.0` `CHANGELOG.md` entry.

## Why this is a security fix, not a breaking change

The analyzer's cross-function information-flow summary **failed to
follow** a `@secret` value across a boundary a first-class,
machine-checked Capa security property depends on: information-flow
control over `@secret` data, in scope per
[`SECURITY.md`](../../SECURITY.md) ("Compilation accepts a program where
a `@secret` value reaches a public sink that the analyzer should
reject"). The prior behaviour was a soundness bug, so tightening it falls
under the `STABILITY.md` security exception and does not force a major
bump. The direction of the change is flag-more: only programs that were
already unsound (a `@secret` reaching a public sink with no `declassify`)
are affected. It ships as a **MINOR** bump, matching every prior
static-analysis-tightening IFC soundness fix (`1.2.0`, `1.3.0`, `1.4.0`,
`1.15.0`, `1.26.0`), each shipped as a MINOR under the same exception.

## Details

Capa's information-flow control is a first-class security property: a
`@secret` value must not reach a public sink (`Stdio.println` /
`eprintln`, `Net.post`, `panic`, a sink-reaching parameter of a further
function, ...) without an explicit `declassify`. Intra-procedurally, and
for the cross-function cases the summary already modelled, this is a
warning by default and a hard error under `@strict_ifc`.

A plain function parameter carries **no** caller-side `@secret` label:
inside the callee that receives it, the parameter is not an
intra-procedural secret, so the caller's cross-function **summary** is
the only pass that can see a leak routed through it. The `1.26.0` fix
gave that summary a branch-scoped content channel and routed a
**callee-mutated** read-back through it. But an **inline** container
mutation written directly inside a `match` arm (`xs.push(secret)`,
`s.add(secret)`, `m.set(k, secret)`, or a struct-field store) was still
carried on the flat `env`, and the summary **copied each `match` arm's
environment in isolation and discarded it**, so the arm's mutation never
reached a read after the `match`. The intra-procedural pass, which tracks
the push on the flat shared label, flagged the identical shape; only the
cross-function summary lost the arm's taint. The shape

- `main` passes a `@secret` value into a caller `leak`'s plain
  `secret: String` parameter;
- `leak` creates a fresh, unaliased local (an empty `List` / `Map` /
  `Set` / a freshly-constructed struct) and, **inside a `match` arm**,
  mutates it inline with the secret (`xs.push(secret)`); and
- after the `match`, `leak` reads the value back out of the local and
  sends it to a public sink, or stores it into one of `leak`'s own
  parameters that the caller later sinks

produced **no** diagnostic: the local's read-back stayed public, `leak`'s
summary never marked its `secret` parameter sink-reaching, and the call
`leak(TOKEN, true, stdio)` in `main` was neither warned nor rejected under
`@strict_ifc`. The identical shape written with an `if` was flagged. This
is the `match`-arm analogue of the `1.26.0`
[param-carried read-back](2026-08-08-ifc-param-carried-readback.md)
false negative: `1.26.0` closed the callee-mutated read-back, this closes
the inline container mutation inside a `match` arm.

### The fix

Two coupled defects both stemmed from the container-mutation taint being
flat / monotone across branches while the `1.26.0` cross-function content
channel was branch-scoped. Both were addressed by giving the
container-mutation taint the same branch scoping, on two tiers:

- **Intra-procedural pass** (`capa/analyzer/_ifc.py`): the
  container-mutation taint is recorded in a separate, per-binding,
  branch-scoped channel joined into a binding's label only on a **read**;
  the shared `Symbol.label`, field labels, struct-alias groups and
  escaped-struct tracking stay flat and untouched. The channel is
  isolated per branch and deferred-unioned back in `_check_if`,
  `_check_match_expr` and the if-expression.
- **Cross-function summary** (`capa/analyzer/_ifc_summary.py`): the inline
  container-mutator read-back is routed into the existing branch-scoped
  content channel instead of the flat `env`, so a push in a `match` arm
  reaches a read after the `match` while `env`'s alias / mutation-target
  role is left untouched.

Both channels are isolated per branch and unioned into the enclosing
scope only **after** all branches are walked (a deferred union). So a
mutation in one branch reaches a read after the construct (no false
negative) and does not contaminate a mutually-exclusive sibling branch's
read (no false positive).

The leak now emits, at the call site, a **warning by default** and a
**hard error under `@strict_ifc`**:

```
information-flow: a @secret value is passed to 'leak' as secret, which
reaches a public sink inside 'leak' (it sends data out of the program).
Route it through declassify(value, reason: "...") if this disclosure is
intended.
```

Branch-isolation of the container-mutation taint covers `if` / `elif` /
`else`, `if ... then ... else`, and `match`. Inside a `while` / `for`
body the taint is **deliberately not** branch-isolated: the loop walks
its body twice (a dry-run pass then the real pass), so a push anywhere in
the body taints every read of that container in the body. This is a sound
MAY over-approximation, disclosed in "Scope and known residuals" below.
Covered by `tests/test_ifc_branch_scoped_container.py`.

## Reproduction

```capa
const TOKEN: @secret String = "s3cr3t"

fun read_print(xs: List<String>, stdio: Stdio)
    match xs.get(0)
        Some(x) -> stdio.println(x)
        None -> stdio.println("empty")

fun leak(secret: String, flag: Bool, stdio: Stdio)
    var xs: List<String> = []
    match flag
        true -> xs.push(secret)
        false -> ()
    read_print(xs, stdio)

fun main(stdio: Stdio)
    leak(TOKEN, true, stdio)
```

On the released **`1.26.0`** binary:

- `capa --check` reports `ok` and exits 0 (no information-flow warning).
- adding `@strict_ifc()` to `main` still reports `ok` and exits 0 (no
  error).
- `capa --run` prints `s3cr3t` and exits 0: the `@secret` value reaches
  the public sink at runtime.

On **`1.27.0`**:

- `capa --check` emits the information-flow **warning** above and exits 0
  (default tier is warn-only).
- with `@strict_ifc()` on `main`, `capa --check` emits the same text as
  an **error** and exits 1.

The store-into-parameter variant behaves the same: a `@secret` pushed in a
`match` arm, then stored after the `match` into one of the function's own
parameters (`b.field = x`) that the caller later prints, was unflagged on
`1.26.0` and is now a warning by default and an error under `@strict_ifc`.

The runtime leak is backend-independent (the analyzer is what should
reject it); the shipped test suite asserts identical output on the Python
and Wasm backends for these shapes.

## Impact

A silent secret-disclosure path: a `@secret` value (PII, a token, a key)
laundered to a public sink through a fresh local mutated inline inside a
`match` arm, then read after the `match` or stored into a parameter, with
no diagnostic at either tier. The author annotated the value `@secret`,
and neither the default warning nor the `@strict_ifc` hard error fired, so
a build gating noninterference on `@strict_ifc` passed while the secret
escaped at runtime.

## Remediation

Upgrade to **`1.27.0`**. After upgrading, the flow is a warning by
default and a hard error under `@strict_ifc`. If a specific disclosure is
intended, route the value through `declassify(value, reason: "...")`,
which the analyzer records as an audited, deliberate declassification.

Because the default tier only warns, programs that want the guarantee
enforced as a build gate should run the analyzer under `@strict_ifc` (or
treat the information-flow warning as an error in CI).

## Scope and known residuals

This fix closes the **fresh, unaliased, inline container mutation inside a
`match` arm** read after the `match` (or stored into a parameter), and its
`if` counterpart, and closes the sibling-branch false positive described
in "Precision" below. Branch-isolation covers `if` / `elif` / `else`,
`if ... then ... else`, and `match`. The following residuals stay open and
are stated so the boundary of the fix is explicit.

1. **Loop bodies are not branch-isolated (a sound over-approximation, not
   a leak).** Inside a `while` / `for` body the container-mutation taint
   is intentionally flat: a push anywhere in the body taints every read of
   that container in the body. This **catches** the intra loop-carried
   read-before-write leak (a read at the top of the body fed by an earlier
   iteration's push, where iteration 2 reads iteration 1's secret), which
   genuinely leaks across iterations. The cost is a safe-direction
   over-approximation: a read in a mutually-exclusive sibling branch
   **inside a loop** is also flagged even when a loop-invariant condition
   would keep the two branches from ever both running, because Capa does
   not prove the condition loop-invariant. It over-reports there and never
   under-reports.

2. **The assignment sibling-branch false positive (unrelated, still
   open).** A whole-value assignment (`x = secret`) in one branch, read in
   a mutually-exclusive sibling branch, still travels on the flat shared
   label (this fix scoped the container-mutation channel, not the
   assignment channel) and can be over-reported. This is a false
   **positive** in the safe direction; it never under-reports a leak.

3. **The general list-aliasing false negatives (still open).** Lists are
   reference types and Capa has no points-to / list-alias analysis, so a
   local that is aliased under a second name (`var b = a; a.push(secret);
   read b`), embedded then mutated, stored then pushed, or mutated through
   a non-plain receiver (`bag.items.push(...)` on a local struct field) is
   not tracked. Disclosed with `1.26.0` and still open. Fundamental
   without a points-to analysis Capa does not have.

4. **Cross-function loop-carried read-before-write (still open).** A read
   placed textually before a cross-function push inside a `while` / `for`,
   where a later iteration would feed the read, is not caught by the
   summary: its loop body is walked once in source order with no iteration
   fixpoint. (This is the summary-tier residual carried over from the
   `1.26.0` advisory; the intra-procedural loop-carried read is caught by
   the two-pass walk in residual 1.)

## Precision (a false positive was also closed, not a security item)

Alongside the false negative, this change closed an unrelated precision
false **positive**, in the opposite direction, on leak-free code. A direct
push of a `@secret` into a fresh local (`xs.push(secret)`) in one branch of
an `if` / `elif` / `else` or `match`, read in a mutually-exclusive sibling
branch that can never co-execute, was flagged by the intra-procedural pass
(a warning by default, a hard error under `@strict_ifc`) because the pass
raised the shared receiver label flatly. Per-branch scoping of the
container-mutation channel makes such a sibling read clean. This is a
precision improvement, not part of this advisory's vulnerability; it never
weakens a real-leak diagnostic. On the closed shape the fix preserves
precision: a `declassify`, a sibling local, a written-but-unread local, an
escaping struct, plain public data, and the must-stay-flagged real leaks
(both-arms push, cross-function effect, embed-mutated-in-a-branch, and the
loop-family leaks) all keep their correct verdict.

## Credit

Found and fixed during the internal hardening pass following the `1.26.0`
release, driven by adversarial dogfooding of the information-flow control.
