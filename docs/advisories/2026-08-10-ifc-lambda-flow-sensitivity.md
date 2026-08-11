# Capa security advisory, 2026-08-10: information-flow lambda-flow sensitivity false negatives

> **Status.** Published with the `1.30.0` release. The findings below are
> silent information-flow false negatives closed in the intra-procedural
> information-flow pass. They are claimed under the
> [`STABILITY.md`](../../STABILITY.md) **security exception** (the same
> soundness-fix carve-out Rust and Python follow) and are therefore shipped
> as a **MINOR** bump, not a MAJOR one. The rationale is stated below. This
> closes the lambda-flow residual disclosed with
> [`2026-08-10-ifc-cross-function-whole-struct-read.md`](2026-08-10-ifc-cross-function-whole-struct-read.md)
> (shipped with `1.29.0`), which named it the most serious open item and more
> general than the whole-struct read that release closed. It does NOT close
> every lambda flow: the closed claim is scoped precisely in
> [Scope and known residuals](#scope-and-known-residuals).

This advisory satisfies the `STABILITY.md` requirement that a security
fix changing observable behaviour without a major bump "ships with a
security advisory ... [that] states explicitly what changed and why the
change is not subject to the major-bump rule."

**Severity:** Low to moderate. Confidentiality impact only (a silent
information-flow / noninterference false negative). It is scoped down by
conditions that must all hold: the data is annotated `@secret`; the program
routes it through a **locally-resolved** lambda (a `let`-bound lambda invoked
in the same scope, or an immediately-invoked `(fun...)(x)`) that sinks its
parameter, or through a closure capturing a container mutated after the
closure is defined whose RESULT is then sunk; and there is a public sink. The
information-flow check is a **warning by default** and a **hard error only
under `@strict_ifc`**, and the noninterference guarantee is claimed **only
under `@strict_ifc`**; the false negatives removed both signals, so a build
that gates noninterference on `@strict_ifc` passed while laundering the secret.
No integrity or availability impact, and no bypass of the capability
discipline itself. Consistent with how the prior IFC laundering advisories
([`2026-06-16-soundness.md`](2026-06-16-soundness.md),
[`2026-07-03-soundness.md`](2026-07-03-soundness.md),
[`2026-08-08-ifc-param-carried-readback.md`](2026-08-08-ifc-param-carried-readback.md),
[`2026-08-08-ifc-match-arm-container-leak.md`](2026-08-08-ifc-match-arm-container-leak.md),
[`2026-08-09-ifc-field-receiver-container-leak.md`](2026-08-09-ifc-field-receiver-container-leak.md),
[`2026-08-10-ifc-cross-function-whole-struct-read.md`](2026-08-10-ifc-cross-function-whole-struct-read.md))
framed the class: "the worst kind of hole" (a silent false negative),
because the author writes `@secret`, believes they are protected, and are
not.

**CVSS-style vector (illustrative):**
`CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` (~5.3). CVSS is an imperfect
fit here: the flaw is a soundness gap in a static verifier. The score
reflects a confidentiality-only break of the information-flow
noninterference guarantee, observable at run time, with no integrity,
availability, code-execution, or memory-safety impact; `AC:H` reflects that
the specific lambda-indirection shape and `@secret` annotation must all be
present.

**Affected versions:** `1.29.0` and earlier on the `1.x` line. The lambda-flow
residual was **`1.29.0`'s own disclosed residual** (its most serious open
item), and the `1.29.0` advisory recorded it as **pre-existing on `1.28.0` and
earlier** (a separate deferred lambda-flow item, more general than the
whole-struct read that release closed: it needs no container, capture, or
push-ordering). The named-argument backend divergence (below) was likewise
pre-existing. The false negatives were concretely **reproduced on the released
`1.29.0` binary** (see [Reproduction](#reproduction)); the exact earliest
affected release below `1.29.0` was **not bisected** by executing each
historical binary. This is the same information-flow-laundering class as the
2026-06-16 (`1.3.0`), 2026-07-03 (`1.15.0`), and the four 2026-08 advisories
(`1.26.0` / `1.27.0` / `1.28.0` / `1.29.0`), which stated their range as the
release before the fix "and earlier on the `1.x` line"; this advisory follows
that convention.

**Fixed in:** `1.30.0`.

**Reporter / process:** internal hardening pass following the `1.29.0`
release, driven by adversarial dogfooding of the information-flow control. The
fix commits are `d8a31c5` (Stage A, the sink-side face), `5189908` (reject
named arguments at a first-class call; disclose the nested-local-lambda sink),
`099e2bc` (Stage B, the capture-side result-sink face), `ff65822` (disclose the
declassify-blind capture re-read over-report), and `38dff85` (restrict the
capture re-read to reference-typed captures, honest capture-side wording, and
the disclosed-residual pins). Covered by
[`tests/test_ifc_branch_scoped_container.py`](../../tests/test_ifc_branch_scoped_container.py),
where the closed cases and each residual are asserted.

**Channel:** this advisory; cross-referenced from
[`SECURITY.md`](../../SECURITY.md) and the `1.30.0` `CHANGELOG.md` entry.

## Why this is a security fix, not a breaking change

The analyzer's intra-procedural information-flow pass **failed to follow** a
`@secret` value across a lambda indirection a first-class, machine-checked Capa
security property depends on: information-flow control over `@secret` data, in
scope per [`SECURITY.md`](../../SECURITY.md) ("Compilation accepts a program
where a `@secret` value reaches a public sink that the analyzer should
reject"). The prior behaviour was a soundness bug, so tightening it falls under
the `STABILITY.md` security exception and does not force a major bump. The
direction of the change is flag-more: only programs that were already unsound
(a `@secret` reaching a public sink with no `declassify`) are affected. It
ships as a **MINOR** bump, matching every prior static-analysis-tightening IFC
soundness fix (`1.2.0`, `1.3.0`, `1.4.0`, `1.15.0`, `1.26.0`, `1.27.0`,
`1.28.0`, `1.29.0`), each shipped as a MINOR under the same exception.

The coupled named-argument change (below) is a **correctness** fix, not a new
IFC flag: it rejects a construct that had no sound meaning and diverged between
the backends. Its resolution is an analysis-level rejection identical on both
backends, so it removes a silent divergence rather than tightening a flow.

## Details

Capa's information-flow control is a first-class security property: a
`@secret` value must not reach a public sink (`Stdio.println` / `eprintln`,
`Net.post`, `panic`, a sink-reaching parameter of a further function, ...)
without an explicit `declassify`. A **direct** named call that carries a
`@secret` into a parameter reaching a sink was already caught by the
cross-function sink summary. A **lambda** carrying the same flow was not.

Two distinct mechanisms produced the false negatives.

### Face 1: the parameter-sink of a locally-resolved lambda

A call whose callee is a `Fun`-typed local (a `let`-bound lambda) or an IIFE
went through a call branch that did **no information-flow work at all**: the
named-call boundary consulted the sink summary, but the `Fun`-typed value
branch bound the arguments positionally and stopped. So a `@secret` bound to a
lambda parameter that reaches a public sink inside the body was silently
public:

```capa
let g: Fun(String) -> Unit = fun(s: String) -> Unit => sink_str(s, stdio)
g(secret)        # was silent; the direct sink_str(secret, stdio) was caught
```

The identical program written as a direct named call (`sink_str(secret,
stdio)`) was flagged. The gap was the lambda indirection, not the sink.

### Face 2: the container-capture result-sink

A closure's captured-variable labels were stamped at the closure's
**definition** and never re-reflected when a captured binding was mutated
afterwards. So a container captured by a closure defined **before** a push, and
read through the closure's **result** after, was silently public:

```capa
let f = fun() -> String => bag.reveal()
bag.items.push(secret)
stdio.println(f())        # printed s3cr3t, no diagnostic
```

A closure defined **after** the push was already caught, because its capture
label was stamped after the taint existed.

### The fix

The change (`capa/analyzer/_ifc.py`, `capa/analyzer/_ifc_summary.py`, and
`capa/analyzer/_dispatch.py`) applies the latent per-lambda signature at the
**application site, not the definition** (FlowCaml's model for first-class
functions), grounded in the access-path / field-sensitive model the earlier
container fixes use:

- **Face 1 (`d8a31c5`).** Every lambda literal is registered as a synthetic
  callable keyed by its id and summarised on the **same** sink-reaching /
  sink-path fixpoint as a named function (the summary machinery the `1.29.0`
  fix built). At a call `g(args)` whose callee resolves through the existing
  binding resolution to **one certain** lambda literal, and at an IIFE
  `(fun(s) => ...)(args)` whose callee **is** the literal, that summary is
  applied to the actual arguments -- the argument label, the read-side field
  clear-gate, and the warn / strict emitter -- exactly as the named-call check
  does. On any ambiguity (a reassigned `var`, an alias, a call-result binding,
  a lambda invoked in a higher-order callee) it falls back to **no check**: a
  conservative miss, never a wrong-target guess.

- **Face 2 (`099e2bc`, `38dff85`).** At the invocation of a locally-resolved
  lambda, each captured free binding's **current live** label is re-read and
  joined into the callee label: the binding's live whole-value label **for a
  reference-typed capture only** (a struct / container: mutable and shared, so
  a later in-place field store IS observed), plus the branch-scoped
  container-mutation taint **for all captures**. It never consults the label
  cached at the lambda's definition. A value-typed / built-in-immutable capture
  (`String` / `Int` / `Float` / `Bool` / `Char`) is captured **by value**, so
  its later reassignment is correctly ignored. Branch-soundness is by
  construction: the container-taint map is live and branch-scoped, so a push in
  a mutually-exclusive branch is not observed at another branch's invocation.

The leaks now emit, at the sink, a **warning by default** and a **hard error
under `@strict_ifc`**. For Face 2 (the caller sinks the closure's result) the
sink is the caller's own `Stdio.println`:

```
information-flow: a @secret value reaches Stdio.println (argument 1), a
public sink that sends data out of the program. Route it through
declassify(value, reason: "...") if this disclosure is intended.
```

For Face 1 (the `@secret` argument reaches a sink inside the lambda body) the
wording names the sink target -- the bound name `g` for a `let`-bound lambda,
or "the closure" for an IIFE:

```
information-flow: a @secret value is passed to 'g' as s, which reaches a
public sink inside 'g' (it sends data out of the program). Route it through
declassify(value, reason: "...") if this disclosure is intended.
```

```
information-flow: a @secret value is passed to the closure as s, which
reaches a public sink inside the closure (it sends data out of the program).
Route it through declassify(value, reason: "...") if this disclosure is
intended.
```

### A coupled correctness fix (a silent backend divergence)

A NAMED argument at a first-class / lambda call site was type-checked
**positionally**, but the Python transpiler emitted kwargs (honouring the
names) while the Wasm backend bound positionally. So a named-argument
first-class call **diverged between the two backends**, and the names could
reorder a `@secret` into an un-sunk slot:

```capa
let g: Fun(String, String) -> Unit = fun(a: String, b: String) -> Unit => sink_str(b, stdio)
g(b: secret, a: "pub")   # 1.29.0: analyze ok, 0 warnings;
                         # --run prints s3cr3t, --run --wasm prints pub
```

A `Fun`-typed value carries no parameter names, so a named argument has no
sound binding. The fix (`5189908`) **rejects** a named argument at a
first-class / lambda call site (a `let`-bound lambda, an IIFE, or a `Fun`-typed
parameter) with a compile-time diagnostic, before the positional binding that
would otherwise misbind it:

```
named arguments are not supported at a call to the function value 'g'; a
function value carries no parameter names, so pass the arguments positionally
```

Being an analysis rejection, it is identical on both backends, closing the
divergence and the leak. Positional first-class calls stay allowed. The named
`fun` / method / variant path DOES carry parameter names and keeps the sound
named-argument path; it is untouched.

## Reproduction

Face 1 (parameter-sink of a `let`-bound lambda):

```capa
const TOKEN: @secret String = "s3cr3t"
fun sink_str(s: String, stdio: Stdio)
    stdio.println(s)
fun leak(stdio: Stdio, secret: @secret String)
    let g: Fun(String) -> Unit = fun(s: String) -> Unit => sink_str(s, stdio)
    g(secret)
fun main(stdio: Stdio)
    leak(stdio, TOKEN)
```

Face 2 (container-capture result-sink):

```capa
const TOKEN: @secret String = "s3cr3t"
type Bag { items: List<String> }
impl Bag
    fun reveal(self) -> String
        match self.items.get(0)
            Some(x) -> return x
            None -> return "empty"
fun leak(stdio: Stdio, secret: @secret String)
    var bag: Bag = Bag { items: [] }
    let f = fun() -> String => bag.reveal()
    bag.items.push(secret)
    stdio.println(f())
fun main(stdio: Stdio)
    leak(stdio, TOKEN)
```

On the released **`1.29.0`** binary (both faces, and the IIFE
`(fun(s: String) -> Unit => sink_str(s, stdio))(secret)`):

- `capa --check` reports `ok` and exits 0 (no information-flow warning).
- adding `@strict_ifc()` to `leak` still reports `ok` and exits 0 (no error):
  the `@strict_ifc` build passes with **zero** errors while the program
  launders the secret.
- `capa --run` and `capa --run --wasm` both print `s3cr3t`: the `@secret`
  value reaches the public sink at runtime on both backends.

On **`1.30.0`**:

- `capa --check` emits the information-flow **warning** above and exits 0
  (default tier is warn-only).
- with `@strict_ifc()` on `leak`, `capa --check` emits the same text as an
  **error** and exits 1.

The named-argument divergence (`g(b: secret, a: "pub")`) on `1.29.0`: `capa
--check` reports `ok` with zero warnings, `capa --run` prints `s3cr3t`, and
`capa --run --wasm` prints `pub`. On `1.30.0` `capa --check` rejects it with
the diagnostic above and exits 1.

The runtime leak is backend-independent (the analyzer is what should reject
it); the shipped test suite asserts the secret on the Python and Wasm backends
for these shapes.

## Impact

A silent secret-disclosure path: a `@secret` value (PII, a token, a key)
routed through a small local lambda -- the idiomatic way to factor out a log or
serialise step -- or captured by a closure and read back after a mutation, with
no diagnostic at either tier. The author annotated the value `@secret`, and
neither the default warning nor the `@strict_ifc` hard error fired, so a build
gating noninterference on `@strict_ifc` passed while the secret escaped at
runtime. The lambda-flow shape is more general than the container residuals of
the prior advisories: the parameter-sink face needs no container, capture, or
push-ordering.

## Remediation

Upgrade to **`1.30.0`**. After upgrading, the flow is a warning by default and
a hard error under `@strict_ifc`. If a specific disclosure is intended, route
the value through `declassify(value, reason: "...")`, which the analyzer
records as an audited, deliberate declassification.

Because the default tier only warns, programs that want the guarantee enforced
as a build gate should run the analyzer under `@strict_ifc` (or treat the
information-flow warning as an error in CI). If a named-argument first-class
call is now rejected, pass the arguments positionally.

## Scope and known residuals

This fix flags secret flows through **locally-resolved** lambdas (`let`-bound
/ IIFE) for the **parameter-sink** and the **container-capture-result-sink**
cases, and nothing more. **Do not read the closed claim as "lambdas are
closed."** A sink internal to a closure body, closures that escape local
resolution, a sink via a nested local lambda, and struct-field-store flows
through captures remain documented residuals requiring higher-order /
points-to analysis, or -- for the capture-internal struct field-store case --
the capture-internal-sink summary that would consume the field-store
access-path channel (a `1.30.1` update: that channel now EXISTS, so this case
no longer waits on a channel Capa lacks; see residual 1). The following stay
open, each an honest, tested false negative that leaks
at run time UNFLAGGED at both tiers on both backends, or a disclosed sound
over-report; each is asserted in
[`tests/test_ifc_branch_scoped_container.py`](../../tests/test_ifc_branch_scoped_container.py).

1. **A sink INTERNAL to the closure body (still open).** A locally-resolved
   closure that captures a value mutated after its definition and SINKS it
   **inside its own body** (a side effect, not the result the caller sinks --
   `f()` returns `Unit` and prints the secret itself) leaks unflagged. Stage
   B's capture re-read carries the later taint into the closure's **result**
   label only, so a caller that sinks the RESULT is caught but an internal sink
   is not. Three shapes: a container pushed then read inside the body, a sink
   through a named callee inside the body, and an in-place struct field store
   printed inside the body. The container-mutation form is closable with a
   capture-sink summary and is a tracked next slice; the struct field-store
   form is the same slice over the field-store `(root, field-path)` access-path
   channel (a `1.30.1` update: that channel now EXISTS -- `1.30.1` field-keyed
   the direct field store -- so closing this no longer waits on a channel Capa
   lacks; the remaining work is the capture-internal-sink summary that consumes
   it). This residual itself STAYS OPEN: the capture re-read still carries a
   field store into the closure's RESULT label only, not into an internal sink.
   Asserted in `TestCaptureInternalSinkResidualDisclosed`.

2. **Closures that ESCAPE local resolution (still open).** A closure the caller
   cannot resolve to one certain lambda literal is not reached by either the
   sink summary or the live capture re-read (both fire only at a
   locally-resolved invocation): a reassigned `var`, an alias `let g2 = g`, a
   call-result binding `let g = mk()`, a closure passed to a higher-order
   callee then invoked there (`apply(f)` where `apply(g)` calls `g()`),
   returned then invoked, stored in a struct / list then invoked, recursive, or
   conditionally selected. Each stays UNFLAGGED though it leaks the secret on
   both backends; closing them needs a higher-order control-flow / points-to
   analysis Capa does not have. Asserted in
   `TestEscapingLambdaSinkResidualDisclosed` (sink side) and
   `TestHofInvokedClosureResidualDisclosed` (capture side).

3. **A sink reached only through a NESTED LOCAL lambda (still open).** A local
   lambda whose body reaches a sink ONLY through a nested local-lambda
   invocation (`let inner = fun(t) => sink_str(t, stdio); let g = fun(s) =>
   inner(s); g(secret)`) is opaque to the summary walk, which resolves a body's
   calls to **named** (`fun` / method) callees only, never to a local-lambda
   binding -- the same limitation named callables have. So "sinks its
   parameter" means directly or via a **named** callee. Asserted in
   `TestNestedLocalLambdaSinkOpaqueResidualDisclosed`.

### Two safe over-reports (known, sound behaviour, not residual leaks)

Both of the following **flag** though nothing secret reaches the sink (they
print the public value at run time). They over-report, never under-report, and
are deliberately disclosed rather than "fixed".

1. **A captured STRUCT whole-reassigned to a secret after the closure is
   defined (still open).** A whole reassign (`box = Box { data: secret }`)
   rebinds the variable to a NEW object and leaves no precise field seed, so the
   reference-typed capture re-read falls back to the binding's whole-value label
   and cannot tell it from a genuine in-place store. So a captured struct
   whole-reassigned to a secret FLAGS under `@strict_ifc` though it is captured
   by value and prints the public value at run time: a safe strict-tier
   over-rejection, precedented by the reassigned-`var` sink recovery also
   failing closed. (A value-typed **primitive** capture reassigned to a secret
   is correctly clean, because a primitive is captured by value; that is the
   `38dff85` correction, not an over-report.) Asserted in
   `TestCaptureRereadReftype`.

   *Clean sibling read of a captured struct: RESOLVED for a DIRECT FIELD read in
   `1.30.1`; still open for a WHOLE / method read.* On `1.29.0` / `1.30.0` the
   capture re-read joined the whole-value label of the captured **root**, so a
   closure reading only a clean sibling (`box.note`) of a struct whose OTHER
   field was stored into or pushed to after the closure was defined FLAGGED
   though nothing leaks. `1.30.1` makes the capture re-read field-precise
   (`1580715`): a read at a determinable FIELD PATH observes only the
   branch-scoped container taints prefix-compatible with that path, so a
   disjoint clean sibling now stays clean (asserted in
   `TestCaptureFieldStoreFieldPrecise`). This is a false-positive removal, not a
   leak fix; it ships as a PATCH with no new advisory. It does NOT close a
   WHOLE / undeterminable read: a closure that reads the captured root through a
   METHOD receiver (`bag.getnote()`), a bare use, or an argument cannot be
   resolved to a field path, so it still observes every container taint on the
   root and still over-reports (asserted, still flagging, in
   `TestCaptureLiveRereadPrecision`). A read of the stored / pushed path, and
   every leak the re-read caught, stay flagged. The gate's soundness now rests
   on a maintenance invariant: every whole-value label raise OUTSIDE the precise
   field-store leaf path (an aliased / escaped / unresolvable-path store, and
   the cross-function whole-value carrier) routes through a single choke-point
   (`_raise_whole_value_label`) that also marks the binding whole-value-dirty,
   so the field-precise re-read never silently suppresses a whole-value taint it
   cannot see.

2. **An in-body `declassify` inside a captured closure.** The Face-2 re-read
   reads the RAW branch-scoped container taint and is **declassify-blind**
   (unlike the result-label path), so a closure that `declassify`s its captured
   value **in-body**, captured before a push and read through the closure,
   FLAGS at both tiers though the disclosure was sanctioned. Sound
   (over-report, never a missed leak), with a clean workaround: declassify at
   the CALL SITE (`declassify(f(), reason: "...")`) stays clean. A
   declassify-aware container channel is a separate, larger item. Asserted in
   `TestCaptureLiveRereadPrecision`.

The whole-struct-read closure and its residuals from `1.29.0`, the loop-body
over-approximation, and the assignment sibling-branch false positive disclosed
with `1.27.0` also stay open and are documented there. As a `1.30.1` update,
the field-store `(root, field-path)` access-path channel the tracked plan for
the field-store family of residual 1 named now EXISTS (`1.30.1` field-keyed the
direct field store, the same access-path model this fix and the `1.29.0`
container fixes build on). Residual 1 STAYS OPEN: the remaining slice is the
capture-internal-sink summary that would carry an in-place struct field store
from that channel into the closure's internal-sink path.

## Credit

Found and fixed during the internal hardening pass following the `1.29.0`
release, driven by adversarial dogfooding of the information-flow control. A
pentester found the capture-side value-typed-capture false positive and an
overclaiming "capture-side closed" framing during Stage B; a reviewer measured
the sound resolution (`38dff85`).
