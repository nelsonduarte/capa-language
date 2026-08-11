# Capa security advisory, 2026-08-11: information-flow capture-internal-sink false negative

> **Status.** Published with the `1.31.0` release. The finding below is a
> silent information-flow false negative closed in the intra-procedural
> information-flow pass, at the invocation of a locally-resolved closure. It is
> claimed under the [`STABILITY.md`](../../STABILITY.md) **security exception**
> (the same soundness-fix carve-out Rust and Python follow) and is therefore
> shipped as a **MINOR** bump, not a MAJOR one. The rationale is stated below.
> This closes the **locally-resolved-direct / named-callee** portion of residual
> 1 (the capture-internal sink) disclosed with
> [`2026-08-10-ifc-lambda-flow-sensitivity.md`](2026-08-10-ifc-lambda-flow-sensitivity.md)
> (shipped with `1.30.0`), whose named blocker -- the field-store access-path
> channel -- was built in `1.30.1` and is consumed here. It does NOT close every
> capture-internal sink: the closed claim is scoped precisely in
> [Scope and known residuals](#scope-and-known-residuals).

This advisory satisfies the `STABILITY.md` requirement that a security
fix changing observable behaviour without a major bump "ships with a
security advisory ... [that] states explicitly what changed and why the
change is not subject to the major-bump rule."

**Severity:** Low to moderate. Confidentiality impact only (a silent
information-flow / noninterference false negative). It is scoped down by
conditions that must all hold: the data is annotated `@secret`; the program
captures it in a **locally-resolved** closure (a `let`-bound lambda invoked in
the same scope, or an immediately-invoked `(fun...)(x)`) whose body **sinks the
capture as a side effect** (not the closure's returned result); and the taint
arrives at the captured value **after** the closure is defined. The
information-flow check is a **warning by default** and a **hard error only under
`@strict_ifc`**, and the noninterference guarantee is claimed **only under
`@strict_ifc`**; the false negative removed both signals, so a build that gates
noninterference on `@strict_ifc` passed while laundering the secret. No integrity
or availability impact, and no bypass of the capability discipline itself.
Consistent with how the prior IFC laundering advisories
([`2026-06-16-soundness.md`](2026-06-16-soundness.md),
[`2026-07-03-soundness.md`](2026-07-03-soundness.md),
[`2026-08-08-ifc-param-carried-readback.md`](2026-08-08-ifc-param-carried-readback.md),
[`2026-08-08-ifc-match-arm-container-leak.md`](2026-08-08-ifc-match-arm-container-leak.md),
[`2026-08-09-ifc-field-receiver-container-leak.md`](2026-08-09-ifc-field-receiver-container-leak.md),
[`2026-08-10-ifc-cross-function-whole-struct-read.md`](2026-08-10-ifc-cross-function-whole-struct-read.md),
[`2026-08-10-ifc-lambda-flow-sensitivity.md`](2026-08-10-ifc-lambda-flow-sensitivity.md))
framed the class: "the worst kind of hole" (a silent false negative), because
the author writes `@secret`, believes they are protected, and are not.

**CVSS-style vector (illustrative):**
`CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` (~5.3). CVSS is an imperfect fit
here: the flaw is a soundness gap in a static verifier. The score reflects a
confidentiality-only break of the information-flow noninterference guarantee,
observable at run time, with no integrity, availability, code-execution, or
memory-safety impact; `AC:H` reflects that the specific closure shape (a capture
sunk inside the body, taint arriving after definition) and the `@secret`
annotation must all be present.

**Affected versions:** `1.30.1` and earlier on the `1.x` line. This
capture-internal sink was **`1.30.0`'s own disclosed residual 1** (a locally
-resolved closure that captures a value mutated after its definition and sinks it
inside its own body). The `1.30.0` advisory recorded it as open, and `1.30.1`
built its named blocker (the field-store `(root, field-path)` access-path
channel) as a precision PATCH without consuming it, so the leak stayed open on
`1.30.1`. The false negative was concretely **reproduced on the released
`1.30.1` binary** (see [Reproduction](#reproduction)); the exact earliest
affected release below `1.30.1` was **not bisected** by executing each historical
binary. This is the same information-flow-laundering class as the 2026-06-16
(`1.3.0`), 2026-07-03 (`1.15.0`), and the six 2026-08 advisories
(`1.26.0` .. `1.30.0`), which stated their range as the release before the fix
"and earlier on the `1.x` line"; this advisory follows that convention.

**Fixed in:** `1.31.0`.

**Reporter / process:** internal hardening pass following the `1.30.1` release,
driven by adversarial dogfooding of the information-flow control. The fix commits
are `1daae28` (the per-lambda capture-side sink-path summary), `cac7917` (apply
it at the locally-resolved invocation against the live, field-precise capture
label), and `9771149` (pin the corpus; no def-time suppression gate). A reviewer
adjudicated the scope and a pentester ran the leak-shape corpus (APPROVE, no new
leak, both backends); the full suite is 5190 with zero regressions. Covered by
[`tests/test_ifc_branch_scoped_container.py`](../../tests/test_ifc_branch_scoped_container.py),
where the closed cases, the no-false-positive cases, the two safe over-reports,
and each residual are asserted.

**Channel:** this advisory; cross-referenced from
[`SECURITY.md`](../../SECURITY.md) and the `1.31.0` `CHANGELOG.md` entry.

## Why this is a security fix, not a breaking change

The analyzer's intra-procedural information-flow pass **failed to follow** a
`@secret` value across a lambda-capture indirection a first-class,
machine-checked Capa security property depends on: information-flow control over
`@secret` data, in scope per [`SECURITY.md`](../../SECURITY.md) ("Compilation
accepts a program where a `@secret` value reaches a public sink that the analyzer
should reject"). The prior behaviour was a soundness bug, so tightening it falls
under the `STABILITY.md` security exception and does not force a major bump. The
direction of the change is flag-more: only programs that were already unsound (a
`@secret` reaching a public sink with no `declassify`) are affected. It ships as
a **MINOR** bump, matching every prior static-analysis-tightening IFC soundness
fix (`1.2.0`, `1.3.0`, `1.4.0`, `1.15.0`, `1.26.0`, `1.27.0`, `1.28.0`, `1.29.0`,
`1.30.0`), each shipped as a MINOR under the same exception. (`1.30.1` was by
contrast a PATCH: it only removed false positives, closing no leak.)

## Details

Capa's information-flow control is a first-class security property: a `@secret`
value must not reach a public sink (`Stdio.println` / `eprintln`, `Net.post`,
`panic`, a sink-reaching parameter of a further function, ...) without an
explicit `declassify`.

The `1.30.0` fix applied a lambda's latent per-lambda signature at the
**application site, not the definition** (FlowCaml's model for first-class
functions). Its capture-side face (Face 2) re-read each captured binding's live
label at the invocation and joined it into the closure's **result** label, so a
caller that sinks the closure's RESULT after a later mutation was caught. But a
sink **internal** to the closure body -- a side effect, where the closure returns
`Unit` and prints (or otherwise sinks) the captured value itself -- was still
type-checked **once at the closure's definition**, when the captured field was
still public, and never re-checked at the invocation. So:

```capa
const TOKEN: @secret String = "s3cr3t"
type Bag { data: String }
fun leak(stdio: Stdio, secret: @secret String)
    var bag: Bag = Bag { data: "pub" }
    let f: Fun() -> Unit = fun() -> Unit => stdio.println(bag.data)
    bag.data = secret        # taint arrives AFTER f is defined
    f()                      # prints s3cr3t; no diagnostic on 1.30.1
fun main(stdio: Stdio)
    leak(stdio, TOKEN)
```

The body `stdio.println(bag.data)` reads a field that was public when `f` was
defined; the def-time body check saw nothing, and there was no invocation-side
capture-internal check. The same shape held when the capture is read through an
index into a captured container, a tuple destructure, a chained method, a `match`
scrutinee, a string interpolation, an alias into a local, a launder into another
container, or a method that sinks `self`, and when the sink is reached through a
NAMED helper the closure calls, and when the taint is delivered by a NAMED
callee's field-write effect (`fill(bag, secret)`) rather than an inline store.

### The fix

The change (`capa/analyzer/_ifc_summary.py`, `capa/analyzer/_ifc.py`,
`capa/analyzer/__init__.py`) adds a **per-lambda capture-side sink-path summary**
and applies it at the invocation, the read-side mirror of the parameter
sink-path summary:

- **The summary (`1daae28`).** After the parameter fixpoint stabilises, each
  lambda's FREE identifiers (its captures) are seeded as sources and the SAME
  declassify-aware body walk records, per capture, the capture-relative field
  paths that reach a public sink inside the body (`()` = the whole capture). A
  sink reached via a NAMED helper composes in through the helper's own
  sink-path summary; an in-body `declassify` records no path, so a closure that
  declassifies the value it sinks carries no entry and stays clean by
  construction.

- **The invocation check (`cac7917`).** At a call that resolves through the
  existing binding resolution to **one certain** lambda literal, or an IIFE whose
  callee IS the literal, the captures are resolved by identity and matched by name
  to the summary. For each summarised capture the **live** label at its SUNK
  paths is taken with the shared `_capture_live_label` gate -- the field-precise
  branch-scoped container-taint read (built on the `1.30.1` field-store
  access-path channel), the reference-typed whole-value re-read, and the
  value-typed capture-by-value skip. Only a live `@secret` capture is flagged, at
  the invocation position, warn by default and a hard error under `@strict_ifc`.

- **No def-time suppression gate (`9771149`).** The check flags whenever a
  summarised sunk-path label is live `@secret`, with no attempt to suppress a
  capture that was "already secret at definition". A per-name whole-value
  definition snapshot cannot tell a secret NON-sunk sibling from the sunk path,
  so such a gate would mask a real leak (a launder-through-a-captured-container
  shape whose actually-sunk field rises secret after the def while a different
  field was secret before it). Flagging on the live sunk-path label is always
  sound.

The leak now emits, at the invocation, a **warning by default** and a **hard
error under `@strict_ifc`**. The wording names the sink target -- the bound name
`f` for a `let`-bound lambda, or "the closure" for an IIFE -- and the captured
binding:

```
information-flow: a @secret value is passed to 'f' as the captured 'bag', which
reaches a public sink inside 'f' (it sends data out of the program). Route it
through declassify(value, reason: "...") if this disclosure is intended.
```

## Reproduction

```capa
const TOKEN: @secret String = "s3cr3t"
type Bag { data: String }
fun leak(stdio: Stdio, secret: @secret String)
    var bag: Bag = Bag { data: "pub" }
    let f: Fun() -> Unit = fun() -> Unit => stdio.println(bag.data)
    bag.data = secret
    f()
fun main(stdio: Stdio)
    leak(stdio, TOKEN)
```

On the released **`1.30.1`** binary:

- `capa --check` reports `ok` and exits 0 (no information-flow warning).
- adding `@strict_ifc()` to `leak` still reports `ok` and exits 0 (no error):
  the `@strict_ifc` build passes with **zero** errors while the program launders
  the secret.
- `capa --run` and `capa --run --wasm` both print `s3cr3t`: the `@secret` value
  reaches the public sink at runtime on both backends.

On **`1.31.0`**:

- `capa --check` emits the information-flow **warning** above and exits 0
  (default tier is warn-only).
- with `@strict_ifc()` on `leak`, `capa --check` emits the same text as an
  **error** and exits 1.

The runtime leak is backend-independent (the analyzer is what should reject it);
the shipped test suite asserts the secret on the Python and Wasm backends for
these shapes.

## Impact

A silent secret-disclosure path: a `@secret` value (PII, a token, a key)
captured by a small local closure -- the idiomatic way to defer a log or a
serialise step -- and sunk inside its body after the captured struct or container
was populated, with no diagnostic at either tier. The author annotated the value
`@secret`, and neither the default warning nor the `@strict_ifc` hard error
fired, so a build gating noninterference on `@strict_ifc` passed while the secret
escaped at runtime.

## Remediation

**Upgrade to `1.31.0`.** On affected versions (`< 1.31.0`) there is **no
analyzer-configuration workaround**: this flow was silent at BOTH tiers, so
neither raising the tier to `@strict_ifc` nor treating information-flow warnings
as errors in CI would have caught it (that silence at both tiers IS the
vulnerability). Upgrading is the only remedy that closes the leak on the code as
written.

After upgrading, the flow is a warning by default and a hard error under
`@strict_ifc`, so a build that gates noninterference on `@strict_ifc` (or treats
the information-flow warning as an error in CI) enforces it from `1.31.0` on.

Two correctly-framed notes, neither a mitigation for the code as written on an
affected version:

- A **source restructuring** was already caught before `1.31.0`: rewriting the
  closure so it RETURNS the captured value and the caller sinks the RESULT
  (`stdio.println(f())`) is flagged on `1.30.0` / `1.30.1` by the result-sink
  face -- a warning by default and a hard error under `@strict_ifc`, verified on
  the released `1.30.1` binary. It is a code change, not an analyzer setting, and
  it does not cover the escaping / nested-local-lambda residuals below.
- `declassify(value, reason: "...")` is for an **intended** disclosure (the
  analyzer records it as audited), not a mitigation for this leak; an in-body
  `declassify` of the sunk value stays clean because the disclosure was
  sanctioned.

## Scope and known residuals

This fix flags a live-`@secret` capture **sunk inside the body** of a
**locally-resolved** closure (a `let`-bound lambda invoked in the same scope, or
an IIFE), where the sink is reached **directly or through a NAMED callee** (a
named helper), the capture is read at a determinable **field path** or through a
**whole / interpolation / method** read, and the taint is delivered by a **field
store**, a **container push**, or a **cross-function field-write effect**,
arriving **after** the closure is defined -- including the
launder-through-a-captured-container masking shape. It closes nothing more.
**Do not read the closed claim as "capture-internal sinks are closed" or "the
locally-resolved space is closed":** a capture-internal sink reached ONLY through
a NESTED LOCAL lambda binding is itself a locally-resolved outer closure whose
nested-only sink is STILL missed (residual 1 below). The following stay open,
each an honest, tested false negative that leaks at run time UNFLAGGED at both
tiers on both backends, or a disclosed sound over-report; each is asserted in
[`tests/test_ifc_branch_scoped_container.py`](../../tests/test_ifc_branch_scoped_container.py).

1. **A sink reached only through a NESTED LOCAL lambda (still open).** A closure
   whose body reaches the capture-internal sink ONLY through a nested
   local-lambda binding (`let inner = fun() => stdio.println(bag.data); let f =
   fun() => inner(); ...; f()`) is opaque to the summary walk, which resolves a
   body's calls to **named** (`fun` / method) callees only, never to a
   local-lambda binding -- the same limitation named callables have. The outer
   `f` IS locally resolved, so this is not an escaping case; the miss is the
   nested-lambda opacity. Asserted in
   `TestCaptureInternalSinkResidualStillDisclosed` (`nested_local_lambda_sink`).

2. **Closures that ESCAPE local resolution (still open).** A closure the caller
   cannot resolve to one certain lambda literal is not reached by the invocation
   check: an alias (`let g = f; g()`), a closure passed to a higher-order callee
   then invoked there (`apply(f)` where `apply(g)` calls `g()`), a returned
   closure, a reassigned `var`, or a call-result binding. Each stays UNFLAGGED
   though it leaks the secret on both backends; closing them needs a higher-order
   control-flow / points-to analysis Capa does not have. Asserted in
   `TestCaptureInternalSinkResidualStillDisclosed` (`escaping_alias`,
   `escaping_hof_invoked`), and on the result-sink side in
   `TestHofInvokedClosureResidualDisclosed` and
   `TestEscapingLambdaSinkResidualDisclosed`.

3. **Different-root / element-rooted points-to (still open, inherited).** The
   invocation check reads the capture's taint on the same `(root, field-path)`
   access-path channel the container and field-store fixes use, so it inherits
   that channel's points-to residuals: a container renamed out of the struct
   (`var lst = bag.items; lst.push(secret)`) taints the fresh local, not the
   captured `bag.items` (`TestFieldChainRenameResidualDisclosed`); a mutator
   whose receiver is rooted at a call or an index rather than a binding
   (`get_items(bag).push(secret)`, `arr[0].items.push(secret)`) has no
   `(root, field-path)` key at all (`TestCallIndexRootedReceiverResidualDisclosed`);
   and a struct reached through a container VALUE or ELEMENT (held as a `Map`
   value or a `List` element, mutated through its own binding and read via
   `.get(...)`) is the same different-root points-to family, which leaks on
   `1.30.1` alike and is documented in
   [`2026-08-10-ifc-cross-function-whole-struct-read.md`](2026-08-10-ifc-cross-function-whole-struct-read.md).

4. **Loop-carried read-before-write in the summary walk (still open,
   inherited).** The capture-side summary walks the body once in source order
   with no iteration fixpoint (the same summary-tier residual disclosed as
   residual 4 of
   [`2026-08-08-ifc-match-arm-container-leak.md`](2026-08-08-ifc-match-arm-container-leak.md)),
   so a capture read placed textually before a push inside a `while` / `for`
   that a later iteration would feed is not recorded as a sunk path. The
   intra-procedural loop-carried read is caught by the two-pass loop walk
   (`TestLoopFamilyLeaksStayFlagged`); the summary-tier one is not.

### Two safe over-reports (known, sound behaviour, not residual leaks)

Both of the following **flag** though nothing secret reaches the sink. They
over-report, never under-report, and are deliberately disclosed rather than
"fixed".

1. **A WHOLE / method read of a CLEAN sibling of a mutated struct.** A closure
   that sinks a captured struct through a WHOLE / method read (`bag.reveal()`,
   whose method returns only a public field) is FLAGGED when a DIFFERENT field is
   stored a secret after the closure is defined, because a whole read observes
   EVERY field taint of the root (the length-0 access-path query) and cannot tell
   the clean field it reveals from the stored sibling. It flags but leaks nothing
   (it prints the public value). This is the sound direction, at exact parity
   with the result-sink whole-read over-report disclosed with `1.30.0`; a
   FIELD-PRECISE read of a clean sibling stays clean. Asserted in
   `TestCaptureInternalSinkWholeReadSiblingOverReportDisclosed`.

2. **A before-def secret carries a duplicate diagnostic.** When the taint arrives
   BEFORE the closure is defined (the captured field is already secret at
   definition), the def-time body check AND the new invocation-site check both
   fire, differing in message and position. Both are sound and land on a
   genuinely-leaking program, so the duplicate reads as two findings, not a
   contradiction and not a false positive: no def-time suppression gate is used
   because it cannot soundly tell a secret non-sunk sibling from the sunk path
   (see the masking shape under "The fix"). Asserted in
   `TestCaptureInternalSinkBeforeDefFlagged`.

The whole-struct-read closure and its residuals from `1.29.0`, the loop-body
over-approximation and the assignment sibling-branch false positive disclosed
with `1.27.0`, and residual 1's nested-local-lambda and escaping portions all
stay open and are documented in their respective advisories. Residual 1 of the
`1.30.0` [`2026-08-10-ifc-lambda-flow-sensitivity.md`](2026-08-10-ifc-lambda-flow-sensitivity.md)
is RESOLVED here for its locally-resolved-direct / named-callee portion and
annotated accordingly there.

## Credit

Found and fixed during the internal hardening pass following the `1.30.1`
release, driven by adversarial dogfooding of the information-flow control. A
reviewer adjudicated the scope (the nested-local-lambda residual is itself a
locally-resolved outer closure, so the closed claim is narrowed to
directly-or-named-callee-reached sinks) and a pentester confirmed no new leak on
the leak-shape corpus, both backends.
