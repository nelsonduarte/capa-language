# Capa security advisory, 2026-08-08: cross-function information-flow param-carried read-back false negative

> **Status.** Published with the `1.26.0` release. The finding below is a
> silent information-flow false negative closed in the cross-function
> information-flow summary. It is claimed under the
> [`STABILITY.md`](../../STABILITY.md) **security exception** (the same
> soundness-fix carve-out Rust and Python follow) and is therefore shipped
> as a **MINOR** bump, not a MAJOR one. The rationale is stated below.

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
[`2026-07-03-soundness.md`](2026-07-03-soundness.md)) framed the class:
"the worst kind of hole" (a silent false negative), because the author
writes `@secret`, believes they are protected, and are not.

**CVSS-style vector (illustrative):**
`CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (~6.2). CVSS is an
imperfect fit here: the flaw is a soundness gap in a static verifier. The
score reflects a confidentiality-only break of the information-flow
noninterference guarantee, observable at run time, with no integrity,
availability, code-execution, or memory-safety impact.

**Affected versions:** `1.25.1` and earlier on the `1.x` line. The
cross-function information-flow summary that this false negative lives in
shipped in the `1.1` line (`feat: add cross-function information-flow
inference`, 2026-06-08, first tagged in the `v1.1.0` line). Before that
line there was no cross-function summary at all, so a `@secret` parameter
laundered through a callee to a public sink was equally undetected on the
`1.0.x` releases; the leak is therefore present across the `1.x` line, and
we state the range as `1.25.1` and earlier. The false negative was
concretely **reproduced on the released `1.25.1` binary** (see
Reproduction); the exact earliest affected release below `1.25.1` was
**not bisected** by executing each historical binary. This is the same
information-flow-laundering class as the 2026-06-16 (`1.3.0`) and
2026-07-03 (`1.15.0`) advisories, which stated their range as the release
before the fix "and earlier on the `1.x` line"; this advisory follows that
convention.

**Fixed in:** `1.26.0`.

**Reporter / process:** internal hardening pass for the `1.26.0`
release, driven by adversarial dogfooding of the information-flow
control. The fix was validated by four adversarial review rounds, a
pentester pass over a leak-shape corpus (every shape now flagged), and an
independent holistic review; the full suite grew from 5056 to 5086 tests
with zero regressions.

**Channel:** this advisory; cross-referenced from
[`SECURITY.md`](../../SECURITY.md) and the `1.26.0` `CHANGELOG.md` entry.

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
`1.15.0`), each shipped as a MINOR under the same exception.

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
the only pass that can see a leak routed through it. Before this fix,
`capa/analyzer/_ifc_summary.py` recorded a callee's write into a caller
container against the caller's own **parameters** (the mutation-TARGET
channel) but never reflected that write on the read-back of a fresh
caller-**local**. So the shape

- `main` passes a `@secret` value into a caller `leak`'s plain
  `secret: String` parameter;
- `leak` creates a fresh, unaliased local (an empty `List` / `Map` /
  `Set` / a freshly-constructed struct) and calls a user callee
  (`push_it(xs, secret)`, `stash(m, secret)`, `b.field = secret`, ...)
  that pushes `secret` into that local; and
- `leak` reads the value back out of the local and sends it to a public
  sink

produced **no** diagnostic: the local's read-back stayed public, `leak`'s
summary never marked its `secret` parameter sink-reaching, and the call
`leak(TOKEN, stdio)` in `main` was neither warned nor rejected under
`@strict_ifc`. The same gap applied when the pushing call sat in a
side-effecting `match`-arm **guard** (which runs on the path to later
arms) rather than in a plain statement.

### The fix

`capa/analyzer/_ifc_summary.py` now carries a distinct, **additive**
content channel. The callee's translated write raises the caller-local's
content label; that label is joined into `_taint_of` on a read of the
name, and it is applied **regardless** of whether the local is itself a
writable mutation target. The independence is load-bearing: the
mutation-target set is empty for a fresh or immutable-seeded local, so a
content write gated on a non-empty target set would close nothing.

The content channel is scoped **uniformly per branch**
(`_content_isolated` / `_content_merge`): each branch or `match` arm is
analyzed from a common pre-construct content snapshot in isolation, and
every branch's delta is unioned into the enclosing scope only **after**
all branches are walked (a deferred union). So one branch's mutation
neither contaminates a mutually-exclusive sibling branch's read (no false
positive) nor is lost to a read after the construct (no false negative).
A branch condition (`if` / `elif`) and a `match`-arm guard run on the
path to later branches / arms, so a side-effecting one's mutation is
evaluated in the enclosing content scope and propagates, matching runtime
control flow. The trailing / implicit-return expression of a value block
is walked exactly once, so a branching tail expression's branches are not
re-isolated from an already-merged baseline.

The leak now emits, at the call site, a **warning by default** and a
**hard error under `@strict_ifc`**:

```
information-flow: a @secret value is passed to 'leak' as secret, which
reaches a public sink inside 'leak' (it sends data out of the program).
Route it through declassify(value, reason: "...") if this disclosure is
intended.
```

This closes the fresh, unaliased, param-carried read-back shape
**uniformly across control-flow positions**: straight-line, the `if` /
`elif` / `else` and `match` statement forms, the `if ... then ... else`
and `match` expression forms, `while` and `for` loop bodies, and
side-effecting `match`-arm guards, in any position (mid-body, tail, a
let-binding, or nested). Covered by
`tests/test_ifc_param_carried_readback.py`.

## Reproduction

```capa
const TOKEN: @secret String = "s3cr3t"

fun push_it(xs: List<String>, v: String)
    xs.push(v)

fun leak(secret: String, stdio: Stdio)
    var xs: List<String> = []
    push_it(xs, secret)
    match xs.get(0)
        Some(x) -> stdio.println(x)
        None -> stdio.println("empty")

fun main(stdio: Stdio)
    leak(TOKEN, stdio)
```

On the released **`1.25.1`** binary:

- `capa --check` reports `ok` and exits 0 (no information-flow warning).
- adding `@strict_ifc()` to `main` still reports `ok` and exits 0 (no
  error).
- `capa --run` prints `s3cr3t` and exits 0: the `@secret` value reaches
  the public sink at runtime.

On **`1.26.0`**:

- `capa --check` emits the information-flow **warning** above and exits 0
  (default tier is warn-only).
- with `@strict_ifc()` on `main`, `capa --check` emits the same text as
  an **error** and exits 1.

The runtime leak is backend-independent (the analyzer is what should
reject it); the test suite asserts identical output on the Python and
Wasm backends for these shapes.

## Impact

A silent secret-disclosure path: a `@secret` value (PII, a token, a key)
laundered to a public sink through a helper that mutates a fresh caller
local, or through a side-effecting `match`-arm guard, with no diagnostic
at either tier. The author annotated the value `@secret`, and neither the
default warning nor the `@strict_ifc` hard error fired, so a build gating
noninterference on `@strict_ifc` passed while the secret escaped at
runtime.

## Remediation

Upgrade to **`1.26.0`**. After upgrading, the flow is a warning by
default and a hard error under `@strict_ifc`. If a specific disclosure is
intended, route the value through `declassify(value, reason: "...")`,
which the analyzer records as an audited, deliberate declassification.

Because the default tier only warns, programs that want the guarantee
enforced as a build gate should run the analyzer under `@strict_ifc` (or
treat the information-flow warning as an error in CI).

## Scope and known residuals

This fix closes the **fresh, unaliased, param-carried read-back** shape,
uniformly across control-flow positions. The following residuals stay
open and are stated so the boundary of the fix is explicit. Each is a
false **negative** (a missed leak) except residual 3, which is a
precision over-approximation (a possible false **positive** in the safe
direction), and the last, which is a pre-existing, unrelated false
positive on a different channel.

1. **The general aliasing / escape case.** A local that escapes, is
   aliased to a second name, is stored into another structure, is
   returned and re-entered, is mutated by a deeper untracked path, or is
   mutated by an **invoked lambda** that captured it, is not tracked.
   This is fundamental without a points-to analysis, which Capa does not
   have.
2. **Loop-carried read-before-write.** A read placed textually **before**
   a cross-function push inside a `while` / `for`, where a later
   iteration would feed the read, is not caught: the loop body is walked
   once in source order with no iteration fixpoint. "Closed uniformly
   inside `while` / `for`" means within a single pass, not across
   loop-carried ordering.
3. **Whole-value rebind precision over-approximation.** The additive
   content channel is monotone (only ever unioned into, never cleared),
   so a whole-value rebind of the local does not lower its accumulated
   content label; it can over-report in the safe (secret) direction. This
   mirrors the existing env channel's monotone accumulation and never
   under-reports a leak.
4. **Pre-existing env-channel direct-push cross-branch false positive
   (unrelated).** A secret pushed **directly** in the caller's own frame
   (tracked by the flat, monotone env channel, not the content channel)
   in one branch and read in a mutually-exclusive sibling branch can be
   over-reported. This is a pre-existing false positive on the env
   channel and is **not** introduced, addressed, or worsened by this
   change, which scoped only the content channel per branch and left the
   env channel as it was.

## Precision (no false positive introduced by the fix)

The fix preserves precision on the closed shape: a `declassify`, a
sibling local, a written-but-unread local, an escaping struct, a tail
read before the push, plain public data, and a pure (non-mutating)
`match`-arm guard all stay clean. The per-branch scoping was added
specifically so a cross-function mutation in one branch is not seen by a
mutually-exclusive sibling branch's read.

## Credit

Found and fixed during the internal hardening pass for the `1.26.0`
release, driven by adversarial dogfooding of the information-flow
control.
