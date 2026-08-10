# Capa security advisory, 2026-08-10: information-flow whole-struct-read container-mutation false negative

> **Status.** Published with the `1.29.0` release. The finding below is a
> silent information-flow false negative closed in the intra-procedural
> information-flow pass. It is claimed under the
> [`STABILITY.md`](../../STABILITY.md) **security exception** (the same
> soundness-fix carve-out Rust and Python follow) and is therefore shipped
> as a **MINOR** bump, not a MAJOR one. The rationale is stated below. It
> closes the whole-struct-read residual disclosed with
> [`2026-08-09-ifc-field-receiver-container-leak.md`](2026-08-09-ifc-field-receiver-container-leak.md)
> (shipped with `1.28.0`), which keyed the container-mutation taint on a
> `(root, field-path)` and caught a FIELD read of the pushed path; this
> advisory extends that catch to a read of the WHOLE struct.

This advisory satisfies the `STABILITY.md` requirement that a security
fix changing observable behaviour without a major bump "ships with a
security advisory ... [that] states explicitly what changed and why the
change is not subject to the major-bump rule."

**Severity:** Low to moderate. Confidentiality impact only (a silent
information-flow / noninterference false negative). It is scoped down by
three conditions that must all hold: the data is annotated `@secret`; the
program has the specific inline-push-then-whole-struct-read shape
(`bag.items.push(secret)` on a local struct, then a read or pass of the
whole `bag`); and there is a public sink. The information-flow check is a
**warning by default** and a **hard error only under `@strict_ifc`**, and the
noninterference guarantee is claimed **only under `@strict_ifc`**; the false
negative removed both signals, so a build that gates noninterference on
`@strict_ifc` passed while laundering the secret. No integrity or
availability impact, and no bypass of the capability discipline itself.
Consistent with how the prior IFC laundering advisories
([`2026-06-16-soundness.md`](2026-06-16-soundness.md),
[`2026-07-03-soundness.md`](2026-07-03-soundness.md),
[`2026-08-08-ifc-param-carried-readback.md`](2026-08-08-ifc-param-carried-readback.md),
[`2026-08-08-ifc-match-arm-container-leak.md`](2026-08-08-ifc-match-arm-container-leak.md),
[`2026-08-09-ifc-field-receiver-container-leak.md`](2026-08-09-ifc-field-receiver-container-leak.md))
framed the class: "the worst kind of hole" (a silent false negative),
because the author writes `@secret`, believes they are protected, and are
not.

**CVSS-style vector (illustrative):**
`CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` (~5.3). CVSS is an imperfect
fit here: the flaw is a soundness gap in a static verifier. The score
reflects a confidentiality-only break of the information-flow
noninterference guarantee, observable at run time, with no integrity,
availability, code-execution, or memory-safety impact; `AC:H` reflects that
the specific inline-push-then-whole-struct-read shape and `@secret`
annotation must all be present.

**Affected versions:** `1.28.0` and earlier on the `1.x` line. On `1.28.0`
the container-mutation taint was keyed on the `(root-binding, field-path)`
the container lives at and caught a FIELD read of the pushed path, but a
read of the WHOLE struct did an exact empty-path lookup that never consulted
the tainted field prefix, so the whole struct laundered the secret back to
public. This was **`1.28.0`'s own disclosed residual** (the whole-struct
read of the same root). On earlier `1.x` releases the field-chain push was
not tracked at all (the subject of the `1.28.0` advisory), so the same
program was equally undetected. The false negative was concretely
**reproduced on the released `1.28.0` binary** (see Reproduction); the exact
earliest affected release below `1.28.0` was **not bisected** by executing
each historical binary. This is the same information-flow-laundering class as
the 2026-06-16 (`1.3.0`), 2026-07-03 (`1.15.0`), and the three 2026-08
advisories (`1.26.0` / `1.27.0` / `1.28.0`), which stated their range as the
release before the fix "and earlier on the `1.x` line"; this advisory follows
that convention.

**Fixed in:** `1.29.0`.

**Reporter / process:** internal hardening pass following the `1.28.0`
release, driven by adversarial dogfooding of the information-flow control.
The fix commits are `5934f48`, `a05b4ae`, and `1a41a8a` (the analyzer
changes) and `f554eea` (a residual-disclosure widening, docs and tests
only). Covered by
[`tests/test_ifc_branch_scoped_container.py`](../../tests/test_ifc_branch_scoped_container.py),
where the closed cases and each residual are asserted.

**Channel:** this advisory; cross-referenced from
[`SECURITY.md`](../../SECURITY.md) and the `1.29.0` `CHANGELOG.md` entry.

## Why this is a security fix, not a breaking change

The analyzer's intra-procedural information-flow pass **failed to follow** a
`@secret` value across a whole-struct read a first-class, machine-checked
Capa security property depends on: information-flow control over `@secret`
data, in scope per [`SECURITY.md`](../../SECURITY.md) ("Compilation accepts
a program where a `@secret` value reaches a public sink that the analyzer
should reject"). The prior behaviour was a soundness bug, so tightening it
falls under the `STABILITY.md` security exception and does not force a major
bump. The direction of the change is flag-more: only programs that were
already unsound (a `@secret` reaching a public sink with no `declassify`)
are affected. It ships as a **MINOR** bump, matching every prior
static-analysis-tightening IFC soundness fix (`1.2.0`, `1.3.0`, `1.4.0`,
`1.15.0`, `1.26.0`, `1.27.0`, `1.28.0`), each shipped as a MINOR under the
same exception.

## Details

Capa's information-flow control is a first-class security property: a
`@secret` value must not reach a public sink (`Stdio.println` / `eprintln`,
`Net.post`, `panic`, a sink-reaching parameter of a further function, ...)
without an explicit `declassify`. Containers (`List` / `Set` / `Map`) do
not track a per-element label, so a mutating method that inserts a `@secret`
value must raise a taint on the container, or a later read would launder the
secret back to public. The `1.28.0` release keyed that taint on the
`(root-binding, field-path)` the container lives at (a plain identifier is
path `()`, a field chain is its field names) and joined it back on a **field
read** at or below that path, so `bag.items.push(secret)` followed by
`bag.items.get(0)` was caught.

That join was an **exact / prefix scan on the read's own access path**, and a
read of the **whole** struct has access path `()`. So a whole-value read of
`bag` looked up only the exact empty-path key `(bag, ())` and never the
tainted `(bag, ("items",))` prefix. After an **inline** field-chain push on a
local struct, reading or passing the WHOLE struct was silently public:

- `"${bag}"` interpolation (through a `to_string` method that reads the
  field),
- a getter or method whose receiver is the struct (`bag.reveal()`, or a
  method that itself sinks the whole receiver, `bag.dump(stdio)`),
- passing the whole `bag` to a sink-reaching callee (`show(bag)`), including
  a callee that sinks the tainted field among clean siblings,

each after `bag.items.push(secret)` on a caller-local `bag`. Because the
whole-value read never observed the tainted field prefix, the value came out
**public**, and sending it to a public sink produced **no** diagnostic: no
default warning, and no `@strict_ifc` error. The identical program that read
the field directly (`bag.items.get(0)`) was flagged by `1.28.0`. This is the
whole-struct-read analogue of the field read the `1.28.0` field-keying
already handled, and is exactly the residual `1.28.0` disclosed.

### The fix

The change (`capa/analyzer/_ifc.py` and `capa/analyzer/_ifc_summary.py`,
commits `5934f48` / `a05b4ae` / `1a41a8a`) makes a whole-aggregate read
prefix-scan the `(root, field-path)` container channel, the length-0
access-path query `x.f^0 = x` from the access-path (FlowDroid) model:

- the effective label of an expression is split into a **container-free
  base** (data-flow / field-store / declared-field label, excluding the
  container channel) and a **container contribution** joined in once at the
  read's own access path;
- a **WHOLE** read of a struct binding joins in every field taint of its root
  (a prefix scan over `(root, *)`), so it observes a push into any field;
- a **FIELD** read still scans only taints at or below its own path, and an
  **escaped** field read falls back to the receiver's base label (no
  container channel), so a public sibling field (`bag.other`) stays clean.

So the fix closes the whole-struct read for `List.push` / `Set.add` /
`Map.set` and nested depth **without** re-introducing the sibling-field /
branch-scope false positives that `1.26.0`, `1.27.0`, and `1.28.0` removed.

The leak now emits, at the sink, a **warning by default** and a **hard error
under `@strict_ifc`**:

```
information-flow: a @secret value reaches Stdio.println (argument 1), a
public sink that sends data out of the program. Route it through
declassify(value, reason: "...") if this disclosure is intended.
```

When the whole struct is passed to a callee, the sink is inside the callee
and the wording names the parameter:

```
information-flow: a @secret value is passed to 'show' as bag, which reaches
a public sink inside 'show' (it sends data out of the program). Route it
through declassify(value, reason: "...") if this disclosure is intended.
```

### A coupled precision gain (not a security claim)

The same release moves the **cross-function** container-mutation effect onto
the field-keyed `(root, field-path)` channel (`5934f48`) and adds a read-side
**field-qualified sink summary** (`1a41a8a`). Two consequences, both
precision, not security:

- A clean sibling read after a callee pushes a secret into a **different**
  field (`fill(bag, secret)` where `fill` does `bag.items.push`, then reading
  the public `bag.other`) is no longer flagged. `1.28.0` over-reported this
  (a false positive), because its cross-function effect raised the whole
  struct's label.
- Passing a whole struct to a callee that sinks only a clean sibling
  (`show_note(bag)` where `show_note` sinks `bag.note`, with the secret in
  `bag.secret_items`) stays clean, rather than being over-tainted by the new
  whole-read prefix scan.

The callee-push whole-read (a callee pushes into `bag.items`, the caller
reads the whole `bag` back) was **already caught on `1.28.0`** through the
whole-value carrier of the old cross-function effect, and it stays caught; a
within-release regression that briefly dropped it while the effect was
being re-keyed is locked out by a regression test. This release does **not**
newly close that direction; it preserves the catch while removing the
false positive above.

## Reproduction

```capa
const TOKEN: @secret String = "s3cr3t"

type Bag { items: List<String> }

impl Bag
    fun to_string(self) -> String
        match self.items.get(0)
            Some(x) -> return x
            None -> return "empty"

fun leak(stdio: Stdio, secret: @secret String)
    var bag: Bag = Bag { items: [] }
    bag.items.push(secret)
    stdio.println("${bag}")

fun main(stdio: Stdio)
    leak(stdio, TOKEN)
```

On the released **`1.28.0`** binary:

- `capa --check` reports `ok (5 items, 21 expressions typed, 9 bindings)`
  and exits 0 (no information-flow warning).
- adding `@strict_ifc()` to `leak` still reports `ok` and exits 0 (no
  error): the `@strict_ifc` build passes with **zero** errors while the
  program launders the secret.
- `capa --run` and `capa --run --wasm` both print `s3cr3t`: the `@secret`
  value reaches the public sink at runtime on both backends.

On **`1.29.0`**:

- `capa --check` emits the information-flow **warning** above and exits 0
  (default tier is warn-only).
- with `@strict_ifc()` on `leak`, `capa --check` emits the same text as an
  **error** and exits 1.

The getter / method shapes (`bag.reveal()`, `bag.dump(stdio)`) and the
pass-to-callee shape (`show(bag)`, including a callee that sinks the tainted
field among clean siblings) behave identically: unflagged on `1.28.0` with
zero `@strict_ifc` errors, a warning by default and a hard error under
`@strict_ifc` on `1.29.0`, printing `s3cr3t` on both backends.

The runtime leak is backend-independent (the analyzer is what should reject
it); the shipped test suite asserts the secret on the Python and Wasm
backends for these shapes.

## Impact

A silent secret-disclosure path: a `@secret` value (PII, a token, a key)
placed into a container held in a struct field and later logged or
serialised by reading the WHOLE struct, or passed whole to a helper that
sinks it, with no diagnostic at either tier. The author annotated the value
`@secret`, and neither the default warning nor the `@strict_ifc` hard error
fired, so a build gating noninterference on `@strict_ifc` passed while the
secret escaped at runtime. This is the most idiomatic shape of the class
(logging or serialising a struct after putting a secret into one of its
fields).

## Remediation

Upgrade to **`1.29.0`**. After upgrading, the flow is a warning by default
and a hard error under `@strict_ifc`. If a specific disclosure is intended,
route the value through `declassify(value, reason: "...")`, which the
analyzer records as an audited, deliberate declassification.

Because the default tier only warns, programs that want the guarantee
enforced as a build gate should run the analyzer under `@strict_ifc` (or
treat the information-flow warning as an error in CI).

## Scope and known residuals

This fix closes the **whole-struct read of the container's DECLARED root
after an inline field-chain push** (`List.push` / `Set.add` / `Map.set`,
nested depth), and nothing more. **Do not read the closed claim as "any
same-root read-back is caught"**: the lambda-flow residual below falsifies
that. The following residuals stay open, each an honest, tested false
negative that leaks at run time UNFLAGGED at both tiers on both backends, or
a disclosed sound over-report; each is asserted in
[`tests/test_ifc_branch_scoped_container.py`](../../tests/test_ifc_branch_scoped_container.py).

1. **Lambda-flow sensitivity (still open, the most serious residual, and
   MORE GENERAL than what this release closes).** A lambda's capture / flow
   labels are stamped at its **definition**; the analyzer neither
   re-reflects a later mutation of a captured binding nor threads a caller's
   taint into a locally-invoked lambda's parameter that reaches a sink. So
   both of these leak, unflagged at both tiers on both backends:
   - a bare `@secret` passed to a local lambda that sinks it,
     `let g: Fun(String) -> Unit = fun(s: String) -> Unit => sink_str(s, stdio); g(secret)`
     (the sink-side face); the direct named call `sink_str(secret, stdio)` is
     caught, so the gap is the lambda indirection, not the sink;
   - a container captured by a closure defined **before** a push and read
     through the closure **after** (the capture-side face); a closure defined
     **after** the push is caught.

   Both are the same single **pre-existing** (`1.28.0` and earlier) deferred
   lambda-flow item, and it is more general than the whole-struct read closed
   here (it needs no container, capture, or push-ordering). It is **not**
   closed by this release and is tracked for a separate lambda-flow fix. As of
   `1.29.0` both faces were asserted as disclosed residuals; a subsequent
   Stage A change closes the **sink-side** face for a locally-resolvable lambda
   or an IIFE (now asserted in `TestSecretIntoLocalLambdaSinkClosed`, with the
   escaping shapes in `TestEscapingLambdaSinkResidualDisclosed`), while the
   **capture-side** face stays disclosed in
   `TestClosureCaptureBeforePushResidualDisclosed` (deferred to Stage B).

2. **Different-root points-to (still open).** The container is reached
   through a root the taint is not keyed on, which only a points-to analysis
   (which Capa does not have) could close:
   - inline push through a whole-struct alias: `var b2 = bag;
     b2.items.push(secret)` then `read bag.items` mutates the same container
     through a **different** root symbol
     (`TestFieldChainRenameResidualDisclosed` covers the sibling rename;
     the inline whole-struct alias push is the same points-to family);
   - field-chain rename out of the struct: `var lst = bag.items;
     lst.push(secret)` taints the fresh local, not `bag.items`, so the
     `bag.items` read-back is missed (`TestFieldChainRenameResidualDisclosed`);
   - embed-then-mutate: pushing into a sub-struct's container through its own
     root after embedding it in an outer struct, then reading through the
     outer.

3. **Receiver not rooted at a binding (still open).** A mutator whose
   receiver is rooted at a call or an index rather than a binding
   (`get_bag(bag).items.push(secret)`, `arr[0].items.push(secret)`) has no
   `(root, field-path)` key at all, so the push itself is untracked and the
   later read of the same container is not caught. Lists are reference
   values, so the push through the returned / indexed alias mutates the very
   container the read then observes; it leaks, unflagged. Asserted in
   `TestCallIndexRootedReceiverResidualDisclosed`.

### Two safe over-reports (known, sound behaviour, not residual leaks)

Both of the following **flag** though nothing secret reaches the sink (they
print the public value at run time). They over-report, never under-report,
and are deliberately disclosed rather than "fixed".

1. **Clean sibling through a whole-value alias taken after the push.**
   `var b2 = bag` created **after** `bag.items.push(secret)`, then reading a
   clean sibling `b2.other`: the copy reads `bag` whole (which now observes
   the container taint) and collapses to a whole-value `@secret` on `b2`,
   which has no per-field map, so the sibling read falls back to it and is
   flagged. This is the sound direction: the same collapse correctly catches
   a read of the **tainted** field through the copy, so clearing the sibling
   needs alias-group-aware per-field tracking (a points-to-adjacent change).
   A copy made **before** the push keeps field precision and is clean.
   Asserted in `TestWholeCopySiblingOverReportDisclosed`.

2. **Clean sibling of a cross-function field store.** A callee that does a
   whole-value field store (`bag.secret_field = secret`) keeps the
   whole-value carrier by design (a whole or getter read must still observe
   it), so a later read of a clean sibling of that struct is flagged though
   nothing leaks.

The monotone reassignment over-report and the loop-body over-approximation
disclosed with `1.27.0` and `1.28.0` also stay open and are documented there.

## Credit

Found and fixed during the internal hardening pass following the `1.28.0`
release, driven by adversarial dogfooding of the information-flow control.
