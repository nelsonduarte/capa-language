# Capa security advisory, 2026-08-09: information-flow field-chain-receiver container-mutation false negative

> **Status.** Published with the `1.28.0` release. The finding below is a
> silent information-flow false negative closed in the intra-procedural
> information-flow pass. It is claimed under the
> [`STABILITY.md`](../../STABILITY.md) **security exception** (the same
> soundness-fix carve-out Rust and Python follow) and is therefore shipped
> as a **MINOR** bump, not a MAJOR one. The rationale is stated below. It
> follows on from
> [`2026-08-08-ifc-match-arm-container-leak.md`](2026-08-08-ifc-match-arm-container-leak.md)
> (shipped with `1.27.0`), which branch-scoped the same container-mutation
> taint; this advisory extends that taint from a plain-identifier receiver
> to a field-chain receiver.

This advisory satisfies the `STABILITY.md` requirement that a security
fix changing observable behaviour without a major bump "ships with a
security advisory ... [that] states explicitly what changed and why the
change is not subject to the major-bump rule."

**Severity:** Low to moderate. Confidentiality impact only (a silent
information-flow / noninterference false negative). It is scoped down by
three conditions that must all hold: the data is annotated `@secret`; the
program has the specific field-chain-mutator-then-read shape
(`bag.items.push(secret)` on a local struct, then a read of `bag.items`);
and there is a public sink. The information-flow check is a **warning by
default** and a **hard error only under `@strict_ifc`**, and the
noninterference guarantee is claimed **only under `@strict_ifc`**; the false
negative removed both signals, so a build that gates noninterference on
`@strict_ifc` passed while laundering the secret. No integrity or
availability impact, and no bypass of the capability discipline itself.
Consistent with how the prior IFC laundering advisories
([`2026-06-16-soundness.md`](2026-06-16-soundness.md),
[`2026-07-03-soundness.md`](2026-07-03-soundness.md),
[`2026-08-08-ifc-param-carried-readback.md`](2026-08-08-ifc-param-carried-readback.md),
[`2026-08-08-ifc-match-arm-container-leak.md`](2026-08-08-ifc-match-arm-container-leak.md))
framed the class: "the worst kind of hole" (a silent false negative),
because the author writes `@secret`, believes they are protected, and are
not.

**CVSS-style vector (illustrative):**
`CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` (~5.3). CVSS is an imperfect
fit here: the flaw is a soundness gap in a static verifier. The score
reflects a confidentiality-only break of the information-flow
noninterference guarantee, observable at run time, with no integrity,
availability, code-execution, or memory-safety impact; `AC:H` reflects that
the specific field-chain-mutator-then-read shape and `@secret` annotation
must all be present.

**Affected versions:** `1.27.0` and earlier on the `1.x` line. The false
negative lives in the intra-procedural container-mutation taint, which
fired only when the mutator's receiver was a plain identifier; a field-chain
receiver was untracked. That plain-identifier restriction predates the
`1.27.0` branch-scoping and has existed since the container-mutation taint
was introduced, so a `@secret` inserted through a field-chain receiver and
read back to a public sink was equally undetected on earlier `1.x`
releases. The false negative was concretely **reproduced on the released
`1.27.0` binary** (see Reproduction); the exact earliest affected release
below `1.27.0` was **not bisected** by executing each historical binary.
This is the same information-flow-laundering class as the 2026-06-16
(`1.3.0`), 2026-07-03 (`1.15.0`), and the two 2026-08-08 advisories
(`1.26.0` / `1.27.0`), which stated their range as the release before the
fix "and earlier on the `1.x` line"; this advisory follows that convention.

**Fixed in:** `1.28.0`.

**Reporter / process:** internal hardening pass following the `1.27.0`
release, driven by adversarial dogfooding of the information-flow control.
The fix commits are `8ebd4dc` (the analyzer change) and `e94f555` (the
residual-disclosure correction). Covered by
[`tests/test_ifc_branch_scoped_container.py`](../../tests/test_ifc_branch_scoped_container.py),
where the closed cases and the three residual classes are asserted.

**Channel:** this advisory; cross-referenced from
[`SECURITY.md`](../../SECURITY.md) and the `1.28.0` `CHANGELOG.md` entry.

## Why this is a security fix, not a breaking change

The analyzer's intra-procedural information-flow pass **failed to follow** a
`@secret` value across a container mutation a first-class, machine-checked
Capa security property depends on: information-flow control over `@secret`
data, in scope per [`SECURITY.md`](../../SECURITY.md) ("Compilation accepts
a program where a `@secret` value reaches a public sink that the analyzer
should reject"). The prior behaviour was a soundness bug, so tightening it
falls under the `STABILITY.md` security exception and does not force a major
bump. The direction of the change is flag-more: only programs that were
already unsound (a `@secret` reaching a public sink with no `declassify`)
are affected. It ships as a **MINOR** bump, matching every prior
static-analysis-tightening IFC soundness fix (`1.2.0`, `1.3.0`, `1.4.0`,
`1.15.0`, `1.26.0`, `1.27.0`), each shipped as a MINOR under the same
exception.

## Details

Capa's information-flow control is a first-class security property: a
`@secret` value must not reach a public sink (`Stdio.println` / `eprintln`,
`Net.post`, `panic`, a sink-reaching parameter of a further function, ...)
without an explicit `declassify`. Containers (`List` / `Set` / `Map`) do
not track a per-element label, so a mutating method that inserts a `@secret`
value must raise a taint on the container, or a later read would launder the
secret back to public. The `1.27.0` release recorded that taint in a
separate, branch-scoped, per-binding channel, joined into a binding's label
only when the container is **read**.

That channel keyed the taint on the **binding alone**, and the mutation was
recorded only when the mutator's receiver was a **plain identifier**
(`xs.push(secret)`). A mutation through a **field-chain receiver** on a
local struct was silently dropped:

- `bag.items.push(secret)` (`List.push`),
- `bag.tags.add(secret)` (`Set.add`),
- `bag.m.set(k, secret)` (`Map.set`),
- nested `o.inner.items.push(secret)` (depth > 1),

where `bag` / `o` is a local struct. Because the field-chain mutation was
never recorded, a later read of that same path (`bag.items.get(0)`) came out
**public**, and sending it to a public sink produced **no** diagnostic: no
default warning, and no `@strict_ifc` error. The identical shape written
with a plain-identifier local (`var xs: List<String> = []; xs.push(secret);
xs.get(0)`) was flagged. This is the field-chain analogue of the plain
container-mutation read-back the `1.27.0` branch-scoping already handled.

### The fix

The change (`capa/analyzer/_ifc.py`, commit `8ebd4dc`) keys the
branch-scoped container-mutation taint on the `(root-binding, field-path)`
the container lives at, instead of the binding alone:

- a plain identifier (`xs`) is path `()`;
- an Ident-rooted field chain (`bag.items`, nested `bag.a.b`) is its field
  names (`("items",)`, `("a", "b")`).

The mutation is recorded at that key, and on a field **read** the taint is
joined back for every recorded key at or below the read path (reading
`bag.items` observes a push into `bag.items`; reading the sub-struct
`bag.a` observes a push into `bag.a.b`). The root binding is left
**un-escaped**: a disjoint sibling path (`bag.other`) matches nothing and
stays public, and, because the channel is still isolated per branch and
deferred-unioned back across `if` / `elif` / `else`, `if ... then ... else`,
and `match`, a mutually-exclusive branch's read is not polluted. So the fix
closes the read-back for `List.push` / `Set.add` / `Map.set` and nested
depth **without** re-introducing the sibling-field / branch-scope false
positives that commits `b895ca6` / `4c69a02` removed for the plain-identifier
case.

The leak now emits, at the sink, a **warning by default** and a **hard error
under `@strict_ifc`**:

```
information-flow: a @secret value reaches Stdio.println (argument 1), a
public sink that sends data out of the program. Route it through
declassify(value, reason: "...") if this disclosure is intended.
```

Inside a `while` / `for` body the container-mutation taint is, as before,
deliberately **not** branch-isolated (the loop walks its body twice, so a
push anywhere in the body taints every read of that path in the body): a
sound MAY over-approximation that catches the intra loop-carried
read-before-write leak. A field-chain push inside a loop stays flagged.
Covered by
[`tests/test_ifc_branch_scoped_container.py`](../../tests/test_ifc_branch_scoped_container.py).

## Reproduction

```capa
const TOKEN: @secret String = "s3cr3t"

type Bag { items: List<String> }

fun leak(stdio: Stdio, secret: @secret String)
    var bag: Bag = Bag { items: [] }
    bag.items.push(secret)
    match bag.items.get(0)
        Some(x) -> stdio.println(x)
        None -> stdio.println("empty")

fun main(stdio: Stdio)
    leak(stdio, TOKEN)
```

On the released **`1.27.0`** binary:

- `capa --check` reports `ok (4 items, 21 expressions typed, 9 bindings)`
  and exits 0 (no information-flow warning).
- adding `@strict_ifc()` to `leak` still reports `ok` and exits 0 (no
  error): the `@strict_ifc` build passes with **zero** errors while the
  program launders the secret.
- `capa --run` and `capa --run --wasm` both print `s3cr3t`: the `@secret`
  value reaches the public sink at runtime on both backends.

On **`1.28.0`**:

- `capa --check` emits the information-flow **warning** above and exits 0
  (default tier is warn-only).
- with `@strict_ifc()` on `leak`, `capa --check` emits the same text as an
  **error** and exits 1.

`Set.add` (`bag.tags.add(secret)`), `Map.set` (`bag.m.set(k, secret)`), and
a nested path (`o.inner.items.push(secret)`) behave identically: unflagged
on `1.27.0`, a warning by default and a hard error under `@strict_ifc` on
`1.28.0`, printing `s3cr3t` on both backends.

The runtime leak is backend-independent (the analyzer is what should reject
it); the shipped test suite asserts the secret on the Python and Wasm
backends for these shapes.

## Impact

A silent secret-disclosure path: a `@secret` value (PII, a token, a key)
placed into a container held in a struct field and later read back and sent
to a public sink, with no diagnostic at either tier. The author annotated
the value `@secret`, and neither the default warning nor the `@strict_ifc`
hard error fired, so a build gating noninterference on `@strict_ifc` passed
while the secret escaped at runtime.

## Remediation

Upgrade to **`1.28.0`**. After upgrading, the flow is a warning by default
and a hard error under `@strict_ifc`. If a specific disclosure is intended,
route the value through `declassify(value, reason: "...")`, which the
analyzer records as an audited, deliberate declassification.

Because the default tier only warns, programs that want the guarantee
enforced as a build gate should run the analyzer under `@strict_ifc` (or
treat the information-flow warning as an error in CI).

## Scope and known residuals

This fix closes the **intra-procedural field-chain container-mutator
read-back on the container's DECLARED root** (`List.push` / `Set.add` /
`Map.set`, nested depth), and nothing more. It does **not** close
whole-struct reads or any aliasing residual; it closes **field-path reads of
the same root** only. The following residuals are three DISTINCT mechanisms,
stated separately so the boundary of the fix is explicit. Each leaks at run
time and stays UNFLAGGED at both tiers on both backends; each is asserted in
[`tests/test_ifc_branch_scoped_container.py`](../../tests/test_ifc_branch_scoped_container.py).

1. **Receiver not rooted at a binding (still open).** A mutator whose
   receiver is rooted at a call or an index rather than a binding
   (`get_items(bag).push(secret)`, `arr[0].items.push(secret)`) has no
   `(root, field-path)` key at all, so the push itself is untracked and the
   later read of the same container is not caught. Lists are reference
   values, so the push through the returned / indexed alias mutates the very
   container the read then observes; it leaks, unflagged. Asserted in
   `TestCallIndexRootedReceiverResidualDisclosed`.

2. **Whole-struct read of the SAME root (still open, the most idiomatic
   residual).** After `bag.items.push(secret)` the taint **is** keyed, on
   `(bag, ("items",))`. But reading or passing the **whole** `bag` misses
   it: `"${bag}"` interpolation (through a `to_string` method), a method
   whose body reads the field (`bag.reveal()`), or passing the whole `bag`
   to a callee that reads `bag.items` (`foo(bag)`), each consults only the
   exact empty-path key `(bag, ())` and never the tainted prefix. This is
   the bare whole-read **asymmetry** (a whole-struct read does an exact-key
   lookup; a field read prefix-scans), **NOT** a points-to gap: the root
   **is** keyed. Closing it needs field-sensitivity-under-escape; a naive
   whole-read prefix-scan would re-introduce the public-sibling false
   positives commits `b895ca6` / `4c69a02` removed, so this is a design item,
   not a quick fix. This is the most idiomatic shape (logging or serialising
   a struct after putting a secret into one of its fields), so it is called
   out first among the open cases. Asserted in
   `TestWholeStructSameRootReadResidualDisclosed`.

3. **Different-root points-to (still open).** The container is reached
   through a root the taint is not keyed on, which only a points-to analysis
   (which Capa does not have) could close:
   - rename out of the struct: `var lst = bag.items; lst.push(secret)` taints
     the fresh local `lst`, not `bag.items`, so the `bag.items` read-back is
     missed (`TestFieldChainRenameResidualDisclosed`);
   - whole-struct alias: `var b2 = bag; b2.items.push(secret)` then
     `read bag.items` mutates the same container through a **different** root
     symbol;
   - embed-then-mutate: pushing into a sub-struct's container through its own
     root after embedding it in an outer struct, then reading through the
     outer.

### A safe over-report (a known, sound behaviour, not a residual leak)

Reassigning the container's root binding, or the field itself, to a fresh
leak-free value after a push and then reading that field keeps the read
**FLAGGED**: the container-mutation taint is monotonic, so once
`(root, field-path)` is tainted it stays tainted.

```capa
bag.items.push(secret)
bag = Bag { items: [] }      // or: bag.items = []
match bag.items.get(0)       // still flagged (a warning by default, an
    Some(x) -> stdio.println(x)   // error under @strict_ifc)
    None -> stdio.println("empty")
```

At run time this program prints the public `"empty"`; nothing secret reaches
the sink. Clearing the taint on reassignment is deliberately **not** done,
because a reassignment to another tainted value would then become a real
false negative. This is a sound, safe-direction over-approximation (it
over-reports, never under-reports), matching the plain-identifier channel;
it is asserted in `TestReassignRootSafeOverReport` and should not be
"fixed".

## Credit

Found and fixed during the internal hardening pass following the `1.27.0`
release, driven by adversarial dogfooding of the information-flow control.
