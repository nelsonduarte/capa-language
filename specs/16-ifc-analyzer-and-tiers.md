# 16. IFC: the analyzer, the tiers and the cross-function analysis

> **What this chapter covers.** How IFC is enforced: the two tiers
> (the warn-then-enforce default versus the fail-closed
> `@strict_ifc()` attribute) over the same flow; what strict mode adds
> (implicit flows); how the cross-function analysis works (per-function
> summaries and their channels) and the field-qualified precision; the
> sibling attribute `@constant_time` (CWE-208) with its four rejection
> classes; the container-mutator taint rule; and the exact scope of
> the guarantee, as published in the compiler's own trust model. Every
> rule is demonstrated with a real, executed example.

**Version documented.** `main` at commit `8e2c609` (`capa 1.32.0` plus
unreleased commits). Every transcript re-run at that commit on
2026-09-11, `python -m capa` importing the checkout under
specification.

Depends on: [15-ifc-model-and-labels.md](15-ifc-model-and-labels.md).

---

## 1. Two tiers over the same flow

IFC is **warn-then-enforce**. A `@secret -> public sink` flow is:

- a **non-fatal warning by default** (unannotated code is untouched,
  and annotated code surfaces the disclosure without breaking the
  build); `--check` exits with code 0.
- a **hard error** when the function containing the sink opted into
  `@strict_ifc()`; `--check` exits with code 1.

The `@strict_ifc` attribute is one of the recognized function
attributes (`_ATTRIBUTE_SCHEMA`,
[`capa/analyzer/_items.py`](../capa/analyzer/_items.py) line 43). The
tier choice happens at the sink site in
[`capa/analyzer/_ifc.py`](../capa/analyzer/_ifc.py): `self._err(...)`
under strict, `self._warn(...)` otherwise.

The same flow, without and with `@strict_ifc()`:

```capa
// warn.capa
fun show(stdio: Stdio, token: @secret String)
    stdio.println("token is ${token}")

fun main(stdio: Stdio)
    show(stdio, "s3cr3t")
```

```
$ python -m capa --check warn.capa
warn.capa:3:19: warning: information-flow: a @secret value reaches Stdio.println (argument 1), a public sink that sends data out of the program. Route it through declassify(value, reason: "...") if this disclosure is intended.
   3 |     stdio.println("token is ${token}")
                         ^

warn.capa: ok (2 items, 7 expressions typed, 4 bindings)
```

```capa
// strict.capa
@strict_ifc()
fun show(stdio: Stdio, token: @secret String)
    stdio.println("token is ${token}")

fun main(stdio: Stdio)
    show(stdio, "s3cr3t")
```

```
$ python -m capa --check strict.capa
strict.capa:4:19: error: information-flow: a @secret value reaches Stdio.println (argument 1), a public sink that sends data out of the program. Route it through declassify(value, reason: "...") if this disclosure is intended.
   4 |     stdio.println("token is ${token}")
                         ^

strict.capa: 1 error
```

The diagnostic text is the same; only the severity (`warning` versus
`error`) and the exit code (0 versus 1) change. A flow that is merely
warned about still compiles and still runs: never read the default
tier as "cannot leak".

## 2. What `@strict_ifc` adds beyond hardening

Turning the warning into an error is not the only difference. Under
`@strict_ifc` the analyzer additionally enforces:

- **Implicit (control-flow) flows.** A sink that runs inside a branch
  whose condition is `@secret` leaks the bit "which branch was taken",
  regardless of the argument labels. This is checked **only under
  `@strict_ifc`**: it is subtle and pervasive, and at the warn tier it
  would be noisy and undermine `declassify`. The default tier stays
  focused on high-value explicit DATA leaks; `@strict_ifc` turns on
  full noninterference (explicit plus implicit, as hard errors).
- **The pc-label join.** Under strict, the control-flow label (the
  pc-label) joins into the label of values computed inside
  secret-conditioned branches.

Both tiers on the same implicit flow:

```capa
// implicit_strict.capa
@strict_ifc()
fun probe(stdio: Stdio, secret: @secret Int)
    if secret > 0
        stdio.println("positive")

fun main(stdio: Stdio)
    probe(stdio, 7)
```

```
$ python -m capa --check implicit_strict.capa
implicit_strict.capa:5:9: error: information-flow (strict): Stdio.println runs under secret control flow (inside a branch whose condition is @secret), which leaks whether that branch was taken. Move the sink outside the secret-conditioned branch so its execution does not depend on the secret.
   5 |         stdio.println("positive")
               ^

implicit_strict.capa: 1 error
```

The same program without the attribute passes `--check` clean (exit 0,
no warning): implicit flows are a strict-only check.

JUDGEMENT. This is why `@strict_ifc` is the only tier where the
noninterference guarantee (Theorem 3 of
[`proofs/CapaNoninterference.agda`](../proofs/CapaNoninterference.agda))
is claimed: only there are implicit flows closed.

## 3. `declassify` closes the flow in both tiers

A flow that passes through `declassify(...)` before the sink does not
count, because `declassify` relabels to `@public` (the model in
[15-ifc-model-and-labels.md](15-ifc-model-and-labels.md), which also
runs the example under `@strict_ifc` on both backends):

```
$ python -m capa --check declass.capa
declass.capa: ok (2 items, 10 expressions typed, 6 bindings)
```

## 4. The cross-function analysis: per-function summaries

The intra-procedural pass of `_ifc.py` catches a `@secret` reaching a
sink INSIDE one body. Crossing a function boundary is the job of
[`capa/analyzer/_ifc_summary.py`](../capa/analyzer/_ifc_summary.py).
For every user-defined function and method it computes a summary, at a
least fixpoint over the call graph (monotone: starts empty, grows
until stable, so direct and mutual recursion terminate). The summary
carries, characterized at a reference level, three channels (each
consulted at the call site):

1. **Environment / parameter channel (the sink-reaching set).** The
   0-based indices of value parameters whose value, by the
   intra-procedural rules, reaches a public-sink position inside the
   body, directly or transitively. At the call site, an argument that
   is `@secret` and binds to a sink-reaching parameter of the callee
   is flagged.
2. **Content channel (mutation effects).** A map
   `(target param, field path) -> source set` recording that the
   callee writes INTO the object bound to a parameter at a given field
   path, from a value tainted by another parameter or by an internal
   secret source. It is field-sensitive: a callee that pushes a secret
   into `bag.items` records `(bag_slot, ("items",))`, not a taint of
   the whole `bag`.
3. **Return channel.** The per-field-path taint of the returned value,
   so a secret returned by a function and re-consumed by the caller is
   followed.

JUDGEMENT (the "env / content / return" naming). This is a reference
characterization of the three channels the summary computes; the code
does not use exactly these three names as labels, but the three
structures correspond one-to-one. The analysis is a sound
over-approximation: a method call whose receiver type is not known
statically is matched against every user method of that name, so it
never under-reports on the flows it models (the module docstring
states the direction is never more permissive).

A `@secret` passed to an UNannotated parameter that reaches a sink
inside the callee is caught at the call site:

```capa
// crossfn.capa
@strict_ifc()
fun emit(stdio: Stdio, msg: String)
    stdio.println(msg)

@strict_ifc()
fun run(stdio: Stdio, token: @secret String)
    emit(stdio, token)

fun main(stdio: Stdio)
    run(stdio, "s3cr3t")
```

```
$ python -m capa --check crossfn.capa
crossfn.capa:8:17: error: information-flow: a @secret value is passed to 'emit' as msg, which reaches a public sink inside 'emit' (it sends data out of the program). Route it through declassify(value, reason: "...") if this disclosure is intended.
   8 |     emit(stdio, token)
                       ^

crossfn.capa: 1 error
```

The text names the callee (`emit`), the parameter (`msg`) and the fact
that it reaches a sink inside it.

## 5. Field-qualified precision

Passing a whole struct to a callee does not over-report when the
callee only consumes a CLEAN sibling: the callee's field-qualified
sunk paths are intersected against the argument's tainted paths at the
call site.

A struct with one `@secret` field and one public field; the callee
consumes only the public field:

```capa
// fieldprec.capa
type Bag { note: String, secret_val: @secret String }

@strict_ifc()
fun show_note(stdio: Stdio, b: Bag)
    stdio.println(b.note)

fun main(stdio: Stdio)
    let b = Bag { note: "hello", secret_val: "s3cr3t" }
    show_note(stdio, b)
```

```
$ python -m capa --check fieldprec.capa
fieldprec.capa: ok (3 items, 10 expressions typed, 5 bindings)
```

The mirror: the same struct, but the callee consumes the `@secret`
field. The leak is caught:

```capa
// fieldmirror.capa
type Bag { note: String, secret_val: @secret String }

@strict_ifc()
fun show_secret(stdio: Stdio, b: Bag)
    stdio.println(b.secret_val)

fun main(stdio: Stdio)
    let b = Bag { note: "hello", secret_val: "s3cr3t" }
    show_secret(stdio, b)
```

```
$ python -m capa --check fieldmirror.capa
fieldmirror.capa:6:19: error: information-flow: a @secret value reaches Stdio.println (argument 1), a public sink that sends data out of the program. Route it through declassify(value, reason: "...") if this disclosure is intended.
   6 |     stdio.println(b.secret_val)
                         ^

fieldmirror.capa: 1 error
```

Reading the clean sibling (`b.note`) stays clean; reading the secret
field (`b.secret_val`) triggers. The precision is bidirectional: no
over-report on the clean sibling, no under-report on the secret field.

## 6. Container mutators: insertion and removal both taint (warn tier)

The `_CONTAINER_MUTATORS` table
([`capa/analyzer/_ifc_tables.py`](../capa/analyzer/_ifc_tables.py)
line 127) marks the CONTAINER as `@secret` when a mutating method
receives a `@secret` argument. The table is:
`("List", "push") {0}`, `("Set", "add") {0}`, `("Set", "remove") {0}`,
`("Map", "set") {0, 1}`, `("Map", "remove") {0}`. The removal
direction is there because a `@secret` used as the KEY of a removal
decides WHICH element leaves, so the container's observable length and
membership come to depend on the secret, the same disclosure `add`
already had, reached from the other side.

This is the normal WARN tier of explicit flows (warning, exit 0), not
a hard error:

```capa
// setrem_secret.capa
fun main(stdio: Stdio)
    let k: @secret Int = 7
    var s = new_set()
    s.add(0)
    s.add(1)
    s.remove(k)
    stdio.println("len=${s.length()}")
```

```
$ python -m capa --check setrem_secret.capa
setrem_secret.capa:8:19: warning: information-flow: a @secret value reaches Stdio.println (argument 1), a public sink that sends data out of the program. Route it through declassify(value, reason: "...") if this disclosure is intended.
   8 |     stdio.println("len=${s.length()}")
                         ^

setrem_secret.capa: ok (1 items, 16 expressions typed, 7 bindings)
```

The program runs on the three execution paths (`--run`, `--run --ir`,
`--run --wasm`) with the warning and byte-identical output `len=2`,
exit 0 (the dependence is real: with the key present the length would
be 1). The same pattern with `Map.remove` and a `@secret` key produces
the same warning (measured). Pinned by `TestRemovalSelectsOnASecret`
in [`tests/test_ifc_container_effect.py`](../tests/test_ifc_container_effect.py).

## 7. The sibling attribute `@constant_time` (CWE-208)

`@constant_time()` is checked by the same label pass: inside a
`@constant_time` function, a `@secret` operand at a variable-latency
site is a timing side channel. `@constant_time` is always a hard error
(it has no warn tier): it is a requirement on the code, not a flow
alert. [`docs/reference.md`](../docs/reference.md) section 6.5
documents the rejections as FOUR classes, all measured below.

**Class 1: control flow over a secret** (an `if` / `elif` / `while` /
`if`-expression condition, a `match` scrutinee):

```capa
// ct_branch.capa
@constant_time()
fun sel(secret: @secret Int) -> Int
    if secret > 0
        return 1
    return 0
```

```
$ python -m capa --check ct_branch.capa
ct_branch.capa:4:8: error: constant-time violation: an if-condition depends on a @secret value, which leaks it through timing. A @constant_time function must not branch on secret data; rewrite it branchless (e.g. a constant-time select / compare).
   4 |     if secret > 0
              ^
```

**Class 2: memory access indexed by a secret** (`xs[secret]`,
`list.get`, `map.get`, `map.contains_key`, `set.contains`,
`str.char_at`, `map.remove(secret)`):

```capa
// ct_mapremove.capa
@constant_time()
fun drop_key(m: Map<Int, Int>, secret: @secret Int) -> Bool
    return m.remove(secret).is_some()
```

```
$ python -m capa --check ct_mapremove.capa
ct_mapremove.capa:4:12: error: constant-time violation: Map.remove with a @secret index / key leaks it through data-dependent memory access (the table-lookup timing side channel). A @constant_time function must not look up by a secret.
   4 |     return m.remove(secret).is_some()
                  ^
```

**Class 3: variable-time arithmetic on a secret** (`/`, `%` with a
`@secret` operand):

```capa
// ct.capa
@constant_time()
fun check(secret: @secret Int, pubv: Int) -> Int
    return secret / pubv
```

```
$ python -m capa --check ct.capa
ct.capa:4:12: error: constant-time violation: '/' on a @secret operand leaks it through timing (division and modulo run on the variable-latency divider). A @constant_time function must avoid variable-time arithmetic on secret data.
   4 |     return secret / pubv
                  ^
```

**Class 4: short-circuiting comparison over a secret** (`==` / `!=`
over `String` / `List`, the ordering operators over `String`, and the
scanning methods `starts_with`, `ends_with`, `contains`, `index_of`,
`list.contains`, `str.split_once`):

```capa
// ct2.capa
@constant_time()
fun verify(secret: @secret String, guess: String) -> Bool
    return secret == guess
```

```
$ python -m capa --check ct2.capa
ct2.capa:4:12: error: constant-time violation: '==' on a @secret String / List operand leaks it through timing -- the comparison short-circuits byte-by-byte and reveals the position of the first difference (the MAC / token compare oracle, CWE-208). Use a dedicated constant-time compare (XOR-accumulate over every byte with no early exit) instead of '=='.
   4 |     return secret == guess
                  ^
```

```
$ python -m capa --check ct_split.capa   # body: secret.split_once(":")
ct_split.capa:4:12: error: constant-time violation: String.split_once on a @secret operand leaks it through timing -- it short-circuits byte-by-byte and reveals where the first difference is (the compare oracle, CWE-208). Use a dedicated constant-time compare (XOR-accumulate over every byte) instead.
```

The membership criterion of class 4 is measured, not by association:
an entry enters when its lowering calls `$str_eq` (the
element-by-element scan). `String.lines()` on a secret is NOT flagged,
because its lowering makes no `$str_eq` call (measured: the
`ct_lines.capa` probe passes `--check` clean; the negative is pinned
in [`tests/test_labels.py`](../tests/test_labels.py) beside the
`split_once` / `Map.remove` positives). Listing these entries asserts
nothing about any method BEING constant-time; it adds diagnostics to
the same mechanism the other entries use.

## 8. The scope of the guarantee

### 8.1 `@strict_ifc`

Under `@strict_ifc`, for a program that passes `--check`: no `@secret`
reaches a public sink without `declassify`, including the implicit
flows of section 2 and the cross-function flows caught by the
summaries, on the flows the analysis models. The analysis is a sound
over-approximation on those flows (it can over-report on a non-flow;
its tightening direction is stated in the `_ifc_summary.py`
docstring). The noninterference theorems (Theorem 3 and 4 in
[`proofs/CapaNoninterference.agda`](../proofs/CapaNoninterference.agda))
are mechanized for the core `lambda_if` calculus of
[`docs/semantics.md`](../docs/semantics.md) section 9, not for the
full implementation. The implementation-level scope is the public
register of [`docs/trust-model.md`](../docs/trust-model.md): the
analysis is source-level, there is no points-to analysis, and the
discipline is opt-in per function (outside `@strict_ifc` a flow warns
and the build passes).

### 8.2 `@constant_time`

Replicated from the published correction
([`docs/advisories/2026-06-17-security.md`](../docs/advisories/2026-06-17-security.md),
finding B2, "Scope of the `@constant_time` claim", and
[`docs/trust-model.md`](../docs/trust-model.md)). What the attribute
obtains is narrower than "the function has no secret-dependent
timing", in three directions a reader relying on it should know:

- **It is a SOURCE-level analysis.** The checks run in the analyzer
  over the Capa source; no constant-time obligation is carried into
  either backend (measured in the advisory: compiling with and
  without the attribute produces byte-identical generated Python and
  byte-identical generated WAT). A source-level analysis cannot see
  what a backend, a JIT or a processor does with the code.
- **It enforces an ENUMERATED set of rejections, not a universal
  property.** The four classes above, driven by fixed tables in
  [`capa/analyzer/_ifc_tables.py`](../capa/analyzer/_ifc_tables.py).
  "No secret-dependent timing" quantifies over the whole language; an
  enumerated set does not, and the two readings must not be confused.
- **It applies where it is written.** The checks are gated on the
  attribute's presence on the analysed function; it is opt-in per
  function.

The consequence in the manifest (measured): the per-function
`constant_time` boolean of `--manifest` reports the PRESENCE of the
attribute, not an analysis outcome:
[`capa/manifest/_funrec.py`](../capa/manifest/_funrec.py) line 1154
computes literally
`any(a.name == "constant_time" for a in fn.attributes)`. Run on a
program with one annotated function, the manifest reports
`constant_time: true` for it and `false` for `main`. See
[29-capability-manifest.md](29-capability-manifest.md) and
[`docs/trust-model.md`](../docs/trust-model.md). None of this changes
what section 7 measured: the rejections are real, and they are hard
errors.

---

## Links

- [15-ifc-model-and-labels.md](15-ifc-model-and-labels.md): the model,
  the labels, the sources and the sinks.
- [14-linearity-consume-typestates.md](14-linearity-consume-typestates.md):
  the linear discipline that shares the capture machinery.
- [29-capability-manifest.md](29-capability-manifest.md): the
  `constant_time` and `declassify` surfaces in the manifest.
- [`docs/trust-model.md`](../docs/trust-model.md): the public register
  of guarantee scopes.
- [`proofs/README.md`](../proofs/README.md): the mechanized core
  noninterference.
