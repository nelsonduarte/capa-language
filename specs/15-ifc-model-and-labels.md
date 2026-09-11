# 15. IFC: the model and the `@secret` / `@public` labels

> **What this chapter covers.** Capa's information-flow control (IFC)
> model: the two-point confidentiality lattice `@public` below
> `@secret`; the `@secret` / `@public` labels on fields, parameters,
> consts and returns; the sources and the public sinks
> (`println`/`eprintln`, `Net.post`, `Fs.write`, `panic`, parameters
> that reach sinks); the `declassify(value, reason: "...")` operation
> as the audited exit hatch, and the fact that it is a runtime NO-OP
> (all the soundness lives in the analyzer). Every rule is demonstrated
> with a real, executed example.

**Version documented.** `main` at commit `8e2c609` (`capa 1.32.0` plus
unreleased commits). Every transcript re-run at that commit on
2026-09-10/11, `python -m capa` importing the checkout under
specification. The sink/source tables were re-read in
[`capa/analyzer/_ifc_tables.py`](../capa/analyzer/_ifc_tables.py) at
this commit.

Depends on: [05-base-and-composite-types.md](05-base-and-composite-types.md),
[02-authority-in-types.md](02-authority-in-types.md).

---

## 1. Two distinct questions: authority and flow

Capabilities (chapters 10 to 13) answer "which effects can a function
exercise". They do not answer "where can a sensitive value flow". A
program can legitimately hold `Net` and legitimately hold a secret;
the IFC question is whether the secret reaches the network sink. It is
a distinct, complementary layer that runs alongside type checking
([`capa/analyzer/_ifc.py`](../capa/analyzer/_ifc.py)).

## 2. The two-point confidentiality lattice

Capa uses a minimal two-point lattice
([`capa/_labels.py`](../capa/_labels.py)):

```
    PUBLIC  below  SECRET
```

`@public` is the bottom (the default of any unlabelled value);
`@secret` is the top (tainted). The join of two labels is the more
restrictive one: `public join secret = secret`. A value may flow into
a position only if its label is below-or-equal the label the position
demands; the forbidden flow is a `@secret` reaching a `@public` sink,
and only `declassify` can bridge it (section 7). The order is encoded
in a single module (`_labels.py`, functions `join` at line 43,
`join_all` at line 51, `flows_to` at line 59), so a future version
with intermediate levels changes only that module.

This lattice models **confidentiality** (who may LEARN a value), not
integrity or taint. That is why the inbound authority `Serve.recv`
(the language's first input-data source) is `@public` and not
`@secret`: "untrusted" is an integrity property, and labelling it
`@secret` would encode it into the wrong lattice, making a server's
most common act (echoing back what the client sent) a reported
violation. The decision is spelled out in the comments of
[`capa/analyzer/_ifc_tables.py`](../capa/analyzer/_ifc_tables.py)
(the source table's "deliberately NOT a source" note). Integrity /
taint tracking would be a second lattice, not a relabelling of this
one.

## 3. How a value becomes `@secret`

Three origins of the `@secret` label, all propagated by join:

1. **Explicit annotation** `@secret` on a parameter, field, const or
   return (type position). The label is read from the binding
   (`Symbol.label`).
2. **Built-in sources.** A method that produces secret data by
   construction. The `_SECRET_SOURCES` table
   ([`capa/analyzer/_ifc_tables.py`](../capa/analyzer/_ifc_tables.py)
   line 94) has exactly one entry, `(Env, get)`: environment variables
   are where keys and tokens live, so the result of `env.get(...)` is
   `@secret` without any annotation. (`Fs.read` is deliberately NOT a
   source: a config file is usually public; one holding a secret can
   be annotated `@secret` at the binding.)
3. **Derivation.** Any expression whose result is the join of the
   labels of the sub-expressions flowing into it: `a + b`, `f(a, b)`,
   a string interpolation, an aggregate literal (a struct/list/tuple
   carries the join of its elements), and so on. A derived value is
   `@secret` iff some operand it depends on is `@secret`.

An annotated `@secret` parameter propagates through interpolation to a
sink:

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

The `Env.get` source produces `@secret` without any annotation:

```capa
// envsrc.capa
fun main(env: Env, stdio: Stdio)
    match env.get("API_KEY")
        Some(k) -> stdio.println("key=${k}")
        None -> stdio.println("no key")
```

```
$ python -m capa --check envsrc.capa
envsrc.capa:4:34: warning: information-flow: a @secret value reaches Stdio.println (argument 1), a public sink that sends data out of the program. Route it through declassify(value, reason: "...") if this disclosure is intended.
   4 |         Some(k) -> stdio.println("key=${k}")
                                        ^

envsrc.capa: ok (1 items, 11 expressions typed, 4 bindings)
```

A `const` annotated `@secret` propagates the same way:

```capa
// constsec.capa
const TOKEN: @secret String = "s3cr3t"

fun main(stdio: Stdio)
    stdio.println(TOKEN)
```

```
$ python -m capa --check constsec.capa
constsec.capa:5:19: warning: information-flow: a @secret value reaches Stdio.println (argument 1), a public sink that sends data out of the program. Route it through declassify(value, reason: "...") if this disclosure is intended.
   5 |     stdio.println(TOKEN)
                         ^

constsec.capa: ok (2 items, 4 expressions typed, 2 bindings)
```

(All three are warnings, exit 0: the default tier warns. Under
`@strict_ifc` the same flow is a hard error; see
[16-ifc-analyzer-and-tiers.md](16-ifc-analyzer-and-tiers.md).)

## 4. The public sinks

A public sink is a capability method that exfiltrates data out of the
program. The `_PUBLIC_SINKS` table
([`capa/analyzer/_ifc_tables.py`](../capa/analyzer/_ifc_tables.py)
line 35) is the source of truth, with the (0-based) argument positions
that are sinks:

| Capability.method | Sink positions |
|---|---|
| `Stdio.print` / `Stdio.println` / `Stdio.eprintln` | `{0}` |
| `Net.get` | `{0}` (the URL) |
| `Net.post` | `{0, 1}` (URL and body) |
| `Fs.write` | `{0, 1}` (path and content) |
| `Db.exec` / `Db.query` | `{0, 1}` |
| `Serve.send` | `{1}` (the payload; arg 0 is the connection id, not data) |

Besides the capability methods, `panic(message)` is treated as a
public sink (it writes the message to stderr;
`_check_ifc_panic_sink`,
[`capa/analyzer/_ifc.py`](../capa/analyzer/_ifc.py) line 3032),
exactly like `Stdio.eprintln`.

JUDGEMENT (why these positions and not others). Query methods / pure
receivers (`allows`, `exists`, `Fs.read`, `Env.get`, `now_secs`, ...)
are NOT sinks: they bring data IN or inspect it, they do not send it
out. The `fs.write` path counts as a sink (a secret written to an
attacker-chosen path is still disclosure), as does the URL of
`net.get`/`post` (a secret in the URL leaks through the request line
and the server's logs). This is what the table's own documentation
states.

## 5. Sinks reached through a parameter (cross-function)

A `@secret` need not reach a sink in the same body: if it is passed to
a parameter (even an unannotated one) that reaches a sink INSIDE the
callee, it is reported at the call site. The cross-function analysis
behind this is covered in
[16-ifc-analyzer-and-tiers.md](16-ifc-analyzer-and-tiers.md); the
model here: a parameter that reaches a sink is itself a transitive
sink.

## 6. Per-field precision

A struct carries, besides its aggregate label, a per-field label map,
so reading a public field of a struct that also holds a secret field
is not over-tainted. The model: one `@secret` field in a mostly public
struct keeps the rest of the struct usable at sinks, and only the
secret field (or a read of the whole struct) triggers. The
cross-function, field-qualified precision is demonstrated in
[16-ifc-analyzer-and-tiers.md](16-ifc-analyzer-and-tiers.md).

## 7. `declassify`: the audited hatch, and a runtime NO-OP

`declassify(value, reason: "...")` is the auditable `@secret ->
@public` bridge. It is **identity on the value**; only the security
label changes (to `@public`). The form is deliberately rigid (the
positional value, then `reason:` as a string literal), so the SBOM can
record an audit trail (the identity shared with the artefact pipeline
lives in [`capa/_declassify.py`](../capa/_declassify.py)).

Under `@strict_ifc`, `declassify` lets the flow pass, and the value is
preserved (identical) on both backends:

```capa
// declass.capa
@strict_ifc()
fun show(stdio: Stdio, token: @secret String)
    let public_view = declassify(token, reason: "audit log needs the token id")
    stdio.println("token is ${public_view}")

fun main(stdio: Stdio)
    show(stdio, "s3cr3t")
```

```
$ python -m capa --check declass.capa
declass.capa: ok (2 items, 10 expressions typed, 6 bindings)
$ python -m capa --run declass.capa
token is s3cr3t
$ python -m capa --run --wasm declass.capa
token is s3cr3t
```

**The runtime NO-OP.** `declassify` changes nothing about the value at
run time. On the Wasm backend the lowering returns the value directly
without emitting any `Call` instruction; the `@secret -> @public`
relabel and the SBOM audit record are compile-time only
([`capa/ir/_lower_expr.py`](../capa/ir/_lower_expr.py) lines 609 to
630; the gate keys on the callee's binding identity, so a user-defined
`fun declassify(...)` that shadows the built-in is lowered as an
ordinary call). On the Python backend a real identity `declassify`
call remains. The central consequence: **all IFC soundness lives in
the analyzer**, not in a runtime monitor. The identical output above
confirms it (the value is the same with or without `declassify`).

A `declassify` of an already `@public` value is a no-op the analyzer
warns about (a dead security annotation is dangerous noise in a
regulated SBOM):

```capa
// deadclass.capa
fun main(stdio: Stdio)
    let x = "hello"
    let y = declassify(x, reason: "not actually secret")
    stdio.println(y)
```

```
$ python -m capa --check deadclass.capa
deadclass.capa:4:13: warning: declassify of a @public value is a no-op (the value is not @secret); remove it or re-check the data flow
   4 |     let y = declassify(x, reason: "not actually secret")
                   ^

deadclass.capa: ok (1 items, 7 expressions typed, 4 bindings)
```

## 8. What the model guarantees, and what it does not

- **Guarantees** (under `@strict_ifc`, see
  [16-ifc-analyzer-and-tiers.md](16-ifc-analyzer-and-tiers.md)):
  noninterference for the two-point lattice, formalized in
  [`proofs/CapaNoninterference.agda`](../proofs/CapaNoninterference.agda)
  (Theorem 3 without `declassify`, Theorem 4, delimited release, with
  `declassify`). The core is the `lambda_if` calculus of
  [`docs/semantics.md`](../docs/semantics.md) section 9.
- **Does not guarantee** integrity or input taint (the lattice is
  confidentiality; section 2).
- Outside `@strict_ifc`, a `@secret -> sink` flow is a **warning**,
  not an error. The theorems cover the core calculus; the
  implementation's guarantee is scoped as stated in
  [16-ifc-analyzer-and-tiers.md](16-ifc-analyzer-and-tiers.md) section
  8.3 and in [`docs/trust-model.md`](../docs/trust-model.md): the
  analysis is source-level, its rejections are enumerated, and the
  discipline is opt-in per function.

---

## Links

- [16-ifc-analyzer-and-tiers.md](16-ifc-analyzer-and-tiers.md): the
  two tiers (warn versus `@strict_ifc`), the cross-function analysis,
  per-field precision, `@constant_time`, and the scope of the
  guarantee.
- [02-authority-in-types.md](02-authority-in-types.md): how IFC
  complements the capability model.
- [29-capability-manifest.md](29-capability-manifest.md): how
  `declassify` sites enter the artefacts.
- [`proofs/README.md`](../proofs/README.md): the formalized
  noninterference.
