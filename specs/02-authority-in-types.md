# 02. The model: authority in the types

> **What this chapter covers.** The theory Capa rests on: capabilities as
> unforgeable values passed by parameter; the elimination of the confused
> deputy; monotone attenuation; the manifest/artefact idea at a high
> level; and how the IFC layer complements the model. Prior art in
> object-capabilities and POLA.

**Version documented.** `main` at commit `8e2c609` (`capa 1.32.0` plus
unreleased commits). Every transcript re-run at that commit on
2026-09-10; see [01-overview.md](01-overview.md) for the isolation proof
convention.

Depends on: [01-overview.md](01-overview.md).

---

## 1. Prior art: object-capabilities and POLA

Capa's model is an object-capability discipline. The relevant lineage:

- **Principle of least privilege (POLA / Least Authority)**, Saltzer and
  Schroeder (1975): each component should hold only the authority its
  function requires.
- **Object-capability model**, Dennis and Van Horn (1966) and Mark
  Miller's work (E, Caja, "Robust Composition", 2006): authority is an
  **unforgeable reference** to an object; holding the reference is
  holding the authority; there is no way to fabricate the reference from
  nothing, nor to name it globally. Designation and authority are the
  same thing.

Capa transposes this to a statically typed language: the "unforgeable
reference" is a **value of capability type**, and the rule "cannot be
fabricated from nothing" is enforced by the analyzer at compile time,
not by a runtime monitor. The core is formalized in Agda (see
[`proofs/README.md`](../proofs/README.md)).

## 2. Ambient authority, and why it is the problem

In a conventional language any function can call `open`, `socket`,
`getenv` or `exec`: the authority lives in the **environment** (the
standard library, globals, the process). This is called **ambient
authority**. Its consequence is that a function's signature constrains
nothing: `fun parse(s: String) -> Ast` can, in the middle of its body,
open a socket and exfiltrate `s`, and nothing in the type betrays it.
All security then depends on auditing the body and trusting the author
(and every transitive dependency).

Capa removes ambient authority entirely. There is no global `open`;
there is `Fs.read(path)` on an `Fs` value the function had to
**receive**.

## 3. Capabilities as unforgeable values passed by parameter

The two halves of the discipline:

**(a) Authority flows only by parameter.** A capability enters a program
through the entry point's signature (`fun main(fs: Fs, net: Net, ...)`,
see [10-capability-model.md](10-capability-model.md)) and propagates by
being passed as an argument to other functions. A function that does not
receive it does not have it.

**(b) A capability can be neither fabricated nor aliased into being.**
There is no constructor for a built-in capability from data. It cannot
appear in a `let`/`var` binding from any expression other than the
parameter itself flowing through calls. Built-in capabilities also
cannot be returned by a regular function (they only flow "inward"), so
that the chain from `main` to any capability value stays visible in the
signatures at every link.

An attempt to forge `Stdio`:

```capa
// forge.capa
fun main(stdio: Stdio)
    let fake: Stdio = Stdio {}
    fake.println("forged")
```

```
$ python -m capa --check forge.capa
forge.capa:3:23: error: 'Stdio' is not a struct type
   3 |     let fake: Stdio = Stdio {}
                             ^

forge.capa:3:5: error: capability 'Stdio' cannot appear in a 'let' binding; capabilities only flow through function parameters
   3 |     let fake: Stdio = Stdio {}
           ^

forge.capa:2:10: error: capability parameter 'stdio' is declared but never used; prefix the name with '_' to silence this check
   2 | fun main(stdio: Stdio)
                ^

forge.capa: 3 errors
```

Two independent barriers fire: `Stdio` is not a struct type (no literal
constructs it) and a capability cannot appear in a `let` binding. The
list of the 10 built-in capabilities has a single source of truth,
`CAPABILITY_NAMES` in [`capa/typesys.py`](../capa/typesys.py) line 190
(`Stdio, Fs, Net, Env, Proc, Clock, Random, Db, Serve, Unsafe`).

## 4. Eliminating the confused deputy

The **confused deputy** (Norm Hardy, 1988) is the pattern where a
privileged component is induced to exercise its authority on behalf of a
caller who should not have it. The root cause is precisely ambient
authority: the deputy holds authority that comes not from the request
but from the environment, and it cannot tell the legitimate request from
the abusive one because authority and designation are separated.

In the object-capability model the confused deputy disappears by
construction: a component acts only with the authority **passed to it
with the request**. If the caller has no `Fs`, it cannot pass `Fs`, and
the deputy has no ambient `Fs` to use instead. In Capa, the authority a
function exercises is exactly the intersection of what it receives.
Designation (the argument) and authority (the capability value) are the
same thing, which is the definition of the property.

JUDGEMENT. This is a direct consequence of (a)+(b) of section 3, not an
additional mechanism: there is no channel through which unpassed
authority enters. The empirical confirmation is the `noauth.capa`
example of [01-overview.md](01-overview.md) (a leaf without the
capability does not compile), reinforced by the manifest's
`provably_excluded_capabilities` field (section 6).

## 5. Monotone attenuation

Holding a capability is not all-or-nothing. A capability can be
**attenuated**: a strictly weaker version is derived from it, and only
that version is passed on. Attenuations are **monotone**: chaining them
can only narrow, never widen. The static type does not change (it is
still `Fs`), but the runtime value carries the restriction set and gates
each operation.

`Fs.restrict_to` limits to a path prefix, and the function that receives
the restricted `Fs` cannot widen it:

```capa
// atten.capa
fun probe(fs: Fs, stdio: Stdio)
    stdio.println("allows /tmp/foo?    ${fs.allows("/tmp/foo")}")
    stdio.println("allows /etc/passwd? ${fs.allows("/etc/passwd")}")

fun main(fs: Fs, stdio: Stdio)
    let tmp_fs = fs.restrict_to("/tmp/")
    probe(tmp_fs, stdio)
```

```
$ python -m capa --run atten.capa
allows /tmp/foo?    true
allows /etc/passwd? false
$ python -m capa --run --wasm atten.capa
allows /tmp/foo?    true
allows /etc/passwd? false
```

The two backends produce identical output. The available attenuators
(`Fs.restrict_to`, `Env.restrict_to_keys`, `Clock.restrict_to_after`,
`Net.restrict_to`, `Random.with_seed`, `Db.restrict_to`,
`Proc.restrict_to`, `Serve.restrict_to`) are declared in
[`capa/builtins.py`](../capa/builtins.py) (lines 374 to 458 at this
commit) and the monotonicity metatheory is formalized in
[`proofs/CapaAttenuation.agda`](../proofs/CapaAttenuation.agda). Detail
in [12-attenuation.md](12-attenuation.md).

## 6. From the model to the artefact: the manifest

Because authority lives in the types, the compiler can **derive** (not
declare) each function's authority surface by reachability analysis over
the call chain. This is the link between the model and the supply chain:
the manifest (`--manifest`) records, per function, the declared
capabilities, the transitively reachable ones, and the **provably
excluded** ones, plus a flag that the authority is provable from the
types.

An excerpt of the manifest of `thread.capa` (the same program as in
[01-overview.md](01-overview.md)):

```
$ python -m capa --manifest thread.capa
...
      "name": "greet",
      "declared_capabilities": [ "Stdio" ],
      "transitively_reachable_capabilities": [ "Stdio" ],
      "provably_excluded_capabilities": [
        "Clock", "Db", "Env", "Fs", "Net", "Proc", "Random", "Serve", "Unsafe"
      ],
      "authority_provable_from_types": true,
      "ceiling_authority_provable": true,
...
```

`provably_excluded_capabilities` is the strong statement: the
capabilities the function **demonstrably does not reach**, derived from
the types and not from the author's word. This is the fact the
supply-chain artefacts (SBOM, VEX, provenance) carry. The envelope, its
composition into products with dependencies, and signing are in
[29-capability-manifest.md](29-capability-manifest.md).

## 7. How IFC complements the model

Capabilities answer "which effects can this function exercise". They do
not answer "where can a sensitive value flow". A program can
legitimately hold `Net` and legitimately hold a secret, and the question
becomes whether the secret reaches the network sink. That is the
question of **information-flow control (IFC)**, a distinct and
complementary layer.

Capa adds a two-point lattice with labels `@secret` (top) and `@public`
(bottom, the default) in type position, and a noninterference analysis:
a `@secret` must not reach a public sink without an explicit
`declassify`. This layer does not replace capabilities; it stacks on top
of them. A `@secret` value that never reaches a sink is harmless; a
`Net` capability with no secrets flowing to it is harmless; IFC governs
the intersection.

Under `@strict_ifc`, the flow `@secret -> Stdio.println` is a hard
error; without the attribute it is a warning (see the `ifc.capa` runs in
[01-overview.md](01-overview.md)). The scope of the guarantee: the
noninterference check is a hard error only under `@strict_ifc`, the
discipline is opt-in per function, and the analysis is source-level with
enumerated rejections (no points-to analysis). The full statement is in
[16-ifc-analyzer-and-tiers.md](16-ifc-analyzer-and-tiers.md) and in
[`docs/trust-model.md`](../docs/trust-model.md).

## 8. What the model guarantees, and what it does not

- **Guarantees** (static, every program that passes `--check`): no
  function exercises authority it did not receive; authority cannot be
  fabricated; attenuation is monotone; the authority surface is
  derivable from the types.
- **Does not guarantee by itself**: that the runtime materializing the
  capabilities is intact. On the Python backend the host runtime is
  **trusted** (capabilities are Python objects). On the Wasm backend the
  boundary is the set of WASI imports, narrower, but the central model
  remains the type (see
  [23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md)).
- **Does not guarantee** noninterference outside `@strict_ifc`; under
  `@strict_ifc` the guarantee holds with the scope stated in
  [16-ifc-analyzer-and-tiers.md](16-ifc-analyzer-and-tiers.md).

---

## Links

- [01-overview.md](01-overview.md): the frame and the verification
  posture.
- [10-capability-model.md](10-capability-model.md): the propagation
  discipline in detail.
- [12-attenuation.md](12-attenuation.md): the attenuators and
  monotonicity.
- [15-ifc-model-and-labels.md](15-ifc-model-and-labels.md): the IFC
  layer.
- [29-capability-manifest.md](29-capability-manifest.md): from the model
  to the artefact.
- [`proofs/README.md`](../proofs/README.md): the formalized core.
