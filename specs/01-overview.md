# 01. What Capa is

> **What this chapter covers.** What Capa is and is not; the thesis in one
> sentence (authority carried in the types, no ambient authority); the
> relationship between the language, the compiler and the two backends;
> where the guarantees hold and where they do not; the honesty posture.
> It frames the reading of the rest of the set.

**Version documented.** `main` at commit `8e2c609` (`capa 1.32.0` plus
unreleased commits). Every transcript in this chapter was re-run at that
commit on 2026-09-10, with `python -m capa` importing the checkout under
specification (verified by printing `capa.__file__` before each battery).
Programs with runtime behaviour were run on both backends.

This header (title, "what this chapter covers", the pinned version, and
the closing links section) is the skeleton every chapter in the set
reuses.

Depends on: nothing.

---

## 1. The thesis in one sentence

Capa is a programming language whose central discipline is: **the
authority to touch the outside world (read files, open sockets, read the
environment, run processes) exists only as a typed value that a function
receives explicitly as a parameter.** There is no ambient authority. A
function that does not receive the corresponding capability cannot
exercise the effect, and the compiler rejects the program before it runs.

The practical consequence is that a function's **signature** is a
provable upper bound on what it can do. If `fun parse(s: String) -> Ast`
receives no capability, then `parse` reads no files, opens no network
connections and reads no environment, and this is checkable from the type
alone, without reading the body or trusting the author.

The minimal demonstration of the absence of ambient authority: a leaf
function that tries to use `stdio` without having received it does not
compile.

```capa
// noauth.capa
fun leak(msg: String)
    stdio.println(msg)

fun main(stdio: Stdio)
    leak("hello")
```

```
$ python -m capa --check noauth.capa
noauth.capa:3:5: error: undefined name 'stdio'
   3 |     stdio.println(msg)
           ^

noauth.capa:5:10: error: capability parameter 'stdio' is declared but never used; prefix the name with '_' to silence this check
   5 | fun main(stdio: Stdio)
                ^

noauth.capa: 2 errors
```

There is no global `stdio` for `leak` to reach: the only way for `leak`
to print would be to receive `Stdio` as a parameter, and that fact would
then be visible in its signature and in every call chain up to `main`.
The detailed model is in
[02-authority-in-types.md](02-authority-in-types.md).

## 2. What it is for

Capa exists to produce **verifiable supply-chain evidence by
construction**. From a program (or a product composed of dependencies)
the compiler derives a manifest of the capabilities each function can
reach, and materializes supply-chain artefacts (CycloneDX/SPDX SBOM, VEX,
SLSA provenance) anchored in that manifest. The property that makes them
useful is that the authority surface is not declared by the author after
the fact: it is **derived from the types** and proven as an upper bound.

For the two-function program of section 3 below, `--manifest` emits, per
function, the declared capabilities, the transitively reachable ones and
the **provably excluded** ones:

```
$ python -m capa --manifest thread.capa
...
      "declared_capabilities": [ "Stdio" ],
      "transitively_reachable_capabilities": [ "Stdio" ],
      "provably_excluded_capabilities": [
        "Clock", "Db", "Env", "Fs", "Net", "Proc", "Random", "Serve", "Unsafe"
      ],
      "authority_provable_from_types": true,
...
```

(Full output is JSON; trimmed here. The structure and the fields are
covered in [29-capability-manifest.md](29-capability-manifest.md).)

## 3. Language, compiler, two backends

Capa is a compiled language. The reference compiler is the Python package
`capa` (its phase structure is in
[18-compiler-pipeline.md](18-compiler-pipeline.md)). There are **two
execution backends**:

- **Python backend** (`--run`): transpiles to Python and runs on the
  interpreter. Source: `capa/transpiler/`, `capa/ir/_emit_python.py`.
- **Wasm Component Model backend** (`--run --wasm`): emits a WebAssembly
  component (Component Model) and runs it on a wasmtime host. Source:
  `capa/ir/_emit_wasm/` (26 modules), `capa/ir/_emit_wit.py`.

The design promise is **ideally byte-identical output** on the two
backends. Throughout this set, every example with runtime behaviour is
run on both and the agreement is recorded.

A minimal program, run on both backends:

```capa
// hello.capa
fun main(stdio: Stdio)
    stdio.println("Hello, Capa")
```

```
$ python -m capa --run hello.capa
Hello, Capa
$ python -m capa --run --wasm hello.capa
Hello, Capa
```

The two backends produce identical output.

Authority passed explicitly between functions (the `thread.capa` program
referenced in section 2):

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

The two backends produce identical output.

## 4. Where the guarantees hold, and where they do not

This section is the honesty frame of the set. Every guarantee claim has a
scope, and the scope is stated.

**The capability discipline** (authority only by parameter; no capability
is created from nothing) is checked statically by the analyzer and holds
for every program that passes `--check`. It is the proven core: the
mechanized theorems live in [`proofs/`](../proofs/README.md), typed in CI
under `--safe`.

**How capabilities are materialized at runtime** differs by backend. On
the Python backend the **host runtime is trusted**: capabilities are
Python objects that interpose the effects, and the guarantee is as strong
as the integrity of the interpreter and the support runtime. On the Wasm
backend the boundary is the component's set of WASI imports, narrower by
construction (see
[23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md)).

**Backend parity is a design promise verified per program by running
both backends.** Some capabilities exist only on the Python backend (by
permanent decision, not backlog): the Wasm emitter refuses them loudly.
The exact scope of the parity promise is in
[24-backend-parity.md](24-backend-parity.md).

`Serve` (inbound-connection authority) is one of those Python-only
capabilities; the Wasm backend refuses any program that reaches it:

```capa
// serve.capa
fun main(serve: Serve, stdio: Stdio)
    let r = serve.listen("127.0.0.1", 8080)
    stdio.println("listening")
```

```
$ python -m capa --run --wasm serve.capa
capa: --wasm: the Serve capability is intentionally not supported on the Wasm backend (binding a listening socket needs wasi:sockets, which is neither vendored in capa/wasi_wit nor reachable from the wasmtime-py bindings the Wasm hosts are built on, so a guest can never be handed an inbound connection). Use the Python backend for these functions, or refactor to remove the Serve parameter.
  - main(serve: Serve)
```

The same program runs normally on the Python backend (exit 0, prints
`listening`). The refusal is deliberate and anchored in
[`capa/ir/_python_only_caps.py`](../capa/ir/_python_only_caps.py) and
[`capa/ir/_capa_types.py`](../capa/ir/_capa_types.py) line 58
(`PYTHON_ONLY_CAPS = {"Unsafe", "Serve"}`).

**Information-flow control (IFC)** is a layer distinct from capabilities
(see [15-ifc-model-and-labels.md](15-ifc-model-and-labels.md)). A flow
from a `@secret` value to a public sink is a hard error **only under
`@strict_ifc`**; outside it, the same flow is a **warning**, not an
error. The analysis is source-level and its rejections are enumerated;
the exact scope of the guarantee is stated in
[16-ifc-analyzer-and-tiers.md](16-ifc-analyzer-and-tiers.md) and in
[`docs/trust-model.md`](../docs/trust-model.md).

The same flow, with and without `@strict_ifc`:

```capa
// ifc.capa
@strict_ifc()
fun leak(stdio: Stdio, token: @secret String)
    stdio.println("token is ${token}")

fun main(stdio: Stdio)
    leak(stdio, "s3cr3t")
```

```
$ python -m capa --check ifc.capa
ifc.capa:4:19: error: information-flow: a @secret value reaches Stdio.println (argument 1), a public sink that sends data out of the program. Route it through declassify(value, reason: "...") if this disclosure is intended.
   4 |     stdio.println("token is ${token}")
                         ^

ifc.capa: 1 error
```

Without the `@strict_ifc()` attribute, the same `leak` produces
`warning: ...` with the same message text and the program passes
`--check` with exit code 0. The strict-versus-warn distinction, the
`declassify` operation and the scope of the guarantee are in
[16-ifc-analyzer-and-tiers.md](16-ifc-analyzer-and-tiers.md).

## 5. What Capa is not

- **Not a pure runtime sandbox.** The primary guarantee is static (in
  the types), not the interposition of system calls by an external
  monitor. On the Wasm backend there is additional runtime confinement
  (WASI imports), but the central model is the type, not the sandbox.
- **Not reliant on an honest author for capabilities.** The authority
  surface is derived, not declared. An author cannot "forget" to declare
  an effect the code exercises: if the code exercises it, the capability
  appears in the signature of some function in the chain.
- **Not, yet, a total IFC verifier.** The IFC discipline is opt-in per
  function, its default tier warns rather than rejects, and its
  guarantee is scoped as stated in
  [16-ifc-analyzer-and-tiers.md](16-ifc-analyzer-and-tiers.md). Capa
  distinguishes what the theorems cover from what the implementation
  guarantees, and never claims more than the code delivers.

## 6. Verification posture (applies to the whole set)

Every claim in this set is traceable to something READ (`file:line`,
commit, test name, advisory) or EXECUTED (command plus pasted output).
Behavioural claims were verified at the pinned commit; no example is
pasted without having been run there. Where a claim rests on a named
test rather than a fresh run, the chapter says so. Scope-of-guarantee
statements follow the public register in
[`docs/trust-model.md`](../docs/trust-model.md) and the published
advisories under [`docs/advisories/`](../docs/advisories/).

---

## Links

- [02-authority-in-types.md](02-authority-in-types.md): the model behind
  the thesis of section 1.
- [04-grammar.md](04-grammar.md): the concrete shape of the language.
- [24-backend-parity.md](24-backend-parity.md): the exact scope of the
  identical-backends promise.
- [29-capability-manifest.md](29-capability-manifest.md): the manifest
  the supply-chain artefacts anchor to.
- [`docs/trust-model.md`](../docs/trust-model.md): the public register of
  guarantee scopes.
