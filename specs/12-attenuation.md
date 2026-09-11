# 12. Attenuation

> **What this chapter covers.** Deriving a strictly weaker version of
> a capability and passing only that version on: the `restrict_to`
> family and the per-capability attenuators; the monotonicity
> guarantee (chaining only removes authority, never adds it) and its
> realization by intersection in the runtime; the static/runtime
> boundary (the type does not change, the value carries the
> restriction); runtime enforcement (an out-of-scope operation fails
> with `Err`); and backend parity. The capabilities and their methods
> are in [11-builtin-capabilities.md](11-builtin-capabilities.md).

**Version documented.** `main` at commit `8e2c609` (`capa 1.32.0` plus
unreleased commits). Every transcript re-run at that commit on
2026-09-11, `python -m capa` importing the checkout under
specification.

Depends on: [11-builtin-capabilities.md](11-builtin-capabilities.md).

---

## 1. What attenuation is

Holding a capability is not all-or-nothing. From a capability value
one can derive an **attenuated** version: a new value of the same type
whose authority is strictly smaller or equal. It is the mechanism that
realizes the principle of least authority (POLA) in practice: `main`
receives `Fs` over the whole filesystem and passes a subroutine only
an `Fs` limited to `/tmp/`.

Attenuation is not a new capability nor a wrapper: the result has the
same static type (it is still `Fs`), but the **value** carries the
restriction set, and the runtime gates each operation against it.

## 2. The attenuators, per capability

Each attenuable capability exposes a method returning a weaker copy of
itself. From [`capa/builtins.py`](../capa/builtins.py) (the `METHODS`
dictionary, line 92):

| Capability | Attenuator | Restriction domain |
|---|---|---|
| `Fs` | `restrict_to(prefix: String) -> Fs` | path prefix |
| `Env` | `restrict_to_keys(keys: List<String>) -> Env` | key set |
| `Clock` | `restrict_to_after(t: Float) -> Clock` | minimum instant |
| `Net` | `restrict_to(host: String) -> Net` | host set |
| `Random` | `with_seed(seed: Int) -> Random` | deterministic seed |
| `Db` | `restrict_to(path: String) -> Db` | path prefix |
| `Proc` | `restrict_to(cmd: String) -> Proc` | basename prefix |
| `Serve` | `restrict_to(spec: String) -> Serve` | `(address, port)` pair |

`Stdio` has no attenuator (the authority to write to stdout/stderr
has no natural subset in this version). `Unsafe` has no attenuator by
design: it is the FFI hatch, not a gradable system authority (see
[11-builtin-capabilities.md](11-builtin-capabilities.md)).

`with_seed` is an attenuator in a specific sense: it replaces the
real entropy source with a deterministic sequence fixed by the seed,
which removes the authority to "obtain unpredictable randomness". The
`allows(...)` methods query the restriction set without doing IO
(useful for tests and for the examples below).

## 3. Each attenuator only narrows: the `Net` example

`Net.restrict_to(host)` limits the reachable host set; the function
that receives the restricted `Net` queries it but cannot widen it:

```capa
// net_atten.capa
fun probe(net: Net, stdio: Stdio)
    stdio.println("allows api.example.com?  ${net.allows("api.example.com")}")
    stdio.println("allows evil.example.com? ${net.allows("evil.example.com")}")

fun main(net: Net, stdio: Stdio)
    let scoped = net.restrict_to("api.example.com")
    probe(scoped, stdio)
```

```
$ python -m capa --run net_atten.capa
allows api.example.com?  true
allows evil.example.com? false
$ python -m capa --run --wasm net_atten.capa
allows api.example.com?  true
allows evil.example.com? false
```

The two backends produce identical output. `Net` attenuation is by
**host** (set membership), not by URL prefix: `restrict_to` stores the
host set and `allows(h)` answers `h in set`
([`capa/runtime/_capabilities.py`](../capa/runtime/_capabilities.py),
`Net.restrict_to` at line 889). The `get`/`post` gate extracts the
host from the URL and checks it against the set, and re-checks the
same set on every redirect hop, so a `302` to another host is refused.

## 4. Monotonicity: chaining can only narrow

The central property of attenuation is **monotonicity**: applying
attenuators in a chain can only remove authority, never add it.
Chaining `restrict_to` is not "pick the last scope"; it is
**intersection**.

`Fs` accumulates prefixes and `allows` only admits a path contained
under ALL of them
([`capa/runtime/_capabilities.py`](../capa/runtime/_capabilities.py),
`Fs.restrict_to` at line 265: the new prefix is unioned into the set,
and the check requires every prefix to hold). The third
`restrict_to("/")` does not widen back, because the restriction to
`/tmp/sub/` still holds:

```capa
// mono.capa
fun main(fs: Fs, stdio: Stdio)
    let a = fs.restrict_to("/tmp/")
    let b = a.restrict_to("/tmp/sub/")
    let c = b.restrict_to("/")
    stdio.println("a /tmp/x        ${a.allows("/tmp/x")}")
    stdio.println("b /tmp/x        ${b.allows("/tmp/x")}")
    stdio.println("b /tmp/sub/x    ${b.allows("/tmp/sub/x")}")
    stdio.println("c /tmp/sub/x    ${c.allows("/tmp/sub/x")}")
    stdio.println("c /etc/passwd   ${c.allows("/etc/passwd")}")
```

```
$ python -m capa --run mono.capa
a /tmp/x        true
b /tmp/x        false
b /tmp/sub/x    true
c /tmp/sub/x    true
c /etc/passwd   false
$ python -m capa --run --wasm mono.capa
a /tmp/x        true
b /tmp/x        false
b /tmp/sub/x    true
c /tmp/sub/x    true
c /etc/passwd   false
```

The two backends produce identical output. Reading the lines:

- `a` allows `/tmp/x` (restricted to `/tmp/`).
- `b` does NOT allow `/tmp/x` (the intersection of `/tmp/` with
  `/tmp/sub/`; the file must be under both).
- `b` allows `/tmp/sub/x`.
- `c`, after `restrict_to("/")`, still does NOT allow `/etc/passwd`
  and still allows only `/tmp/sub/x`: adding `/` does not restore
  removed authority.

The same monotonicity holds for `Net` (host-set intersection) and the
other attenuable caps. The metatheory is formalized in
[`proofs/CapaAttenuation.agda`](../proofs/CapaAttenuation.agda).

JUDGEMENT. Because the only ways to obtain a capability value are
`main`'s parameter or an attenuation of an existing value
([10-capability-model.md](10-capability-model.md) section 3), and each
attenuation only narrows, the authority scope of any `Fs` value in a
program is always a subset of what `main` received. No operation
widens it.

## 5. Runtime enforcement: out of scope fails with `Err`

The restriction is checked BEFORE any system call, so a refused target
never reaches the IO layer. IO-performing operations return
`Result<..., IoError>`; an out-of-scope target is an `Err`, not a
crash.

An `Fs` restricted to `/tmp/allowed/` refuses reading `/etc/passwd`:

```capa
// enforce.capa
fun main(fs: Fs, stdio: Stdio)
    let scoped = fs.restrict_to("/tmp/allowed/")
    match scoped.read("/etc/passwd")
        Ok(text) -> stdio.println("read ${text.length()} bytes")
        Err(e) -> stdio.println("denied: ${e.message}")
```

```
$ python -m capa --run enforce.capa
denied: Fs capability does not permit read on '/etc/passwd'
$ python -m capa --run --wasm enforce.capa
denied: Fs capability does not permit read on '/etc/passwd'
```

The two backends produce identical output, including the `IoError`
text. The `read` never touched the disk: the decision is the gate's.

## 6. The type does not change; the value carries the restriction

A design point: attenuation is a **runtime fact about the value**, not
a distinction in the **static type**. `fs.restrict_to("/tmp/")` still
has type `Fs`. Consequences:

- A function that receives `Fs` does not know statically whether it
  received a wide or a restricted `Fs`; it only knows it holds `Fs`
  authority, and the runtime gates every operation against the
  concrete scope it was passed.
- The authority surface the manifest derives is about TYPES (`Fs`
  yes/no), not about the concrete runtime scope. The scope (which
  prefix, which hosts) is a dynamic property; what is static and
  provable is "this function can reach `Fs`" (see
  [29-capability-manifest.md](29-capability-manifest.md)).
- On the Wasm backend, the attenuable caps are handle-bearing
  (`HANDLE_BEARING_CAPS`,
  [`capa/ir/_capa_types.py`](../capa/ir/_capa_types.py) line 79):
  each value lowers to an `i32` handle into the host's cap table, so
  the scope travels with the value across function boundaries,
  exactly as on the Python backend.

The layer that fixes authority at startup time, orthogonal to this
one (`--preopen`, `--allow-host`, the WASI ceilings), is in
[23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md).

---

## Links

- [10-capability-model.md](10-capability-model.md): the propagation
  discipline attenuation is a case of.
- [11-builtin-capabilities.md](11-builtin-capabilities.md): each
  capability's methods, including the attenuators and `allows`.
- [23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md):
  operator-fixed attenuation at startup (distinct from this page's
  in-language attenuation).
- [29-capability-manifest.md](29-capability-manifest.md): why the
  manifest reasons over types and not runtime scopes.
- [`proofs/CapaAttenuation.agda`](../proofs/CapaAttenuation.agda):
  the monotonicity metatheory.
