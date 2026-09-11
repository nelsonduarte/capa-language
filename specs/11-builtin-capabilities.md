# 11. The 10 built-in capabilities

> **What this chapter covers.** The EXACT set of built-in capabilities
> the compiler recognizes (ten, single source of truth in
> `capa/typesys.py`), and for each one: the authority it grants, its
> methods (from `capa/builtins.py`), and the scope notes (`Serve`
> exists only on the Python backend; `Unsafe` is the FFI exit hatch).
> Includes the full method table and examples verified on both
> backends. The model (why there are only these doors) is in
> [10-capability-model.md](10-capability-model.md); attenuation
> (`restrict_to` and kin) in [12-attenuation.md](12-attenuation.md).

**Version documented.** `main` at commit `8e2c609` (`capa 1.32.0` plus
unreleased commits). Every transcript re-run at that commit on
2026-09-11, `python -m capa` importing the checkout under
specification; the method table was regenerated from
[`capa/builtins.py`](../capa/builtins.py) at this commit.

Depends on: [10-capability-model.md](10-capability-model.md).

---

## 1. The set: exactly ten

The capabilities the system recognizes are a fixed `frozenset`,
`CAPABILITY_NAMES` in [`capa/typesys.py`](../capa/typesys.py) line
190:

```python
CAPABILITY_NAMES: frozenset[str] = frozenset({
    "Stdio", "Fs", "Net", "Env", "Proc", "Clock", "Random", "Db",
    "Serve", "Unsafe",
})
```

They are opaque names to the checker: parameters of type `Stdio`,
`Fs`, etc. are accepted as annotations and subject to the capability
discipline ([10-capability-model.md](10-capability-model.md)), and the
method types come from [`capa/builtins.py`](../capa/builtins.py).
There is no way for a program to add an eleventh: the list is the
boundary of built-in authority.

| Capability | Authority granted | Wasm-backend representation |
|---|---|---|
| `Stdio` | Write to stdout/stderr, read one line from stdin | erased (`ERASED_CAPS`) |
| `Fs` | Read/write/list the filesystem, attenuable by path prefix | handle (`HANDLE_BEARING_CAPS`) |
| `Net` | HTTP GET/POST, attenuable by host | handle |
| `Env` | Read environment variables and argv, attenuable by key | handle |
| `Proc` | Run subprocesses, attenuable by basename prefix | handle |
| `Clock` | Read wall and monotonic clocks, sleep, attenuable by instant | handle |
| `Random` | Integers in a range and floats in `[0,1)`, seedable | erased |
| `Db` | Execute SQL (SQLite), attenuable by path prefix | handle |
| `Serve` | Accept inbound TCP connections (Python only) | erased (rejected before lowering) |
| `Unsafe` | FFI hatch: import/invoke arbitrary Python (Python only) | erased (rejected before lowering) |

The right-hand column comes from
[`capa/ir/_capa_types.py`](../capa/ir/_capa_types.py):
`HANDLE_BEARING_CAPS = {Fs, Net, Db, Proc, Env, Clock}` (line 79)
lower to an `i32` handle into the host's cap table (so a restricted
cap keeps its restriction across function boundaries on Wasm);
`ERASED_CAPS = {Stdio, Random, Unsafe, Serve}` (line 101) push no
value. `Serve` and `Unsafe` are in `PYTHON_ONLY_CAPS` (line 58): the
Wasm paths refuse them before lowering (sections 5 and 6).

## 2. The method table

From [`capa/builtins.py`](../capa/builtins.py), the `METHODS`
dictionary (line 92). Signatures in Capa form (`Result<T, E>`,
`Option<T>`, `List<T>`). The `restrict_to*` / `with_seed` / `allows`
methods are the attenuation surface and its query, covered in
[12-attenuation.md](12-attenuation.md).

| Capability | Method | Signature |
|---|---|---|
| `Stdio` | `print` | `(String) -> ()` |
| `Stdio` | `println` | `(String) -> ()` |
| `Stdio` | `eprintln` | `(String) -> ()` |
| `Stdio` | `read_line` | `() -> Result<String, IoError>` |
| `Fs` | `restrict_to` | `(String) -> Fs` |
| `Fs` | `allows` | `(String) -> Bool` |
| `Fs` | `read` | `(String) -> Result<String, IoError>` |
| `Fs` | `write` | `(String, String) -> Result<Unit, IoError>` |
| `Fs` | `exists` | `(String) -> Bool` |
| `Fs` | `is_dir` | `(String) -> Bool` |
| `Fs` | `mkdir` | `(String) -> Result<Unit, IoError>` |
| `Fs` | `list_dir` | `(String) -> Result<List<String>, IoError>` |
| `Env` | `restrict_to_keys` | `(List<String>) -> Env` |
| `Env` | `allows` | `(String) -> Bool` |
| `Env` | `get` | `(String) -> Option<String>` |
| `Env` | `args` | `() -> List<String>` |
| `Clock` | `restrict_to_after` | `(Float) -> Clock` |
| `Clock` | `allows` | `() -> Bool` |
| `Clock` | `now_secs` | `() -> Float` |
| `Clock` | `now_monotonic` | `() -> Float` |
| `Clock` | `sleep` | `(Float) -> ()` |
| `Net` | `restrict_to` | `(String) -> Net` |
| `Net` | `allows` | `(String) -> Bool` |
| `Net` | `get` | `(String) -> Result<String, IoError>` |
| `Net` | `post` | `(String, String) -> Result<String, IoError>` |
| `Random` | `with_seed` | `(Int) -> Random` |
| `Random` | `int_range` | `(Int, Int) -> Int` |
| `Random` | `float_unit` | `() -> Float` |
| `Db` | `restrict_to` | `(String) -> Db` |
| `Db` | `allows` | `(String) -> Bool` |
| `Db` | `exec` | `(String, String) -> Result<Unit, IoError>` |
| `Db` | `query` | `(String, String) -> Result<String, IoError>` |
| `Proc` | `restrict_to` | `(String) -> Proc` |
| `Proc` | `allows` | `(String) -> Bool` |
| `Proc` | `exec` | `(String, String) -> Result<String, IoError>` |
| `Serve` | `restrict_to` | `(String) -> Serve` |
| `Serve` | `allows` | `(String, Int) -> Bool` |
| `Serve` | `listen` | `(String, Int) -> Result<Unit, IoError>` |
| `Serve` | `local_port` | `() -> Result<Int, IoError>` |
| `Serve` | `accept` | `() -> Result<Int, IoError>` |
| `Serve` | `recv` | `(Int, Int) -> Result<List<Int>, IoError>` |
| `Serve` | `send` | `(Int, List<Int>) -> Result<Unit, IoError>` |
| `Serve` | `close` | `(Int) -> Result<Unit, IoError>` |
| `Serve` | `stop` | `() -> Result<Unit, IoError>` |

`Unsafe` has no methods of its own: it is consumed by two free
functions (`FREE_FUNCTIONS` in
[`capa/builtins.py`](../capa/builtins.py) line 483),
`py_import(Unsafe, String) -> ?` (line 490) and
`py_invoke(Unsafe, ?, List<?>) -> ?` (line 491). See section 5.

IO errors unify into a single `IoError`, a built-in struct with
fields `message: String` and `cause: String`, so the boundary shape is
the same on both backends.

## 3. Verified example: `Random`

`Random.with_seed(n)` derives a deterministic generator; the sequence
is byte-identical on both backends.

```capa
// rand.capa
fun main(stdio: Stdio, random: Random)
    let r = random.with_seed(42)
    stdio.println("a=${r.int_range(1, 100)}")
    stdio.println("b=${r.int_range(1, 100)}")
    stdio.println("c=${r.int_range(1, 100)}")
```

```
$ python -m capa --run rand.capa
a=65
b=83
c=91
$ python -m capa --run --wasm rand.capa
a=65
b=83
c=91
```

The two backends produce identical output.

## 4. Verified example: `Env`

`Env.get` reads an environment variable (returns `Option<String>`);
`Env.allows` queries the allowed key set without doing IO. Here with
an already-attenuated set (attenuation detail in
[12-attenuation.md](12-attenuation.md)):

```capa
// env_atten.capa
fun probe(env: Env, stdio: Stdio)
    stdio.println("allows PATH?      ${env.allows("PATH")}")
    stdio.println("allows SECRET?    ${env.allows("SECRET")}")

fun main(env: Env, stdio: Stdio)
    let scoped = env.restrict_to_keys(["PATH", "HOME"])
    probe(scoped, stdio)
```

```
$ python -m capa --run env_atten.capa
allows PATH?      true
allows SECRET?    false
$ python -m capa --run --wasm env_atten.capa
allows PATH?      true
allows SECRET?    false
```

The two backends produce identical output.

## 5. `Unsafe`: the FFI hatch

`Unsafe` is the only capability that does not represent an attenuable
system authority; it represents the exit to arbitrary Python code
(FFI). It is obtained like any other, as a `main` parameter, and
consumed by the free functions `py_import` / `py_invoke`. It has no
attenuator and never benefits from relaxations (it cannot be a struct
field, not even in a cap-bearing struct; see
[13-user-defined-capabilities.md](13-user-defined-capabilities.md)).

Accepted by the checker, and refused loudly by the Wasm backend:

```capa
// unsafe_use.capa
fun main(unsafe: Unsafe, stdio: Stdio)
    let os = py_import(unsafe, "os")
    stdio.println("imported")
```

```
$ python -m capa --check unsafe_use.capa
unsafe_use.capa: ok (1 items, 6 expressions typed, 3 bindings)
$ python -m capa --run --wasm unsafe_use.capa
capa: --wasm: the Unsafe capability is intentionally not supported on the Wasm backend (it grants raw pointer / FFI / memory-map primitives that have no sandboxed Wasm equivalent). Use the Python backend for these functions, or refactor to remove the Unsafe parameter.
  - main(unsafe: Unsafe)
```

That a function reaches `Unsafe` is recorded in the manifest
(`has_unsafe`, `functions_crossing_unsafe`), precisely because it is
the fact an auditor wants to see.

## 6. `Serve`: Python backend only

`Serve` (inbound TCP connection authority) is connection-level on
purpose: the trusted runtime binds/accepts and moves bytes; the
protocol (HTTP or other) is parsed by ordinary Capa code, so a
protocol bug is not a bug in the trusted computing base
([`capa/builtins.py`](../capa/builtins.py), the `Serve` block
comment). It is `recv`/`send` over bytes (`List<Int>`, each element in
`0..=255`), sequential (one open connection at a time).

`Serve` is in `PYTHON_ONLY_CAPS`: the program passes the checker, runs
on the Python backend, and is refused loudly by the Wasm backend (no
`wasi:sockets` vendored or reachable from the wasmtime-py bindings).

```capa
// serve.capa
fun main(serve: Serve, stdio: Stdio)
    let r = serve.listen("127.0.0.1", 8080)
    stdio.println("listening")
```

```
$ python -m capa --check serve.capa
serve.capa: ok (1 items, 7 expressions typed, 2 bindings)
$ python -m capa --run --wasm serve.capa
capa: --wasm: the Serve capability is intentionally not supported on the Wasm backend (binding a listening socket needs wasi:sockets, which is neither vendored in capa/wasi_wit nor reachable from the wasmtime-py bindings the Wasm hosts are built on, so a guest can never be handed an inbound connection). Use the Python backend for these functions, or refactor to remove the Serve parameter.
  - main(serve: Serve)
```

Scope. The refusal of `Serve` and `Unsafe` on Wasm is a permanent
decision, not backlog; the exact scope of the identical-backends
promise is in [24-backend-parity.md](24-backend-parity.md).

---

## Links

- [10-capability-model.md](10-capability-model.md): why there are only
  these doors and how authority propagates.
- [12-attenuation.md](12-attenuation.md): the `restrict_to*` /
  `with_seed` methods and monotonicity.
- [13-user-defined-capabilities.md](13-user-defined-capabilities.md):
  composing these built-ins into a higher-level capability.
- [23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md):
  how the handle-bearing caps are materialized in the Wasm host.
- [24-backend-parity.md](24-backend-parity.md): `Serve` and `Unsafe`
  as the Python-only capabilities.
- [`docs/stdlib.md`](../docs/stdlib.md): the non-capability types and
  methods (String, List, Map, Option, Result, ...).
