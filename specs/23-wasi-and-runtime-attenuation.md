# 23. WASI: the import boundary, preopens, runtime attenuation

> **What this chapter covers.** The runtime ENFORCEMENT layer that
> backs the compile-time capability model on the Wasm Component Model
> backend. It describes the experimental `--wasi` mode (migrating the
> capability touch-points from the `capa:host` interfaces to the
> canonical WASI Preview 2 interfaces), the resulting import boundary,
> the **static authority ceilings** (`_fs_ceiling`, `_net_ceiling`,
> `_env_ceiling`) the compiler computes and materializes in the host,
> filesystem **preopens** (`--preopen`, the Level 2 operator grant),
> the `--allow-host` network grant (with what is and is NOT
> mitigated), the `--wasi-surface` argv surface, the
> `--wasm-memory-cap` memory ceiling, and the untrusted-foreign limits
> (`--foreign-fuel`, `--foreign-memory-cap`, `--foreign-result-cap`).
> It builds on [22-wasm-component-model-backend.md](22-wasm-component-model-backend.md)
> and on [11-builtin-capabilities.md](11-builtin-capabilities.md).

**Version documented.** `main` at commit `8e2c609` (`capa 1.32.0` plus
unreleased commits). Every transcript re-run at that commit on
2026-09-11, `python -m capa` importing the checkout under
specification, with `wasm-tools 1.249.0` and wasmtime-py 46.0.1
(`--wasi --run` additionally requires wasmtime-py's WASI Preview 2
support). The network measurements of section 6 ran on a machine with
access to `example.org`.

Depends on:
[22-wasm-component-model-backend.md](22-wasm-component-model-backend.md),
[11-builtin-capabilities.md](11-builtin-capabilities.md).

---

## 1. WASI as the execution layer of authority

Capa's capability model is static: authority enters through `main`'s
signature, propagates explicitly, and the checker proves no function
touches a capability it did not receive. On the Wasm backend that
compile-time proof needs a runtime enforcement mirroring it: a Wasm
guest only reaches an effect if the host satisfies the corresponding
import.

WASI (the WebAssembly System Interface) is capability-based by
design: a WASI component has no ambient authority over the filesystem
or the network; it receives PREOPENED descriptors granted by the host
at instantiation, and cannot open anything outside them. That model is
Capa's own, and the `--wasi` mode exploits the coincidence: instead of
the `capa:host` host mediating each `Fs.read` through a Python
callback, the component imports `wasi:filesystem` and wasmtime itself
enforces the preopen boundary. The authority ceiling the compiler
PROVES (which directories / hosts / keys the program can touch) is
then MATERIALIZED as the host's WASI configuration, and the boundary
is enforced by the sandbox, not by trusted runtime code.

The layer has two levels, in the nomenclature the code uses
([`docs/design/wasi-attenuation.md`](../docs/design/wasi-attenuation.md)):

- **Level 1** (enforced by the WASI host at instantiation): the
  `wasi:cli/environment` env set and the `wasi:filesystem` preopens.
  A ceiling wasmtime applies regardless of what the guest attempts.
- **Level 2** (enforced guest-side by compiler-generated code): the
  fine attenuation `Fs.restrict_to` / `Net.restrict_to` /
  `Env.restrict_to_keys` and the `Net` host gate, plus the operator
  grants `--preopen` / `--allow-host`. Proven by the compiler (the
  guest only narrows) and honoured by Capa's host, but not
  re-verified by a stock WASI host.

The mode is EXPERIMENTAL and opt-in (`--wasi`; the CLI help says so).
The default `capa:host` path is unchanged.

## 2. The import boundary: `capa:host` versus `wasi:*`

`--wasi` is only valid with `--wasm --component`. When active, it
migrates the SUPPORTED touch-points of `Random`, `Clock`, `Env`,
`Fs`, `Net` and `Stdio` from the `capa:host` interfaces to the
canonical WASI Preview 2 interfaces; everything else (notably
`panic`) stays on `capa:host`. The component imports both families at
once: the host satisfies the `wasi:*` ones via wasmtime's
`Linker.add_wasip2()` and the `capa:host` ones via the existing
custom registrations
([`capa/ir/_emit_wasm/_wasi/__init__.py`](../capa/ir/_emit_wasm/_wasi/__init__.py)).

The exact set of rerouted (capability, method) pairs is
`_WASI_MIGRATED_METHODS`
([`capa/ir/_emit_wasm/_wasi/_constants.py`](../capa/ir/_emit_wasm/_wasi/_constants.py)
line 14). Capa deliberately pins the `wasi:*@0.2.0` snapshot, both in
the vendored WIT (`capa/wasi_wit/`) and in the import strings; the
interfaces Capa touches are at Phase 3 (Implementation) of the WASI
process and are not described here as "standardized".

| Capa | Method(s) | WASI import |
|---|---|---|
| `Random` | `system_seed` | `wasi:random/random@0.2.0` |
| `Clock` | `now_secs`, `now_monotonic` | `wasi:clocks/wall-clock@0.2.0`, `wasi:clocks/monotonic-clock@0.2.0` |
| `Env` | `get`, `args` | `wasi:cli/environment@0.2.0` |
| `Env` | `restrict_to_keys`, `allows` | (guest-side, no import) |
| `Stdio` | `print`, `println`, `eprintln`, `read_line` | `wasi:cli/stdout` \| `stderr` \| `stdin` + `wasi:io/streams@0.2.0` |
| `Fs` | `exists`, `is_dir`, `mkdir` | `wasi:filesystem/types@0.2.0` + `preopens` |
| `Fs` | `read`, `write`, `list_dir` | `wasi:filesystem` + `wasi:io/streams` |
| `Fs` | `restrict_to`, `allows` | (guest-side, no import) |
| `Net` | `get`, `post` | `wasi:http/outgoing-handler@0.2.0` + `types` + `wasi:io/streams` + `poll` |
| `Net` | `restrict_to`, `allows` | (guest-side, no import) |

Unit/shape conversions are done guest-side in WAT (nanoseconds to
seconds, the canonical `list<string>` layout), so the Capa surface
keeps exposing `f64` seconds and `Option<String>` / `List<String>`
identically to the default backend.

**What does NOT migrate is refused loudly.** `_validate_wasi_caps`
([`capa/ir/_emit_wasm/_wasi/_core.py`](../capa/ir/_emit_wasm/_wasi/_core.py))
rejects, at emission, what this mode cannot translate, so a program
never miscompiles silently: `Clock.sleep` (it would pull in
`wasi:io` polling, out of scope) and the `Clock.restrict_to_after` /
`Clock.allows` attenuation (the `wasi:clocks` interfaces are pure
readers with no host-side handle table to enforce a deadline).
Measured:

```
$ python -m capa --run --wasm --component --wasi clocksleep.capa
capa: --wasm: Clock.sleep is not supported in the WASI mode yet; use the default capa:host backend (drop --wasi).
```

All `Fs` operations migrate (`_WASI_FS_REJECTED` is the empty set,
`_constants.py` line 168); `Fs.read` under `--wasi` is measured in
section 4.

## 3. The static ceilings: the common model

Before instantiating the component, the compiler computes three
authority CEILINGS, one per attenuable system capability, each in its
own `capa/ir/` module:

| Ceiling | File | What it computes | Level |
|---|---|---|---|
| `FsCeiling` | [`capa/ir/_fs_ceiling.py`](../capa/ir/_fs_ceiling.py) | the preopen directories the program can reach | 1 |
| `NetCeiling` | [`capa/ir/_net_ceiling.py`](../capa/ir/_net_ceiling.py) | the host set the program can reach | 2 (guest-side) |
| `EnvCeiling` | [`capa/ir/_env_ceiling.py`](../capa/ir/_env_ceiling.py) | the environment keys the program can read | 1 |

The three share the same architecture:

1. **Computed from the CIR**, after the loader inlined imported
   functions: every reachable `fs.*` / `net.get|post` / `env.get`
   call site is visible.
2. **The literal/dynamic rule.** A string-LITERAL argument
   contributes (the path's parent directory, the URL's host, the
   key); a NON-literal argument (a local, a param, a computed value)
   makes the ceiling undeterminable at compile time and marks it NOT
   CLOSED.
3. **The fail-closed policy.** An unclosed ceiling is NOT
   materialized. For `Fs` and `Net` this is total FAIL CLOSED (no
   preopen; the guest gate refuses every host); for `Env` it degrades
   to `inherit_env` (Level 2), because a missing key merely reads
   `none` while a wrong preopen would be real filesystem authority.

The `net_ceiling` is only computed when the program uses a `Net`
REQUEST operation (`get`/`post`): a program that only narrows /
queries keeps it `None` so `wasi:http` is never linked (a clean total
deny).

## 4. Fs: preopens and their enforcement

The `FsCeiling` maps `main`'s `Fs` ceiling onto the host's preopen
configuration. For each literal path at an `fs.*` call site, the
preopen is the path's PARENT directory, with READ_WRITE permission
when the op mutates (`mkdir`/`write`) and READ_ONLY otherwise; the
basename becomes a relative path addressed against the preopen's
descriptor. Nested preopens are COALESCED (a correctness requirement:
wasmtime collapses overlapping preopens, so the outer parent survives
and absorbs any coalesced member's READ_WRITE permission). Each
literal call site records the INDEX of its preopen in the ordered
list, and the host registers the preopens in the same order, so
guest index K names host directory K.

In the host, `_apply_fs_preopens`
([`capa/runtime/_wasm_component_host.py`](../capa/runtime/_wasm_component_host.py)
line 469) registers each ceiling directory at a synthetic guest path
`/capa-preopen-K` (the guest addresses by index, never by path
string), with the ceiling's permission. A ceiling directory that does
not exist on the host is registered against an empty READ_ONLY
placeholder tempdir, keeping index K aligned (fail-closed-as-absent);
measured: a literal-path program over a nonexistent directory returns
a graceful `Err` (`DENIED: failed to read file`, exit 0). The
docstring states the guarantee: preopens are a hard runtime ceiling;
wasmtime denies traversal outside a preopened directory and denies a
write through a READ_ONLY preopen, independent of guest behaviour.

**Preopen grants exactly one directory; traversal is denied.** A
program reads a literal file inside the derived preopen
(`data/inside.txt`, whose parent `data` is preopened READ_ONLY) and
attempts a traversal outside (`data/../secret.txt`). The Python
backend (`capa:host`, a root `Fs` with no preopen boundary) reads
both; the WASI component denies the traversal:

```
$ python -m capa --run fslit.capa
inside: hello from inside
traversal READ: SECRET outside preopen
$ python -m capa --run --wasm --component --wasi fslit.capa
inside: hello from inside
traversal DENIED: failed to read file
```

The contrast is the point: the preopen ceiling is a runtime boundary
the WASI component enforces (the traversal returns `Err(IoError)`),
while the root `Fs` of the `capa:host` backend has no such system
boundary. The DENIAL is measured; that wasmtime guarantees it against
any guest is the design reading of WASI preopens (JUDGEMENT, see
section 10).

## 5. Fs: dynamic paths and the `--preopen` operator grant

A NON-literal `Fs` path (`fs.read(p)` with `p` from argv, a param, or
a computed value) opens the ceiling. The policy is fail-closed at TWO
points: `_validate_wasi_caps` rejects at compile time, and
`_apply_fs_preopens` registers no preopens.

Without `--preopen`, a dynamic path is refused at emission, with the
argv-to-sink surface named in the message:

```
$ python -m capa --run --wasm --component --wasi fsdyn.capa -- data/inside.txt
capa: --wasm: Fs in WASI mode requires every filesystem path to be a string literal (the static preopen ceiling must be closed); this program passes a dynamic path to an Fs operation, so no preopen can be derived (fail-closed). The compiler proved this program routes argv (env.args()) to Fs: argv[*] -> Fs.read (read-only). Run with --preopen <dir> to grant the component filesystem authority over the directory containing that path (the operator-declared WASI --dir model), or use the default capa:host backend (drop --wasi).
```

`--preopen <dir>[:ro|:rw]` is the Level 2 OPERATOR grant (WASI's
`--dir` model): it grants authority over `<dir>` to unblock the
dynamic paths the compiler could not derive. The default permission is
`rw`; `:ro` makes it READ_ONLY. This increment supports ONE
`--preopen` (more than one is refused). The grant is registered in
the host by `_apply_operator_preopen`
(`_wasm_component_host.py` line 559) AFTER the derived preopens, and
in the SBOM as an operator-declared grant, distinct from the derived
surface ([29-capability-manifest.md](29-capability-manifest.md)).

With `--preopen`, the dynamic path resolves at runtime relative to
the granted directory; a path inside the preopen reads, a traversal
outside returns a graceful `Err`:

```
$ python -m capa --run --wasm --component --wasi --preopen data fsdyn.capa -- inside.txt
read: hello from inside
$ python -m capa --run --wasm --component --wasi --preopen data fsdyn.capa -- ../secret.txt
DENIED: failed to read file
```

`--preopen` requires `--wasi` (it has no effect on the default
backend):

```
$ python -m capa --run --wasm --component --preopen data fslit.capa
capa: --preopen requires --wasi (or an SBOM / --manifest command): it is the operator-declared filesystem grant for the WASI mode, recorded in the SBOM; it has no effect on the default execution backend
```

## 6. Net: `--allow-host`, the guest-side gate, and the SSRF analysis

`Net`'s ASYMMETRY against `Fs`/`Env` is documented in the code
itself ([`capa/ir/_net_ceiling.py`](../capa/ir/_net_ceiling.py)):
unlike preopens (Level 1, enforced by the WASI host), the `Net`
ceiling is NOT enforced by wasmtime. The wasmtime `wasi:http` C-API in
this release is ALLOW-ALL, with no allowed-hosts surface, so there is
no host-side ceiling to map. The `NetCeiling` is therefore enforced
GUEST-SIDE (codegen, Level 2): the `$Net_get` / `$Net_post` wrapper
refuses any host outside the static ceiling, returning `Err(IoError)`
without calling the `wasi:http` handler. An unclosed ceiling (a
dynamic URL) fails closed; the rejection is at compile time,
symmetric with `Fs`.

`--allow-host <host>[:get|:post]` is the operator grant unblocking a
dynamic URL: granted hosts are unioned into the guest-side host
ceiling. It is REPEATABLE (an allowlist is a set). `<host>` may be a
bare host, `host:port` or a URL, normalized (lowercased, port and
userinfo stripped, trailing dot removed) by the SAME `normalize_host`
the gate uses. The `:get` suffix grants only READ (GET), `:post` only
WRITE (POST); no suffix grants both. A MALFORMED method suffix is
REJECTED with an error, never silently widened to both.

**The gate refuses an ungranted host and admits the granted one.**
Granting `example.com` and requesting a different real host
(`example.org`, resolvable) is refused; granting `example.org`, the
same request passes, proving the gate (not a network failure)
decides:

```
$ python -m capa --run --wasm --component --wasi --allow-host example.com netdyn.capa -- http://example.org/
DENIED: HTTP GET failed
$ python -m capa --run --wasm --component --wasi --allow-host example.org netdyn.capa -- http://example.org/
OK <!doctype html><html lang="en"><head><title>Example Domain</...
```

**Method scope is enforced.** `--allow-host example.com:get` grants
only GET; a `net.post` to `example.com` is refused:

```
$ python -m capa --run --wasm --component --wasi --allow-host example.com:get netpost.capa -- http://example.com/
DENIED: HTTP POST failed
```

**The SSRF / DNS-rebinding analysis: what IS and is NOT mitigated.**

- **Measured (a warning, not a block).** Granting an internal /
  non-routable IP (loopback, link-local, unspecified, private) emits
  a stderr WARNING, but the grant is PERMITTED
  (`_classify_internal_ip` tests a LITERAL IP):

  ```
  $ python -m capa --run --wasm --component --wasi --allow-host 169.254.169.254 netdyn.capa -- http://denied.invalid/
  capa: WARNING: --allow-host 169.254.169.254 grants a link-local address; this is usually an SSRF risk
  DENIED: HTTP GET failed
  ```

  (`169.254.169.254` is the cloud metadata endpoint, the classic
  SSRF target.)

- **NOT mitigated (DNS rebinding), by declared design boundary.** The
  gate compares the URL's HOSTNAME against the allowlist; DNS
  resolution happens host-side inside `wasi:http`, which is allow-all
  and does not filter the resolved IP. A hostname allowlist cannot
  defend against DNS rebinding: a granted name that resolves (or
  re-resolves) to an internal IP is not refused. The code declares
  this itself: the `--allow-host` help says "a hostname allowlist
  cannot defend against DNS rebinding (wasi:http is host-side
  allow-all, so the resolved IP is not filtered)". This statement is
  read from the code and its help; no rebinding attack was exercised
  here (JUDGEMENT grounded in the source, section 10).

## 7. Env: the env-set ceiling (Level 1) and guest-side attenuation

The `EnvCeiling` is the set of keys the program can read via
`env.get` (literals; `env.args` reads argv and does not widen it;
`restrict_to_keys` / `allows` only narrow / query). With the ceiling
closed, the host instantiates the component with an env set
restricted to the union of the literals, read from the host
environment: the component NEVER receives a variable outside the
ceiling, closing the leak-by-default of `inherit_env`. A key in the
ceiling but absent from the environment reads as `none` (fail-closed,
identical to the oracle). An unclosed ceiling (a dynamic key)
degrades to `inherit_env` (Level 2), the one non-total fail-closed of
the three, because a missing key only denies a read, never grants
authority.

The FINE attenuation `Env.restrict_to_keys` / `Env.allows` is
implemented guest-side in WAT with semantics byte-identical to the
Python oracle (the `Env` class of
[`capa/runtime/_capabilities.py`](../capa/runtime/_capabilities.py)):
`Env.get` FAILS CLOSED when the restricted key is not in the list,
without reading the environment. The guarantee is honestly Level 2:
under a stock / tampered WASI host the full environment would be
reachable and the narrowing would not be re-verified (the module's
"GUARANTEE LEVEL (honest)" docstring).

Reading a literal key under `--wasi` (with the environment holding
more than the read key):

```
$ CAPA_ALLOWED=yes CAPA_SECRET=hunter2 python -m capa --run --wasm --component --wasi envlit.capa
CAPA_ALLOWED=yes
```

(the accompanying information-flow warning is the IFC layer,
[16-ifc-analyzer-and-tiers.md](16-ifc-analyzer-and-tiers.md),
orthogonal to WASI.)

## 8. `--wasi-surface`: the argv-to-sink surface

`--wasi-surface` is a read-only static inspection: it prints which
`env.args()` arguments the compiler PROVES reach an `Fs` / `Net` /
`Env` sink, and whether read or write. It neither compiles nor runs;
it uses the linked AST and computes the surface with
`compute_path_arg_surface`
([`capa/ir/_wasi_path_arg_surface.py`](../capa/ir/_wasi_path_arg_surface.py)).
It is a by-construction audit fact, distinct from operator-declared
grants, and a SOUND over-approximation: no reaching argv argument is
omitted; a closure that escapes its frame has its param-fed sinks
conservatively reported at `argv[*]`.

Measured, for section 6's `netdyn.capa`:

```
$ python -m capa --wasi-surface netdyn.capa
netdyn.capa: WASI path-arg surface (compiler-derived, by-construction):
  argv[*] -> Net.get (read-only)
  (sound over-approximation: no reaching argv argument is omitted; ...)
```

The output itself declares its VALUE-FLOW residual scope: a closure
carried by a value not statically tied back to a lambda may be
under-reported (the printed note states this).

## 9. `--wasm-memory-cap` and the untrusted-foreign limits

`--wasm-memory-cap <pages>` limits the emitted linear memory to that
many 64 KiB pages. The bump allocator's `memory.grow` traps at a
deterministic ceiling instead of at a host-dependent OOM point.
Default: `MEMORY_CAP_DEFAULT_PAGES = 256` (16 MiB); `0` skips the
cap. It applies with `--wasm` (no `--wasi` needed). Measured in the
memory declaration (the second number is the page maximum):

```
$ python -m capa --wasm --transpile mem.capa | grep -m1 '(memory'
  (memory (export "memory") 1 256)
$ python -m capa --wasm --transpile --wasm-memory-cap 4 mem.capa | grep -m1 '(memory'
  (memory (export "memory") 1 4)
```

The three `--foreign-*` flags belong to a different path: a
`--wasm --run` of a CORE module importing an untrusted foreign
component (the `capa:foreign/<comp>` imports of
[22-wasm-component-model-backend.md](22-wasm-component-model-backend.md)),
which the `WasmHost` runs in a SEPARATE fuel-metered store
([`capa/runtime/_wasm_host.py`](../capa/runtime/_wasm_host.py),
[`capa/runtime/_foreign.py`](../capa/runtime/_foreign.py)). They are
the untrusted CHILD's resource ceiling:

| Flag | Limits | Default (`_foreign.py`) |
|---|---|---|
| `--foreign-fuel <N>` | the child's CPU per call (about 1 fuel per instruction); an infinite loop traps by exhaustion | `DEFAULT_FOREIGN_FUEL = 1_000_000_000` |
| `--foreign-memory-cap <MiB>` | the child's linear-memory growth | 256 MiB |
| `--foreign-result-cap <MiB>` | the HOST-side buffer of a mediated result (`fs.read` / net body / `db.query`); aborts early instead of OOMing the host | 256 MiB |

`configure_foreign_limits` applies them: `None` keeps the default, a
value greater than 0 sets the ceiling, and `0` explicitly opts out. A
NEGATIVE value is rejected up front, so a typo like
`--foreign-fuel -5` does not silently DISABLE the DoS protection.

## 10. Notes

- **Scope of the measurements.** The pasted outputs are from minimal
  programs (`fslit.capa`, `fslit_absent.capa`, `fsdyn.capa`,
  `netdyn.capa`, `netpost.capa`, `envlit.capa`, `clocksleep.capa`,
  `mem.capa`), run from a scratch folder at `8e2c609` with
  `wasm-tools 1.249.0` and wasmtime-py 46.0.1, on one machine with
  network access to `example.org`. No absolute personal path appears
  in the outputs.
- **Measured versus judgement (preopen enforcement).** The DENIAL of
  the `data/../secret.txt` traversal by the WASI component (section
  4) and of `../secret.txt` under `--preopen data` (section 5) was
  observed by execution. That wasmtime guarantees it independently of
  guest code is the reading of WASI's preopen model and of the
  `_apply_fs_preopens` docstring: the denial is MEASURED; its
  adversarial irrefutability is JUDGEMENT grounded in wasmtime's
  design, not an exhaustive proof against a hand-built hostile guest.
- **Measured versus judgement (`Net` gate).** The refusal of
  `example.org` under `--allow-host example.com` and the admission
  under `--allow-host example.org` were observed by execution, the
  contrast proving the gate decides. The claim that the gate refuses
  WITHOUT touching the network is the `_net_ceiling` docstring
  (source reading), not a packet-level observation.
- **NOT VERIFIED (foreign limits, section 9).** The runtime
  enforcement of the `--foreign-*` ceilings (the fuel-exhaustion
  trap, the memory / result caps) is described from source and
  pinned by the `tests/test_foreign_*` suites; it was not exercised
  by execution in this chapter (it would require building an
  untrusted foreign component). Only `--wasm-memory-cap` was measured
  here.
- **NOT VERIFIED (DNS rebinding).** The "not mitigated" statement is
  the code's own declared boundary (the `--allow-host` help); no
  rebinding attack was exercised.

---

## Links

- [22-wasm-component-model-backend.md](22-wasm-component-model-backend.md):
  the Wasm backend this layer rests on: the i32 handle table, the two
  hosts, the component wrap, and the vendored WASI WIT.
- [11-builtin-capabilities.md](11-builtin-capabilities.md): the ten
  capabilities and the attenuation surface these ceilings
  materialize.
- [12-attenuation.md](12-attenuation.md): the monotone in-language
  attenuation the guest-side gates reimplement in WAT with oracle
  parity.
- [24-backend-parity.md](24-backend-parity.md): the parity scope
  between `capa:host` and the `--wasi` path.
- [25-cli-commands-and-flags.md](25-cli-commands-and-flags.md): the
  full reference of `--wasi`, `--preopen`, `--allow-host`,
  `--wasi-surface`, `--wasm-memory-cap` and the `--foreign-*` flags.
- [29-capability-manifest.md](29-capability-manifest.md): the SBOM's
  `operator_declared_grants` block where `--preopen` /
  `--allow-host` are recorded, distinct from the derived surface.
