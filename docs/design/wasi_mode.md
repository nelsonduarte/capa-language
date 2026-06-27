# Experimental WASI Preview 2 mode (`--wasi`)

Status: experimental proof of concept (2026-06-27).

Capa's Wasm backend produces Component Model components whose
capability imports live in a custom `capa:host` namespace, satisfied
by Capa's own Python host (`capa.runtime._wasm_component_host`). This
note describes an opt-in mode that migrates the reader touch-points of
**three** capabilities, Random, Clock and Env, to import the
**canonical WASI Preview 2 (`0.2.0`)** interfaces instead, so they are
satisfied by any standard WASI P2 host (here, `wasmtime`'s
`Linker.add_wasip2()`). Env additionally keeps its attenuation
(`restrict_to_keys` / `allows`) working in this mode, implemented
guest-side (Level 2 of `docs/design/wasi-attenuation.md`), and, when
its read keys are static, maps its **authority ceiling** onto the host
env-set (**Level 1**; see "Env ceiling (runtime-imposed, Level 1)"
below).

It is a viability spike, not a general WASI port. The default
`capa:host` path is completely unchanged.

## What the flag does

`capa --wasm --component --wasi <file>` (also `--transpile --wasi` to
see the WAT) rewrites the migrated touch-points:

| Capa surface | Default (`capa:host`) | WASI mode |
| --- | --- | --- |
| `Random.system_seed` | `capa:host/random.system-seed` | `wasi:random/random@0.2.0` `get-random-u64` |
| `Clock.now_monotonic` | `capa:host/clock.now-monotonic` | `wasi:clocks/monotonic-clock@0.2.0` `now` |
| `Clock.now_secs` | `capa:host/clock.now-secs` | `wasi:clocks/wall-clock@0.2.0` `now` |
| `Env.get` | `capa:host/env.get` | `wasi:cli/environment@0.2.0` `get-environment` |
| `Env.args` | `capa:host/env.args` | `wasi:cli/environment@0.2.0` `get-arguments` |
| `Env.restrict_to_keys` | `capa:host/env.restrict-to-keys` (host handle table) | guest-side allow-list intersection (no host) |
| `Env.allows` | `capa:host/env.allows` (host handle table) | guest-side allow-list membership (no host) |

Every **other** capability the program uses (Stdio for printing the
results, and anything else) stays on `capa:host`. The component
imports the `wasi:*` interfaces and the `capa:host` interfaces
simultaneously. This **hybrid coexistence** is the central thing the
PoC proves.

### Env reader migration (guest-side search / list reshape)

`wasi:cli/environment` delivers the whole environment and argv as
canonical-ABI lists; the Capa `Env.get` / `Env.args` shapes are
reconstructed guest-side in WAT, the same strategy the Clock wrappers
use for unit conversion, so the call-site emitters and the
`option_string` / `list_string` materialisers are unchanged:

- `get-environment -> list<tuple<string, string>>` is an indirect
  return (data_ptr, len) of 16-byte `(k_ptr, k_len, v_ptr, v_len)`
  records. `$Env_get` linear-scans for the requested key via `$str_eq`
  and writes an `option<string>` (WIT tag convention, none=0/some=1)
  into the call site's return area. A missing key yields `none`,
  **fail-closed**, identical to the Python `Env.get`
  (`capa/runtime/_capabilities.py:368-372`) and the `capa:host`
  bridge.
- `get-arguments -> list<string>` is an indirect return (data_ptr,
  len) whose data layout (N packed `(str_ptr, str_len)` i32 pairs) is
  **byte-identical** to a Capa `List<String>` data array, so `$Env_args`
  copies the (data_ptr, len) pair straight through with no per-element
  copy.

The host provides the values through the `WasiConfig`. The env-set it
installs depends on the **static Env ceiling** (see "Env ceiling
(runtime-imposed, Level 1)" below): a restricted env-set of exactly the
ceiling keys when the ceiling is closed, `inherit_env()` otherwise. The
argv is always `argv = <program args>` (so `env.args()` matches the
default backend's `sys.argv[1:]`, with no synthetic argv[0]).

### Env attenuation (guest-side, Level 2)

`Env.restrict_to_keys` and `Env.allows` are **supported** under
`--wasi`, implemented **guest-side** in WAT because
`wasi:cli/environment` is a pure reader with no host-side cap object to
hold an allow-list (this is **Level 2** of
`docs/design/wasi-attenuation.md`). The semantics are **byte-identical**
to the Python oracle (`capa/runtime/_capabilities.py:355-372`) and to
the `capa:host` backend (which enforces the same narrowing host-side
through its handle table).

The Env value (the i32 the host passes to `main`, and that
`restrict_to_keys` returns) is **reinterpreted** guest-side:

- `0` = **unrestricted** (the root Env `main` receives; the host passes
  `0` in this mode, since the `capa:host` handle has no meaning on the
  wasi path).
- non-zero = a pointer to a `List<String>` header (16 bytes: len@0,
  cap@4, data_ptr@8, pad@12) whose data array holds the **allow-list**
  as N packed `(str_ptr, str_len)` i32 pairs - the same layout a Capa
  `List<String>` uses, so the keys argument and the produced allow-list
  share one shape and one scan helper (`$str_eq`).

The three guest-side wrappers (`capa/ir/_emit_wasm/_wasi.py`):

- `$Env_restrict_to_keys(handle, keys_data_ptr, keys_len) -> i32`
  builds a new allow-list = the **intersection** of the current
  allow-list with `keys` (monotonic; never widens; an unrestricted
  `handle` intersected with `keys` becomes restricted to `keys`),
  allocates a fresh `List<String>` for it, returns the pointer. An
  empty intersection yields a non-zero pointer to a zero-length
  allow-list - a restricted-to-nothing Env, distinct from the
  unrestricted `0` sentinel. Identical to `Env.restrict_to_keys`
  (`new & self._allowed_keys`).
- `$Env_allows(handle, key_ptr, key_len) -> i32` returns 1 iff
  `handle == 0` (unrestricted) OR `key` is in the allow-list (the
  shared `$Env_key_allowed` helper).
- `$Env_get` gains a **fail-closed** prologue: when the Env is
  restricted and the key is not allowed it writes `none` WITHOUT
  reading the environment, identical to `Env.get`
  (`if not self.allows(name): return None_`).

`Env.args` is **not** attenuated (the oracle has no arg restriction).

**Guarantee level (honest).** The fine allow-list narrowing
(`restrict_to_keys` / `allows` / the `get` fail-closed gate) is
**Level 2**: imposed by the **compiler-generated guest code**, not by
the WASI host. It is **proved** by the compiler (the guest only ever
narrows) and **reinforced** by our host (which generated the guest);
under a stock or tampered WASI host the fine narrowing would not be
re-checked at the syscall.

The **ceiling** (which env vars the component receives **at all**) is
now **Level 1** when the program's `env.get` keys are static: the host
delivers only the ceiling keys, so a variable outside the ceiling is
not reachable even under a stock host. When a key is dynamic the host
falls back to `inherit_env` (a full-environment ceiling, Level 2). See
"Env ceiling (runtime-imposed, Level 1)" below. The byte-parity test
(`tests/test_wasi_mode.py::TestWasiEnvAttenuation`) pins the guest-side
narrowing to the host-side `capa:host` narrowing and the Python oracle
for the controlled keys.

### Env ceiling (runtime-imposed, Level 1)

`wasi:cli/environment` lets the host fix the env-set at instantiate
time, so the **authority ceiling** (which variables the component can
ever observe) is a thing a conformant host imposes. This mode maps
`main`'s Env ceiling onto that env-set when the ceiling is **static**,
closing the leak-by-default that `inherit_env` left open (the audit M1
trust-boundary note: an unrestricted Env saw the **whole** host
environment, secrets included).

**Computing the ceiling (static analysis).** The ceiling is the set of
keys the program can read through `Env.get`. It is computed from the
CIR (`capa/ir/_env_ceiling.py`, `compute_env_ceiling`) after the loader
has inlined imported functions, so every reachable `env.get` is visible.
The analysis walks every `MethodCall` whose receiver is an `Env` and
whose method is `get`:

- a **string-literal** argument contributes its key to the ceiling;
- any **non-literal** argument (a local / param / computed value) marks
  the ceiling **NOT CLOSED** (the key is decided at runtime, so the set
  cannot be materialised).

Only `Env.get` defines the ceiling: `Env.args` reads argv (no key), and
`restrict_to_keys` / `allows` only narrow or query, so neither can make
the program read a key it does not already pass to `env.get`. A literal
routed through an intermediate `let` (`let k = "FOO"`, then
`env.get(k)`) appears as a local at the call site and is treated
**conservatively as dynamic**; this declines the Level 1 tightening in
that case but never under-delivers a key (folding consts into the scan
is a possible future refinement, not a correctness requirement).

**Host decision.**

- **Ceiling closed** (no dynamic `env.get`): the host instantiates the
  component with `WasiConfig.env` set to **exactly** the ceiling keys,
  read from the host environment. A ceiling key absent from the host
  environment is simply omitted (the guest reads it as `none`,
  fail-closed). The component **never receives** a variable outside the
  ceiling. This is **Level 1**: the ceiling is imposed by the runtime
  on any conformant WASI host.
- **Ceiling not closed** (a dynamic `env.get` key): the host falls back
  to `inherit_env` (the full environment, Level 2 ceiling). The
  guest-side allow-list still narrows under our host, but the env-set
  is not tightened.

**No observable change.** Because the closed ceiling contains every
literal `env.get` reads, the program never requests a key outside it,
so the functional output is **identical** to the `inherit_env` path
(byte-for-byte across Python, `capa:host`, and WASI Level 1). The only
difference is that the component stops **receiving** the variables
outside the ceiling. The guest-side fine attenuation (Level 2) still
operates **on top** of the ceiling: the internal allow-list filters
further; the env-set only limits what the host delivers at the root.

**Wiring.** `capa/cli.py` computes the ceiling in the
`--wasi --component --run` path and passes it to
`WasmComponentHost(..., env_ceiling=...)`; the host builds the
restricted `WasiConfig.env` (or `inherit_env`) accordingly and records
the installed env-set in `WasmComponentHost._wasi_env_applied` (a dict
for a closed ceiling, the sentinel `"inherit"` otherwise) so the
leak-closed guarantee is inspectable. Tests:
`tests/test_wasi_mode.py::TestWasiEnvCeilingAnalysis` (pure analysis)
and `::TestWasiEnvCeilingLevel1` (end-to-end: `CAPA_SECRET` set in the
host env is **not** delivered to the component; output parity across
the three backends; dynamic-key fallback to `inherit_env`).

## Generated WIT (Clock + Random + Stdio)

For a program that seeds a `Random`, reads both clocks, and prints
via `Stdio`, the WASI-mode world is:

```wit
package capa:host;

interface stdio {
  println: func(msg: string);
}

world program {
  import wasi:random/random@0.2.0;
  import wasi:clocks/monotonic-clock@0.2.0;
  import wasi:clocks/wall-clock@0.2.0;
  import stdio;
  export main: func(clock: u32);
}
```

Note that no `capa:host` `random` / `clock` interface is emitted; the
migrated caps move entirely to `wasi:*`. Stdio keeps its `capa:host`
interface and world import. The `export main: func(clock: u32)`
handle param is still present because the core module un-erases Clock
into an `i32` handle slot (the WASI wrappers simply ignore it).

## Unit conversion (guest-side, in WAT)

The Capa surface keeps exposing `f64` **seconds** for both clocks; the
WASI interfaces deliver other units, so the conversion is done in the
guest:

- `monotonic-clock.now -> instant` is **u64 nanoseconds**. The wrapper
  `$Clock_now_monotonic` does `f64.convert_i64_u` then `/ 1e9`.
- `wall-clock.now -> datetime{seconds: u64, nanoseconds: u32}` is an
  indirect return into a fixed 16-byte scratch slot. The wrapper
  `$Clock_now_secs` reads `seconds` (u64 @0) and `nanoseconds`
  (u32 @8) and returns `seconds + nanoseconds / 1e9`.
- `get-random-u64 -> u64` is a drop-in for the old `system-seed`
  import; `$Random_system_seed` just forwards it.

The wrappers expose the exact `$Cap_method` binding the existing
call-site emitters already `call`, so no call-site emitter changed.
The wrappers drop the unused handle param the call sites still push.

## Host recipe (one Linker, both worlds)

`WasmComponentHost(wasi=True)` keeps **all** the existing `capa:host`
registrations and additionally:

```python
wasi_cfg = wasmtime.WasiConfig()
wasi_cfg.inherit_stdout()
wasi_cfg.inherit_stderr()
# Env ceiling (Level 1): a closed ceiling restricts the env-set to its
# keys; otherwise inherit_env (Level 2). See "Env ceiling" above.
if ceiling is not None and ceiling.closed:
    wasi_cfg.env = list(ceiling.host_env_set(dict(os.environ)).items())
else:
    wasi_cfg.inherit_env()       # env.get reads the host environment
wasi_cfg.argv = list(self._args) # env.args reads these (no argv[0])
store.set_wasi(wasi_cfg)
linker.add_wasip2()
```

`add_wasip2()` provides `wasi:random` + `wasi:clocks` +
`wasi:cli/environment` (and the rest of WASI P2) on the same
`wasmtime.component.Linker` the `capa:host` interfaces are registered
on. Registering `capa:host` interfaces the WASI component does not
import (the `capa:host/env` registration in particular) is harmless.
Instantiation then satisfies both namespaces.

## What is included / excluded

Included: `Random.system_seed`, `Random.with_seed` /
`int_range` / `float_unit` (these already run 100 % guest-side and are
unaffected), `Clock.now_secs`, `Clock.now_monotonic`, `Env.get`,
`Env.args`, and **Env attenuation** (`Env.restrict_to_keys`,
`Env.allows`, and the `Env.get` fail-closed gate), implemented
guest-side (Level 2; see "Env attenuation (guest-side, Level 2)"
above).

Excluded (rejected with a clear compile-time error so a program never
silently miscompiles):

- **`Clock.sleep`** would pull `wasi:io/streams` / `wasi:io/poll`,
  well beyond a clock-reading spike.
- **Clock attenuation** (`restrict_to_after`, `allows`). The
  `capa:host` Clock enforces a `restrict_to_after` deadline via the
  host's per-instance handle table; the `wasi:clocks` interfaces are
  pure readers with no host-side cap object to consult. Honouring
  attenuation through a standard WASI clock is a future design item
  (likely a guest-side deadline gate, since the wall clock is
  readable).

Env attenuation was previously excluded too; it is now supported
guest-side (Level 2). Mapping `main`'s Env **ceiling** onto the host
env-set (Level 1, so a stock host cannot even observe a variable
outside the ceiling) is now done when the program's `env.get` keys are
**static** (see "Env ceiling (runtime-imposed, Level 1)"); a program
with a dynamic `env.get` key falls back to `inherit_env` (Level 2
ceiling). Guest-side Level 2 still enforces the fine narrowing under
our host on top of whichever ceiling is in effect.

A program that reaches for one of the still-excluded methods in WASI
mode gets, e.g.:

```
capa: --wasm: Clock.sleep is not supported in the WASI mode yet;
use the default capa:host backend (drop --wasi).
```

## Vendored WIT

`wasm-tools component embed` resolves the `wasi:random` /
`wasi:clocks` / `wasi:cli` package references from a `deps/`
directory. We vendor a trimmed subset of the official WASI P2 `0.2.0`
WIT in `capa/wasi_wit/deps/` (random + clocks + cli/environment;
`now` / `get-random-*` / `get-environment` / `get-arguments` only; the
`subscribe-*` poll-dependent clock functions and the cli
`initial-cwd` are omitted because Capa only reads the clocks and the
env-set / argv). `_wrap_as_component(..., wasi=True)` copies these next
to the generated world before embedding; a program imports only the
packages it uses, and the unused deps are ignored by the embed.
Provenance and update instructions are in `capa/wasi_wit/README.md`.

## Validation

The migrated touch-points are non-deterministic, so validation is by
property (see `tests/test_wasi_mode.py`):

- **Pipeline**: a Clock + Random + Stdio program compiles, embeds the
  WASI WIT, instantiates, and runs without trap.
- **Seeded parity**: `with_seed(fixed) + int_range` is byte-identical
  to the Python backend (the WASI random import never fires on the
  seeded path).
- **Clock properties**: `now_monotonic` is non-decreasing across
  successive reads; `now_secs` is a plausible Unix timestamp close to
  the host clock.
- **system_seed**: an unseeded `Random()` produces distinct values
  between runs (fresh OS entropy each run).
- **Env (controlled-key determinism)**: a key the test sets in
  `os.environ` is returned by `env.get(KEY)` identically on the Python
  backend and in WASI mode; an absent key reads as `None` on both
  (fail-closed). `env.args` matches the host-supplied argv. The full
  environment is non-deterministic, so only the controlled key + the
  semantics are asserted, not the whole dump.
- **Env attenuation (three-backend byte-parity)**: with the controlled
  keys set, `restrict_to_keys([A,B]).restrict_to_keys([B,C])` admits
  only `B` (intersection), `allows` reflects it, `get` is fail-closed
  against it (a denied-but-set key reads `None`), the wider parent
  still admits `A`, the unrestricted root admits everything, and
  `restrict_to_keys([])` admits nothing. The full output is asserted
  **byte-identical** across the Python oracle, the `capa:host` backend
  (host-side narrowing) and the WASI backend (guest-side narrowing) -
  `TestWasiEnvAttenuation`.
- **Env ceiling (Level 1)**: `TestWasiEnvCeilingAnalysis` pins the
  static analysis (literal keys close the ceiling; a dynamic / let-bound
  key opens it; `args` / `restrict_to_keys` / `allows` do not widen it;
  no `env.get` yields an empty closed ceiling). `TestWasiEnvCeilingLevel1`
  is the end-to-end leak-closed proof: with `CAPA_PUBLIC` and
  `CAPA_SECRET` both set in the host env, a program that reads only
  `CAPA_PUBLIC` by literal is run in `--wasi` with the env-set installed
  on the component asserted to be `{CAPA_PUBLIC: ...}` (so `CAPA_SECRET`
  is **not** delivered); the output is byte-identical across Python,
  `capa:host` and WASI; and a dynamic-key program falls back to
  `inherit_env`.

## Files

- `capa/ir/_emit_wasm/_wasi.py` - WASI import + adapter-wrapper
  emission (Random / Clock / Env readers + guest-side Env attenuation
  `$Env_restrict_to_keys` / `$Env_allows` / `$Env_key_allowed`) and the
  excluded-surface validation.
- `capa/ir/_emit_wit.py` - WASI-mode world generation
  (`_emit_wit_wasi`).
- `capa/ir/_env_ceiling.py` - the static Env authority-ceiling analysis
  (`EnvCeiling` / `compute_env_ceiling`) backing Level 1.
- `capa/runtime/_wasm_component_host.py` - the `wasi=True` host recipe
  (the env-set: a restricted ceiling projection when closed, else
  `inherit_env`; `argv` for the Env readers; passes `0` as the Env root
  so the guest-side `0`-is-unrestricted convention holds; records the
  installed env-set in `_wasi_env_applied`).
- `capa/cli.py` - the `--wasi` flag, the WASI-deps embed path, and the
  ceiling computation handed to the host on `--wasi --component --run`.
- `capa/wasi_wit/` - vendored WASI P2 WIT subset (random / clocks /
  cli-environment).
- `examples/wasm/wasi_random_clock.capa` - the Random + Clock demo.
- `examples/wasm/wasi_env.capa` - the Env reader demo.
- `examples/wasm/wasi_env_attenuation.capa` - the guest-side Env
  attenuation demo (intersection + fail-closed).
