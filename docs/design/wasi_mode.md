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
| `Fs.restrict_to` | `capa:host/fs.restrict-to` (host handle table) | guest-side prefix allow-list union (no host) |
| `Fs.allows` | `capa:host/fs.allows` (host handle table) | guest-side prefix containment with lexical `.`/`..` normalisation (no host; symlinks unresolved) |
| `Net.get` | `capa:host/net.get` (host handle table) | `wasi:http/outgoing-handler.handle` + the wasi:http request/response chain + `wasi:io/streams` body read, gated guest-side by the static ceiling **and** the fine allow-list |
| `Net.post` | `capa:host/net.post` (host handle table) | the Net.get chain + `wasi:io/streams` flow-controlled outgoing-body **write** of the request body before the handle, same two guest-side gates |
| `Net.restrict_to` | `capa:host/net.restrict-to` (host handle table) | guest-side host allow-list intersection (no host) |
| `Net.allows` | `capa:host/net.allows` (host handle table) | guest-side exact-hostname allow-list membership (no host) |

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
(`tests/wasi/test_wasi_env.py::TestWasiEnvAttenuation`) pins the guest-side
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
`tests/wasi/test_wasi_env.py::TestWasiEnvCeilingAnalysis` (pure analysis)
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
migrated caps move entirely to `wasi:*`. The `export main: func(clock: u32)`
handle param is still present because the core module un-erases Clock
into an `i32` handle slot (the WASI wrappers simply ignore it).

> **Update (2026-06-29):** Stdio no longer keeps a `capa:host` interface
> in `--wasi`. Its **output** ops (`print` / `println` / `eprintln`)
> migrated to `wasi:cli/stdout` | `wasi:cli/stderr` (Phase 1), and
> `read_line` migrated to `wasi:cli/stdin` + `wasi:io/streams`
> (`input-stream.blocking-read`, byte-at-a-time until `"\n"` / EOF;
> Phase 2). `read_line` strips a single trailing `"\r"` for `"\r\n"`
> text-mode parity with the Python oracle, and relies on the underlying
> stdin position being owned by the host descriptor (so a fresh
> `get-stdin` + drop per call preserves the read cursor). It recognises
> only `"\n"` and `"\r\n"` as line terminators; a lone `"\r"` (CR not
> followed by `"\n"`) is a deliberate, documented divergence from the
> oracle's universal-newline text mode (see "read_line lone-CR
> divergence" below). Only the `panic` builtin (`capa:host/panic`) now
> remains on `capa:host` for a `--wasi` program.
>
> #### read_line lone-CR divergence (deliberate, documented)
>
> The `--wasi` `read_line` reaches **byte-identical** parity with the
> Python oracle and the `capa:host` backend for input whose line
> terminators are `"\n"` or `"\r\n"` (the modern terminal / pipe / file
> endings) -- that is the calibrated, tested case. It does **not**
> implement full universal-newlines. The Python oracle reads stdin in
> text mode (`sys.stdin.readline()`), which treats **any** isolated
> `"\r"` as a line break; the `--wasi` reader breaks only on `"\n"`
> (stripping a single trailing `"\r"` to absorb `"\r\n"`), so an isolated
> `"\r"` -- a CR **not** immediately followed by `"\n"`, at **any**
> position -- is kept as an ordinary byte rather than a terminator. The
> two therefore diverge whenever the input carries an embedded or
> terminal lone CR, **even when the input also ends in `"\n"`**:
>
> | input | oracle / `capa:host` | `--wasi` |
> | --- | --- | --- |
> | `"a\rb\n"` | `["a", "b"]` | `["a\rb"]` |
> | `"abc\rdef\rghi\r"` (classic pre-2001 Mac) | `["abc", "def", "ghi"]` | `["abc\rdef\rghi"]` |
>
> This is a **deliberate** decision, not a bug: a correct lone-CR split
> would need lookahead across a `blocking-read` boundary that risks
> over-consuming the next line's first byte, and the lone-CR text format
> is the legacy Mac OS (pre-2001) convention, practically extinct on
> terminals, pipes and files. The read_line / stdin byte-parity claim is
> accordingly **qualified to `"\n"` and `"\r\n"` inputs**; the lone-CR
> case is the documented exception. (This qualification touches **only**
> read_line / stdin: the byte-parity of every other migrated capability
> -- Fs / Net / Env / Stdio output -- is unaffected.) The lone-CR case is
> asserted in the test suite only as the **expected `--wasi` behaviour**
> (`tests/wasi/test_wasi_core.py::TestWasiStdinReadLine::test_lone_cr_is_not_a_line_break_wasi_divergence`),
> never inside a three-backend parity assertion.

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
above), plus the **Fs metadata** operations `Fs.exists`, `Fs.is_dir`,
and `Fs.mkdir` (see "Fs metadata + preopen ceiling" below), the
streaming **`Fs.read`** / **`Fs.write`** (see "Fs.read via streams" /
"Fs.write via streams" below), the directory enumeration
**`Fs.list_dir`** (see "Fs.list_dir via directory enumeration" below),
and **Fs attenuation** (`Fs.restrict_to`, `Fs.allows`, and every op's
fail-closed gate), implemented guest-side (Level 2; see "Fs attenuation
(guest-side, Level 2)" below). With this, **every Fs operation is
migrated** under `--wasi` -- the Fs reconciliation is complete.

### Fs metadata + preopen ceiling

`Fs.exists` / `Fs.is_dir` / `Fs.mkdir` migrate to `wasi:filesystem`:

- `exists` / `is_dir` -> `descriptor.stat-at(symlink-follow, rel)`:
  the result discriminant is `Ok` iff the entry exists (`exists`), and
  the `descriptor-stat.%type` field (at Ok-payload offset 8) is
  `directory` (== 3) for `is_dir`. A denied / absent path reports
  false (fail-closed-as-absent, matching the Python oracle).
- `mkdir` -> `descriptor.create-directory-at(rel)`: idempotent, an
  `already-exists` error (code `exist` == 7) is folded to `Ok`,
  replicating `os.makedirs(path, exist_ok=True)`. **Recursive**: a
  multi-segment relative target (`a/b/c`) creates every missing
  intermediate, matching `os.makedirs`'s tree creation. WASI
  `create-directory-at` is single-segment (it returns `no-entry` if an
  intermediate parent is missing), so the compiler splits the resolved
  relative path into its cumulative prefixes -- all **compile-time
  literals** (`a`, `a/b`, `a/b/c`) -- and emits one idempotent
  `create-directory-at` per prefix in order, sharing one result area and
  short-circuiting on a genuine (non-`exist`) error. There is no runtime
  string-splitting in the guest. The three backends are byte-identical
  for a multi-segment `mkdir` whose intermediates do not yet exist
  (`TestWasiFsMode::test_recursive_mkdir_multi_segment_three_backend_parity`).

None of these use streams. The metadata wrappers address the
host-granted **preopen** descriptors: a `wasi:filesystem` operation
needs a directory descriptor plus a relative path, and the host
preopens exactly the directories the program can reach.

**The preopen ceiling.** The compiler computes a static Fs ceiling
(`capa/ir/_fs_ceiling.py`) by scanning every `fs.*` path-bearing call:
each literal path contributes a preopen for its **parent** directory
(so a file path's parent is granted and the basename is the relative
argument; a `mkdir`/`is_dir` of a directory grants its parent), with
`READ_WRITE` permission when a mutating op (`mkdir`/`write`) targets it
and `READ_ONLY` otherwise. The host registers these preopens in the
ceiling's sorted order; `wasi:filesystem/preopens.get-directories`
returns the descriptors in registration order, so the compiler
resolves each literal call site to a `(preopen_index, basename)` pair
and the guest wrapper addresses preopen index K with no runtime
string-matching. Preopens are a **hard runtime ceiling**: wasmtime
denies traversal outside a preopened directory and denies a write
through a `READ_ONLY` preopen, independent of guest behaviour.

**The preopen over-grants; the literal-only gate is the fine boundary
(honest).** A preopen is a whole **directory** descriptor, so it grants
the runtime authority over the **entire subtree** of that directory,
which is **wider** than the specific set of literal paths the program
names. Two effects compound this:

- **Parent granularity.** A literal `data/a` is addressed relative to a
  preopen of its **parent** `data`, so the descriptor handed to the
  guest can in principle reach every sibling under `data`, not just `a`.
- **Coalescing.** When the program names paths under nested directories
  (`data/a`, `data/sub/b`), overlapping preopens are illegal in wasmtime
  (it collapses them and the inner descriptor index then traps), so the
  ceiling **coalesces** them to the **outermost** root (`data`) and
  addresses the inner targets with multi-segment relative paths. The
  surviving preopen is therefore even **broader** than the union of the
  named parents.

So the **preopen is NOT the fine attenuation boundary** -- it is a
deliberately coarse Level-1 ceiling. The boundary that actually limits
the program to the paths it names is the compiler's **compile-time,
literal-only gate**: the guest WAT only ever calls a metadata wrapper
with a `(preopen_index, relative_literal)` pair the compiler **resolved
from a string literal in the source** (`_emit_wasi_fs_metadata_call`),
and a dynamic path is **rejected at compile time** (fail-closed, below).
There is **no** guest code path that constructs a relative path at
runtime, so the guest can only ever address the **resolved basenames of
the literals** -- a set the compiler fixes statically and that the
emitted module **provably cannot get past** (no runtime string can
become a new target). The preopen subtree is the authority the
**runtime** holds; the literal set is the authority the **guest can
express**. We do not over-sell the preopen as the tight boundary: the
honest tight boundary is the literal-only compile gate, and the preopen
is the (wider) hard ceiling underneath it.

**Fail-closed for dynamic paths.** If any Fs op takes a non-literal
path, the ceiling is **not closed**: the host materialises **no
preopens at all** (the component can open nothing) and the compiler
**rejects** the program in `--wasi` mode. This is tighter than the Env
ceiling (which falls back to `inherit_env`) because a wrongly-derived
preopen is real filesystem authority; a missing preopen merely denies.
Such a program runs unchanged on the default `capa:host` backend.

**TOCTOU window (honest limitation).** The metadata ops are
time-of-check / time-of-use exposed, and the guest WASI path is weaker
here than the Python host. Two distinct points:

- **Check-then-use race.** Between a `stat-at` (`exists` / `is_dir`)
  and any later op against the same path, the filesystem state can
  change (a concurrent process creates, deletes, or retypes the entry),
  so a `true` from `is_dir` is a statement about the past, not a lock on
  the present. This is the ordinary TOCTOU caveat of any `stat`-then-act
  code and is identical on every backend.
- **No guest-side kernel-true-path defence.** The Python host has an
  extra TOCTOU defence the guest WASI path **cannot replicate**. On the
  `capa:host` backend a restricted Fs op opens the target and then
  re-derives the **kernel-true path** of the open handle
  (`capa/runtime/_fs_guard.py`: Linux `/proc/self/fd`, macOS
  `fcntl F_GETPATH`, Windows `GetFinalPathNameByHandleW`) and
  re-validates *that* against the cap's allowed prefixes
  (`_post_open_allows`, `capa/runtime/_capabilities.py:191-213`),
  catching a symlink or rename that swapped the target between the
  `realpath` check and the open. Under WASI the guest holds only the
  **preopen descriptor** and a relative path string; it has no way to
  ask the runtime for a descriptor's kernel-true path, so that post-open
  re-validation has **no equivalent** here. The mitigation that remains
  is structural, not a re-check: the **preopen is a hard runtime
  ceiling** -- wasmtime resolves the relative path against the preopen
  descriptor and denies any result that escapes the preopened subtree,
  including through a symlink, regardless of guest behaviour. The
  metadata `stat-at` does pass `symlink-follow`, so a symlink *inside*
  the preopen is followed (matching the oracle's `realpath`-based
  `exists` / `is_dir`); what it cannot do is follow a symlink *out of*
  the preopened subtree, because the descriptor's authority stops at the
  preopen boundary. So a TOCTOU swap can still change *what* a name
  inside the preopen resolves to between check and use, but it can never
  grant authority *outside* the preopened subtree, and (because
  `read` / `write` are rejected under `--wasi`) no file is opened
  through the racy name in this mode at all.

### Fs.read via streams

`Fs.read` migrates to a streaming read over `wasi:filesystem` +
`wasi:io/streams`. It is the **first** touch-point that uses
`wasi:io/streams`. The guest wrapper `$Fs_read`
(`capa/ir/_emit_wasm/_wasi.py`) addresses the same **preopen** ceiling
the metadata ops do (literal path -> `(preopen_index, relative_literal)`,
no runtime string-matching; READ_ONLY preopen) and runs:

1. `descriptor.open-at(preopen_desc, symlink-follow, rel, open-flags=0,
   descriptor-flags=read)` -> `result<descriptor, error-code>`.
2. `descriptor.read-via-stream(offset = 0)` ->
   `result<input-stream, error-code>` (the `input-stream` is an **OWN**
   resource).
3. a **loop** of `input-stream.blocking-read(chunk)` ->
   `result<list<u8>, stream-error>`, appending each chunk's bytes to a
   heap accumulation buffer.
4. on EOF, build the Capa `String` from the accumulated bytes ->
   `Ok(String)`.

**EOF is `stream-error::closed`, not an error.** `blocking-read`'s
`stream-error` is a variant: discriminant `0` is
`last-operation-failed(error)` (a genuine read failure that carries an
`error` resource), discriminant `1` is `closed` -- the **normal**
end-of-stream. The loop treats `closed` as EOF (break and build the
String, which is `Ok("")` for a 0-byte file, the first `blocking-read`
being `closed` immediately) and only `last-operation-failed` as an
`Err`. This convention was confirmed empirically (an oracle component
built with `wasm-tools` and run under `wasmtime` over controlled
small / empty / large / UTF-8 files) before the WAT was written; the
exact return-area offsets and discriminants are recorded in
`capa/ir/_emit_wasm/_wasi.py`'s `$Fs_read` docstring.

**Resource drops on every path (no leak, no double-drop).** The
`descriptor` returned by `open-at` and the `input-stream` returned by
`read-via-stream` are **OWN** handles the guest must drop. `$Fs_read`
drops them on **every** exit:

- success / EOF: drop `input-stream`, then drop the opened `descriptor`.
- `open-at` error: nothing was opened -> no drop.
- `read-via-stream` error: drop the opened `descriptor` (no stream
  exists).
- `blocking-read` `last-operation-failed`: drop the carried `error`
  resource (via `wasi:io/error` `[resource-drop]error`), then the
  `input-stream`, then the `descriptor`.

The **preopen ROOT** descriptors are **never** dropped -- they are the
runtime's per-instance ceiling and live for the component's lifetime
(`$__wasi_fs_preopen_desc` caches them). A double-drop or a dropped root
would trap a later op; the
`TestWasiFsRead::test_interleaved_reads_and_metadata_no_resource_leak`
test ends with metadata ops on the same preopen to prove the root stays
live across several open/read/drop cycles.

**Memory.** `$Fs_read` uses a dedicated 32-byte static scratch
(`_wasi_fs_read_scratch_offset` in `capa/ir/_emit_wasm/__init__.py`) for
its three indirect returns at distinct sub-offsets (`open-at` @+0,
`read-via-stream` @+8, `blocking-read` @+16), **separate** from the
104-byte metadata scratch and from the cached `get-directories` list
buffer, so a read interleaved with metadata ops corrupts neither. The
chunk **bytes** the host writes land in canonical-ABI memory (via the
component's exported `cabi_realloc` / `$alloc`); the wrapper copies them
into a geometrically-grown heap accumulation buffer (`$alloc` +
`memory.copy`), so a large file reallocs `O(log n)` times rather than
once per chunk.

**Parity.** `Ok(String)` is **byte-identical** to the Python oracle's
`f.read()` (UTF-8) and the `capa:host` bridge across small, empty,
large-multi-chunk, and UTF-8 multi-byte files
(`TestWasiFsRead`). A missing file inside the preopen is a coherent
`Err(IoError)` on all three backends; the Err **message** differs (the
oracle carries the OS errno, the WASI wrapper writes a fixed
`failed to read file`), so parity there is on the Result
**discriminant** (`is_err`), as the metadata / Net error paths already
assert.

All Fs operations are migrated; `Fs.list_dir` is covered below and the
fine attenuators `Fs.restrict_to` / `Fs.allows` are implemented
guest-side (see "Fs attenuation (guest-side, Level 2)" below).

### Fs.write via streams

`Fs.write` migrates to a streaming write over `wasi:filesystem` +
`wasi:io/streams` -- the **inverse** of `Fs.read`, reusing the same
preopen ceiling and the same proven stream machinery. The guest wrapper
`$Fs_write` (`capa/ir/_emit_wasm/_wasi.py`) addresses the literal path
against its preopen (`(preopen_index, relative_literal)`, no runtime
string-matching; the targeted preopen is `READ_WRITE` because `write`
mutates) and runs:

1. `descriptor.open-at(preopen_desc, symlink-follow, rel,
   open-flags=create|truncate (9), descriptor-flags=write (2))` ->
   `result<descriptor, error-code>`. `create` makes a new file,
   `truncate` empties an existing one -- matching the Python oracle's
   `open(path, "w")` create-or-truncate. On error nothing is opened.
2. `descriptor.write-via-stream(offset = 0)` ->
   `result<output-stream, error-code>` (the `output-stream` is an
   **OWN** resource).
3. a **loop** of `output-stream.blocking-write-and-flush((cursor, n))`
   -> `result<_, stream-error>`, handing the `content` bytes (already in
   linear memory) to the stream in chunks of at most **one OS page
   (4096 bytes)** per call.
4. a final `output-stream.blocking-flush()` for durability of any
   buffered bytes, then `Ok(Unit)`.

**The output-stream write convention (confirmed empirically).** WASI
0.2's `output-stream` exposes a permit-window protocol:
`check-write()` reports how many bytes the stream accepts **now**,
`write(contents)` is non-blocking and valid only within that window, and
`blocking-write-and-flush(contents)` writes **and** flushes but is
bounded to **<= 4096 bytes (one page) per call** by the contract. This
wrapper uses **only** `blocking-write-and-flush` in a loop capped at
4096 bytes: because that call self-limits to a page **and** flushes, the
guest never has to track the `check-write` permit window itself -- the
simplest provably-correct write loop, and the exact inverse of the read
loop's `blocking-read(chunk)` accumulation. A **zero-length** `content`
runs the loop zero times; the file is already truncated empty by `open`,
so a 0-byte file results (matching `open(p, "w")` + `write("")`). This
4096-byte per-call limit and the open-flag bits (path-flags
`symlink-follow`=1; open-flags `create|truncate`=9; descriptor-flags
`write`=2) were confirmed by an oracle run (build + `wasmtime` over
controlled small / empty / large-multi-chunk / UTF-8 / overwrite
content, with **write-then-read-back** comparing the on-disk bytes)
before the WAT was finalised; the exact offsets and discriminants are in
`$Fs_write`'s docstring.

**Resource drops on every path (no leak, no double-drop).** The
`descriptor` returned by `open-at` and the `output-stream` returned by
`write-via-stream` are **OWN** handles dropped on **every** exit:

- success: drop `output-stream`, then drop the opened `descriptor`.
- `open-at` error: nothing was opened -> no drop.
- `write-via-stream` error: drop the opened `descriptor` (no stream
  exists).
- `blocking-write-and-flush` / `blocking-flush` `last-operation-failed`:
  drop the carried `error` resource (via `wasi:io/error`
  `[resource-drop]error`), then the `output-stream`, then the
  `descriptor`.

The **preopen ROOT** descriptors are **never** dropped. A write through
a `READ_ONLY` preopen is denied by `wasmtime` at `open-at` (the open
error path fires, with no drops and **no file** left on disk), returning
a coherent `Err`.

**Memory.** `$Fs_write` uses a dedicated 32-byte static scratch
(`_wasi_fs_write_scratch_offset`) for its two indirect returns
(`write-via-stream` / the open-at reuse `result<...>` @+0, the
`blocking-write-and-flush` / `blocking-flush` `result<_, stream-error>`
@+8), **separate** from the 104-byte metadata scratch, the 32-byte
**read** scratch, and the cached `get-directories` buffer, so a write
interleaved with read / metadata ops corrupts none of them. The
`content` **bytes are not copied**: they already live in linear memory
(the String argument) and each chunk is handed to
`blocking-write-and-flush` as `(content_ptr + cursor, n)`.

**Pre-interning the write strings (write-only parity fix, 2026-06-28).**
Two strings the write path needs -- the resolved relative **basename**
the literal path resolves to (the `(ptr, len)` `open-at` addresses) and
the fixed `failed to write file` Err message -- must be interned
**before** the static `(data ...)` segment is written, in the same
up-front Fs pre-intern pass that already handles `exists` / `is_dir` /
`mkdir` / `read`. `write` was originally **missing** from that pass's
op set, so a program whose **only** Fs op was `write` (no read / metadata
sharing the same literal) interned the basename only at `$Fs_write`
emission time -- after the data segment was laid out -- and the string
got a valid offset but **no backing data segment**. The relative path
the guest handed to `open-at` was then undefined memory: `open-at`
failed, the wrapper returned `Err(IoError)`, and **no file** was written,
diverging from Python / `capa:host`. A co-present `read` of the same
path masked the bug by interning the shared basename early. The pre-intern
pass now includes `write` (and pre-interns `failed to write file`), so a
write-only program lands both strings in the data segment deterministically.

**Parity.** `Ok(Unit)` and **the bytes on disk** are byte-identical to
the Python oracle's `open(p, "w") + f.write(content)` and the
`capa:host` bridge across small, empty, large-multi-chunk, UTF-8
multi-byte, and overwrite (truncate) content -- proved by
write-then-read-back **and** a direct on-disk byte comparison after each
backend (`TestWasiFsWrite`). A write denied through a `READ_ONLY`
preopen is a coherent `Err` on all three with no file left behind; the
Err **message** differs (the wrapper writes a fixed
`failed to write file`), so parity is on the Result **discriminant**.

`TestWasiFsWriteOnly` covers the **write-only** programs the
write-then-read-back cases could not (every `TestWasiFsWrite` case also
reads, which masked the pre-intern bug above): a single create, an
overwrite/truncate of a pre-existing file, several sequential writes, and
a write denied through a `READ_ONLY` preopen -- each with **no** `fs.read`
in the source, so the on-disk bytes are read back directly in Python and
compared across all three backends.

The fine attenuators `Fs.restrict_to` / `Fs.allows` are implemented
guest-side (see "Fs attenuation (guest-side, Level 2)" below).

### Fs.list_dir via directory enumeration

`Fs.list_dir` migrates to a directory walk over `wasi:filesystem`. It is
the **last** Fs touch-point to land, and unlike `Fs.read` / `Fs.write`
it uses **no** `wasi:io/streams`: the `directory-entry-stream` is a
`wasi:filesystem/types` resource. The guest wrapper `$Fs_list_dir`
(`capa/ir/_emit_wasm/_wasi.py`) addresses the same **preopen** ceiling
the other ops do (literal path -> `(preopen_index, relative_literal)`, no
runtime string-matching; READ_ONLY preopen, a directory walk is a read)
and runs:

1. `descriptor.open-at(preopen_desc, symlink-follow, rel,
   open-flags=directory (2), descriptor-flags=read (1))` ->
   `result<descriptor, error-code>`. The `directory` open-flag makes
   opening a **non-directory** (a regular file) fail at `open-at`, so a
   `list_dir` of a file is a clean `Err` with nothing opened.
2. `descriptor.read-directory()` ->
   `result<directory-entry-stream, error-code>` (the
   `directory-entry-stream` is an **OWN** resource, value @4).
3. a **loop** of `directory-entry-stream.read-directory-entry()` ->
   `result<option<directory-entry>, error-code>`, accumulating each
   entry's `name` into a heap buffer of packed `(str_ptr, str_len)` i32
   pairs.
4. a guest-side **sort** of the accumulated `(ptr, len)` pairs, then
   `Ok(List<String>)`.

**The return-area convention (confirmed empirically).**
`read-directory-entry` returns into a 20-byte area:
`result disc @0` (Ok==0); `option disc @4` (**none==0 is END OF STREAM**,
the normal terminator, NOT an error; some==1); the `directory-entry`
record at @8 (`%type` @8, **ignored**; `name` ptr @12, len @16).
`read-directory` returns 8 bytes (disc @0, stream-own @4). These
offsets, the `directory` open-flag bit, the none==end convention, and
the fact that `read-directory` returns entries in **filesystem order**
and does **not** include `.` / `..` (matching `os.listdir`) were all
confirmed by an oracle component (built with `wasm-tools`, run under
`wasmtime` over a controlled multi-entry / empty / non-directory /
UTF-8-named directory) **before** the WAT was written; the exact offsets
and discriminants are recorded in `$Fs_list_dir`'s docstring.

**The guest-side sort is what makes the ORDER match (the sensitive
parity point).** The Python oracle returns
`sorted(os.listdir(path))` -- a lexicographic sort over `str` code
points. `wasi` `read-directory` yields entries in **filesystem order**,
which is NOT sorted, so the guest **must** sort to match. `$Fs_list_dir`
runs a stable insertion sort over the `(ptr, len)` pairs using the
existing `$str_cmp` helper, which compares the name bytes **unsigned**;
for well-formed UTF-8 an unsigned byte-by-byte comparison yields the same
order as comparing Unicode code points, which is **exactly** Python's
`str` ordering (the same property the String `<` / `>` operators rely
on). So an UPPERCASE name (`Z`, 0x5A) sorts before the lowercase ones
(`a` / `b`, 0x61 / 0x62), and a high-code-point UTF-8 name (`你好`) sorts
last, byte-identically across all three backends. `$str_cmp` is normally
gated on a String `<` / `>` operator being present; a WASI-only
`list_dir` program may use neither, so the emission is additionally
gated on `Fs.list_dir` under `--wasi`
(`_wasi_fs_list_dir_needs_str_cmp`).

**Resource drops on every path (no leak, no double-drop).** The
`descriptor` returned by `open-at` and the `directory-entry-stream`
returned by `read-directory` are **OWN** handles dropped on **every**
exit: success/EOF drops the stream then the descriptor; an `open-at`
error opened nothing (no drop); a `read-directory` error drops the
descriptor; a `read-directory-entry` error drops the stream then the
descriptor. `read-directory-entry`'s error is an `error-code` **enum**
(no carried resource), so list_dir -- unlike read/write -- imports no
`wasi:io/error` `[resource-drop]error`. The **preopen ROOT** descriptors
are **never** dropped.

**Memory.** `$Fs_list_dir` uses a dedicated 32-byte static scratch
(`_wasi_fs_list_dir_scratch_offset`) for its two indirect returns
(`read-directory` / the `open-at` reuse @+0 (8B), `read-directory-entry`
@+8 (20B)), **separate** from the metadata / read / write scratches and
the cached `get-directories` buffer. The entry **name bytes are not
copied**: the host writes them into canonical-ABI memory (via the
component's `cabi_realloc`) and the accumulation buffer stores only the
`(ptr, len)` pairs pointing at them, exactly as the `get-arguments` /
`get-environment` readers do for their string lists; the
`result_list_string_io_error` materialiser then wraps the pair buffer in
a 16-byte `List<String>` header.

**Parity.** `Ok(List<String>)` is **byte-identical** -- including the
ORDER -- to the Python oracle's `sorted(os.listdir(path))` and the
`capa:host` bridge across a multi-entry directory (mixed case + a
subdirectory), an empty directory (`-> []`), and UTF-8 multi-byte names
(`TestWasiFsListDir`). A missing path and a path that is a FILE (not a
directory) are coherent `Err(IoError)` on all three backends; the Err
**message** differs (the wrapper writes a fixed `failed to list
directory`), so parity is on the Result **discriminant** (`is_err`), as
the read / write / metadata / Net error paths already assert.

The fine attenuators `Fs.restrict_to` / `Fs.allows` are implemented
guest-side (see "Fs attenuation (guest-side, Level 2)" below).

### Fs attenuation (guest-side, Level 2)

`Fs.restrict_to` and `Fs.allows` are **supported** under `--wasi`,
implemented entirely **guest-side** -- `wasi:filesystem` grants authority
through whole-directory **preopens** (the coarse Level-1 ceiling) and has
no host-side cap object to hold a finer per-call allow-list, so the fine
narrowing has no host runtime home. This is **Level 2** of
`docs/design/wasi-attenuation.md`, the **direct analogue of the Env
guest-side attenuation** above, with **path-prefix containment** in place
of key equality. This **closes the full Fs reconciliation**: every Fs op
now runs under `--wasi`.

**State representation.** The Fs value (an `i32` the host passes to
`main`, and that `restrict_to` returns) is **reinterpreted** guest-side,
exactly like Env:

- `0` = **unrestricted** (the root Fs `main` receives; the host passes
  `0` in this mode, since the `capa:host` handle table is not consulted
  on the wasi path).
- non-zero = a pointer to a `List<String>` header (16 bytes: len@0,
  cap@4, data_ptr@8, pad@12) whose data array holds the **prefix
  allow-list**: N packed `(str_ptr, str_len)` pairs (the canonical Capa
  `List<String>` layout). The prefixes are the literal paths the source
  passed to `restrict_to`.

**The three operations, all in WAT:**

- `$Fs_restrict_to(handle, pre_ptr, pre_len) -> i32` builds a NEW
  allow-list = the parent's prefixes **UNION** `prefix` (the prefix bytes
  are shared, not copied), allocates a fresh `List<String>`, returns the
  pointer. Identical to the oracle `Fs.restrict_to`
  (`existing | {canon}`, `capa/runtime/_capabilities.py:168-171`). Note
  the contrast with Env: Env **intersects** its key set, Fs
  **accumulates** prefixes and `allows` then requires containment in ALL
  of them -- so the EFFECTIVE admitted set is the **intersection of the
  containments**, the monotone narrowing the model intends.
- `$Fs_allows(handle, path_ptr, path_len) -> i32` returns 1 iff
  `handle == 0` (unrestricted) OR `path` is contained in EVERY stored
  prefix (`$Fs_path_allowed` -> `$Fs_path_contained` per prefix). Mirrors
  `Fs.allows` (`is_relative_to` ALL prefixes,
  `capa/runtime/_capabilities.py:173-183`).
- Every privileged op (`read` / `write` / `exists` / `is_dir` / `mkdir`
  / `list_dir`) is extended with a **fail-closed prologue**: it consults
  `$Fs_path_allowed(handle, FULL_path)` (the FULL original literal path,
  against which the prefixes were recorded -- NOT the preopen-relative
  path) BEFORE touching the filesystem, and on a deny returns the
  fail-closed result (`Err(IoError)` for read / write / mkdir / list_dir;
  `false` for exists / is_dir) WITHOUT any `open-at` / `stat-at` /
  `create-directory-at`. Byte-identical (on the Result discriminant /
  Bool) to the Python oracle's `if not self.allows(path): ...`. A denied
  `write` / `mkdir` therefore leaves **nothing** on disk -- the gate
  fires before the file is opened.

**Path containment (LEXICAL `.`/`..` normalisation, symlinks not
resolved).** The oracle canonicalises both the prefix and the queried
path with `os.path.realpath` (resolving `..` / `.` / symlinks) before the
`is_relative_to` boundary check. The guest has **no realpath syscall**,
so `$Fs_path_contained` **lexically normalises** the `.` and `..`
segments of BOTH the path and the prefix FIRST (via `$__fs_normalize`,
the `os.path.normpath`-style collapse that preserves a leading `..` so an
escape stays an escape), and only then does the path-segment containment:
strip trailing `/` from both, then the path is contained iff its first
`len(prefix)` bytes equal the prefix AND the next byte is `/` or the path
IS the prefix (the segment boundary that stops `data/ab` matching
`data/a`). The `.`/`..` normalisation reproduces what `realpath` does for
those segments in the no-symlink case, so a dynamic path such as
`sub/../secret.txt` normalises to `secret.txt` (NOT contained in `sub` ->
**denied**, matching the oracle), while `sub/../sub/ok.txt` normalises to
`sub/ok.txt` (contained -> **allowed**). The `$__fs_normalize` rule is
validated byte-for-byte against `os.path.normpath` and over a 9331-input
segment fuzz (see the scratchpad reference behind
`TestWasiFsDynamicPreopen.test_restricted_fs_dynamic_path_dotdot_normalized`).
`realpath` also prepends the SAME process CWD to a relative path and its
relative prefix (so the CWD cancels in the containment) and leaves a
canonical absolute path unchanged, so for non-symlink paths the result is
**byte-identical** to the oracle. **SYMLINKS are still NOT resolved** --
the gate is lexical, so a symlink inside a prefix that points outside it
is admitted by the guest (and caught only by the Level-1 preopen
ceiling). That symlink (TOCTOU) loss is the **only** remaining Level-2
divergence from the realpath oracle; `.` and `..` are now handled.

**Interaction Level 1 + Level 2.** The guest-side allow-list (fine,
Level 2) operates ON TOP OF the preopen (the Level-1 ceiling): the fine
check is always at least as tight as the preopen, so the two are
coherent. The preopen is real **runtime** authority enforced by any
conformant WASI host; the fine narrowing is **compiler-proved** and
**reinforced by our host** (which generated the guest), but under a stock
or tampered WASI host the fine narrowing would not be re-checked at the
syscall (Level 2, honest).

**Parity.** Three-backend byte-parity (Python oracle == `capa:host` ==
WASI) is asserted by `TestWasiFsAttenuation` in
`tests/wasi/test_wasi_fs.py` over a controlled temp directory:
`restrict_to` + `allows` + every op's fail-closed deny, chaining
(intersection), isolation (a child Fs does not affect its parent), the
unrestricted root, and the **cross-function-boundary** restriction
survival (a restricted Fs passed to a helper keeps its allow-list,
because the `i32` pointer travels with the value).

### Net.get via wasi:http (Phase 1)

`Net.get` migrates to the canonical WASI Preview 2 outbound HTTP chain
over `wasi:http` + `wasi:io`. It is the **first** touch-point that uses
`wasi:http`, and the **largest** WASI increment to date (eight OWN
resources, a synchronous poll, and a triple-nested result lift). The
guest wrapper `$Net_get` (`capa/ir/_emit_wasm/_wasi.py`) runs, with the
url split at the call site into its compile-time-resolved scheme /
authority / path:

1. `fields.new()` -> `outgoing-request.new(fields)` [**consumes**
   `fields`].
2. `set-method(GET)`, `set-scheme(some(scheme))`,
   `set-authority(some(authority))`,
   `set-path-with-query(some(path))`. Each returns a flat `result` i32
   (no payload), dropped.
3. `outgoing-request.body()` -> `result<own<outgoing-body>>`;
   `outgoing-body.finish(obody, none)` [**consumes** `obody`].
4. `outgoing-handler.handle(request, none)` ->
   `result<own<future-incoming-response>, error-code>` [**consumes**
   `request`]. The `error-code` variant carries an `option<u64>`, so the
   result is **8-aligned** and the Ok value sits at ret+8, not ret+4.
5. `future.subscribe()` -> `pollable.block()` (a **synchronous** wait;
   `wasi:io/poll`), then **loop** `future.get()` ->
   `option<result<result<own<incoming-response>, error-code>>>`. The
   **triple lift** (option disc, the future-already-consumed result, the
   transport result) is the heaviest ABI point: `none` = not ready ->
   resubscribe + block + retry; `some(err())` = already consumed -> Err;
   `some(ok(err(code)))` = transport error -> Err;
   `some(ok(ok(resp)))` = the response.
6. `incoming-response.status()`; **fail-closed on any non-2xx status**:
   only `200..=299` yields `Ok(body)`; **any** other status (`3xx`
   redirects, `<200`, and `4xx` / `5xx`) drops the response and returns
   `Err` **without reading the body**. The wasi:http handler delivers a
   `3xx` / `4xx` / `5xx` as `some(ok(ok(resp)))` with that status (NOT an
   `error-code`), so the wrapper checks the status and converts. This is
   a **deliberate, more-restrictive divergence** from the urllib oracle /
   `capa:host` (which follow a redirect **whose target host the same
   capability permits**, and surface only `4xx` / `5xx` as errors): the
   guest does **not** follow redirects at all. See "Redirects are
   fail-closed (anti-SSRF)" below.
7. `incoming-response.consume()` -> `incoming-body.stream()` -> a
   **loop** of `input-stream.blocking-read(chunk)` over `wasi:io/streams`,
   accumulating each chunk into a geometrically-grown heap buffer until
   `stream-error::closed` (EOF) -- the **same** machinery as `Fs.read`.
8. `Ok(String)` from the accumulated bytes (UTF-8 by construction).

**Resource drops on every path (no leak, no double-drop).** All eight
OWN handles are dropped on every exit: the consuming calls
(`outgoing-request` by `handle`, `outgoing-body` by `finish`) are the
only handles NOT dropped, and only on the paths that reach them; the
`future` is dropped after `get` on every path that read it; the
`pollable` is dropped after each `block`; a `last-operation-failed`
stream error drops the carried `error` resource (via `wasi:io/error`).
The whole chain (the receipt, the eight resources, the triple lift, the
status mapping, the EOF convention, the drops) was confirmed by an
**oracle spike** -- a hand-written WAT component built with `wasm-tools`
and run under `wasmtime` against a local HTTP server -- before the
emitter was written; a 1500-GET loop in one instance proved no handle
exhaustion.

**The Net ceiling is GUEST-SIDE (the honest asymmetry).** Unlike the Fs
preopen ceiling and the Env env-set ceiling -- both **Level 1**, imposed
by the WASI host at instantiate -- wasmtime's `wasi:http` C-API
(`set-wasi-http`) is **allow-all**, with no allowed-hosts configuration
surface in this release, so there is **no host ceiling to map onto**. The
ceiling is therefore enforced **guest-side** (codegen): the compiler
collects the HOSTS of the LITERAL urls passed to `net.get` (the static
`NetCeiling`, `capa/ir/_net_ceiling.py`) and the guest wrapper's
per-method `$Net_host_allowed_get` / `$Net_host_allowed_post` gates refuse
any host the program never names (nor the operator grants for that
method). A
**dynamic** url (built at runtime) cannot be split into a wasi:http
request at compile time, so the call site **fail-closes** to `Err`
WITHOUT reaching the network -- the same fail-closed policy a dynamic Fs
path gets (a wrongly-admitted host is real outbound authority). This is
**Level 2-style**: proved by the compiler (the guest only ever reaches a
named host) and reinforced by our host (which generated the guest), but
NOT runtime-enforced by a stock WASI host. See
`docs/design/wasi-attenuation.md` for the full stratification. The
per-value **fine** attenuation (`Net.restrict_to` / `Net.allows`) sits on
top of this ceiling gate (see "Net fine attenuation (guest-side, Level 2,
Phase 3)" below).

**The host links `wasi:http` only when Net.get is used.** wasmtime 44+
does not expose `add_wasi_http` on the high-level component API, so the
host reaches the C-ABI through `wasmtime._bindings`
(`wasmtime_component_linker_add_wasi_http(linker)` +, **obligatorily**,
`wasmtime_context_set_wasi_http(context)` -- without the latter the
C-API panics `Option::unwrap`-on-`None` the moment a wasi:http import is
linked). The host links + arms wasi:http **only** when the program uses
`Net.get` (signalled by a non-None `net_ceiling`), so a non-Net program
is a clean total deny and never triggers that context panic.

**Memory.** `$Net_get` and `$Net_post` share a 192-byte static scratch
(`_wasi_net_scratch_offset`) for their indirect returns at distinct
sub-offsets (`body` @+0, `finish` @+8, `handle` @+16 value@+8,
`future.get` @+32 the 32-byte triple, `consume` @+64, `stream` @+72,
`blocking-read` @+80; post additionally uses `write/flush` @+96,
`outgoing-body.write` @+112, `check-write` @+128), **separate** from every
Fs / Env / Clock scratch. The body **bytes** the host writes land in
canonical-ABI memory and are copied into a geometrically-grown heap
accumulation buffer, exactly like `Fs.read`; post's REQUEST body is handed
to the output-stream straight from linear memory as `(ptr, len)`, no copy,
exactly like `Fs.write`.

**Parity.** `Ok(String)` is **byte-identical** to the Python oracle's
`urlopen(url).read().decode("utf-8")` and the `capa:host` bridge across
small, empty, large-multi-chunk, and UTF-8 multi-byte bodies, fetched
from a **local 127.0.0.1 server** (no external network); `4xx` / `5xx`
(404 / 500) and a connection-refused transport error are coherent `Err`
on all three backends (the Err **message** differs -- the wrapper writes
a fixed `HTTP GET failed` -- so parity is on the Result **discriminant**,
as the Fs error paths already assert). `3xx` redirects are the **one
deliberate divergence** (the `--wasi` guest fails closed where the oracle
follows the redirect; see "Redirects are fail-closed (anti-SSRF)" below),
so they are **not** asserted as three-backend parity. `TestWasiNetGet` /
`TestWasiNetCeiling` / `TestWasiNetWitGeneration` / `TestWasiNetRejections`
in `tests/wasi/test_wasi_net.py`.

### Redirects are fail-closed (anti-SSRF, security decision)

In `--wasi` mode the guest **does not follow HTTP redirects**, and it
treats **any** response that is not `2xx` (`200..=299`) as `Err` -- so a
`3xx` (`301` / `302` / `303` / `307` / `308`, and a bodyless `304`) is a
**fail-closed** `Err(IoError)`, the response is dropped without reading
its body, and **no** redirect `Location` is fetched. The status gate in
`$Net_get` / `$Net_post` is "status NOT in `[200,299]`", not the old
"`status >= 400`".

**This is a deliberate divergence from the oracle, in the more
restrictive direction.** The Python oracle and the `capa:host` bridge use
`urllib`, which **follows** `3xx` redirects (and raises for a `3xx`
without a `Location`), so neither ever hands a `3xx` back to the program
-- they either follow it or raise. The `--wasi` guest instead **refuses**
it. This is **not a bug**; it is a documented security choice
("option B").

**Why fail-closed and not follow.** Following a redirect implicitly would
let an **allowed** host redirect the request to a host the program never
named -- a host outside both the static `NetCeiling` and the fine
`Net.restrict_to` allow-list. Because those gates are checked on the
**original** request URL (the only URL the compiler can see), an
auto-followed redirect would reach the redirect target **without** any
host-authority check, an **SSRF / host-authority bypass** that would
break Capa's central capability / host guarantee. Refusing `3xx`
preserves that guarantee: the only hosts the guest ever contacts are the
ones it statically named and is gated against. It is **secure-by-default**
and gives **predictable, auditable** behaviour, aligned with **CRA**
(secure-by-default) and **NIS2** (predictable / auditable handling).

A program that genuinely needs to follow a redirect must do so
**explicitly** -- read the (non-2xx) `Err`, derive the new URL itself, and
issue a fresh `net.get` against it, which then passes through the host
ceiling + allow-list gates like any other request.

**The Python oracle / `capa:host` used to have exactly the bypass this
section describes** (2026-07): urllib followed a `Location` to a host the
capability forbade, with no check on the hop, so a program restricted to
`127.0.0.1` reached `localhost` while `--manifest` recorded only the
narrow `restrict_to`. It no longer does: `Net` now runs its requests
through an opener that **re-checks the same capability on every hop**
(host **and** scheme), so a hop to a forbidden host or to a non-`http(s)`
scheme is `Err` and the forbidden peer is never contacted
(`tests/test_net_hop_gate.py`). **What still differs between the
backends is only the PERMITTED hop**: `--wasi` refuses it too, because
its request parts (scheme / authority / path) are resolved from a
**literal** URL at compile time and a `Location` header is only known at
run time, so the guest has nothing to build the next request from. The
divergence is therefore **`--wasi` is strictly more restrictive on a
redirect whose target the capability permits**, and the three backends
**agree** on every hop the capability forbids.

This is covered by `TestWasiNetRedirectFailClosed` in
`tests/wasi/test_wasi_net.py` (a local server returning `301` / `302` / `307`
/ `308` with a `Location`, and a `304` without one, for both `Net.get`
and `Net.post`); those are **fail-closed behaviour** tests, **not**
three-backend parity tests (the oracle / `capa:host` intentionally
diverge by following / raising), and are deliberately **excluded** from
the Net parity harness.

### Net.post via wasi:http (Phase 2)

`Net.post` **reuses the entire `$Net_get` chain** (host gate, the
Fields -> OutgoingRequest -> set-* -> body -> finish -> handle -> future
poll -> status -> consume -> stream -> input-stream read loop, the
triple-result lift, the **fail-closed non-2xx mapping** (only `200..=299`
-> `Ok`; `3xx` redirects are **not** followed; see "Redirects are
fail-closed (anti-SSRF)" above), and every resource drop) and changes
only two things:

1. **set-method sends `POST`** -- the `method` variant **discriminant 2**.
   No string is interned: a non-`other` method variant carries no payload,
   so the `POST` literal never appears in the data segment.
2. **The REQUEST body is written before `finish`.** `outgoing-body.write()`
   yields the **output-stream** (a **ninth** OWN resource, a **child** of
   the outgoing-body that **must be dropped before `finish`**, else
   `finish` traps). The body is then written with the **flow-controlled**
   `wasi:io` pattern, **not** `Fs.write`'s `blocking-write-and-flush`: a
   `wasi:http` outgoing-body stream only **drains once the request is sent
   at `handle`**, which runs **after** the write loop, so the blocking
   variant deadlocks past the initial permit window (proven: a **4097-byte**
   body hangs while **4096** succeeds). The loop is `check-write` (the
   permitted budget) -> non-blocking `write` of `<= budget` bytes straight
   from linear memory (no copy) -> `subscribe` + `pollable.block` to await
   permits when the budget is momentarily 0 -> a final non-blocking `flush`.
   A zero-length body runs the loop zero times. The output-stream is dropped
   before `finish`, on success **and** on every error branch that reaches
   after the stream is created.

**Chunked vs Content-Length.** `wasi:http` sends the POST body with
`Transfer-Encoding: chunked` (no `Content-Length`) by default. This affects
only what the **server observes** (the wire framing), not the bytes; the
Python oracle (`urllib`) sends a `Content-Length`. Parity is on the
**RESPONSE** `Ok(String)`, which is identical regardless of framing. The
test server reads the body under **either** framing and asserts it received
the **exact** bytes the client sent, so the request body is verified, not
only the response.

**Parity (post).** `Ok(String)` (the response body, the same shape as get)
is **byte-identical** to the oracle's
`urlopen(Request(url, data=body)).read().decode("utf-8")` and the
`capa:host` bridge across small / empty / **large-multi-chunk** request
bodies (the server confirms the complete received body), large-multi-chunk
responses, and UTF-8 in both directions; `status >= 400` and a
connection-refused transport error are coherent `Err` (fixed message
`HTTP POST failed`, parity on the discriminant). A **1500x leak loop** runs
with no handle exhaustion. The Net **ceiling** now collects the hosts of
literal `net.post` urls too, and a **dynamic** post url is fail-closed.
`TestWasiNetPost` / `TestWasiNetPostCeiling` in `tests/wasi/test_wasi_net.py`.

### Net fine attenuation (guest-side, Level 2, Phase 3)

`Net.restrict_to` and `Net.allows` are **supported** under `--wasi`,
implemented **guest-side** (Level 2 of `docs/design/wasi-attenuation.md`),
the **direct analogue of the Env guest-side attenuation** above, with
**exact-hostname equality** in place of Env's key equality. This **closes
the Net surface** in `--wasi`: `get` / `post` / `restrict_to` / `allows`
all compile, with **byte-identical** semantics to the Python oracle and
the `capa:host` backend.

The runtime representation of a Net value (the `i32` handle threaded
through every Net method and across function boundaries; `0` is the
unrestricted root `main` receives) is **reinterpreted** guest-side:

- `0` = the unrestricted root (admits every host the ceiling admits);
- non-zero = a pointer to a `List<String>` allow-list header (the same
  16-byte `len@0 / cap@4 / data_ptr@8 / pad@12` shape Env / Fs use), whose
  entries are the **hostnames** `restrict_to` narrowed to, packed as
  `(str_ptr, str_len)` pairs.

The guest wrappers (no `capa:host/net` import):

- `$Net_restrict_to(handle, host_ptr, host_len) -> i32` builds the
  **INTERSECTION** of the parent's allow-list with `{host}`, identical to
  `Net.restrict_to` (`new = frozenset({host}); if parent: new = new &
  parent`, `capa/runtime/_capabilities.py:565-569`). On the unrestricted
  root the result is `[host]`; on a restricted parent the result is
  `[host]` if the parent admits `host`, else an **empty** (but non-zero)
  allow-list = a Net that admits nothing. This is why a chain
  `restrict_to(A).restrict_to(B)` with `A != B` **collapses** to the empty
  set (`{B} & {A} == frozenset()`). The host bytes are **shared, not
  copied**, and stored **verbatim** (no case-folding). A fresh header is
  always allocated, so deriving a narrower child **never mutates the
  parent** (the oracle's immutable `Net` value).
- `$Net_handle_allows(handle, host_ptr, host_len) -> i32` is the shared
  **exact-hostname membership** test: `handle == 0 -> 1`, else scan the
  allow-list and return 1 on the first `$str_eq` (byte-exact) match, 0
  otherwise. Membership is **equality, NOT containment**: a host that is a
  substring / super-domain / differing-case of an allowed host does **not**
  pass -- the security point (`restrict_to("example.com")` admits neither
  `evil-example.com` nor `example.com.evil.com` nor `Example.com`). This is
  the hostname analogue of Env's `$str_eq` key equality, **not** the Fs
  prefix-containment model.
- `$Net_allows(handle, host_ptr, host_len) -> i32` delegates straight to
  `$Net_handle_allows`, so the query answer equals the enforcement.
  Matching the oracle, `allows` passes its argument through **unchanged**
  (no case-folding), while `get` / `post` compare the **lowercased** URL
  host (`urlparse(url).hostname` / `split_net_url`); a differing-case query
  against a verbatim-stored allow-list entry therefore returns false,
  byte-identical to the oracle.

**Layered on top of the ceiling.** Every Net request op (`$Net_get` /
`$Net_post`) consults **two** guest-side gates before building any
request: first the per-method ceiling gate (`$Net_get` calls
`$Net_host_allowed_get`, `$Net_post` calls `$Net_host_allowed_post`), then
`$Net_handle_allows` (the receiver cap's fine allow-list). A request passes
only when the host is in the (method-scoped) ceiling **AND** in the fine
allow-list; a host outside either **fail-closes** to `Err(IoError)` before
touching the network, exactly as the oracle's `if not self.allows(host):
return Err(...)` prologue does (the fine gate; the ceiling gate has no
oracle counterpart -- it is the codegen-enforced asymmetry). The
unrestricted root (handle `0`) passes the fine gate trivially, so it is a
no-op for an unrestricted Net. The two ceiling gates differ only in the
operator grant they fold in (see `--allow-host` below); the
compiler-derived literal ceiling is combined into both.

`TestWasiNetAttenuation` / `TestWasiNetRejections` in
`tests/wasi/test_wasi_net.py` cover restrict + allowed + denied (get and post),
`allows` true / false, chaining / intersection-collapse, parent isolation,
the unrestricted root, and **exact-equality-not-substring**, each with
byte-identical output across the three backends. Example:
`examples/wasm/wasi_net_attenuation.capa`.

Finer attenuation of the request body (e.g. setting an explicit
`content-length` header to align the server's framing observation) is a
later refinement.

### `--allow-host`: the operator Net grant (dynamic URLs)

A DYNAMIC (argv-derived / computed) URL to `net.get` / `net.post` cannot
have its host resolved at compile time, so the static ceiling cannot be
materialised and the program is **rejected fail-closed** by default (the
symmetric analogue of a dynamic Fs path). `--allow-host <host>` is the
operator's escape, the Net analogue of `--preopen`: it grants the component
authority to reach `<host>` (repeatable; the allowlist is a set), which
suppresses the rejection and **unions the granted hosts into the guest-side
ceiling** the per-method gates check. It is `--wasi`-only and recorded in
the SBOM as an operator-declared grant
(`capa:operator_declared_grant:allow-host`), distinct from the
compiler-derived surface.

**Per-method scope (`:get` / `:post`).** The grant is scoped per HTTP
method: `--allow-host h:get` grants **read (GET) only**, `h:post` grants
**write (POST) only**, and a suffix-less `--allow-host h` grants **both**
(backward-compatible). This is least-authority: an operator can let a
program read from a host without also permitting a POST to it. The suffix is
recognised only when the tail after the **last** `:` is exactly `get` /
`post` **and** the head is a valid host, so a port (`h:8080`) or a bracketed
IPv6 authority (`[::1]:8080`) is never mistaken for a suffix while
`[::1]:get` is. A **malformed** method suffix -- a near-miss the operator
plainly meant as a scope (`h:GET` mis-cased, `h:get ` with a stray space,
`h:get:post` ambiguous) -- is **rejected** with an actionable error rather
than silently broadened to a both-methods grant (least-authority: never
grant more than asked). Enforcement is guest-side: `$Net_host_allowed_get`
admits
`ceiling | get-granted-hosts`, `$Net_host_allowed_post` admits `ceiling |
post-granted-hosts`; the compiler-derived literal ceiling is combined into
both (the literal `net.get` / `net.post` source is the truth). So a `h:get`
grant lets a dynamic `net.get` to `h` through, but a dynamic `net.post` to
`h` is denied at runtime by the post gate (`h` is not in the post set) --
proven by `tests/test_allow_host_method_scope.py`. The SBOM `access` field
records the scope (`get` / `post` / `connect`, the last for get+post).

**Runtime host extraction (the security core).** Because the URL is now a
runtime string, the guest extracts its host at runtime via `$Net_url_extract`
(the WAT realization of `capa.ir._net_host.extract_url_parts`), then runs the
SAME two gates the literal path does (the method-scoped
`$Net_host_allowed_get` / `$Net_host_allowed_post`, then the fine
`$Net_handle_allows` restrict_to gate), building the request only for a host
that passes both. Everything else stays `Err(IoError)`, fail-closed.

The extractor is validated **byte-for-byte against its Python reference** by
a differential WAT-vs-Python harness (`tests/test_allow_host_wat_diff.py`)
over an adversarial corpus (userinfo `@`, fragment `#`, uppercase, trailing
dot, IPv6, bad port, non-http schemes, whitespace). Its **security
contract**: the `authority` handed to wasi:http is BUILT FROM the same host
it verifies (host `[+ ":" port]`), so **the host gated is exactly the host
contacted** -- wasi:http receives that authority, never a re-parsed raw URL,
so no second parser can disagree. It **fails closed** (denies) rather than
guess on: no `://`; a scheme other than http/https; a bracketed IPv6
authority; a non-numeric port; or an empty host.

**SSRF posture.** A redirect from an allowed host to an internal one is
already refused (the guest treats any non-2xx as `Err`, see below).
Granting an internal / link-local / loopback / private IP prints a warning
but is allowed (the operator may have a reason). The one **honest residual
limitation**: this is a **hostname** allowlist, and wasi:http is host-side
allow-all, so Capa **cannot defend against DNS rebinding** -- a granted
hostname that resolves to an internal IP at connect time is not filtered at
this layer. `docs/design/wasi_mode.md` and `capa.ir._net_host` document this.

`tests/test_allow_host_oracle.py` (the normalization + reference oracle),
`tests/test_allow_host_wat_diff.py` (the differential extractor oracle), and
`tests/test_allow_host_e2e.py` (runtime reachability + deny-by-default +
bypass vectors + restrict_to-on-top over a local wasi:http server) cover it.

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
`wasi:clocks` / `wasi:cli` / `wasi:filesystem` / `wasi:io` package
references from a `deps/` directory. We vendor a trimmed subset of the
official WASI P2 `0.2.0` WIT in `capa/wasi_wit/deps/` (random + clocks
+ cli/environment + filesystem + io; `now` / `get-random-*` /
`get-environment` / `get-arguments` / `get-directories` / `stat-at` /
`create-directory-at` are the functions Capa calls; the `subscribe-*`
poll-dependent clock functions and the cli `initial-cwd` are omitted).
The `wasi:filesystem` `descriptor` resource and the `wasi:io`
stream/error resources it `use`s are vendored **structurally** so the
filesystem package type-checks at embed time, even though Capa calls
none of the stream-bearing methods (the metadata ops use no streams).
`_wrap_as_component(..., wasi=True)` copies these next to the generated
world before embedding; a program imports only the packages it uses,
and the unused deps are ignored by the embed. Provenance and update
instructions are in `capa/wasi_wit/README.md`.

## Validation

The migrated touch-points are non-deterministic, so validation is by
property (see `tests/wasi/`):

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
- **Fs metadata (three-backend parity over a controlled temp dir)**:
  `TestWasiFsMode` creates a known directory with a file and a
  subdirectory, then asserts `exists` (present file -> true, missing ->
  false), `is_dir` (directory -> true, file -> false), and `mkdir`
  (creates, and the second call is idempotent -> still `Ok`). The full
  output is byte-identical across the Python oracle, the `capa:host`
  backend, and the WASI backend. The component is shown to **import
  `wasi:filesystem/types` + `preopens`** (`wasm-tools component wit`),
  the host's applied preopen set is asserted **minimal** (exactly the
  one `READ_WRITE` data dir), and a non-closed ceiling installs **no**
  preopens. `TestWasiFsCeilingAnalysis` pins the static analysis
  (literal paths close the ceiling; the parent is the preopen;
  `READ_WRITE` only when a mutating op targets it; a dynamic path opens
  it; literal -> `(index, basename)` resolution; `mkdir_prefixes`
  cumulative-segment splitting). `TestWasiFsRejections`
  pins the acceptance of `read` / `write` (emit the wasi:filesystem +
  wasi:io stream wrappers, no `capa:host/fs`) and the compile-time
  rejection of `list_dir` / `allows` and of a dynamic metadata path
  (fail-closed).
- **Recursive `mkdir` (three-backend parity)**:
  `TestWasiFsMode::test_recursive_mkdir_multi_segment_three_backend_parity`
  creates `data/sub/new` when the intermediate `sub` does **not** exist;
  the WASI guest emits one `create-directory-at` per cumulative prefix
  (`sub`, then `sub/new`), so the whole tree is built and the output is
  byte-identical across Python, `capa:host`, and WASI (and an idempotent
  re-run is still `Ok`).
- **`stat-at` scratch sizing (no preopen corruption)**:
  `TestWasiFsMode::test_stat_after_mkdir_does_not_corrupt_preopen`
  exercises a `mkdir` followed by two `is_dir` on the same preopen. The
  shared Fs indirect-return scratch holds the full 104-byte
  `result<descriptor-stat, error-code>` that `stat-at` writes; an
  earlier 16-byte slot overflowed into the cached `get-directories`
  buffer and the second `is_dir` trapped with "unknown handle index" on
  a corrupted preopen descriptor.

## Path-arg surface (Layer 1: by-construction, transparent)

The dominant ecosystem pattern is a CLI tool that receives paths in
`argv` (`env.args()`) and feeds them to `fs.read` / `fs.write` (or
`net.get` / `env.get`). Such a path is a COMPUTED value at the sink, so
the static preopen / host / key ceiling cannot be derived and `--wasi`
fail-closes (rightly: an operator still uses `--preopen <dir>` to grant
access; see the layer b1 section). Layer 1 does **not** unblock that
program automatically and does **not** move the trust frontier (deriving
preopens from `argv` would be a separate Layer 2, out of scope). Instead
it turns the fail-closed point into an **auditable, machine-verifiable
fact**: the compiler PROVES which `argv` arguments reach which `Fs` /
`Net` / `Env` sinks, read or write.

**The analysis** (`capa/ir/_wasi_path_arg_surface.py`,
`compute_path_arg_surface`) is a sound, REACHABILITY-BLIND, forward
argv-taint fixpoint, reusing the const-prop's callable collection +
argument binding. It seeds on the result of `env.args()` and propagates
taint through `let` / `var` bindings, destructure patterns (`match
args.get(0) { Some(p) -> p }`), every operation on a tainted value (field
read, index, interpolation, method call), struct / list / tuple
construction with a tainted member, function arguments (to the callee
parameter) and function returns (to the call result). When a tainted
value lands in a built-in `Fs` / `Net` / `Env` sink slot, it records
`(arg_index_or_any, capability, method, access)`. Sink recognition is
broadened beyond the const-prop's param-only rule to include a sink whose
receiver is `self.<field>` for a cap-typed struct field (e.g. the
`ReadOnlyFsImpl { fs: Fs }` shape whose `read` does `self.fs.read(path)`)
and a local aliasing a cap parameter, so a built-in sink reached through a
wrapper cap is never omitted.

**Soundness** (verified by `tests/test_wasi_path_arg_surface_soundness.py`
against a hand-written ground-truth corpus): it is a CORRECT OVER-
APPROXIMATION -- it NEVER omits an `argv` argument that can reach a sink,
and NEVER reports an index narrower than statically proved. A concrete
index is emitted only when the sink slot resolves to a single argv index
in its own frame (`args.get(<lit>)` / `args[<lit>]` / `args.first()`,
directly or via a `let path = match args.get(0) { Some(p) -> p }`
destructure); in every other case (a struct field, a helper return, a
computed index, a loop) the index is `argv[*]`.

**Three consumers:**

1. **SBOM** -- a `compiler_derived_path_arg_surface` block in the manifest
   (`capa/manifest/_funrec.py::build_path_arg_surface`), surfaced in
   CycloneDX (`capa:compiler_derived:path_arg_surface` properties) and
   SPDX (`compiler_derived:path_arg_surface` annotations). It is labelled
   `compiler-derived` -- the OPPOSITE trust level to
   `operator_declared_grants`. An auditor reads it as a property the
   compiler PROVED, not as an operator's declared trust.
2. **Actionable rejection** -- the `--wasi` fail-closed message for a
   dynamic `Fs` / `Net` path (`_validate_wasi_caps`) now NAMES the proven
   arg -> sink (e.g. `argv[0] -> Fs.read (read-only)`) and suggests
   `--preopen <dir>`.
3. **Inspection** -- `capa --wasi-surface <prog>` prints the surface
   without compiling or running the program (read-only). Output reads e.g.
   `argv[0] -> Fs.read (read-only)`.

The existing const-prop literal resolution and the static ceilings are
unchanged: the surface is a READ-only provenance extension, never altering
which literals resolve or what the ceilings materialise.

## Files

- `capa/ir/_wasi_path_arg_surface.py` - the Layer 1 path-arg surface
  analysis (`compute_path_arg_surface`, `PathArgSurface`, `PathArgFact`):
  the forward argv-taint fixpoint + read/write classification + concrete-
  index provenance, reused by the SBOM, the actionable message, and
  `--wasi-surface`.
- `capa/ir/_emit_wasm/_wasi.py` - WASI import + adapter-wrapper
  emission (Random / Clock / Env readers + guest-side Env attenuation
  `$Env_restrict_to_keys` / `$Env_allows` / `$Env_key_allowed`; the Fs
  metadata wrappers `$Fs_exists` / `$Fs_is_dir` / `$Fs_mkdir` +
  `$__wasi_fs_preopen_desc`; the stream-bearing `$Fs_read`
  (read-via-stream + blocking-read loop) and `$Fs_write`
  (open-at create|truncate + write-via-stream +
  blocking-write-and-flush loop + blocking-flush, all OWN-resource
  drops); the directory-enumeration `$Fs_list_dir` (open-at directory +
  read-directory + read-directory-entry loop + guest-side `$str_cmp`
  sort, stream + descriptor drops)) and the excluded-surface validation.
- `capa/ir/_emit_wasm/_caps.py` - the WASI Fs call-site emitters
  (`_emit_wasi_fs_metadata_call`: literal -> preopen index + basename,
  mkdir result materialisation; `_emit_wasi_fs_read_call` /
  `_emit_wasi_fs_write_call` / `_emit_wasi_fs_list_dir_call`: literal
  path (+ content) -> `$Fs_read` / `$Fs_write` / `$Fs_list_dir`,
  `result_string_io_error` / `result_unit_io_error` /
  `result_list_string_io_error` materialisation).
- `capa/ir/_emit_wit.py` - WASI-mode world generation
  (`_emit_wit_wasi`; Fs routes to `wasi:filesystem` imports).
- `capa/ir/_env_ceiling.py` - the static Env authority-ceiling analysis
  (`EnvCeiling` / `compute_env_ceiling`) backing Level 1.
- `capa/ir/_fs_ceiling.py` - the static Fs preopen-ceiling analysis
  (`FsCeiling` / `FsPreopen` / `compute_fs_ceiling` / `resolve_fs_call`):
  literal paths -> sorted parent preopens with derived perms; resolves
  each literal call to `(preopen_index, basename)`.
- `capa/runtime/_wasm_component_host.py` - the `wasi=True` host recipe
  (the env-set; `argv`; the Fs preopen registration `_apply_fs_preopens`
  in ceiling order with derived perms, fail-closed for a non-closed
  ceiling; passes `0` as the Env and Fs roots; records the installed
  env-set / preopens in `_wasi_env_applied` / `_wasi_fs_applied`).
- `capa/cli.py` - the `--wasi` flag, the WASI-deps embed path, the
  Env + Fs ceiling computation handed to the host on
  `--wasi --component --run`, and the read-only `--wasi-surface`
  inspection command (Layer 1).
- `capa/manifest/_funrec.py` - `build_path_arg_surface`, the
  `compiler_derived_path_arg_surface` SBOM block (Layer 1), surfaced in
  `capa/manifest/_cyclonedx.py` + `capa/manifest/_spdx.py`.
- `capa/wasi_wit/` - vendored WASI P2 WIT subset (random / clocks /
  cli-environment / filesystem / io).
- `examples/wasm/wasi_random_clock.capa` - the Random + Clock demo.
- `examples/wasm/wasi_env.capa` - the Env reader demo.
- `examples/wasm/wasi_env_attenuation.capa` - the guest-side Env
  attenuation demo (intersection + fail-closed).
- `examples/wasm/wasi_fs_metadata.capa` - the Fs metadata demo
  (`exists` / `is_dir` / `mkdir` via `wasi:filesystem` + the preopen
  ceiling).
- `examples/wasm/wasi_fs_read.capa` - the Fs.read demo (open-at ->
  read-via-stream -> blocking-read loop over `wasi:io/streams`).
- `examples/wasm/wasi_fs_write.capa` - the Fs.write demo (open-at
  create|truncate -> write-via-stream -> blocking-write-and-flush loop
  -> blocking-flush over `wasi:io/streams`; write-then-read-back +
  overwrite/truncate).
