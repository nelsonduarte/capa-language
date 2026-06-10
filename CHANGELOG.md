# Changelog

All notable changes to Capa are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
starting at 1.0; before then, minor-version bumps may introduce
breaking changes and the discipline is still being shaped.

## [Unreleased]

### Bug fix: silent Wasm divergence, parse_json accepted raw control characters in JSON strings

The bundled Wasm-side JSON parser (`capa/ir/_builtin_json.capa`)
accepted raw control characters (newline, tab, anything below
0x20) inside a JSON string and returned `Ok` with the character
embedded, where the Python backend's `json.loads` correctly
returns `Err` (RFC 8259 section 7 requires control characters to
be escaped). The same scan also accepted invalid escape
introducers (`"\q"` parsed `Ok` as a literal `q`; Python: Err
"Invalid \escape") and decoded `\b` / `\f` to the letters `b` /
`f` instead of U+0008 / U+000C. All three now match Python:
raw control characters and invalid escapes are `Err` on both
backends, `\b` / `\f` decode to the real control characters, and
the serialiser emits `\b`, `\f` and `\u00XX` for control
characters exactly like `json.dumps`. (`\uXXXX` escapes still
parse `Ok` but pass the hex digits through verbatim on Wasm, a
pre-existing documented v1 limitation; pinned Ok-parity only.)
Covered by `tests/test_ir_wasm_parity.py::TestJsonAndLargeStringParity`
(raw newline / tab / 0x00 / 0x01 / 0x0D / 0x1F in values and keys,
valid-escape round-trip, invalid escape, `\u` Ok-parity).

### Bug fix: Wasm trap ("out of bounds memory access") on strings over ~64 KiB where Python returned Ok

Passing a string past ~64 KiB to `parse_json` -- or merely
printing a 70 KiB string literal -- trapped the Wasm backend while
the Python backend ran fine. Two distinct causes shared the
symptom. (a) The emitted `(memory ...)` declaration hard-coded ONE
initial page, so any module whose static string data crossed
64 KiB failed at instantiation when the active data segment was
bounds-checked against the initial size; `--wasm-memory-cap` never
mattered because `$alloc`'s grow path never ran. The initial page
count is now sized to the data segment (and a cap smaller than the
static data is a loud compile-time `WasmEmissionError` instead of
an invalid `min > max` limits clause). (b) The bundled JSON parser
accumulated string contents one character at a time through the
no-free bump allocator, O(n^2) bytes, so even runtime-built large
inputs blew the 16 MiB default cap inside `$alloc`; per-character
probes also went through `substring`'s O(n) code-point translation,
O(n^2) time. The parser now threads a `List<String>` of
one-codepoint views (O(1) probes) and extracts string values with
a single `substring` (or between-escape chunks), so 100 KiB+
strings and >128 KiB documents parse in linear memory on both
backends with identical values. Covered by
`tests/test_ir_wasm_parity.py::TestJsonAndLargeStringParity`
(100 KiB literal, runtime-built 100 KiB, >128 KiB document,
70 KiB literal interpolation) and
`tests/test_ir_wasm.py::TestWasmMemoryCap` (WAT initial-pages
shape, loud cap-below-data error).

### Security: Fs read/write symlink-swap TOCTOU window closed via post-open handle verification

The long-documented symlink-swap race between `Fs.allows()`
(realpath + prefix check) and the underlying `open()` is closed
for the data operations. `read` and `write` on a restricted `Fs`
now verify the *open handle*: after opening, the OS reports the
symlink-resolved path of the file descriptor (Linux
`/proc/self/fd`, macOS `fcntl F_GETPATH`, Windows
`GetFinalPathNameByHandle`; new module
`capa/runtime/_fs_guard.py`) and that path is re-validated against
the allowed prefixes before any byte moves. A symlink swapped in
any path component, at any moment, can no longer leak or modify a
file outside the prefixes. The destructive vector is handled
explicitly: `write` opens without `O_TRUNC` and truncates only
after the handle passes, so a denied write leaves pre-existing
out-of-prefix data byte-for-byte intact. `O_NOFOLLOW` is applied
to the final component where supported, as defence in depth (with
a retry so legitimate in-prefix symlinks keep working).

Scope and residuals, stated precisely: only `read`/`write` are
hardened (they are the data vectors). `exists` / `is_dir` /
`list_dir` / `mkdir` still check-then-act and keep their TOCTOU
window; on a platform with none of the three handle-path
mechanisms the data ops fall back to the pre-open check alone
(explicit, commented fallback); a denied `write` may leave a
zero-byte file behind when the swapped target did not previously
exist; and hard links are not distinguished: a hard link created
inside a prefix to an out-of-prefix file passes both the pre-open
realpath check and the post-open handle check (the OS reports the
link's own in-prefix name for both), a containment limit shared
with the previous realpath-only check rather than a regression. User-visible semantics are unchanged: same deny messages,
same `IoError` shapes, UTF-8 and newline behaviour identical, and
unrestricted `Fs` instances skip the guard entirely.

Both backends are covered: the core-Wasm and Component Model host
shims (`_wasm_host.py`, `_wasm_component_host.py`) now route file
IO through the same shared `Fs._open_read` / `Fs._open_write`
guarded helpers instead of calling `open()` directly. Covered by
`tests/test_fs_toctou.py`: helper unit tests, a deterministic
race simulation (pre-check forced open, post-check must deny, on
both the Python and Wasm paths), final-component and
intermediate-component symlink swaps, and the
no-truncation-on-denial regression test.

### Bug fix: silent Wasm divergence in nested-variant match arms with outer sibling binders

A `match` arm whose variant payload mixes a nested variant pattern
with sibling binders (`Pair(n, Some(m))` against
`type P = Pair(Int, Option<Int>)`) silently miscompiled on the Wasm
backend: the nested-arm emission paths bound only the nested
variant's own payloads and never the outer siblings, so the outer
binder read its Wasm local's default value. Python printed
`pair 3 4`, Wasm printed `pair 0 4`, with no error on either side -
the worst class of divergence. Both nested-arm paths (the nested
if/else cascade and the flat-block guarded form) now bind every
outer non-variant payload (binders and wildcards before and after
the nested variant, in any count) from the outer record before the
inner binds, reusing the same payload-bind helper as flat variant
arms.

The same audit found and fixed two more defects in the nested-arm
emitter:

- **Several nested-variant siblings took the wrong arm.**
  `Duo(Some(a), Some(b))` only tag-checked and bound the FIRST
  nested sibling, so `Duo(Some(3), None)` matched the
  `Duo(Some(a), Some(b))` arm with `b` reading 0. The arm predicate
  now checks every nested sibling's inner tag (each extraction
  short-circuited behind the accumulated predicate, so an inner-sum
  pointer is only decoded from a slot the outer tag proved valid)
  and binds each sibling's payloads.
- **Guards on nested-variant arms are now supported.** Previously a
  loud `WasmEmissionError` ("nested variant pattern with arm guard
  not yet supported"); the binds land ahead of the guard check, so
  `Pair(n, Some(m)) if n > m` works and the guard can read both the
  outer and inner binders.

Covered by the new cross-backend parity program
`examples/wasm/match_nested_variant_outer_binds.capa` (binder
before / after / around the nested variant, wildcard + binder
siblings, outer literal + outer binder + nested variant together,
String / Float / Bool / Int sibling shapes, two nested siblings
across all four tag combinations, guards reading outer + inner
binders, payloadless nested variants, expression-form match).

### Wasm backend: literal patterns inside variant payloads

`match flag { Some(true) -> ..., Some(false) -> ..., None -> ... }`
now compiles and runs on the Wasm backend (`--wasm --run`),
byte-identical with the Python reference. Previously the Wasm
sum-match emitter raised "Phase 6C: nested pattern PatLiteral inside
variant payload not yet supported" (found by a downstream `capa_cli`
smoke pass). The literal equality check (Int, Bool, String, Float)
refines the variant tag predicate, short-circuited behind the tag
check so a non-matching variant's payload slot is never decoded
under the wrong encoding, and a literal mismatch falls through to
the next arm. Works in flat and guard-bearing matches, alongside
binders in multi-payload variants, and one level deep inside a
nested variant pattern (`Some(Ok(0))`).

### Per-function positions on SBOM surfaces: right file, root-relative

Bug fix with observable value on every surface that displays the
manifest's per-function `pos` (`--manifest`, CycloneDX `capa:pos`,
SPDX annotations, `--doc`, `capa migrate`): in a linked multi-file
program, an imported function's position stamped the ROOT file's
name onto the imported file's line/col, i.e. it pointed into the
wrong file. Each declaration now records the file it was actually
declared in.

Recorded paths are also root-relative and separator-stable now: a
declaration file under the root file's directory (vendored modules
included) is written relative to that directory with `/` separators
on every OS. Previously imported declarations would have carried the
loader's absolute paths, leaking the builder machine's directory
layout (and username) into SBOMs and breaking byte-reproducibility
across machines. A file resolved from outside the root tree (e.g.
via `CAPA_PATH`) keeps its path as lexed, which preserves the
"this code came from outside the project" signal.

Note the change of *shape* this implies for consumers that parse
`pos`: functions declared in the root file used to echo the path
exactly as passed on the command line (possibly absolute, native
separators); they now display the root-relative form, i.e. the root
file's basename. The same display form now also backs the manifest's
top-level `filename` field, the `file` field and header of
`capa migrate`, and the filename-derived identifier seeds (see the
identifier entry below), so the whole artefact, not just each `pos`,
is byte-identical regardless of invocation style, cwd, or machine.

### New subcommand: `capa migrate`

`capa migrate <file.capa>` reports gradual-hardening progress for a
Python-to-Capa migration: how many functions are already
`Unsafe`-free, which functions declare an `Unsafe` they provably
never exercise (removable now; the detection is transitive over the
call graph and conservative by construction), and which still-using
functions are cheapest to harden next (fewest `py_import` /
`py_invoke` bridge calls first). `--json` emits the same report
machine-readably for CI gates. The same removable-`Unsafe` detection
also backs a compiler warning on every compile and an LSP diagnostic.
See `docs/migration.md`.

### `capa migrate`: per-file breakdown and next-file ranking

`capa migrate --json` gains two additive keys for multi-file
projects: `files` (per-source-file totals, still-Unsafe count,
removable count and Unsafe-free percentage) and `file_ranking` (the
next files to harden, least remaining migration cost first). The
human-readable report grows the matching "Per-file progress" section
only when the program spans more than one file; all pre-existing JSON
keys keep their program-wide meaning.

### Attestation and SBOM identifiers: capa-language.com URIs, reproducible seeds

One combined, observable format change for downstream consumers that
pin these values; both halves land in this release window, so
deterministic identifiers change exactly once.

First, the domain. The project's domain is capa-language.com; the
URIs emitted in audit artefacts previously pointed at capa-lang.org,
a domain the project does not own.

- **SLSA provenance** (`--provenance`): `buildType` is now
  `https://capa-language.com/build/transpile-to-python/v1` and
  `runDetails.builder.id` is `https://capa-language.com/cli`.
  Verifiers that pinned the old `capa-lang.org` URIs must update.
- **SPDX** (`--spdx`): `documentNamespace` now starts with
  `https://capa-language.com/spdx/`.
- **CycloneDX** (`--cyclonedx`): the deterministic `serialNumber`
  UUID namespace moved with the domain. No URI is visible in the
  output.

Second, the seeds. The deterministic UUIDv5 identifiers (CycloneDX
`serialNumber`, the UUID component of the SPDX `documentNamespace`,
the provenance `invocationId`) were seeded from the root filename
exactly as passed on the command line, so the same project produced
different identifiers depending on invocation style (relative vs
absolute path, cwd) and on each builder's directory layout. All
three are now seeded the way the provenance `invocationId` already
was: from the root-relative display form of the filename (for the
root file, its basename) plus the sha256 of the root source, and
the manifest's top-level `filename` field records the display form
too. Two builders on different machines, or two invocation styles
on the same machine, now produce byte-identical manifests, SBOMs,
and provenance modulo timestamps; two unrelated projects that share
a root basename (every project called `main.capa`) no longer
collide on the same identifier. Consequence of the digest in the
seed: the CycloneDX `serialNumber` and SPDX `documentNamespace` now
change whenever the source changes, identifying a concrete build
input rather than a file name.

The JSON schemas are unchanged; only these values differ.

### Bug-hunt fixes: cross-backend parity, soundness, and Wasm patterns

A deep bug hunt across both backends fixed a batch of correctness gaps.
Behaviour-changing items are noted; all are covered by new tests.

- **Integer division `/` now floors on both backends.** The Wasm
  backend emitted truncating `i64.div_s` while the Python backend
  floored, so `-7 / 2` was `-3` on Wasm vs `-4` on Python. Wasm now
  applies the floor correction (matching the already-floored `%`), and
  both backends trap on `MIN / -1` (a new `_capa_idiv` helper guards the
  Python side). Integer `/` and `%` are now floor + trap on both.
- **Unary integer negation traps on `i64::MIN`** on both backends
  (was: Python produced the out-of-range bignum `2**63`, Wasm wrapped).
- **Float division by zero traps on the Wasm backend**, matching
  Python's `ZeroDivisionError` and the existing float-`%` trap.
- **A match used for its value must be exhaustive.** A non-exhaustive
  match expression was accepted, then crashed the Python backend and
  returned an empty value on Wasm; the analyzer now rejects it.
- **`break` / `continue` inside a lambda are rejected** by the analyzer
  (they cannot cross the lambda's function boundary).
- **`String.index_of` returns a code-point offset on Wasm** (was a byte
  offset), matching Python and the code-point contract of `length` /
  `substring` / `char_at`.
- **`Set<Float>` equality no longer crashes the Wasm backend** (an
  undeclared `$_alloc_tmp_f64` local in the set-equality helper).
- **A user function named `parse_int` / `parse_float` no longer collides
  with the builtin helper on Wasm**; the user definition shadows the
  builtin on both backends.
- **A `Bool` reached through a tuple index interpolates as `true` /
  `false`** (was Python-style `True` / `False`).
- **Tuple indexing is now typed at the root.** A constant tuple index
  `t[k]` resolves to the k-th element type (was `Unknown`, which masked
  type errors), a constant out-of-range index is a compile-time error
  (was: Python `IndexError` at runtime vs Wasm silently returning 0),
  and a nested tuple index `t[0][1]` no longer emits invalid Wasm.
- **Wasm match patterns**: identifier-binding catch-alls in sum matches,
  float-literal patterns, binding-free or-patterns (`A | B`), and struct
  patterns (`P { x: 0, y }`) now lower and run on the Wasm backend with
  Python parity. Still loudly unsupported on Wasm (compile-time error,
  never a silent miscompile): char-scrutinee match (`Char` has no Wasm
  value encoding yet) and or-patterns that bind.

### Tail-call optimisation on the Wasm backend (roadmap P4)

A call whose result is immediately returned (`return f(x)`) now lowers
to a Wasm `return_call`, so accumulator-style and mutually recursive
functions run in constant stack space instead of overflowing. The
peephole fires for tail calls in `if` / `else` branches, in
statement-`match` arms (`_ -> return f(...)`), and in straight-line
bodies; it covers ordinary user functions (variant constructors,
intrinsics, and closure calls keep their normal lowering). A
1,000,000-deep tail recursion that would blow an ordinary call stack
now returns cleanly (`examples/wasm/tail_recursion.capa` is the parity
example; a dedicated Wasm-only test exercises the deep case). The
expression form `return match n { ... }` is not yet optimised (the
match result is bound to a temporary before the return, so the tail
call is not adjacent to it); use the statement-`match` form for a tail
call. No wasmtime configuration change is needed: the tail-call
proposal is enabled by default in the engine we ship against.

### Constant-time: reject variable-time arithmetic (roadmap S4)

A `@constant_time` function now rejects `/` and `%` when either operand
is `@secret`. Division and modulo run on the CPU's variable-latency
divider (integer `idiv`, float `divsd`), so their timing depends on the
operand values, the CWE-208 side channel. This closes the documented S4
gap; add / subtract / multiply stay legal (fixed-latency). The only
remaining S4 follow-up is defense-in-depth enforcement in the Wasm
emitter (the guarantee lives in the analyzer today).

### Typestate state-specific methods (roadmap S3.5)

Operations on a typestate can now be methods, written in an `impl
Type[State]` block, callable only when the receiver is in that state:
`door.label()` type-checks on a `Door[Open]` but is rejected on a
`Door[Closed]`. A transition can be a method too: `fun open_it(consume
self) -> Door[Open]` consumes the value and returns it in the new
state, so `door.open_it()` reads as a natural protocol step. Inside an
`impl Type[State]`, `self` carries that state. An `impl Type[State]` on
a non-typestate, or on a state the typestate does not declare, is
rejected. State is compile-time-only, so the methods are ordinary
struct methods at runtime; `examples/wasm/typestate_methods.capa` runs
byte-identically on both backends. With this, the typestate feature
(S3) is complete: declarations, state-indexed types, construction,
`become` transitions, fields, and state-specific methods.

### Typestate fields / payload (roadmap S3.4)

A typestate can now carry data, not just a state: `typestate Socket
{ fd: Int }` declares shared fields, constructed with `Socket[Created]
{ fd: 7 }` and read with `s.fd`. A transition (`become`) preserves the
fields. This makes typestate usable for real protocol handles (wrap an
fd / connection) rather than being a bare protocol token. Under the
hood a typestate is a state-indexed struct, so it reuses the struct
machinery end to end: field validation at construction (missing /
unknown / wrong-type / capability-typed fields are rejected), field
access, the Python class, and the Wasm struct lowering (the field is a
real slot; `examples/wasm/typestate_socket.capa` runs byte-identically
on both backends). State-specific receiver methods remain a follow-up.

## [1.0.0], 2026-06-03

First stable release. No feature changes from `1.0.0-rc.7`; this
release flips the version and brings the [`STABILITY.md`](STABILITY.md)
commitment into effect (the listed surfaces now follow SemVer:
breaking changes require a major bump, deprecations get one minor
release of warning first).

The 1.0 surface, in one place:

- **Capability discipline**: the authority a function holds is in its
  signature; the default is zero capabilities, widening is explicit,
  and attenuation (`restrict_to`) is monotonic. Enforced on the Python
  backend and soundly across function boundaries on the Wasm backend.
- **Information-flow control (S2)**: `@secret` / `@public` labels,
  secret-to-sink enforcement (warn-then-enforce, `@strict_ifc`),
  `declassify(value, reason)` as the single auditable bridge, recorded
  in the SBOM as `declassification_sites`.
- **Constant-time markers (S4)**: `@constant_time()` rejects
  secret-dependent control flow and memory access (CWE-208).
- **Typestate / session types (S3)**: `typestate` + `Name[State]` +
  `become`, with the protocol enforced by the type checker plus
  linearity; recorded in the SBOM as `typestates` / `protocol_states`.
- **Linear handles (S1)**: must-consume types, surfaced as
  `linear_obligations`.
- **Two backends with parity**: a Python transpiler and a fully
  functional Wasm Component Model backend, output byte-identical
  across a parity harness.
- **Supply-chain artifacts by construction**: capability manifest,
  CycloneDX + SPDX SBOMs, VEX, SLSA provenance, all emitted by the
  compiler.
- **Tooling**: package manager + signed registry, REPL, LSP server,
  formatter, and a VSCode Marketplace extension.

## [1.0.0-rc.7], 2026-06-03

### Typestate foundation: typestate declarations + state-indexed types (roadmap S3.1)

The first slice of typestate / session types. A `typestate Name`
declaration lists the named states of a protocol; a value carries its
current state in the type, written `Name[State]`, and is linear (it
must be consumed or transitioned, reusing the S1 must-consume
discipline). Because the state lives in the type, the ordinary type
checker enforces the protocol: `Socket[Created]` and
`Socket[Connected]` are distinct types, so passing one where the other
is expected is a compile-time error. A transition is then just a
function that consumes a value in one state and returns it in another.

The foundation (S3.1) ships the type-level machinery: the `typestate`
declaration, the `Name[State]` type syntax, state-exact type
compatibility (in `compatible` / `unify` / `ty_str`), registration of
typestate types as linear, and validation that every `[State]` names a
declared state.

S3.2 makes it usable: `Name[State] {}` constructs a value in a state,
and `become(value, State)` transitions it (consuming the old-state
value so its must-consume obligation moves to the result rather than
being dropped or duplicated). A full protocol now type-checks and runs
on the Python backend: a wrong-state operation, a dropped value, or a
bad transition target are all compile-time errors. The manifest gains
a top-level `typestates` list (each protocol with its ordered states)
and a `protocol_states` summary count.

S3.3 brings typestate to the Wasm backend with parity: a v1 typestate
(which carries no data) lowers as a zero-field struct, so its value is
an i32 heap pointer, construction is a fieldless `MakeStruct`, and
`become` is identity. A door-protocol example runs byte-identically
under Python and Wasm (`examples/wasm/typestate_door.capa`, in the
parity suite). State-specific receiver methods and typestate fields /
payloads remain follow-ups.

### Constant-time markers: @constant_time (roadmap S4)

A function annotated `@constant_time()` must not let a `@secret` value
drive its execution time, the CWE-208 side channel. Building directly
on the S2 information-flow labels, the analyzer rejects, inside such a
function: a control-flow decision on a secret (`if` / `elif` / `while`
/ `match` / `if`-expression condition), and a memory access indexed by
a secret (`xs[secret]`, `list.get(secret)`, `map.get(secret)`,
`map.contains_key(secret)`, `set.contains(secret)`,
`str.char_at(secret)`). Arithmetic and branches on public data stay
legal, so a branchless constant-time formulation type-checks. The
guarantee is surfaced in the manifest as a per-function `constant_time`
boolean, so the SBOM records which functions carry it (relevant to the
crypto subset of a CRA conformity pack). Variable-time arithmetic
(e.g. division by a secret) is not yet modelled.

## [1.0.0-rc.6], 2026-06-02

### Information-flow control: @secret / @public labels + declassify

Capabilities control which effects a function may exercise; this
release adds information-flow control, which constrains where data
may flow. A two-point security lattice (`@public` below `@secret`)
attaches to type expressions, parameters, and struct fields
(`token: @secret String`). Labels propagate automatically by join
through every derived value: arithmetic, string interpolation
(`"${secret}"` is secret), field reads, indexing, the `?` operator,
and function results (a call with a secret argument returns secret).

`env.get(...)` is a secret-by-default source: its result is `@secret`
with no annotation, so the read-a-key-then-exfiltrate case is caught
without the programmer labelling anything. A `@secret` value that
reaches a public sink (`Stdio.print/println/eprintln`, `Net.get/post`,
`Fs.write`, `Db.exec/query`) is an information-flow violation. The
rollout is warn-then-enforce: a compile-time warning by default, a
hard error inside a function annotated `@strict_ifc()`.

`declassify(value, reason: "...")` is the single auditable
secret-to-public bridge. It is identity at runtime and relabels the
result `@public`; the `reason` must be a named string literal.
Declassifying a non-secret value is reported as a no-op warning. Every
call site is recorded in the manifest as `declassifications` per
function (`reason`, `value`, `pos`) and counted as
`declassification_sites` in the summary, so the SBOM carries a
machine-checkable record of exactly where, and why, a program
discloses sensitive data.

Implicit flow (a sink inside a branch guarded by a `@secret`
condition) is enforced under `@strict_ifc` only, so the default tier
stays focused on the high-value explicit data leaks. Laundering is
closed intra-procedurally: aggregate literals (struct / list / tuple)
carry the join of their element labels, a for-loop variable inherits
the iterable's label, and a secret pushed / added / set into a mutable
`List` / `Set` / `Map` taints the container. The analysis is
intra-procedural by design (a secret crossing a function boundary
needs an explicit `@secret` parameter) and whole-aggregate in
granularity (per-field precision is future work). New flagship example
`capa_paymentguard` exercises the whole story on a PCI DSS / PSD2
payment-security core.

### Wasm: Stdio.read_line parity coverage

`Stdio.read_line` worked end-to-end on the core and Component Model
Wasm hosts but had no parity test, the last method of the
host-bridge pile left uncovered. Added a stdin-fixtured parity test
(core + Component Model) and the `read_line_echo.capa` example. With
this, every host-bridged capability method (`read_line`, `Clock.sleep`,
`Fs.exists/is_dir/mkdir/list_dir`, `Env/Fs/Clock.allows`) has Wasm
parity coverage, and the "fully functional Wasm" arc (all capabilities,
Random, Net, String methods, Map.keys/values, tuple arities, range
iteration, Option/Result higher-order methods) is verified against the
Python reference.

## [1.0.0-rc.5], 2026-05-27

### Manifest: source-level names in SBOM emission

The loader rewrites every non-pub item in an imported module
to `_capa_m{N}__<source>` so the merged AST stays flat without
name collisions. Before rc.5, the manifest builder copied
`fn.name` straight into the SBOM, so an auditor reading the
CycloneDX or SPDX output for a multi-module program saw
entries like `_capa_m2__as_object_or_err` where the source
identifier was `as_object_or_err`. The fix surfaces source-
level names in regulator-facing output while keeping the
loader-time identifiers for internal cross-module
collision-stability.

New [`_demangle`](capa/manifest/_funrec.py) helper parses the
prefix back into `(source_name, module_index)`. Each function
record now carries `source_name`, `source_container`, and
`source_module_index` alongside the existing (loader-time)
`name` and `container`. The loader-time fields stay because
bom-ref / SPDXID keying and the call-resolution map rely on
them for two-same-source-named helpers from different imports
not collapsing into one entry.

CycloneDX emitter ([`capa/manifest/_cyclonedx.py`](capa/manifest/_cyclonedx.py))
displays `source_name` and `source_container` on the public
`name` / `qualname` field; a new `capa:source_module_index`
property is added when the function came from a non-pub
imported module so the auditor can still tell two same-source-
named helpers apart.

SPDX emitter ([`capa/manifest/_spdx.py`](capa/manifest/_spdx.py))
gets the same treatment, with a `source_module_index`
annotation in place of the CycloneDX property.

Verified end-to-end on the
[capa_governance_pack](https://github.com/nelsonduarte/capa_governance_pack)
downstream: `still-mangled: 0` across all 40 components in
its `--cyclonedx` output (pre-fix the count was substantial).
The downstream program still runs end-to-end; the audit pack
content is unchanged because the program does not consume
its own SBOM.

5 regression tests in [`tests/test_manifest.py`](tests/test_manifest.py):
`TestSourceNameDemangle` exercises root-module no-op,
imported non-pub demangled with `module_index` set, imported
pub kept as-is via the real loader harness;
`TestSourceNameInSboms` covers CycloneDX + SPDX integration.

Closes the fifth and last of the five bugs surfaced by the
capa_governance_pack stress test in rc.4.

## [1.0.0-rc.4], 2026-05-27

### Empirical study at scale: 20-library SBOM-diff corpus

Closes P1 #1 (the "quantitative validation" item from §5 of
the paper draft). Twenty library pairs at
[`evaluation/sbom_diff/`](evaluation/sbom_diff/) compare a
PURL-style "naive" SBOM (Python imports of the transliterated
source) against Capa's per-function capability-aware SBOM
(`capa --cyclonedx` over the Capa rewrite). Every pair carries
`naive.py`, `capa.capa`, and `README.md`.

The harness extracts per-function `capa:declared_capability`
properties via a subprocess `capa --cyclonedx` call, scans the
naive Python file's `import` statements, and intersects against
a 30-entry cap-bearing allowlist. Aggregate metrics over the
corpus: 122 transliterated functions (73 pure / 49 with caps),
6 distinct capability axes
(`Clock`, `Env`, `Fs`, `Net`, `Random`, `Stdio`), and 61
per-function (function, capability) attribution facts. The
pair-combination coverage matrix spans `Fs+Env`, `Fs+Clock`,
`Fs+Net`, `Net+Clock`, `Env+Clock`, `Random+Clock`, and the
`Fs+Env+Net` triple.

The corpus also surfaced two pre-existing soundness bugs in
the compiler, both fixed in the same release: an `Int/Int`
transpiler-vs-typer mismatch (Python true-division emitted
where the type system promised `Int`) and a silent
octal-escape miscompile (`\033` lexed to `\0` + literal `33`).

See [`evaluation/sbom_diff/summary.md`](evaluation/sbom_diff/summary.md)
for the full per-pair table.

### Formatter v3: AST round-trip with comment preservation

`capa --fmt` now defaults to a full AST round-trip pipeline
(lex + parse + walk + emit), with the v1+v2 line-level
pipeline as a graceful fallback on any lex / parse / emit
failure (mid-edit sources, syntax errors). Comments survive
the round-trip via a new `CommentMap` side-table keyed by
`id(node)`, matching the `analyzer.types` / `transpiler.types`
convention; each entry has four slots
(`leading`, `trailing`, `trailing_header`, `interior`).

Four phases shipped together:
- **Phase 1 (lexer sidecar)**: new `CommentKind` enum + frozen
  `Comment` dataclass in [`capa/tokens.py`](capa/tokens.py);
  `Lexer.comments` populated as plain `//` and `/* */` are
  consumed. Token stream unchanged.
- **Phase 2 (CommentMap attachment)**:
  [`capa/formatter/_comments.py`](capa/formatter/_comments.py)
  (~588 LOC). Block-aware file-header heuristic plus
  token-aware end-offset refinement keep attachment correct
  inside section-divider-wrapped blocks and on trailing
  comments on the last token of a statement.
- **Phase 3 (pretty-printer)**:
  [`capa/formatter/_emit.py`](capa/formatter/_emit.py) plus
  `_emit_items.py` / `_emit_stmts.py` / `_emit_exprs.py`
  (~1431 LOC across four files, per the 700-line-per-file
  ceiling). Every AST node type is handled with
  precedence-based parenthesisation and canonical
  string-literal escaping (uses `\u{1b}` for ESC since the
  Capa lexer rejects octal).
- **Phase 4 (dispatch)**: wired into the existing
  `format_source` entry point with the `_lines` pipeline as
  fallback.

Two comment-ordering fixes shipped alongside the promotion: a
block-aware file-header heuristic (a standalone comment
attaches to `Module.leading` only when its contiguous block
has no section divider AND is separated from the first item
by a blank line; otherwise the whole block attaches to the
next item's `leading`), and token-aware end offsets in
`_build_node_index` (so a `let x = 1 // trailing`-style
comment's `_smallest_containing_node` lookup lands on the
`LetStmt` rather than the enclosing `Block`).

Three follow-ups required by the promotion:
`test_formatter::test_javadoc_block_canonicalised_to_line_form`
reflects the new `/** */` -> `///` canonicalisation;
`init_project._MAIN_TEMPLATE` drops a blank line so the
scaffolded project is in canonical form; `format_source`
guards against degenerate lone-`\` line-continuation sources
that lex to empty token streams.

Tests: 10 lexer-sidecar (`TestCommentSidecar`) + 10
attachment (`TestCommentMap`) + 66 pretty-printer
(`TestPrettyPrinterStructure` + `TestPrettyPrinterRoundtrip` +
`TestPrettyPrinterIdempotence`). Structural AST round-trip
green on 71 corpus files (51 examples + 20 sbom_diff);
byte-exact idempotence 71/71 via the promoted `format_source`
path. Design doc at
[`docs/formatter-v3-comment-map-design.md`](docs/formatter-v3-comment-map-design.md).

### REPL v2: readline / history + in-process exec

Two slices land together, giving ~100x speedup per turn
(subprocess fork + exec was 30-200ms on Windows; in-process
is ~1.2ms measured locally) plus persistent line editing /
history.

**Slice A (readline + history)**: `_init_readline` tries the
stdlib `readline` module first (POSIX), falls back to
`pyreadline3` (Windows), and silently skips when neither is
present. `~/.capa_repl_history` (exposed as `_HISTORY_FILE`
module constant) is read on startup, written on clean exit
(`.exit` / `.quit` / EOF), and capped at 1000 entries. All
history-I/O is wrapped in `try / except` so the REPL never
crashes on a read-only home dir.

**Slice B (in-process exec)**: `_try_compile_and_run` no
longer fork-execs `python` on the transpiled output. The new
`_exec_in_process` builds a fresh namespace per turn
(`__name__ = "__main__"` so the transpiler bootstrap fires),
captures stdout / stderr via `contextlib.redirect_stdout`,
and formats Python tracebacks into the error channel. POSIX
gets the same 10s hard timeout the subprocess path had, via
`signal.SIGALRM`. Windows loses the hard timeout (no
`SIGALRM` in stdlib); documented in the function docstring
and the module-level v2 notes. Ctrl-C still works.

Tests: 4 new (`TestReplReadline` x 2, `TestReplInProcessExec`
x 2) plus all 63 pre-v2 REPL tests stay green. Slice C
(persistent namespace + true incremental analyzer state
across turns) remains the bigger architectural piece, still
open.

### LSP v2 polish: documentHighlight + foldingRange + formatting

Three new LSP features alongside the existing v1 surface
(diagnostics, hover, definition, references, documentSymbol,
code actions, rename, completion, semantic tokens). All
three follow the established pattern: a pure `compute_*`
helper returning Capa-native types in a sibling module, then
a thin handler in [`capa/lsp/server.py`](capa/lsp/server.py)
translating LSP wire types both ways.

- `textDocument/documentHighlight` at
  [`capa/lsp/document_highlight.py`](capa/lsp/document_highlight.py)
  (54 LOC): thin adapter over `compute_references` so the
  editor highlights every in-file occurrence of the
  identifier under the cursor. v1 emits
  `DocumentHighlightKind.Text` uniformly; read / write
  distinction deferred.
- `textDocument/foldingRange` at
  [`capa/lsp/folding.py`](capa/lsp/folding.py) (153 LOC):
  AST walk emitting gutter +/- regions for `FunDecl`,
  `TypeStruct`, `TypeSum`, `ImplBlock`, `TraitDecl`,
  `IfStmt`, `ForStmt`, `WhileStmt`, `MatchExpr`, `LambdaExpr`
  bodies. Returns empty on parse failure so a mid-edit file
  does not confuse the editor.
- `textDocument/formatting` + `textDocument/rangeFormatting`
  at [`capa/lsp/formatting.py`](capa/lsp/formatting.py) (75
  LOC): hooks `capa.formatter.format_source` (the v3 AST
  round-trip pipeline) to the editor's Format Document /
  Format Selection commands. `rangeFormatting` falls back to
  whole-document since v3 is parse-then-emit. The formatter
  never raises (v1+v2 fallback) so the handlers never raise
  either.

Full circle: the Format Document command in VSCode now calls
the v3 AST round-trip pipeline this release ships.

Tests: 17 new (11 compute-level + 6 server-handler
integration via the existing `TestLspServerHandlersInProcess`
harness). Remaining v2 polish (signatureHelp, inlayHint,
workspace/symbol, codeLens, selectionRange) is deferred until
a real-user session surfaces a specific need.

### Compiler: reserve Ok/Err/Some/None as un-redeclarable variant names

Bug found by writing a real-world ~900-LOC downstream Capa
program ([nelsonduarte/capa_governance_pack](https://github.com/nelsonduarte/capa_governance_pack)).
A user-declared sum variant named
`Ok` / `Err` / `Some` / `None` used to silently overwrite the
built-in `Result` / `Option` constructor in the global scope,
with the declaration site's behaviour explicitly commented as
"Collisions with built-ins are silently ignored". Subsequent
calls like `return Ok(1)` from a `Result`-returning function
then resolved to the user's nullary variant and produced the
misleading error `variant 'Ok' takes no payload`.

Fix: hard-ban the four reserved names at declaration time in
[`capa/analyzer/_declarations.py`](capa/analyzer/_declarations.py)
with an actionable diagnostic that names the colliding
built-in and suggests common alternatives:

```
variant 'Ok' is reserved (collides with the built-in
Result::Ok constructor). Rename this variant. Common
alternatives: Compliant, Success, Hit, Ready.
```

The user's variant is dropped (no global-scope overwrite);
the built-in remains accessible at every call site. Scope:
the four universal `Result` / `Option` names only.
`JsonValue` variants (`JNull`, `JBool`, ...) are
domain-specific and not reserved.

5 regression tests in `TestReservedVariantNames`.

### Formatter + parser: three polish fixes from real-world stress test

Three smaller bugs surfaced by the same real-world ~900-LOC
program:

- **Formatter v3: trailing `//` on a `match` arm body no
  longer hoisted onto its own line.** `MatchArm` is an
  `A.Node` but not `A.Stmt` / `A.Item`, so the
  trailing-comment attacher walked past it to the enclosing
  `LetStmt`. `_attach_trailing` in
  [`capa/formatter/_comments.py`](capa/formatter/_comments.py)
  now short-circuits to a containing `MatchArm` whose
  `pos.line == c.start.line` and whose body is a single
  `Expr`; `_emit_match_arm` in `_emit_stmts.py` calls
  `_emit_trailing(arm)` on both single-line arm shapes.
  `Some(v) -> v  // tolerate` round-trips byte-exact.
- **Formatter v3: blank line preserved between a `// =====`
  section divider and the following `///` doc block.**
  `_emit_item` in `_emit_items.py` now inserts one blank
  line whenever the item has BOTH a non-empty leading-comment
  block AND a `///` doc string. Applies uniformly to
  `FunDecl`, `TypeStruct`, `TypeSum`, `TraitDecl`. The AST
  does not carry the doc's source-line so this is a
  deliberate canonical choice rather than position-preserving.
- **Parser: `doc comments are not valid on X` diagnostic now
  names the `///` syntax and suggests the `//` alternative.**
  Three sites in
  [`capa/parser/_items.py`](capa/parser/_items.py) (import,
  const, impl). New message: "doc comments (`///`) attach to
  declarations and are not valid on 'import'. Use a plain
  comment (`//`) for module-level headers, or move the doc
  above the next declaration."

3 regression tests
(`tests/test_pretty_printer.py::TestPrettyPrinterCommentPlacement`
x 2; `tests/test_parser.py::TestErrors::test_doc_comment_on_import_suggests_plain_comment`).

A fifth bug from the same stress test (`--cyclonedx` mangles
cross-module non-pub function names) remains open as the
design-heavier residual.

### Supply chain: SHA-256 verification + git URL allow-list

Two adjacent supply-chain holes from the 2026-05-25 audit
(item #5) closed together.

**Binary install scripts now verify SHA-256.**
[`deploy/install.sh`](deploy/install.sh) and
[`deploy/install.ps1`](deploy/install.ps1) used to `curl|bash`
the latest release binary into a user-PATH directory without
checking integrity, even though the release pipeline at
[`.github/workflows/release-binaries.yml`](.github/workflows/release-binaries.yml)
already publishes a `<asset>.sha256` sibling for every artefact.
The installers now fetch the `.sha256`, hash the downloaded
binary locally, and refuse to expose it on a mismatch (the
tampered file is removed before exit). Confirmed end-to-end
against `v1.0.0-rc.3`. Closes the man-in-the-middle / CDN-
cache-poisoning surface the previous flow ignored.

**`capa install` rejects dangerous git URLs at manifest-load
time.** [`capa.pkg._manifest._parse_dep`](capa/pkg/_manifest.py)
now calls `_validate_git_url` on every `[dependencies.X].git`
string. The validator allow-lists `https://`, `http://`,
`ssh://`, `git://`, `file://`, and the `git@host:path` SSH
shortcut; everything else is refused with a `ManifestError`
naming the rule and citing the CVE class.

Two specific shapes the validator blocks:
- ``ext::sh -c <cmd>``-style URLs that abuse the ``ext::`` git
  transport into an RCE primitive (CVE-2017-1000117 family).
- URLs starting with ``-``, which ``git clone`` would parse as
  command-line options (``-uupload-pack=<cmd>``, ``--exec=...``).
- The SSH-shortcut variant where the path segment after ``:``
  starts with ``-`` (option injection on the remote side).

Coverage: 11 new tests in `TestGitUrlAllowList`
([`tests/test_pkg.py`](tests/test_pkg.py)), six asserting the
allowed transports parse cleanly and five asserting each
attack shape is rejected with a specific error string. Suite
1364 -> 1375.

### Tests: Python<->Wasm output parity harness

The README's claim that the Wasm backend produces output
bit-identical to the Python reference path had no in-tree
verification: every Wasm execution test in
[`tests/test_ir_wasm.py`](tests/test_ir_wasm.py) compared the
Wasm output to a hand-rolled expected string, never to the same
program's Python output. Audit 2026-05-25 (item #4) recommended
a cross-backend parity harness; without it the claim has no
evidence.

New [`tests/test_ir_wasm_parity.py`](tests/test_ir_wasm_parity.py)
runs six parity-clean examples from
[`examples/wasm/`](examples/wasm/) -- `hello`, `fizzbuzz`,
`shape_area`, `strings`, `word_count`, `closures` -- through both
backends in-process and asserts byte-equal stdout. All six pass:
the parity claim now has six independent witnesses spanning
arithmetic, control flow, sum types, pattern matching, strings,
maps, and closures with HOF (`map` / `filter` / `fold`).

A seventh test asserts every `.capa` file under `examples/wasm/`
is either in the parity list or in a documented-excluded dict
with a one-line rationale. Forces any future example to either
join parity coverage or declare why it can't.

Three examples are deliberately excluded:
- `clock_demo.capa`: `Clock.now_secs` / `now_monotonic` are
  time-dependent.
- `env_demo.capa`, `fs_demo.capa`: depend on host process state
  / real filesystem; need fixtures both backends agree on.

(`json_demo.capa` was previously excluded for a Float-printing
divergence where `$ftoa` truncated at 6 decimals; that gap is
now closed - `$ftoa` is byte-exact with Python's `repr` via
Grisu3 + a Dragon4 fallback - and `json_demo.capa` is a passing
parity case.)

Suite 1357 -> 1364. The parity tests skip cleanly on machines
without `wasm-tools` + `wasmtime-py`; CI does not currently
install either, so they exercise on dev machines only (same
posture as the existing Wasm-execution tests).

### Wasm CM: strip phantom `capa:host/json` from the WIT

The `parse_json` / `to_json` free functions used to route through
a synthetic `Json` capability with canonical-ABI host imports.
They now compile to plain `call $__capa_parse_json` /
`call $__capa_to_json` against the bundled Capa-source parser
injected by [`capa.ir._builtin_json`](capa/ir/_builtin_json.py),
so no host bridge is needed and the Wasm output imports nothing
under `capa:host/json`. The Wasm-side discovery already excluded
`Json` (comment at
[`capa/ir/_emit_wasm/_discovery.py:358`](capa/ir/_emit_wasm/_discovery.py#L358)),
but the WIT emitter still picked the calls up and advertised an
`interface json` with an `import json` in the world, leaving the
two views inconsistent. Audit 2026-05-25 (item #3).

Fix: drop the `parse_json` / `to_json` detection from
`collect_used_capabilities`, drop `Json` from
`_KNOWN_CAPABILITIES`, drop the `(Json, ...)` rows from both
`_WIT_SIGNATURES` and the Wasm side's `_CANONICAL_INDIRECT_RETURN`.
After the fix the same source compiled with `capa --wit` and
`capa --wasm` agrees on the used-cap set: only the actual host
capabilities (`stdio`, `clock`, `env`, `fs`) appear, and
`--component --run` for JSON-using programs no longer asks for
a host import nothing provides.

Coverage: three new tests in `TestWitGeneration`
([`tests/test_ir_wasm.py`](tests/test_ir_wasm.py)). Two assert
the WIT for a `parse_json` / `to_json` program does not mention
`interface json` or `import json`; the third runs both the WIT
and Wasm discovery passes over the same module and asserts the
two used-cap sets are equal -- a cross-side parity test the
audit explicitly recommended. Suite 1354 -> 1357.

### Soundness: close two capability-discipline holes surfaced by the 2026-05-25 audit

Two adjacent gaps were both letting cap-bearing struct fields
escape the flow discipline:

A. **Capability fields could be re-bound.** `mailer.net =
   other_net` (where `mailer: SmtpMailer` and `SmtpMailer`
   carries `net: Net` because it implements a user-defined
   capability) passed silently. The mutability check in
   [`_check_assign`](capa/analyzer/_statements.py) only fired on
   bare `Ident` targets; `FieldAccess` / `Index` targets skipped
   it. Result: the cap-bearing-struct construction-time check
   could be laundered by a single re-assignment.

   Fix: `_check_assign` now refuses to assign to any
   `FieldAccess` / `Index` target whose declared type contains a
   capability. Construction-time binding (struct literal) and
   function-parameter binding remain the only legal sites.

B. **Aliasing via FieldAccess paths was missed.**
   `take_two(mailer.net, mailer.net)` passed because
   `_is_capability_ident` only canonicalised bare `Ident`
   expressions; two `FieldAccess` nodes were dict-keyed as
   distinct entries even when they referenced the same path.

   Fix: `_is_capability_ident` now returns a dotted-path string
   for Ident-rooted `FieldAccess` chains whose final type is a
   capability (`box.cap`, `outer.inner.cap`). The aliasing check
   compares the canonical paths, so same-path references collide
   correctly and different-owner references stay distinct.
   `_check_call` and `_check_method_call` reorder their work so
   args / receiver are typed before the aliasing check runs
   (the FieldAccess path lookup needs the cached type).

Both fixes ship with five new tests in
[`tests/test_analyzer.py`](tests/test_analyzer.py)
(`TestCapabilityFieldDiscipline`): the two rejection paths, a
user-cap variant of the rejection, plus two sanity tests
confirming that non-capability fields and different-owner paths
still pass.

**Known gap deferred to a later slice**: hole C from the same
audit (`fun store<T>(box: Box<T>, x: T)` instantiated with
`T = Stdio` does not re-check the resulting `Box<Stdio>` at the
call site) needs a different fix: call-site re-validation of
generic instantiation against the structural rule. Tracked in
[`TODO.md`](TODO.md).

## [1.0.0-rc.3], 2026-05-25

### Language: opt-in Display protocol via `to_string()`

`${value}` interpolation of a user struct now routes through
the struct's `fun to_string(self) -> String` method when
declared in an impl block, on both the `--python` and `--wasm`
backends. Closes the long-standing "Wasm FormatStr on arbitrary
user struct types" P1 item without committing the language to
an auto-derived default format.

```capa
type Point { x: Int, y: Int }
impl Point
    fun to_string(self) -> String
        return "Point<${self.x}, ${self.y}>"

fun main(stdio: Stdio)
    let p = Point { x: 3, y: 4 }
    stdio.println("${p}")    // prints: Point<3, 4>
```

Structs that do not declare `to_string()` keep their
pre-existing behaviour:
- `--python` falls through to dataclass repr (unchanged).
- `--wasm` raises a `WasmEmissionError` with a message
  pointing the user at the protocol (`Either declare
  `fun to_string(self) -> String` in an impl block ..., or
  interpolate a specific field`).

Implementation:
- Wasm emitter's `_emit_format_part_stash` consults
  `_method_table[(ty_head, "to_string")]`; when present,
  emits `call $<MangledName>` and stashes the multi-value
  String return into the per-part `(ptr, len)` slot.
- Python transpiler's pre-pass collects every type whose
  impl block declares `fun to_string(self) -> String`; the
  f-string emitter wraps interpolated expressions of those
  types in `({expr}).to_string()` instead of leaving them
  as bare `{expr}`.

A formal `trait Display { fun to_string(self) -> String }`
could supersede the duck-typed method check in a later slice;
the current shape is minimal but already gives a single
authoritative rendering rule shared by both backends.

### Soundness fixes surfaced by Wasm match coverage pass

Two bugs surfaced while pushing
[`capa/ir/_emit_wasm/_match.py`](capa/ir/_emit_wasm/_match.py)
coverage from 43% to 86%, both caught by tests written
directly against the missing-line ranges from
`coverage report --show-missing`:

1. **Top-level IdentPat catch-all declared with wrong Wasm
   type.** A program like `match b ; other -> ...` (Bool
   scrutinee) or `match p ; whole -> ...` (tuple scrutinee)
   declared `$other` / `$whole` as the Unknown-default
   `i64`, then assigned an `i32` scrutinee into it, which
   the Wasm validator rejected. Root cause: the analyser's
   `_refine_pattern_binds` had cases for `TuplePat` and
   `VariantPat` but no top-level `IdentPat` branch, so the
   binder local stayed `Unknown`. Fix in
   [`capa/ir/_lower.py`](capa/ir/_lower.py): add the
   `IdentPat` case that propagates `scrut_ty` to the binder.

2. **`$str_eq` helper not imported for tuple-match arms
   with String literal sub-patterns.** A program like
   `match (s, n) ; ("yes", x) -> ...` emitted a `call
   $str_eq` into a module that never imported the helper;
   `wasm-tools parse` refused with `unknown func: failed
   to find name $str_eq`. Root cause: the discovery pass
   that decides which helpers to emit only checked for
   String-scrutinee matches, not tuple-match sub-patterns.
   Fix in
   [`capa/ir/_emit_wasm/_discovery.py`](capa/ir/_emit_wasm/_discovery.py):
   extend `_uses_map_ops` to walk Match arms' tuple
   patterns and trigger on String literal sub-patterns.

Both bugs were silent: nothing in the existing test suite
caught them. Regression coverage added in
`TestWasmMatchEmission` (`test_bool_match_with_pat_ident_catch_all`,
`test_tuple_match_catch_all_pat_ident_whole`,
`test_tuple_match_with_literal_string_sub_pattern`).

### CIR: match-arm guards with non-trivial prelude

The IR lowerer no longer rejects guard expressions whose ANF
form requires intermediate locals. `MatchArm` gains a
`guard_setup: list[Instr]` field that carries the prelude;
the Python emitter inlines it back into the case clause by
walking the setup and building a `dst -> python_expr`
substitution map, so a guard like `not t.done` renders as
`case High() if (not t.done):` (identical to the legacy
transpiler's output). Inlineable shapes: `FieldAccess`,
`Index`, `UnaryOp`, `BinOp`. Non-inlineable shapes (Call,
MethodCall, ...) raise `UnsupportedInIR` from the emitter,
which the CLI's `--ir` path catches and falls back to the
legacy direct-to-Python transpiler exactly as before.

Effect on CIR coverage of the example suite: 45/46 → 46/46.
The remaining gap was `examples/tasks.capa`, which uses a
`High if not t.done` guard. Wasm emitter still rejects all
guards (it would need an arm-level fall-through block
restructure); see `capa/ir/_emit_wasm/_match.py`.

### Soundness fix: user-defined-cap aliasing

The non-aliasing rule ("each call uses each capability at most
once") only fired on built-in caps (`CAPABILITY_NAMES`). User-
defined caps slipped through: `dispatch(my_llm, my_llm)` passed
`--check`, violating the single-flow property the paper claims
the discipline guarantees. Surfaced by the slice-6 fuzz panel
attempt `cat_llm_dispatch_escape / llm_aliased_dispatch`.

Fix: [`_is_capability_ident`](capa/analyzer/_discipline.py)
now recognises both built-in caps and user-defined ones (it
walks the global scope to see if the type name resolves to a
`SymbolKind.CAPABILITY` symbol). Regression covered by
`test_user_defined_cap_aliasing_rejected` in
[tests/test_analyzer.py](tests/test_analyzer.py).

This is the second soundness escape surfaced during the
empirical-study build-out (after the capability-forge fix
in the preceding section). Both were silent regressions in
the legacy `--python` backend that `--wasm` was incidentally
protected against.

### Soundness fix: capability-forge in --python mode

The analyzer now rejects any call where the callee resolves to a
capability symbol (built-in or user-defined). Before this fix, a
function declared `main(stdio: Stdio)` could write `let fs = Fs()`
and obtain unrestricted filesystem authority through the legacy
--python backend: the transpiler emitted a literal `Fs()`
instantiation and the runtime `Fs.__init__` defaults to an
unrestricted instance. The bug was incidentally absent in --wasm
(the cap constructor produced TyUnknown and the Wasm emitter
refused to dispatch methods on it, surfacing as an emission
error rather than a leak), so the leak only affected --python.

Surfaced 2026-05-24 by the empirical-study fuzz harness on the
first attack program written for slice 1; this is exactly the
class of negative test §5.5 of the paper is meant to provide.
Fix: `_check_call` in [capa/analyzer/_dispatch.py](capa/analyzer/_dispatch.py)
emits `capability 'X' cannot be constructed at a call site;
capabilities only flow through function parameters ...` and
returns `TyName(X)` so downstream method calls do not avalanche
with secondary "unknown receiver" diagnostics. Coverage added
in `TestCapabilityForgeRejected` in
[tests/test_analyzer.py](tests/test_analyzer.py): 7 new tests
covering every built-in cap, user-defined caps, in-helper and
in-main forge attempts, plus the positive case that
capability-as-param is still accepted.

### Milestone: every downstream demo runs end-to-end under `--wasm --run`

Cross-demo smoke on 2026-05-27. All four downstream consumers
of the seed libraries now compile to Wasm CM and execute
through `WasmHost` with output matching the Python `--run`
path:

- **`capa_showcase`** (JSONL log processor, 5 files, JsonValue
  parse + serialise, lambdas, generics, attenuated cap):
  ✓ green, byte-identical to Python output
- **`policy-eval`** (recursive-sum policy tree, custom CLI):
  ✓ green, 7 findings rendered, gate fails as expected
- **`audit-trail-reporter`** (CSV + JSON + alerts, multi-file
  output, capa_datetime + capa_log + capa_cli):
  ✓ green, 15 flagged transactions, all 4 output files
  written
- **`sbom-watch`** (SBOM risk grading, license + CVE +
  banned-package rules): ✓ green, 7 findings, gate logic
  matches Python

The original public-pitch claim ("Capa has a Wasm CM
backend that runs the demos") is now demonstrably true for
every demo, not just the toy ones. Zero new compiler gaps
surfaced -- the 8 fixes that landed for the `capa_showcase`
assessment over the past three days (commits `80ffe8f`,
`9de9d3c`, `3e31c41`, `49367b2`, `8b47d78`, `4d7a6fd`,
`01bb305`, `bdaa869`) cover every non-trivial code path
the other three demos hit.

### Wasm: `${io}` interpolation for `IoError` + closure-type monomorphiser unification

Two fixes that together close the last `capa_showcase` blocker
under `--wasm --run`. The showcase now executes end-to-end with
byte-identical output to the Python path.

**IoError in FormatStr.** `_emit_format_part_stash` gains an
`IoError` case that mirrors Python's `__str__`: load the
`message` field (a String at offset 0 of the 16-byte IoError
record, per `_IOERROR_LAYOUT`) and push (ptr, len) into the
format buffer. The `cause` field is intentionally skipped --
Python's `__str__` also drops it when empty, and the common
pattern is just `${e}` for a one-line diagnostic. General
struct-to-string codegen for arbitrary user types is a
separate (open) item; the error message at the unsupported
branch now points users at `${e.message}` as the near-term
workaround for non-IoError structs.

**`Fun(T) -> R` unification in the monomorphiser.** The
string-based `_parse_ty` in `capa/ir/_monomorphise.py` had no
case for closure types, so it treated `Fun(T) -> String` as
an opaque atom. A generic HOF whose param list included a
closure (the showcase's
`count_by<T>(items: List<T>, key: Fun(T) -> String)`) failed
unification at every call site and was never monomorphised,
leaving an undefined `$count_by` call in the WAT. Fix:
decompose `Fun(P, ...) -> R` into a pseudo-head `(fun)` with
the params + return as args so the existing recursive unifier
infers `T=LogEntry` etc. The closure type now structurally
participates in inference like tuples and parameterised types.

Tests: `TestWasmIoErrorFormatStr` (1 case, real `fs.read` on
a missing path + `${e}` interpolation) and
`TestWasmGenericMonomorphisationFunType` (1 case, a generic
`count_matching<T>` with a `Fun(T) -> Bool` predicate).

Suite: 1266 → 1268 tests, 4 platform-skips. The
`capa_showcase` (the 5-file JSONL log processor we built as
the assessment yardstick) is now bit-for-bit Python-equivalent
under `--wasm --run` -- a first for any non-trivial Capa
program.

### Lowerer: tag `cap_used` on built-in cap method calls reached via field access

`_lower_method_call` set `MethodCall.cap_used` only when the
receiver was a capability parameter (e.g.
`stdio.println(...)`). User-defined cap impls that reach a
built-in cap through a struct field (e.g.
`self.fs.read(...)` inside `impl ReadOnlyFs for
ReadOnlyFsImpl { fs: Fs }`) left `cap_used = None`, so the
Wasm backend's canonical-ABI detector in `_collect_locals`
(the `has_indirect_cap_call` gate) missed the call and
`$_ret_area` went undeclared. wasm-tools then rejected the
WAT with `unknown local: failed to find name $_ret_area`.

Fix: extend the lowerer's tagging logic to also fire when
`receiver.ty`'s head resolves to a built-in cap, regardless
of how the receiver was bound. Now every method call on a
built-in cap (parameter, field access, let-binding, etc.)
carries the cap name through to the IR -- the manifest
builder, capability discipline checks, and Wasm
indirect-return area allocation all see it consistently.

`TestWasmCapCallViaFieldAccess` (1 case) pins the
`impl method -> self.fs.read(...) -> match Result` pattern
that capa_showcase's `ReadOnlyFs` wrapper exercises.

Suite: 1265 → 1266 tests, 4 platform-skips.

The capa_showcase smoke advances past this gap and surfaces
the next documented P1 (FormatStr on user struct types,
e.g. `${e}` where `e: IoError`).

### Wasm: top-level String const support end-to-end

`pub const SCHEMA: String = "1.0"` referenced from any
function body used to fail the Wasm backend with one of three
errors depending on the use shape:

- ``cannot push string Value of kind 'global' as (ptr, len)``
  (interpolation site, ``"${SCHEMA}"``)
- ``cannot bind String dst ... from value Value(kind='global',
  ...)`` (let-binding, ``let g = SCHEMA``)
- ``String arg of kind 'global' not supported`` (passing the
  const as a function argument)

Root cause was two-fold: the three emit helpers above had no
``global`` Value-kind case, and even if they had, the
constant's UTF-8 bytes were never interned in the data segment
(discovery walks function bodies only, never ConstDecl) so
the lookup would push offset=0 -- the data segment's start,
NUL bytes interpolated where the user expects the constant's
text.

Two-part fix in `capa/ir/_emit_wasm/`:

1. `__init__.py`: pre-intern every String-typed top-level
   constant at module-emit init, alongside the existing
   `"true"` / `"false"` Bool-FormatStr pre-intern. Collapsed
   the hand-inlined String-arg branch in `_emit_user_call`
   into the shared helper (was the only site that diverged).
2. `_strings.py`: add `global` cases in
   `_push_string_value_as_ptr_len` (recurses into the const's
   stored `lit_str` Value) and `_emit_string_assign` (same
   recursion shape into the let-binding path). Both consult
   `_const_values` which the init pass populates.

`TestWasmGlobalStringConst` (3 cases): interpolation, let-bound,
passed-as-arg. All three execute end-to-end under `--wasm
--run` with the expected string content (no NULs).

Suite: 1262 → 1265 tests, 4 platform-skips.

### Analyzer: propagate return type of user-capability method calls

`_check_method_call` used to gate the cap-method-table consult on
`recv_ty.name in CAPABILITY_NAMES` -- only built-in caps (Stdio,
Fs, Env, Clock, Random, Net, Proc, Db, Unsafe) got their method
return types. User-defined caps (e.g.
`capability Logger { fun info(self, msg: String) -> Unit }`) fell
through to `TyUnknown`, which propagated as `?` through the
lowerer and broke the Wasm backend on any user-cap method call
result. The Python `--run` path tolerated it (duck typing); the
Wasm `--wasm --run` path crashed at layout time or downstream
during pattern matching with a generic `TryUnwrap on '?'` error.

Same root pattern as the Fun-typed-callee fix from 2026-05-25.
Two-part fix:

1. `capa/analyzer/_declarations.py`: extend the
   `TraitDecl`-handling second pass to populate `sym.methods`
   with typed `FUNCTION` Symbols, parallel to how the impl-block
   handler populates target struct/sum types' method tables. The
   method types come from the existing `_method_type_from_decl`
   helper, which already handles `Self` resolution via
   `self.self_type = TyName("Self")`.
2. `capa/analyzer/_dispatch.py::_check_method_call`: broaden the
   capability-routing check from `recv_ty.name in
   CAPABILITY_NAMES` to any `cap_sym.kind ==
   SymbolKind.CAPABILITY`. Built-in and user-defined caps now
   share the same dispatch path; the only difference is who
   populates their method table.

Bonus fix in the same commit: `_type_name` in the lowerer
(`capa/ir/_lower.py`) gains a `TupleType` AST case. The fall-
through to `repr(te)` was stuffing AST node text into a `ty`
string for bare tuple types (`fun f(p: (String, Int))`). Wrapped
forms like `List<(String, Int)>` worked by accident because
`_wasm_type`'s `head in ("List", ...)` branch short-circuits
without inspecting the args; the showcase surfaced this when its
`top_k_insert` helper used a bare tuple param.

`TestWasmUserCapMethodDispatch` (2 cases) and
`TestWasmTupleParamTypes` (1 case) pin both fixes end-to-end
under `--wasm --run`. Suite: 1259 → 1262 tests, 4 platform-skips.

Two more pre-existing Wasm gaps were surfaced (and filed as
P1 follow-ups in TODO.md) when the showcase advanced past
these fixes: the canonical-ABI `_ret_area` local isn't
declared for a user-cap method that returns Result and is
matched in scrutinee position; and the Wasm emitter's
`_push_string_value_as_ptr_len` doesn't handle the `global`
Value kind for top-level `pub const STRING_NAME = "..."`.
Both are smaller than the analyzer fix; deferred to keep
this round focused.

### Wasm: multi-value lowering for String in lambda params + returns

Closures with `String` parameters and/or `String` return types
used to fail closure registration with `Capa type 'String' has
no Wasm encoding yet`. The call-site emitter
(`_emit_closure_call`) and lifted-lambda body emitter
(`_emit_lifted_lambda`) had ALREADY been wired for the
(ptr, len) convention; what was missing was the signature
plumbing in `_register_lambda` and `_fun_type_to_sig_key`.

Three surgical edits in `capa/ir/_emit_wasm/_closures.py`:

1. `_register_lambda`: when a param `ty == "String"`, append two
   `i32`s to `param_wasm_tys`. When `return_type == "String"`,
   use `"i32 i32"` as `result_ty` (multi-value Wasm result).
2. `_fun_type_to_sig_key`: same treatment for the return-type
   side so the sig_key the call-site builds matches what
   `_register_lambda` registered.
3. `_emit_lifted_lambda`: move the String check before
   `_wasm_type(p.ty)` (which raises on String) so the
   `${name}_ptr` / `${name}_len` param convention is honoured.

Plus two discovery walkers in
`capa/ir/_emit_wasm/_discovery.py` that needed `MakeLambda`
recursion: `_uses_format_str` and `_uses_float_format`. A
format-string inside a closure body now correctly triggers
`$itoa` / `$ftoa` helper emission. Fixed the latent
`MakeLambda`/`MakeList`/`MakeSet`/`Function` imports the
discovery module had been referencing through dead branches
since they were added.

`TestWasmClosureStringTypes` (2 cases):
- `test_lambda_with_string_param`: count items with a
  closure that takes a `String` and returns a `Bool`
- `test_lambda_returning_string`: map a list of `Int`s
  through a closure that returns `String` via interpolation
  ("n=${n}")

Closes the second of the three Wasm gaps surfaced by the
`capa_showcase` assessment. The last remaining gap (analyzer
not propagating user-cap method return types, surfaced as
`TryUnwrap on type '?'` on `fs.read(path)?` where `fs` is a
user-defined capability) stays open as the next P1
follow-up. Same root pattern as the Fun-typed-callee fix
that landed yesterday.

Suite: 1258 → 1259 tests, 4 platform-skips. The
pre-existing `test_lambda_with_string_param_gives_clear_error`
is removed (gap closed); its actionable-error placeholder
class stays in place for future surfaces.

### Wasm: generic-function monomorphisation

`fun first<T>(items: List<T>) -> Option<T>` (and any other
generic free function) used to crash the Wasm backend at
layout time: the IR carried `T` as a string, and
`_wasm_type('T')` had no encoding. As of 2026-05-25 we
swallowed the failure into an actionable error directing
users to `capa --run`; this commit goes further and actually
runs them under `--wasm`.

New IR pass at [`capa/ir/_monomorphise.py`](capa/ir/_monomorphise.py)
walks the lowered module, identifies generic free functions
(`type_params != []`), walks every call into them, infers
each call's type-parameter substitution by string-unifying
the call's arg types against the callee's generic param
types, and synthesises a specialised clone per unique
substitution (mangled name like `first__Int` / `first__String`).
Call sites are rewritten to target the mangled name; original
generic Functions are removed before emit. Plumbed into
`compile_wat` only (Python `--run` doesn't need it; duck
typing handles substitution at runtime). Iterates to a fixed
point so generic-calls-generic chains fully specialise.

Scope (v1):
- Free functions only. Generic methods (`impl<T>`), generic
  struct types, and generic capability methods still hit the
  actionable "no Wasm encoding" error.
- String-based unification: handles `T` directly, `List<T>`,
  `Map<K, V>`, `(T, U)`, `Option<T>`, `Result<T, E>`. Nested
  arities work; unbound type parameters abort the rewrite.
- No partial application; every type parameter must be
  resolved from the concrete argument types.

`TestWasmGenericMonomorphisation` (3 cases):
- `test_generic_first_with_int_arg`: `first<T>` instantiated
  with `Int`
- `test_generic_first_with_string_arg`: same with `String`
- `test_same_generic_function_called_with_two_types`: dedupe
  by substitution, not by source name

Closes one of the three Wasm gaps surfaced by the
`capa_showcase` assessment. The remaining gap (lambda
multi-value lowering for non-scalar param / return types)
stays open in TODO.md as a P1 follow-up.

Suite: 1256 → 1258 tests, 4 platform-skips. The pre-existing
`test_generic_user_function_gives_clear_error` (which pinned
the actionable error) is removed; its slot is the new
success-case class.

### Analyzer: propagate return type through Fun-typed callees

`capa.analyzer._dispatch._check_call` used to return `TyUnknown`
when the callee was a parameter / local / constant typed as
`Fun(P...) -> R`. The code carried a comment admitting "Leaving
the TyUnknown return matches the pre-existing behaviour for
these call shapes." This was load-bearing: the unknown type
propagated through the lowerer as `?`, which the Wasm emitter
mapped to an `i64` fallback. When the actual closure returned
`Bool` (`i32` at Wasm level), the `local.set $_ir_t1` after the
`call_indirect` failed the wasm-validator with `i64 vs i32 type
mismatch`. The third Wasm gap surfaced by `capa_showcase`.

The fix: when the callee resolves to a `TyFun`-typed sym,
`_check_call` now returns `fun_ty.ret` directly (and raises
an arity-mismatch error if the call arity disagrees with the
function signature). The existing closures tests didn't catch
this because their lambdas all returned `Int` (which by
coincidence agreed with the i64 fallback).

`TestWasmClosures::test_call_through_fun_typed_param_returning_bool`
is the regression guard: an `apply_pred` style helper takes
a `Fun(Int) -> Bool` predicate, the lambda body counts even
numbers, runs end-to-end under `--wasm`, asserts `2` for
`[1, 2, 3, 4, 5]`.

Suite: 1255 → 1256 tests, 4 platform-skips. Case A of the
showcase Wasm-gap assessment is now closed end-to-end; the
remaining two gaps (generic function monomorphisation +
multi-value lowering for non-scalar lambda params/returns)
stay open in TODO.md as P1 items.

### Wasm: actionable errors for generic functions + non-scalar lambda params

Surfaced by the `capa_showcase` assessment on 2026-05-25.
Three pre-existing Wasm backend gaps used to manifest as
confusing tracebacks; this round replaces them with explicit
`WasmEmissionError` messages that name the user-level
construct and the workaround.

1. **Generic user functions**: `_collect_locals` in
   `capa/ir/_emit_wasm/_locals.py` previously caught the
   `WasmEmissionError` raised by `_wasm_type` on an unresolved
   type parameter and silently fell back to `i64`, which made
   downstream emit produce wasm that the validator rejected at
   runtime with a generic "i32 vs i64 type mismatch at offset
   N". On top of that, the `except` clause referenced
   `WasmEmissionError` without importing it, so the catch
   raised `NameError` instead of running. Now: the import is
   added and the catch re-raises with an actionable message
   pointing at the generic function and suggesting either the
   Python backend (`capa --run`) or manual specialisation.

2. **Lambda params / return types with non-scalar shape**:
   `_register_lambda` in `capa/ir/_emit_wasm/_closures.py`
   called `_wasm_type(p.ty)` for each lambda param, which
   raises on `String` / `List<T>` / `Map<K,V>` / user structs
   because those need multi-value lowering (the closure
   signature emits one Wasm type per param, but a String is a
   (ptr, len) pair). Same gap on the lambda's return type.
   Now: both raise with a message naming the lambda param /
   return + the actual unsupported type + the workaround
   (Python backend, or refactor into a named function).

Test coverage: `TestWasmActionableErrors` (2 cases) pins the
new error shape: one for the generic + Option<T> case, one
for the lambda-over-String case (the exact construct the
showcase used).

Underlying feature gaps (full monomorphisation of generic
user functions + multi-value lowering for lambda params)
remain open as P1 follow-ups; the work is multi-day. Until
they ship, the Wasm backend now fails LOUDLY and CORRECTLY
on the unsupported shapes rather than producing invalid wasm.

Suite: 1253 → 1255 tests, 4 platform-skips.

### Tests: extended loader coverage (60% -> 65%)

Continues the 2026-05-25 coverage-review pass. Seven new
tests on `tests/test_loader.py`:

  - `TestQualifiedCallShadowing` extended with five cases
    covering the AST-binder shapes the earlier round's tests
    did not exercise:
    * `test_tuple_pattern_shadow_in_let`: `let (mylib, _n) = pair`
    * `test_struct_pattern_shorthand_shadow_in_let`: `let Foo { x } = obj`
    * `test_for_pattern_tuple_shadow`: destructuring in for-loop
    * `test_lambda_param_shadow`: `fun (mylib) => mylib.method(x)`
    * `test_if_elif_else_shadow`: shadow introduced inside a
      nested else branch
  - New `TestLoaderErrorFormat` class with two cases for the
    `LoaderError.format` rendering (with positional anchor and
    without; both branches of the conditional).

These exercise the `_names_bound_by_pattern` TuplePat /
StructPat-shorthand branches, the `_walk_*_for_binders`
LambdaExpr / IfStmt-elif paths, and the `LoaderError`
diagnostic format. Suite: 1246 → 1253 tests.

### Tests: end-to-end coverage for `WasmComponentHost`

`capa/runtime/_wasm_component_host.py` (the Component Model
runtime that drives `--wasm --component --run` artifacts) had
0% coverage until 2026-05-25: nothing in the test suite invoked
it. The CLI was its only client and we never exercised that
path under `unittest`. Lifting that to 74% with four
end-to-end smoke tests (`TestWasmComponentHost` in
`tests/test_ir_wasm.py`):

  - `test_hello_under_component_host`: Stdio.println basic path
  - `test_stdio_with_string_interpolation`: string interp lift
  - `test_env_args_round_trip`: Env.args() argv lifting (3 args)
  - `test_clock_now_secs_returns_positive_float`: Clock bridge

Each compiles a small Capa source to a core wasm, wraps it as
a Component Model component via `wasm-tools component embed/new`
(reusing `capa.cli._wrap_as_component`), instantiates
`WasmComponentHost`, and asserts on captured stdout. Skipped
gracefully when `wasm-tools` or `wasmtime-py` are missing
(same guard as the existing Wasm tests).

Total suite: 1242 → 1246 tests (+4), 4 platform-skips.

### Loader: scope-aware qualified-call rewrite

`capa.loader._rewrite_qualified_calls` (the post-link pass that
turns `mod.fn(args)` into a plain `fn(args)` once the merged
module already holds `fn` at the top level) used to be
scope-blind. If a function had a local binding whose name
happened to match an imported module alias, the rewriter still
matched and dropped the receiver. Concrete bite: in
`capa_agent_demo` v0.1.0,

```capa
import attenuated   // transitively `import capa_http.http`

pub fun tool_get_url(http: GetOnlyHttp, url: String) -> String
    match http.get(url)        // ← silently rewritten to get(url)
        Ok(body) -> return body
        ...
```

was lowered into `match get(url):` calling
`capa_http.http::get` (a free function returning `Request`),
ignoring the `http: GetOnlyHttp` parameter entirely. The
analyzer's `--check` accepted the resulting AST since it
type-checked as a different (free-function) call; only the
runtime crashed. The demo worked around it by renaming the
wrapper method from `.get` to `.fetch`.

The fix: before walking each FunDecl / impl method body, the
rewriter now collects every name introduced by a local
binding (parameters, `let` / `var` / `for` patterns, match
arm pattern binders, `LambdaExpr` parameters) into a
function-level shadow set. The `MethodCall(Ident(name), ...)`
rewrite skips when `name` is in that set. Scoping is
function-level rather than block-level, slightly
over-conservative (a `let http = ...` on line 10 shadows the
alias for the whole function, including line 5) but SOUND:
the loader never silently drops a method receiver in favour
of a free-function call.

Test coverage: 5 new cases in
`tests/test_loader.py::TestQualifiedCallShadowing` (parameter
shadow, `let` shadow, `for` shadow, match-pattern shadow, and
a negative regression-control where no shadow exists and the
rewrite still fires correctly).

### `capa_http` v0.1.3 + `capa_agent_demo` workaround removed

[`capa_http` v0.1.3](https://github.com/nelsonduarte/capa_http/releases/tag/v0.1.3)
fixes the `urllib_client.capa::make_urllib_client` factory to
probe both `./vendor/capa_http/` (the package-manager path)
and `./libraries/capa_http/` (the legacy hand-vendoring path)
for `urllib_helper.py`, instead of only the latter. Surfaced
by `capa_agent_demo` v0.1.0's smoke run on 2026-05-23, which
had to inject the vendor path in its own `main` as a six-line
workaround.

`capa_agent_demo` updated to consume `capa_http` v0.1.3
([commit `1cf666f`](https://github.com/nelsonduarte/capa_agent_demo/commit/1cf666f)),
removing the workaround so `main` becomes the clean wiring
point the README claims. Runtime-verified end-to-end on
2026-05-25: `make_urllib_client` resolves without manipulation,
the LLM request/response loop runs through.

Both releases shipped with the full supply-chain stack
(signed tag + SLSA L2 attestation in Sigstore Rekor); the
demo's `capa install` exercises all three layers (lockfile
SHA + GPG verify-tag + `gh attestation verify`) on the new pin.

### Website extracted to its own repo

The marketing + learning-pages site (`docs/index.html`,
`docs/learn/`, `docs/style.css`, the rest of the HTML assets)
moves out of this repo and into
[nelsonduarte/capa-language-website](https://github.com/nelsonduarte/capa-language-website).
`capa-language.com` now serves from there via GitHub Pages.

Extraction was via `git filter-repo` so the per-file history
is preserved: the earliest commits in the new repo are the
original website-only commits from this repo. No git-blame
loss for anyone tracing a layout choice or copy edit.

What stays here, in `docs/`: every Markdown document the
website links to via absolute github.com URLs (semantics,
packages, regulatory, paper draft, CVE case studies, etc.),
plus the templates folder. The split is "the rendered site
vs. the source documents that ship with the language."

README's Documentation map gets a small rewrite to point at
`capa-language.com` for the HTML pages and keep the `docs/*.md`
table for the in-repo Markdown. CONTRIBUTING, STABILITY, and
the GitHub issue / PR templates pick up the new URLs.

### LLM tool-use demo at `capa_agent_demo`

A four-tool agent harness in ~400 lines of Capa, live-verified
against the Anthropic Messages API on 2026-05-23. Lives at
[nelsonduarte/capa_agent_demo](https://github.com/nelsonduarte/capa_agent_demo)
v0.1.0 with the full three-layer supply-chain stack (signed
tag + SLSA L2 attestation in Sigstore Rekor).

The pitch: every other LLM agent framework (LangChain, OpenAI
function-calling, MCP servers) ships tools as arbitrary
functions with no permission system. The blast radius is
implicit. Capa flips this: each tool's signature names its
capabilities, the agent loop's signature names the union, and
the compiler refuses any call to an authority outside the
declared bound. The manifest is the audit contract:

```
tool_read_file:    [ReadOnlyFs]
tool_list_dir:     [ReadOnlyFs]
tool_get_url:      [GetOnlyHttp]
tool_current_time: [Clock]
dispatch_tool:     [Clock, GetOnlyHttp, ReadOnlyFs]
run_agent_loop:    [Clock, GetOnlyHttp, LlmClient, Logger,
                    ReadOnlyFs, Stdio]
main:              [Clock, Env, Fs, Stdio, Unsafe]
```

Two attenuated wrappers (`ReadOnlyFsImpl { fs: Fs }`,
`GetOnlyHttpImpl { http: Http, allowed_hosts: List<String> }`)
show that attenuation is a cap-bearing-struct coding pattern,
not a language feature. The demo is also the fourth downstream
consumer of the seed libraries (`capa_http`, `capa_log`) at
v0.1.2, exercising the full lockfile + GPG + SLSA install
path.

The smoke run surfaced two real bugs filed as P1 follow-ups
in TODO.md: a `capa_http` v0.1.2 sys.path hard-coding that
breaks against the package-manager vendor path, and a codegen
method-name shadow when a user-defined-capability method has
the same name as an imported free function. Both have
documented workarounds in the demo.

### Package manager: implicit SLSA L2 verification on install

`capa install` now also verifies the SLSA L2 build-provenance
attestation against Sigstore Rekor when a dep declares
`verify_key` and is hosted on GitHub. The verification is
implicit: no new manifest field, no opt-in flag. If you trust
the publisher with `verify_key` and the repo is on GitHub, we
also check the build came through the attested CI path.

```toml
[dependencies.capa_log]
git = "https://github.com/nelsonduarte/capa_log"
tag = "v0.1.2"
verify_key = "6C1D222D491FB88031E041A536CFB426101AA24B"
# capa install now refuses on:
#   1. SHA mismatch vs capa.lock                       (existing)
#   2. GPG tag signature invalid / wrong fingerprint   (existing)
#   3. SLSA attestation in Rekor invalid or tampered   (new)
```

The verifier shells out to `gh attestation verify` (no new
runtime dependency on `capa-language`; `gh` is already the
canonical Sigstore client). Graceful skip (no warning, install
continues) when:

- the repo is not GitHub-hosted (no Sigstore pipeline today);
- the pin is a `rev` (releases live on tags);
- `gh` is not on the consumer's PATH;
- the GitHub release ships no source-tarball asset (publisher
  hasn't adopted attesting yet);
- the network is unreachable.

The skip-on-missing semantics are deliberate: SLSA augments
the GPG layer rather than replacing it, so publishers
pre-attestation keep working. A future `verify_provenance =
"required"` field can flip every skip path to fail-closed for
strict consumers. Test coverage: six new unit tests with
mocked `gh` for each skip + success + fail branch, plus a
URL-parser test class.

The three downstream demos (policy-eval, audit-trail-reporter,
sbom-watch) now exercise the full three-layer stack on every
`capa install`: lockfile + GPG + SLSA, all enforced.

### Supply-chain: SLSA L2 build provenance via Sigstore

Each seed-library repo (capa_cli, capa_datetime, capa_log,
capa_http) now ships a
[`.github/workflows/release.yml`](docs/templates/release.yml)
that fires on `v*` tag push, builds a source tarball via
`git archive`, generates a SLSA Level 2 build-provenance
attestation through `actions/attest-build-provenance@v1`, and
publishes it to the public Sigstore Rekor transparency log via
GitHub's OIDC identity. The tarball lands on the corresponding
GitHub release.

```bash
# Consumer-side verification (manual today; auto-verify in
# `capa install` is the next supply-chain tier):
gh release download v0.1.2 \
    --repo nelsonduarte/capa_cli \
    --pattern '*.tar.gz'

gh attestation verify capa_cli-v0.1.2.tar.gz \
    --owner nelsonduarte
```

The attestation certifies, in machine-checkable form, that the
published tarball was produced by an unmodified CI run
triggered by the signed `v*` tag on the named repository. It
is a stronger claim than the GPG signature alone: even with
the publisher's GPG key compromised, moving a tag still
requires landing a new commit and re-running CI under the
attacker's OIDC identity, which would be visible in the
public Rekor log.

The three downstream demos (policy-eval, audit-trail-reporter,
sbom-watch) now pin v0.1.2 of each seed library, which is the
first SLSA L2 attested release. The publisher GPG fingerprint
remains
`6C1D222D491FB88031E041A536CFB426101AA24B`
across both layers.

This stacks on top of the existing supply-chain layers:

1. **Lockfile SHA enforcement** (catches tag retag).
2. **GPG tag signature + `verify_key` pinning** (catches
   account compromise that moves a tag to an attacker commit).
3. **SLSA L2 build provenance + Sigstore Rekor** (catches a
   publisher whose GPG key is compromised but whose CI
   identity is not, and makes the build path auditable).

A consumer-side auto-verification path in `capa install` (the
SLSA-verification-grade tier) is the next adjacent step;
deferred so the producer-side story can land in a focused
release.

### Package manager: optional GPG signature verification

A git dependency in ``capa.toml`` may now carry a
``verify_key`` field with the publisher's 40-character GPG
fingerprint. ``capa install`` then runs ``git verify-tag``
(or ``git verify-commit`` for a ``rev`` pin) against the
consumer's local GPG keyring and refuses to install on any
signature failure: unsigned ref, unknown key, key mismatch,
or invalid signature.

```toml
[dependencies.capa_log]
git = "https://github.com/nelsonduarte/capa_log"
tag = "v0.1"
verify_key = "1234 5678 90AB CDEF 1234 5678 90AB CDEF 1234 5678"
```

The trust anchor is the fingerprint itself; the consumer
imports the publisher's key once (``gpg --import``,
``gpg --recv-keys``, or out-of-band copy of the .asc file),
after which every ``capa install`` independently re-verifies
each signed tag. ``capa.lock`` grows a ``signing_key`` field
recording the verified fingerprint for the audit trail.

Closes the "account compromise + retag" supply-chain vector
that the SHA-only lockfile check still let through on the
*first* install (an attacker compromising the account before
any consumer has installed could ship a malicious initial
release with no SHA on record to compare against). With
``verify_key`` declared, an attacker who pushes a malicious
tag also needs the publisher's private key.

Defaults: ``verify_key`` is opt-in. Existing capa.toml files
without the field continue to work unchanged; verification
runs only when the user explicitly declares a fingerprint.
``LockMismatchError`` and ``VerificationError`` are both
subclasses of ``InstallError``, so callers that catch the
base class keep working.

### Package manager: lockfile enforcement + rev-pinning docs

``capa install`` now treats ``capa.lock`` as authoritative.
For every git dep whose ``capa.toml`` source + pin are
unchanged across runs, the resolved commit SHA must match the
lockfile entry; otherwise ``LockMismatchError`` (a subclass of
``InstallError``) raises with a precise diff. The check
catches the canonical "upstream tag was force-pushed" supply-
chain signal that previously slipped through silently because
the lockfile was a record, not an enforcement gate.

Two explicit escape hatches when the new SHA is deliberate:

- delete ``capa.lock`` and re-run ``capa install`` (signals
  "I accept the new resolution"); or
- pass ``capa install --update`` (or the API kwarg
  ``allow_lock_update=True``) to overwrite the lockfile.

Docs (README and docs/packages.md) now show
``rev = "<commit-sha>"`` as the production-grade pin form,
with ``tag = "v0.1"`` documented as the convenience form that
relies on lockfile enforcement to stay honest. Cargo's
``cargo build --frozen`` and ``cargo update`` set the
precedent for the same shape.

### `capa_http` extracted to its own repo

The last hand-vendored seed library moves out of
``libraries/capa_http/`` and into
[nelsonduarte/capa_http](https://github.com/nelsonduarte/capa_http)
at tag ``v0.1``. ``libraries/`` is now empty and removed from
the working tree; the four seed libraries (capa_cli,
capa_datetime, capa_log, capa_http) all live in standalone
repos consumed via the package manager:

```toml
[dependencies]
capa_http = { git = "https://github.com/nelsonduarte/capa_http", tag = "v0.1" }
```

No code change to the library surface; the contents of the
extracted repo are a verbatim copy of
``libraries/capa_http/`` plus a README rewritten for the
``capa.toml`` consumption path (instead of the prior
``CAPA_PATH=libraries`` ad-hoc invocation).

### License: dual MIT OR Apache-2.0

Capa is now dual-licensed under either the MIT License or the
Apache License 2.0, at the user's option (SPDX
`MIT OR Apache-2.0`). The previous MIT-only file is preserved
verbatim at [`LICENSE-MIT`](LICENSE-MIT); the Apache-2.0 text
lives at [`LICENSE-APACHE`](LICENSE-APACHE); the top-level
[`LICENSE`](LICENSE) is a short dispatcher explaining the
choice and the rationale.

Why both? MIT preserves the friction-free permissive story Capa
shipped with; Apache-2.0 adds an explicit patent grant
(Section 3) and an automatic termination clause against
litigants. The patent grant matters for institutional adopters
in regulated supply-chain contexts (EU CRA, NIS2, DORA) that
prefer or require Apache-style protection.

Contributions are now dual-licensed under the same terms, per
the clause in [`CONTRIBUTING.md`](CONTRIBUTING.md). No CLA
required; submitting a PR is enough.

### Wasm Component Model backend

A real Wasm backend now sits next to the Python emitter inside
`capa.ir`. Capa programs in a defined subset compile to genuine
`.wasm` modules and Component Model components, with the capability
story carried end-to-end:

- **Capabilities as WIT imports.** Each built-in capability the
  program uses turns into a `capa:host/<cap>` WIT interface. A
  Capa program with `fun main(stdio: Stdio)` becomes a Wasm
  component that imports `capa:host/stdio` and exports `main`.
  The capability parameter has no Wasm runtime value -- its
  methods are imported by name, matching the WIT.
- **Linear memory layout for aggregates.** Structs, sums, lists,
  and maps are heap-allocated via a bump allocator. Layouts:
  structs use natural-aligned fields, sums use tag@0 + payload@8,
  lists use a 16-byte header + element array (grows via
  `memory.copy`), maps use a 16-byte header + (key_ptr, key_len,
  value) triples.
- **String values as (ptr, len) pairs.** String locals expand to
  two i32 Wasm locals; String params take two i32s; String
  returns use Wasm 2.0 multi-value `(result i32 i32)`. The host
  decodes UTF-8 through the module's exported memory.
- **Built-in Option<T> / Result<T, E>** registered as sum-type
  layouts inside the emitter so user code can pattern-match on
  them without declaring the type in source.
- **String interpolation** ("hello ${name}") lowers to inline
  concatenation: each value part stashes (ptr, len), total length
  is summed, the buffer is allocated, and pieces copied in order.
  Int parts use a `$itoa` helper emitted alongside `$alloc`.

CLI surface:

- `capa --wit file.capa` -- print the WIT spec describing the
  program's capability imports.
- `capa --wasm --transpile file.capa` -- emit WAT (text format).
- `capa --wasm --run file.capa` -- assemble + execute via wasmtime
  with a Python host bridge wired to `sys.stdout` / `sys.stderr`.
- `capa --wasm -o X.wasm file.capa` -- save the assembled binary.
- `capa --wasm --component -o X.wasm file.capa` -- wrap in a CM
  component via `wasm-tools component embed` + `component new`.
  The resulting `.wasm` is consumable by any CM-aware runtime.

Demo gallery in `examples/wasm/`: hello, fizzbuzz, shape_area
(recursive sums + pattern matching), word_count (Map<String,Int>
with Option-returning get), strings (String methods chained). All
five run end-to-end through `capa --wasm --run`.

Coverage (Phase 6 of the IR roadmap):

- 6A: Int / Bool arithmetic, comparisons, control flow.
- 6B: Capability method calls (Stdio) via imported functions.
- 6C: Sums, structs, pattern matching, bump allocator.
- 6D: String literals + locals + methods (length, contains,
  starts_with, ends_with, substring, to_upper, to_lower, trim);
  List<Int> (literal, push with realloc, length, iter, indexing);
  Map<String, V> (set, get returning Option, contains_key,
  length, is_empty).
- 6F: CM component packaging via wasm-tools, demo gallery.

Known gaps (documented in `TODO.md`):

- Capabilities other than Stdio (Fs, Env, Clock, Net) -- need
  Float type, Result<T, E> propagation across the host boundary,
  and a richer WIT signature table.
- Closures / lambdas (6E) -- Wasm has no first-class functions
  in the form Capa source produces; closure conversion lifts
  lambdas to top-level + an environment record, work for a later
  phase.
- `List.map/filter/fold`, `Map.keys/values/pairs` -- need
  closures or richer List element types (List<(K, V)>).
- `String.split/replace`, `Stdio.read_line` -- need List<String>
  or Result<String, IoError>.

The three downstream demos (`audit-trail-reporter`,
`policy-eval`, `sbom-watch`) currently exceed Phase 6's Wasm
coverage; they remain on the Python pipeline. Pushing them
through Wasm waits for the Fs/Env/Clock work above.

### CIR: capability-aware intermediate representation

A new IR layer sits between the analyzer's typed AST and the
Python emitter. Lowering is ANF/three-address; every operation
binds its result to a fresh local, every method-call site
records the capability it exercises, every function preserves
its declared capability set. The IR was built so a future
backend (WebAssembly Component Model, LLVM, Cranelift) has a
clean structure to lower from without needing to re-derive
capability information that the analyzer already computed and
that legacy direct-to-Python emission discards.

Coverage and pipeline:

- `capa.ir.lower(module, types)` produces a `capa.ir.Module`
  with `functions`, `types`, `impls`, `traits`, `consts`, and
  `imports`. The lowerer accepts every top-level item the
  legacy transpiler accepts; constructs the IR does not yet
  cover raise `UnsupportedInIR(shape)` with a precise reason.
- `capa.ir.emit_python(ir_module)` emits per-function Python
  matching the legacy transpiler's idiomatic shape (method
  dispatch for `String` / `List` / `Map` / `Set` rewritten to
  Python idioms; sum variants emit as `@dataclass`; `?`
  expands inline via `TryUnwrap`).
- `capa.ir.compile_program(module, filename, types)` wraps
  the function emission with the legacy runtime prelude and
  the `if __name__ == "__main__":` bootstrap, producing a
  directly-runnable Python program.
- **CLI: `--ir`** opts into the new pipeline. The legacy
  transpiler stays the default; `--ir` falls back to it with
  a one-line stderr breadcrumb when lowering hits an
  unsupported construct, so the user-visible behaviour is
  identical.

What's covered:

- Function bodies in full: literals, identifiers, binops
  (with short-circuit `and` / `or` re-expansion so out-of-bounds
  Python evaluation never crosses a short-circuit boundary),
  unary ops, calls, method calls (with type-aware dispatch for
  the builtin collection / string surface), interpolated
  strings, list / tuple / map / set literals, struct literals,
  field access, indexing, `?`, lambdas (block and expression
  body, closures), match (statement and expression position
  with block-as-expression semantics for the latter), `if` /
  `elif` / `else` / `if`-as-expression, `for`, `while`
  (recomputes condition before every iteration including
  `continue`-driven ones), `break`, `continue`, `let` (incl.
  tuple-pattern destructuring), `var`, plain and compound
  assignment.
- Top-level: structs, sums (with method attachment to every
  variant for `impl T` blocks where `T` is a sum), traits,
  user-defined capabilities, impl blocks (inherent + trait
  impls), `const`, `import` (emits the same defence-in-depth
  breadcrumb the legacy uses).
- Capability metadata: `Function.declared_caps`,
  `MethodCall.cap_used`, `TraitDecl.is_capability`, and
  `Param.is_capability` flow through the IR unchanged.

Equivalence: 36 of 38 runnable examples produce byte-identical
stdout between the legacy and IR pipelines (the two that don't
need files / network outside the harness's bare-exec namespace,
not divergence). The multi-module `audit-trail-reporter`
program at <https://github.com/nelsonduarte/audit-trail-reporter>
compiles fully through `--ir` with no fallback.

Known IR-only gaps:

- `TuplePat` in match patterns (in `let` it works).
- Match arm with guard expression (guard references
  pattern-bound names that don't survive ANF flattening; would
  need an inline-expression escape).

Both gaps raise `UnsupportedInIR` and the CLI falls back to
the legacy path, so no user-visible regression.

Internals (not user-visible):

- Twelve commits across `capa/ir/`, ~1600 lines of new code,
  ~80 new unit tests. Per-function emission stays under 350
  lines (the legacy is ~600). See commits `b53f6fd` (Phase 1)
  through `a36c139` (Phase 5C+) for the staged history.
- New CLI flag wired through `capa/cli.py`; the legacy code
  path is unchanged for invocations that don't pass `--ir`.

## [1.0.0-rc.2], 2026-05-20

Two analyzer-precision fixes surfaced by a focused bug-hunt
session, plus the full Agda mechanisation of the four
load-bearing soundness theorems. Both analyzer fixes are
backwards-compatible at the source level for code that
already obeyed the intended semantics; the second fix tightens
the rule set and rejects a small class of programs whose
runtime behaviour previously disagreed with the source.

### Language correctness

- **Analyzer rejects block-scope shadowing of function-local
  bindings.** A `let` inside a nested block (`if` / `for` /
  `while` / `match` body) that shadowed a name already bound
  in an enclosing function scope previously passed the
  analyzer, and the transpiler then emitted plain
  `x = ...` for both bindings. Python has function scope, not
  block scope, so the inner assignment overwrote the outer
  binding for the rest of the function. A program reading
  like
  ```
  let x = 1
  if cond
      let x = 2
      ...
  stdio.println("${x}")    // source says 1; runtime printed 2
  ```
  silently violated source semantics. The analyzer now
  rejects every such shadow with a diagnostic pointing at the
  previous binding and telling the user to rename one of the
  two. Module-level shadowing (`const N` shadowed by
  `let N` inside a function) stays allowed because Python's
  function scope handles it correctly. Test count: 1075 ->
  1080.

- **Analyzer precision: NLL-style consume tracking around
  divergent branches.** A branch (if/elif/else body, or match
  arm body) that consumes a capability and then diverges
  (ends in `return`, `break`, or `continue`) cannot flow its
  consumption past the merge point: the divergent path never
  reaches the continuation. The analyzer was naively unioning
  every branch's consumed set, producing a false positive
  that rejected programs like
  ```
  if b
      adoptar(stdio)   // consume
      return
  stdio.println("after")    // was rejected; stdio is in fact live here
  ```
  Both `_check_if` and `_check_match_expr` now skip branches
  whose body diverges when merging, consistent with the
  divergence treatment match-arm type-unification already
  uses (`_block_diverges`). Soundness preserved: the fix only
  makes the analyzer more permissive on programs the
  discipline would have accepted anyway. Test count: 1070 ->
  1075.

### Mechanisation

- **All four soundness theorems mechanised in Agda.** The
  [`proofs/`] directory now contains real definitions (no
  `postulate` survives) for Progress, Preservation, Capability
  Soundness, and a multi-step Manifest Completeness theorem.
  Roughly 600 lines of self-contained Agda (no agda-stdlib
  dependency); follows the PLFA template. The
  Capability Soundness proof uses an inductive `_∈caps_`
  relation rather than a Bool-indicator function to sidestep
  higher-order-unification friction with the clausal `_||_`.
  The Manifest Completeness statement was reformulated from
  the original skeleton equation (`declared-caps t ==
  caps-of-reachable t`, which is false in general -- a function
  can declare a cap parameter and never use it) to the
  honestly-provable multi-step soundness form. CI workflow
  at `.github/workflows/agda.yml` typechecks both files on
  every push that touches `proofs/`. See the `proofs/README.md`
  status table for the stage-by-stage shape of the proof.

## [1.0.0-rc.1], 2026-05-19

Polish iteration on top of `1.0.0-rc.0`. The headline change is
a soundness fix on the `?` operator (see below); the rest is
stdlib gaps surfaced while writing real Capa programs, a new
example pinning the legitimate `?`-in-lambda shape, and a
website pass.

### Language correctness

- **`?` requires the enclosing function or lambda to return
  `Result` or `Option`.** Previously the analyzer accepted `?`
  anywhere the inner expression was `Result` / `Option`,
  regardless of the enclosing return type. At runtime this let
  an `Err` flow out of a function declared `-> Int` /
  `-> String` / `-> Unit`, and inside a lambda the raised
  `_CapaTryEarlyReturn` could escape past the lambda's caller
  (which had no decorator to catch it) and crash the program.
  The analyzer now rejects every `?` whose enclosing fn/lambda
  returns a different shape, with a diagnostic that names the
  actual return type. Lambdas push their own
  `current_return_type` in both block-body and expression-body
  paths so the rule is checked against the lambda's contract,
  not the outer function's.
- **Transpiler: lambdas containing `?` get their own
  `@_capa_wrap`** (block-bodied) or `_capa_wrap(...)` wrap
  (expression-bodied). Combined with the analyzer rule above,
  the legitimate shape (a `Result`-returning lambda whose body
  uses `?`) is now sound end-to-end. `_uses_try` also treats
  `LambdaExpr` as a function boundary, mirroring `FunDecl`, so a
  nested lambda's `?` does not force the outer function to
  carry a redundant decorator.
- **`?` in `var x = foo()?` / `x op= foo()?`** now hoists inline
  the same way `let x = foo()?` does. Previously these positions
  went through the slow `_capa_try` exception path AND
  `_uses_exception_try` optimistically skipped the
  `@_capa_wrap` decorator -- so the raised
  `_CapaTryEarlyReturn` escaped the function uncaught. The
  decorator is now emitted defensively for any function
  containing `?`, and the hoist covers `VarStmt`, `AssignStmt`
  (every op), `LetStmt`, `ReturnStmt`, and `ExprStmt`.

### Stdlib additions

- **`Fs.mkdir(path)`, `Fs.list_dir(path)`, `Fs.is_dir(path)`.**
  Closed the three daily-friction gaps in the `Fs` capability;
  the demos previously had to shell out via `Unsafe`.
- **`List.sorted_by(comparator)`.** Returns a fresh sorted list
  given a `(a, b) -> Int` comparator. Stable, non-mutating.
- **`String.trim_start()` / `String.trim_end()`.** Asymmetric
  trims; the symmetric `String.trim()` was the only one before.

### Examples

- **`examples/quota_check.capa`** -- a Kubernetes-style
  resource-quota checker built around the
  `?`-in-`Result`-lambda shape. Policies are closures of type
  `Fun(JsonValue) -> Result<Unit, Violation>` produced by
  factories that capture their thresholds; the closure body
  chains "extract field" with "validate value" via `?`. The
  closure is built in one function and called in another, so
  the `?` propagation crosses a function boundary -- the case
  the soundness fix locked in. Pins the legitimate lambda+`?`
  pattern as part of the example suite.

### Documentation site

- **Cleaner landing page** with a light/dark toggle and a
  hamburger nav that overlays the header on mobile (no
  page-content shift on open). Single accent, no shadows, no
  centered text. The dense first-impression page is gone; the
  value props lead.
- **Roadmap simplified.** "Known limitations" was removed (it
  duplicated the README), and the "Where we are today" table
  now has a single status column instead of side-by-side
  "shipped" vs "not yet".

## [1.0.0-rc.0], 2026-05-19

The first **release candidate** for Capa 1.0. The compiler
surface, the runtime API, the manifest + SBOM + VEX + SLSA
emission shapes, the module loader, and the new package
manager are now feature-frozen pending feedback. Breaking
changes against this candidate are still possible (that is
the point of an rc), but the stability commitment in
[`STABILITY.md`](STABILITY.md) starts the moment `1.0.0`
ships.

Headline shifts since `0.8.4-beta`:

### Language additions

- **Block-as-expression match arms.** A match arm whose body
  is a block that ends in a bare expression now contributes
  that expression's value to the match. Lets `let x = match`
  hold multi-line branches without a `var` + `if` rewrite.
  (Was a daily friction in two downstream demos.)
- **Variants with multiple payload types.** `Variant(A, B, C)`
  is now legal in both type declarations and patterns. The
  AST, parser, analyzer, transpiler, builtin `Result` /
  `Option` / `JsonValue`, LSP hover, document symbols, and
  docgen all updated together. `policy-eval` dropped three
  wrapper structs after the migration.
- **Inherent `impl Type`** (no trait or capability after the
  name) now works for both struct and sum types. The sum-type
  case used to crash because Python `typing.Union` is not
  monkey-patchable; the transpiler now attaches methods to
  every variant class instead of the alias.
- **Recursive sum types** (a variant whose payload references
  the type being defined) confirmed working end-to-end and
  exercised by the new `policy-eval` demo's `Condition` AST.

### Capability discipline

- **`Fs.restrict_to` is now path-aware**, not string-prefix.
  Both the stored allowed prefixes and the queried path are
  canonicalised via `os.path.realpath` (resolves `..` segments
  and follows symlinks to their final target) before the
  `pathlib.Path.is_relative_to` containment check. Closes the
  `data/../etc/passwd` and symlink-out bypasses. A TOCTOU race
  remains and is documented; closing it needs open-at-dirfd.

### Module system + package manager

- **Submodule can `import` a sibling of the root file.**
  Multi-directory projects (`sinks/csv_sink.capa` importing
  `domain` at the project root) now work without extra
  configuration. The loader adds the root file's directory
  to its search paths once `load_root` is called.
- **`capa install` + `capa.toml` + `capa.lock`**. A minimal
  package manager: declare git or path dependencies in
  `capa.toml`, run `capa install`, the loader picks up
  `./vendor/` automatically when the manifest declares git
  deps. Strict TOML parser, idempotent re-install across
  pin changes, Windows-friendly rmtree on `.git/objects/pack`
  read-only files. Documented in
  [`docs/packages.md`](docs/packages.md).
- **Loader resolution order is now spelled out**: importer-
  local, `CAPA_PATH`, `./vendor/` (when `capa.toml` declares
  a git dep), path-dep parents, `./libraries/`, root-file
  directory.

### CLI

- **Args after `--` are forwarded** to the program: `capa
  --run myprog.capa -- input.json --verbose` puts `["input.json",
  "--verbose"]` in `env.args()`. `capa --watch` carries the
  passthrough across the subprocess respawn.
- **`./libraries/` auto-discovered** in cwd when present, no
  `CAPA_PATH` needed. Mirrors the `node_modules` / `vendor`
  conventions.

### Seed library ecosystem

Three seed libraries extracted to standalone repos and
consumed via the package manager:

- [`capa_cli`](https://github.com/nelsonduarte/capa_cli)
  `v0.1` - argument parser
- [`capa_datetime`](https://github.com/nelsonduarte/capa_datetime)
  `v0.1` - ISO 8601 + Y/M/D/h/m/s arithmetic
- [`capa_log`](https://github.com/nelsonduarte/capa_log)
  `v0.1` - levelled logging via a `Logger` capability

The in-tree copies under `libraries/capa_{cli,datetime,log}`
are deleted. `capa_http` stays in `libraries/` pending its
own extraction.

### Three real downstream programs

To stress the language at non-toy scale (and to surface the
bugs you can't find with synthetic tests), three substantial
programs in standalone repos:

- [`audit-trail-reporter`](https://github.com/nelsonduarte/audit-trail-reporter)
  - AML compliance toolkit: four detection rules, four
    report sinks, attenuated read+write `Fs` split. 1100+
    lines across 9 files.
- [`sbom-watch`](https://github.com/nelsonduarte/sbom-watch)
  - SBOM operationaliser: cross-references a CycloneDX SBOM
    against an OSV-style CVE database and a policy file.
    700 lines.
- [`policy-eval`](https://github.com/nelsonduarte/policy-eval)
  - JSON-encoded policy-as-code engine. Tree-walk
    interpreter over a recursive `Condition` AST.

Writing these surfaced (and fixed) seven distinct gaps in the
language: multi-statement match arms, multi-payload variants,
path canonicalisation, UPPERCASE-as-identifier transpilation,
multi-directory module resolution, `--` arg passthrough, and
inherent impl on sum types.

### Documentation + commitment

- New [`STABILITY.md`](STABILITY.md) documents the post-1.0
  compatibility commitment: what surfaces are covered by
  SemVer, what is explicitly outside (diagnostic wording,
  transpiled-Python output shape, internal Python modules),
  breaking / additive / patch classification, deprecation
  window, security exception, pre-1.0 plan.
- [`docs/packages.md`](docs/packages.md) added: manifest
  schema, sources, lockfile semantics, library-extraction
  recipe.
- `docs/reference.md` §7 Imports completely rewritten (the
  previous text claimed the module system was "reserved for
  a future version"; it has been live for many releases).
  Capability-discipline labels renamed from `(v1)/(v2)/(v3)`
  to `Structural/Flow/Linear`.
- `docs/roadmap.html` updated: "Native module system" and
  "Package manager" both promoted to DONE.
- README condensed from 1008 to ~280 lines; reference
  content moved into `docs/`.

### Explicitly deferred to post-1.0

- **Block-form `if`-as-expression.** Only the ternary
  `if cond then a else b` is an expression today. The
  block-as-expression `match` form is a clean workaround.
  Documented in `docs/reference.md` §4.2 and in STABILITY.md.

### Numbers

- **1046 tests** spanning lexer, parser, analyzer,
  transpiler, LSP, formatter, attributes, dataflow, the
  package manager, and Hypothesis-based property tests.
  Green on Ubuntu / macOS / Windows.
- **5 public repos** in the org (compiler + 3 seed libs +
  the in-tree `capa_http`), 3 standalone downstream demos.
- **First time** a Capa program can declare a `capa.toml`,
  run `capa install`, and have its deps fetched + locked
  by the toolchain.

## [0.8.4-beta], 2026-05-18

A **diagnostic-correctness pass** on the analyser. Five
silent false-negatives that used to compile cleanly and then
explode at runtime with a confusing Python ``TypeError`` /
``RuntimeError`` are now caught at compile time, each at the
source location where the mistake was made and with the
actual type the user wrote. Plus two diagnostic-quality
improvements that turn generic typo guesses into specific
hints.

### Fixed

- **``?`` on a value that is not ``Result<T, E>`` or
  ``Option<T>``** is now rejected at type-check time. Before:
  ``return x?`` where ``x: Int`` compiled cleanly and raised
  ``RuntimeError: ? applied to a value that is not Result or
  Option`` at runtime, with the position pointing at the runtime
  helper rather than the source. Now:

      file.capa:2:12: error: `?` is only valid on Result<T, E>
      or Option<T>; this expression has type Int

  ``TyVar`` and ``TyUnknown`` stay permissive so generic code
  that unifies to Result / Option still type-checks.

- **Non-Unit functions must ``return`` on every code path.**
  A function declared ``-> T`` (for any ``T`` other than
  ``Unit``) whose body could fall through without producing a
  value used to compile silently and return ``None`` at
  runtime. The most common shape was
  ``fun classify(c: Color) -> String\n    match c { ... }``
  where the trailing ``match`` is an ExprStmt whose value is
  discarded; the function then fell through. Now rejected with
  a precise error; the fix is always ``return X`` or
  ``return match ...``. ``examples/basics.capa`` had this bug
  in ``classify``; updated in the same commit. Two pre-existing
  tests that exercised the bug-permissive analyser were
  updated to test the idiomatic ``return match ...`` shape.

- **Calling a non-function silently passed.** ``let x = 5; let
  y = x(2)`` (or any call expression whose callee resolves to
  an Int local, a String constant, a struct value, etc.) used
  to type-check cleanly and explode at runtime as ``TypeError:
  'int' object is not callable``. The analyser now reports
  ``'x' is not callable; it has type Int`` at the call site.
  Function-typed locals (lambdas) keep working: when the
  bound symbol's type is a ``TyFun``, the call falls through
  to the existing non-Ident-callee path that handled lambdas
  before.

- **Match arms after a guardless catch-all are now rejected.**
  Once a ``match`` arm has a guardless catch-all pattern
  (``_`` or a bare binding ident), every arm after it is
  unreachable: the catch-all has already matched every
  possible value. Previously the analyser accepted this
  silently and the unreachable arms were just dead code in
  the transpiled output. Guarded ``x if cond -> ...`` is not
  a catch-all (the guard may fail), so later arms stay
  reachable.

- **``impl`` method without ``self`` cannot be called via
  ``receiver.method()``.** Calling ``c.get()`` where
  ``Counter.get`` is declared as ``fun get() -> Int`` (no self
  parameter) used to pass the analyser silently and explode
  at runtime as ``TypeError: _Counter_get() takes 0 positional
  arguments but 1 was given``. The fix records ``has_self``
  on the method's Symbol at registration (before the
  ``param_names`` strip), and gates the new check on
  ``type_sym.pos != BUILTIN_POS`` so built-in methods
  (``stdio.println``, ``json.as_object``, ``xs.length``)
  remain unaffected. Static-like impl methods (``fun zero()
  -> Ponto`` as a constructor) are still accepted at the impl
  boundary because the check only fires at the dot call site;
  Capa simply has no public static-method call syntax yet.

### Changed

- **Duplicate-binding diagnostic** names the previous-binding
  location and reminds the user of the ``var`` + bare-
  assignment idiom. Before:

      file.capa:3:9: error: duplicate binding 'x'

  After:

      file.capa:3:9: error: duplicate binding 'x' (previous
      binding at line 2, col 9); use `var x` for a mutable
      binding and `x = ...` to reassign, or rename if you
      want a distinct value

- **``self.field`` hint inside impl methods.** A bare
  identifier in an ``impl`` method body that matches a field
  of ``self``'s struct type is now flagged with the targeted
  hint (`did you mean \`self.v\`?`) instead of the generic
  Levenshtein typo guess. The single most common port-from-
  Python error in user-defined types where Python's implicit-
  self convention does not carry over.

### Numbers

- **989 tests** (was 962 in v0.8.3-beta), green on Ubuntu /
  macOS / Windows &times; Python 3.10 / 3.12 / 3.14. The 27 new
  tests are: 4 in TestQuestionMarkOnNonResultOption, 2 in
  TestDuplicateBindingDiagnostic, 6 in TestReturnOnAllPaths, 3
  in TestCallNonCallable, 3 in TestSelfFieldHint, 4 in
  TestUnreachableMatchArm, 5 in TestMethodWithoutSelfNotCallable.

## [0.8.3-beta], 2026-05-17

A polish release on top of v0.8.2-beta. No new tentpole
feature; the focus is taking the discipline-and-artefact
story closer to adoption. Six concentrated arcs landed:
the Python-to-Capa migration walkthrough, an LSP
positional-fidelity fix that had been pending since the LSP
v1, transpiler type-aware specialisation that closes the
list-heavy benchmark by a third, a 10k-example property-test
stress hunt (no regressions found), the repo rename to
``capa-language`` (with the matching ``capa-language.com``
domain), and GitHub Discussions opened as the conversation
space for the language.

### Added

- **Python-to-Capa migration walkthrough**,
  ``docs/migration.md`` plus a paired example at three
  stages. The example is a small status fetcher (~35 lines of
  Python touching Fs + Env + Net); the three Capa stages show
  the same program with everything ``Unsafe``-wrapped via
  ``py_import``/``py_invoke``, with one helper moved to typed
  Capa, and finally with every function carrying an explicit
  capability signature. The manifest tracks the migration:
  ``main = [Stdio, Unsafe]`` shrinks to
  ``main = [Stdio, Fs, Unsafe]`` shrinks to
  ``main = [Stdio, Fs, Env, Net]`` with no ``Unsafe`` anywhere.
  Three new tests assert the manifest shape at each stage.

- **GitHub Discussions** opened on the repo as the
  conversation space (Show and tell, Q&A, Ideas,
  Announcements). README ``## Community`` section points at
  it and routes security reports to the private advisory
  channel. Two seed discussions: a pinned welcome and a
  worked example of the LLM tool-use sandboxing pattern from
  v0.8.2.

- **GitHub Topics** set on the repo so the project shows up
  in topic-based discovery (``capability-security``,
  ``programming-language``, ``compiler``, ``type-system``,
  ``sbom``, ``cyclonedx``, ``spdx``, ``slsa``, ``vex``,
  ``supply-chain-security``, ``static-analysis``,
  ``language-design``, ``cra``, ``nis2``, ``llm-security``).

### Changed

- **Repo renamed to ``capa-language``** to match the domain
  (``capa-language.com``) and disambiguate from the many
  ``capa`` projects on GitHub. The old URL redirects
  indefinitely; existing clones continue to work. The 37
  hardcoded ``nelsonduarte/capa`` references in
  README / CHANGELOG / docs / deploy scripts / issue
  templates / VSCode extension manifest were updated to the
  new canonical URL in the same commit.

- **Transpiler type-aware specialisation** for built-in
  methods and variant ``match``. The simple ``List<T>``
  methods (``length``, ``push``, ``contains``, ``is_empty``,
  ``get``) lower to native Python equivalents (``len``,
  ``.append``, ``in``, ``len == 0``, inline bounds-checked
  index) on receivers whose static type the analyser knows.
  Payload-less variant ``match`` lowers to an
  ``if isinstance(...)`` chain when every arm is a
  payload-less variant, a wildcard, or an or-pattern of
  those, with no guard. Anything else (Some(x), struct
  destructure, literals, guards, higher-order list methods)
  stays on the general path. Ten new tests in
  ``TestBuiltinSpecialisations`` pin both the emitted
  fast-path code and the cases that must keep using the
  general path.

- **Benchmark numbers shift**: the list-heavy
  ``scope_analyser`` workload went from 1.20x to 1.12x
  against hand-Python (CPython 3.14, ``--iterations 30
  --repeat 15``). The pure-compute ``fib`` stays at 1.00x.
  The string-plus-struct ``ua_parse`` stays at 1.45x:
  the match-on-enum part was a small fraction of that
  workload's time; the remaining gap is per-call class
  instantiation (the hand-Python baseline uses string
  constants rather than class instances per variant, which
  is a different design point). Documented honestly in
  ``benchmarks/README.md``.

### Fixed

- **LSP positional fidelity for typos inside ``${...}``
  interpolations**. Before this release, an undefined
  identifier inside a string interpolation
  (e.g. ``"Hello, ${nme}!"``) reported its source position at
  the string literal's opening quote (line 1, col 1 for a
  one-line program) and the identifier name was lost from
  the diagnostic. The lexer now records the source ``Pos`` of
  every top-level ``${`` opener in the ``STRING_LIT`` token;
  the parser threads each one into the sub-Lexer it spawns
  for the interpolation contents, so the sub-Lexer starts
  counting from the right ``line`` / ``col`` / ``offset`` in
  the outer source. Typos inside ``${...}`` now report the
  actual identifier position, with the snippet rendering the
  right line and the caret on the right column, and the
  identifier name and Levenshtein hint both make it through.
  Three new tests in ``TestInterpolatedString`` cover the
  regression (simple typo, typo after escape sequences
  earlier in the literal, two interpolations where the
  second has the typo).

### Verified

- **Property-test stress hunt at 10k examples per test** (one-
  shot, not committed to CI). Roughly 50k generated programs
  across the lexer / parser / formatter / pipeline / soundness
  properties; the soundness invariant
  ``runtime_classes ⊆ manifest_classes`` held over ~14k
  programs across the multi-capability strategies. Zero
  regressions surfaced from the rename, migration walkthrough,
  or interpolation-positions changes. Side finding: the simple
  ``_program_with_caps`` strategy exhausts its space at 87
  unique programs (the advanced strategy with 4181 programs
  is the better stress target if CI ever raises the budget
  above the conservative defaults).

### Numbers

- **962 tests** (was 946 in v0.8.2-beta), green on Ubuntu /
  macOS / Windows &times; Python 3.10 / 3.12 / 3.14.

## [0.8.2-beta], 2026-05-16

A content-and-tooling release on top of v0.8.1-beta. Three
big new pieces landed: the full **LLM tool-use sandboxing
arc** (four runnable demos + writeup), the **complete Learn
tutorial track** (twelve chapters, hands-on, syntax-checked
end-to-end), and a **site restructure** that moved the
public-facing voice from SBOM-first to language-first.

### Added

- **LLM tool-use sandboxing arc**, four files demonstrating the
  central 2026 adoption argument for Capa, that capability
  discipline is structurally the right shape for sandboxing
  agentic tool use:

  - ``examples/llm_tool_sandbox.capa`` &mdash; static demo. An
    agent function declares ``(SearchWeb, SendEmail)`` and
    provably cannot escalate to ``RunCode`` even though
    ``RunCode`` exists in the same compilation unit. Manifest
    emits the bound.
  - ``examples/llm_agent_runner.capa`` &mdash; mock LLM + Capa-typed
    tool dispatch loop. Scripts a three-turn conversation
    (search &rarr; email &rarr; reply) so the demo is offline
    and deterministic, exercises the full dispatch path with
    string-keyed routing into capability methods.
  - ``examples/llm_anthropic_real.capa`` &mdash; real Anthropic
    Messages API round-trip, single-turn (no tools), isolating
    the network-integration path. Bridges through a small
    Python helper (``examples/llm_anthropic_helper.py``) for
    the HTTP+auth dance Capa's built-in ``Net`` does not
    cover in v1.
  - ``examples/llm_anthropic_agent.capa`` &mdash; the capstone:
    real model + Capa-typed tool dispatch end-to-end. The
    headline audit claim aguenta: ``agent_loop`` declares only
    ``(Stdio, LlmClient, SearchWeb)`` and provably excludes
    ``Net``, ``Fs``, ``Env``, ``Unsafe`` even with a real model
    in the loop deciding which tools to call.

  Plus ``docs/llm-tool-sandbox.md``, the writeup: motivation
  (the 2026 prompt-injection / jailbreak / confused-deputy
  problem), the pattern in three pieces, attenuation at the
  boundary, the manifest as audit artefact, a comparison table
  with allow-lists and OS-level sandboxes, and the honest
  limits (does not prevent the LLM from being prompted, does
  not address content-level attacks, etc.).

  Surfaced on the homepage as a featured section ("LLM
  tool-use sandboxing") and a new persona ("Builders of LLM
  agents") at the top of the personas grid. Six new tests at
  ``tests/test_transpiler.py`` cover the smoke runs and the
  manifest discipline claims.

- **Learn tutorial track**, complete. ``docs/learn/`` with
  twelve hands-on chapters from "Hello, Capa" to "A small
  project":

  1. Hello, Capa
  2. Values and types
  3. Functions
  4. Control flow
  5. Collections
  6. Structs and sum types
  7. Errors as values
  8. Your first capability
  9. Attenuating capabilities
  10. Defining your own capability
  11. Modules and visibility
  12. A small project

  Each chapter has the same shape: goal &rarr; runnable code
  &rarr; "Try this" callout &rarr; the two common error modes
  &rarr; "where you are now". Prev/next navigation between
  chapters, breadcrumb back to the ToC. The earlier survey-
  style ``tour.html`` was removed; pedagogical content lives
  in ``learn/``, dense reference in ``reference.html``. Three
  syntax bugs introduced during the initial chapter pass were
  caught and fixed (Rust-style ``|x| body`` lambdas, multi-
  payload variants, ``Map.insert`` vs ``Map.set``); every
  remaining code sample verified by extraction into a temp
  file and ``capa --run``.

- **Specialised diagnostic when reaching for a private item**:
  the "undefined name" / "undefined type" hint now recognises
  when the missing reference is a private item of an imported
  module and points at the right fix (already shipped in
  v0.8.0, but explicitly noted here because it makes the
  module system feel polished).

### Changed

- **Site restructure**, language-first throughout:

  - ``tour.html`` removed (replaced by the Learn track). Top
    nav slimmed to Home / Why / Learn / Reference / Get started
    / Roadmap / GitHub. Manifest and Community moved to the
    footer.
  - ``manifest.html`` shrunk 580 &rarr; 296 lines: the dedicated
    CRA-mapping block now links out to ``docs/cra.md`` and
    ``docs/regulatory.md`` instead of duplicating them; the
    CycloneDX / SPDX / VEX / SLSA JSON-dump sections were
    condensed into a single "the same source, in standard
    formats" block pointing at the CLI flag and the
    ``examples/`` demo for each.
  - Subtitle, meta tags, release banner copy, personas order,
    comparison-table caption, FAQ ordering, and the "where to
    go next" footer all rebalanced. Capa is now described as
    a capability-typed language first; the supply-chain
    artefacts come second. ``positioning.md`` reframed the
    one-sentence thesis the same way.

- **Long-form design / paper drafts are local-only**: removed
  the ``WHITEPAPER.md`` stub (placeholder pointing at a doc
  never going to be written publicly) and untracked
  ``docs/paper-draft.md``. Both stay on disk; ``.gitignore``
  now lists ``docs/paper-draft.md`` alongside the pre-existing
  ``Capa-WhitePaper.md``. Stale ``WhitePaper §X.Y`` forward
  references in source comments and ``Capa-EBNF.md`` were
  replaced with self-contained descriptions.

### Fixed

- **Learn track syntax bugs in chapters 3, 5, 6, 12**:
  Rust-style pipe lambdas (``|x: T| body``) replaced with
  Capa's actual ``fun (x: T) -> R => body``; variants with
  multiple payloads (``Rectangle(Float, Float)``) replaced
  with tuple payloads (``Rectangle((Float, Float))``) and
  tuple-pattern destructure in match arms;
  ``Map.insert`` / ``Set.insert`` replaced with the correct
  ``Map.set`` / ``Set.add``. Caught during the LLM-agent demo
  build because the agent's parsing code wanted to use chained
  ``.and_then(|v| ...)`` and the compiler refused. Every
  fixed sample was verified by extraction + ``capa --run``.

### Numbers

- 946 tests, green on Ubuntu / macOS / Windows &times; Python
  3.10 / 3.12 / 3.14 (up from 938 in v0.8.1).

## [0.8.1-beta], 2026-05-16

A polish release on top of v0.8.0-beta. Three concentrated
arcs landed: the ``?`` operator gained an inline-hoist fast
path (and now actually works on ``Option<T>``, a latent bug),
the LSP became module-aware (no more false "undefined name"
on imported functions, completion no longer leaks mangled
private names), and a focused unit-test pass lifted
``capa.runtime`` coverage from 56% to 85%. Public-facing
framing (``tour.html``, ``start.html``, ``positioning.md``)
was also brought in line with the language-first voice from
the v0.8.0 homepage rebalance.

### Fixed

- **LSP no longer shows false "undefined name" for imported
  functions**: when the buffer the editor is showing imports
  other files that exist on disk, the LSP now runs the module
  loader and analyses the linked module. Calls to imported
  ``pub`` functions used to surface as ``undefined name``
  diagnostics in the editor because the LSP analysed each file
  alone. The single-file path is still the fallback whenever
  the loader can't resolve (missing import, cycle, in-memory
  buffer with no on-disk path).

- **`?` operator now works on `Option<T>`**: the runtime helper
  ``_capa_try`` only handled ``Ok`` / ``Err`` before, so any
  ``?`` applied to an ``Option`` raised
  ``RuntimeError: ? applied to non-Result value`` even though
  the analyzer accepted the construct. The helper now also
  unwraps ``Some(x)`` and propagates ``None_`` via the same
  early-return exception path.

### Changed

- **LSP completion is module-aware**: when ``LspContext`` runs
  the loader successfully, completion gains the imported public
  names directly from the linked module's top-level items.
  Mangled private names (``_capa_m<N>__<name>`` introduced by
  the ``pub`` enforcement pass) are filtered out so the
  suggestion list only carries names the importer's source can
  actually reach. ``LspContext.idents`` and ``.decl_sites`` are
  also filtered to entries originating in the current buffer so
  cursor-position lookups don't collide with line numbers from
  imported files.

  6 new tests at
  ``tests/test_lsp.py::TestLspModuleAwareness`` cover: no
  false-positive ``undefined name`` for imported calls, imported
  ``pub`` names in completions, private names absent, mangled
  names absent, single-file fallback when the loader fails, and
  the in-memory-filename skip. Full suite: 938 passed (was 932).

- **`?` operator: inline hoist when the position allows it**.
  The transpiler now special-cases the three statement contexts
  that don't need an exception to propagate failures:
  ``let pat = expr?``, ``return expr?``, and ``expr?`` as a
  bare expression statement. Each is lowered to an inline
  ``isinstance(__capa_try_N, Err) or __capa_try_N is None_``
  guard followed by an early return on failure and a
  ``.value`` read on success.

  ```capa
  // before, exception-based:
  let a = xs.first()?

  // after, inline:
  __capa_try_0 = xs.first()
  if isinstance(__capa_try_0, Err) or __capa_try_0 is None_:
      return __capa_try_0
  a = __capa_try_0.value
  ```

  When every ``?`` in a function falls in a hoist-eligible
  position, the ``@_capa_wrap`` decorator is also skipped, so
  the function pays no per-call overhead at all. ``?`` in
  expression positions (call arguments, operands of an
  operator, branches of an ``if`` expression) keeps using the
  existing ``_capa_try`` exception path.

  Micro-benchmark (200k iterations on Python 3.14):
  - Ok path: 0.30us/call → 0.22us/call (1.36x).
  - Err path: 0.52us/call → 0.06us/call (8.91x), no exception
    raised when the ``?`` is hoist-eligible.

  Implementation: ``capa/transpiler/_statements.py``
  (``_emit_let``, ``_emit_stmt`` for ``ReturnStmt`` and
  ``ExprStmt``, helper ``_emit_try_check``) and
  ``capa/transpiler/__init__.py`` (new ``_uses_exception_try``
  walker; updated ``_TRY_HELPER`` for ``Option`` support).

  7 new tests at
  ``tests/test_transpiler.py::TestQuestionMarkHoisting`` cover
  the hoisted let / expression-stmt shapes, the
  ``@_capa_wrap`` skip when only hoisted, the expression-
  position fallback still using ``_capa_try``, ``?`` on
  ``Option`` in both hoisted and expression positions, and
  multi-``?`` chains getting unique temps. Full suite: 932
  passed (was 925).

## [0.8.0-beta], 2026-05-15

This release graduates Capa from alpha to beta. The label
change reflects the maturity of what is in the box rather than
new feature work: the module system is feature-complete (with
`pub` enforcement landing this cycle), the REPL is genuinely
usable, the manifest gained a per-function ineligibility proof,
and the public-facing voice (homepage, README, why.html) was
rebalanced so the language reads as a capability-typed language
first and a supply-chain artefact emitter second. What still
keeps Capa pre-1.0 is ecosystem (no native backend, no package
manager) and any pre-1.0 syntax shifts, not language
completeness.

### Changed

- **Long-form design / paper drafts are local-only**: removed
  the `WHITEPAPER.md` stub (placeholder pointing at a document
  that was never going to be written publicly) and untracked
  `docs/paper-draft.md` (the workshop paper draft). Both stay
  on disk; the `.gitignore` now lists `docs/paper-draft.md`
  alongside the pre-existing `Capa-WhitePaper.md` so a local
  copy is the canonical location. The paper track is private
  until / unless it becomes a venue submission; the design
  rationale that fed it stays public in
  `docs/semantics.md`, `docs/positioning.md`, `docs/cra.md`,
  `docs/regulatory.md`, `docs/empirical_micro.md`, and the
  `benchmarks/README.md`.

  Knock-on cleanups so the public surface no longer points at
  the removed files:
  - `README.md`: dropped the `WHITEPAPER.md` and
    `docs/paper-draft.md` entries from the file-tree and the
    "User-defined capabilities (WhitePaper §4.6)" prose.
  - `CONTRIBUTING.md`: replaced the `WHITEPAPER.md` "internals"
    pointer with concrete pointers to `docs/semantics.md`,
    `docs/positioning.md`, and `Capa-EBNF.md`.
  - `.github/PULL_REQUEST_TEMPLATE.md` and
    `.github/ISSUE_TEMPLATE/feature_request.yml`: dropped the
    `WHITEPAPER.md` link; the issue template now points at
    `docs/positioning.md` instead.
  - Source comments / docstrings: removed the stale
    `WhitePaper §4.3` / `§4.6` forward-references in
    `capa/analyzer/_discipline.py`,
    `capa/analyzer/_declarations.py`, `capa/parser/_items.py`,
    `capa/runtime/_capabilities.py`,
    `examples/net_attenuation.capa`,
    `examples/user_capabilities.capa`, and `Capa-EBNF.md`. The
    comments still describe what they describe; they just no
    longer cite a private document.
  - `TODO.md`: renamed "WhitePaper promises still open" to
    "Pending design items", updated the paper-draft entry to
    reflect its local-only status, removed remaining
    "whitepaper" mentions in prose.

  No behavioural change. Full suite: 887 passed.

### Fixed

- **Impl methods of capability traits now declare their trait**:
  a method inside `impl Trait for Type` where `Trait` is a
  capability (built-in like `Stdio` or user-defined like
  `Logger`) now lists the trait in
  `declared_capabilities`. Previously the trait was missing
  because no parameter carried its type, even though the method
  exercises the capability via `self`.

  This fixes a soundness gap in the ineligibility proof
  introduced in the same release: the exclusion set for those
  methods used to falsely name the trait, claiming the method
  was provably incapable of using a capability it actually
  implements. With the fix, the trait appears in
  `declared_capabilities` for impl methods, and is therefore
  correctly absent from `provably_excluded_capabilities`.

  Inherent impls (`impl Type` with no `Trait for`) are unchanged.
  Non-capability traits (e.g. plain `trait Eq`) are unchanged.
  Only the case where the impl's trait is in the capability
  universe propagates the trait through.

  Implementation: `capa/manifest/_funrec.py::build_manifest`
  passes an `implicit_cap` argument into `_fun_record` for impl
  methods; `_fun_record` appends it to `declared_caps` before
  computing the exclusion set. 4 new tests at
  `tests/test_attributes.py::TestIneligibilityProofs`:
  cap-trait impl, inherent impl unchanged, non-cap-trait impl
  unchanged, built-in-cap impl. Full suite: 887 passed
  (was 883).

### Added

- **Ineligibility proofs in the manifest**: every function record
  now carries a `provably_excluded_capabilities` field listing
  capabilities the function is provably incapable of exercising.
  The reviewer of the whitepaper called this out as the most
  original contribution Capa could make on the supply-chain
  axis: an SBOM that says not just "this function can touch Fs"
  but "this function provably cannot touch Net, Env, Clock,
  Random, Db, Proc, or Unsafe" is the antithesis of npm's
  permission manifest.

  ```json
  {
    "name": "render_page",
    "declared_capabilities": ["Stdio"],
    "provably_excluded_capabilities": [
      "Clock", "Db", "Env", "Fs", "Net", "Proc", "Random", "Unsafe"
    ],
    "has_unsafe": false
  }
  ```

  Soundness: Capa's discipline makes `declared_capabilities` an
  upper bound on what the function can exercise (any capability
  a callee touches must be in scope here to be passed). The
  complement against the known universe (built-in caps plus any
  user-defined caps declared in this module) is therefore a
  sound under-claim of unreachable capabilities. The proof is
  voided when `Unsafe` is declared: the escape hatch can
  side-step the discipline, so for those functions
  `provably_excluded_capabilities` is empty rather than an
  over-claim.

  Also embedded in the SBOM emitters:
  - CycloneDX as `capa:provably_excluded_capability` properties
    on each function component.
  - SPDX 2.3 as `provably_excluded_capability` annotations.

  Known caveat: impl methods whose `impl` is *of* a capability
  trait do not currently list the trait in
  `declared_capabilities` even though they exercise it via
  `self`. A follow-up will populate that from the impl's
  `trait_name`.

  6 new tests at `tests/test_attributes.py::TestIneligibilityProofs`
  cover Stdio-only, no-caps, Unsafe voiding the proof, user-defined
  capability in the universe, declared user cap not excluded, and
  the CycloneDX property emission. Full suite: 883 passed
  (was 877).

- **REPL: `.types <expr>` meta command**: prints the inferred
  type of an expression without running the program. Uses the
  current accumulated state's scope, so locals, imported items,
  and pre-bound capabilities are all visible.

  ```
  capa> .types 1 + 2
  : Int
  capa> .types stdio
  : Stdio
  capa> .types [1, 2, 3]
  : List<Int>
  capa> let name = "Capa"
  capa> .types name
  : String
  ```

  Mechanism: the REPL appends the expression as a bare
  expression statement (not a `let` binding, so capability
  references like `stdio` still type-check, Capa's discipline
  forbids binding caps to a `let`), runs the analyzer, and
  reads back the type of the last main-body statement from
  `result.types` keyed by node id. The transpiler / runtime are
  not involved, so side effects do not fire: a `.types
  stdio.println("MARKER")` prints `: ()` and the MARKER is not
  emitted.

  6 new tests at `tests/test_repl.py::TestReplEndToEnd`
  exercise primitives, capabilities, current-scope locals,
  the no-run guarantee, the empty-arg usage hint, and graceful
  handling of compile errors. Full suite: 877 passed (was 871).

- **REPL: multi-line block continuation**: `if`, `for`, `while`,
  and `match` statements at the prompt now switch to a
  continuation prompt that gathers the indented body and any
  `else` / `elif` arms, terminating on a blank line.

  ```
  capa> let x = 5
  capa> if x > 0
  ...       stdio.println("positive")
  ...   else
  ...       stdio.println("non-positive")
  ...
  positive
  capa>
  ```

  Previously, only top-level forms (`fun`, `type`, etc.) got
  the continuation prompt; statement-level blocks were not
  reachable interactively because the parser could not see a
  full block in a single one-line input.

  Mechanism: a small `_starts_block_statement(line)` heuristic
  in `capa/repl.py` recognises the four block-opening keywords;
  the REPL loop then re-uses the existing top-form continuation
  pattern (`input("... ")` until blank line) and feeds the
  gathered lines into `main_lines` with one extra indent each.

  4 new tests at `tests/test_repl.py` cover the heuristic plus
  end-to-end `if`/`for`/`while` blocks. Full suite: 871 passed
  (was 867).

- **REPL pre-binds every standard capability**: `capa repl` now
  ships `stdio`, `fs`, `net`, `env`, `clock`, and `random` in
  scope at the prompt, all under their conventional lowercase
  names. Previously only `stdio` was available and users had to
  declare a wrapper function to reach for anything else.

  ```
  $ capa repl
  Capa REPL. Type .help for commands, .exit to leave.
  capa> clock.now_secs()
  1715812345.123
  capa> random.float_unit()
  0.4827
  ```

  `Unsafe` is intentionally not pre-bound. The escape-hatch
  pattern (declare a function that takes `Unsafe`, call it from
  the prompt) is the same as in production code and stays the
  way to opt in.

  Mechanism: the synthesised main signature now lists every cap
  as a parameter, and the body opens with one read-only probe per
  cap (`fs.allows("/")`, `net.allows(...)`, etc.) so the
  analyzer's "declared but never used" check passes regardless of
  what the user has typed yet. The transpiler's main-bootstrap
  already iterates `main`'s params and instantiates each
  capability by name, so the run side picks up the new caps with
  zero change there.

  2 new tests at `tests/test_repl.py::TestReplEndToEnd` exercise
  `clock` and `random` directly at the prompt. Full suite: 867
  passed (was 865).

- **Specialised diagnostic when reaching for a private item**:
  the "undefined name" / "undefined type" hint now recognises
  when the missing reference is a private item of an imported
  module and points at the right fix.

  ```
  error: undefined name 'helper' (private to module 'util';
                                  mark it 'pub' to expose)
     3 |     let n = helper(3)
                     ^
  ```

  When the same private name appears in two or more imports the
  diagnostic lists them all so the user can pick. The typo
  ("did you mean") hint still wins for names that are not
  private in any import.

  Mechanism: the loader hands the analyzer a per-alias map of
  private names (alongside the existing per-alias map of public
  names). The shared ``_hint_did_you_mean`` helper consults the
  private map first and short-circuits the typo guess when it
  finds a match. Both the `_check_ident` and `_check_type_name`
  sites pick up the new hint without code changes at the call
  sites.

  4 new tests at
  `tests/test_loader.py::TestPrivateDiagnostic`: function,
  type, regression that typos still hint, and two-module
  collision. Full suite: 865 passed (was 861).

- **`pub` visibility enforcement**: the `pub` keyword has parsed
  on every top-level item for a long time without doing anything;
  it now actually blocks imported modules' private items from
  being reached by importers.

  ```capa
  // util.capa
  fun helper(x: Int) -> Int          // private to util
      return x + 1
  pub fun outer(x: Int) -> Int       // visible to importers
      return helper(x)

  // main.capa
  import util
  fun main(stdio: Stdio)
      stdio.println("${outer(3)}")   // works: 4
      stdio.println("${helper(3)}")  // error: undefined name 'helper'
  ```

  Mechanism: per-module name mangling at link time. For each
  non-root imported module the loader picks a unique prefix
  (`_capa_m<N>`) and renames every private item's declaration to
  `<prefix>__<name>`. References to the same names inside the
  module's own items are rewritten to match: `Ident` references,
  `TypeName` annotations, `StructLit.type_name`, and
  `ImplBlock.trait_name` / `type_name`. Public items are not
  renamed, so importers continue to call them by their declared
  names. The qualified-call rewriter's exports map is also
  filtered to pub-only, so `M.private_fn()` is denied too.

  The analyzer is unchanged: it still sees a single flat global
  scope. The importer's call to a private function hits the
  regular "undefined name" diagnostic because the original name
  is no longer in scope.

  **Behavior change**: pre-existing multi-file Capa code that
  imported modules without putting `pub` on the imported items
  will now fail at the call site with "undefined name". Add
  `pub` to anything an importer is expected to reach.

  Implementation: `capa/loader.py::_mangle_private_items` +
  `_PrivateRenameWalker`. 8 new tests at
  `tests/test_loader.py::TestPubVisibility` cover: private
  function blocked from importer; private function still
  callable inside its module; private type usable internally;
  private qualified call blocked; same private name in two
  modules with no clash; `pub` on root items as no-op;
  private const blocked from importer; private type blocked
  from importer.

  Closes the only follow-up left on the module-system axis.

  Full suite: 861 passed (was 853).

- **Stdlib paths via `CAPA_PATH`**: the module loader now
  accepts a configurable list of search roots. After failing to
  find an import relative to the importer's directory, it tries
  each entry in turn; proximity wins so a project-local module
  always shadows one of the same name on the search path.

  ```sh
  $ export CAPA_PATH=/usr/local/share/capa:./libs
  $ capa --run app.capa     # 'import greeter' now resolves to
                            # ./libs/greeter.capa (or /usr/local/...)
                            # if no greeter.capa sits next to app.capa
  ```

  Entries are separated by `os.pathsep` (`;` on Windows, `:`
  elsewhere). Empty entries and non-existent directories are
  silently skipped, so a stale `CAPA_PATH` does not turn into
  a noisy error on every run. Missing-import diagnostics now
  list every path that was tried, so it is obvious whether
  the fix is to install the dependency, adjust `CAPA_PATH`,
  or correct the import statement itself.

  No bundled stdlib ships yet; this is the resolution
  mechanism that future stdlib modules will hang off of.

  Implementation: `ModuleLoader(search_paths=[...])` accepts
  the search roots; the CLI reads `CAPA_PATH` and passes the
  existing directories to the loader (both in the regular
  run/check path and inside the watch loop's mtime-expansion
  pass). 6 new tests in
  `tests/test_loader.py::TestSearchPathResolution`.

  Full suite: 853 passed (was 847).

- **Watch mode**: `capa --watch file.capa` re-runs the program
  every time the file (or any of its imported modules) changes
  on disk. Implies `--run`. Useful for iterative development
  in the same shape as `cargo watch run` or `node --watch`.

  ```
  $ capa --watch hello.capa
  Capa watch mode. Watching hello.capa for changes. Ctrl-C to exit.
  Hello, world!
  --- rerun at 14:32:07 ---
  Hello, Capa!
  ```

  Implementation: a polling loop spawns a fresh `python -m
  capa --run <file>` subprocess on each iteration; the watch
  process keeps zero compilation state across runs. The
  watched-file set starts at the root and expands after each
  successful run with whatever the loader reported as
  imported sources. Cycles, parse errors, and missing imports
  during a rerun are shown via the child's stderr and the
  watcher keeps polling. Ctrl-C exits cleanly.

  Trade-off: ~50-100ms process-startup cost per iteration,
  against zero refactor of `main()`'s state machine. For
  interactive watch use, the cost is invisible.

  2 new tests in `tests/test_watch.py::TestWatchSyncEdges`
  cover the synchronous edges (missing file argument, file
  not found). The interactive loop itself is left
  test-covered by exercise; subprocess-and-signals tests
  proved too flaky across platforms to justify their
  brittleness.

  CLI subcommand structure unchanged; `--watch` is a top-
  level flag like `--run`. Help text and `docs/start.html`'s
  CLI table both updated.

  Full suite: 847 passed (was 845).

- **Qualified module access**: `foo.fn(args)` now resolves to
  the function `fn` imported from module `foo`. Closes one of
  the three pending items left after the MVP. Both forms
  work side by side:

  ```capa
  import util

  fun main(stdio: Stdio)
      stdio.println(util.greet("Capa"))   // qualified
      stdio.println(greet("Capa"))        // unqualified still ok
  ```

  Aliasing via `as` works too:

  ```capa
  import util as U
  ...
      U.greet("alias")
  ```

  Mechanism: a post-link rewrite pass in
  `capa.loader::_rewrite_qualified_calls` walks the merged
  AST and replaces every `MethodCall(Ident(alias), method,
  args)` with `Call(Ident(method), args)` when `alias` is a
  registered import alias and `method` is one of that
  module's directly-declared names. The analyzer and
  transpiler do not need to know about modules; they only
  see plain function calls. Two imports sharing the same
  alias (without disambiguating `as`) raise a clear loader
  error.

  4 new tests in `tests/test_loader.py::TestQualifiedModuleAccess`
  covering qualified call resolution, unqualified-still-works
  regression, alias-qualified call, and a unit test of the
  `LinkedModule.module_exports` map. Full suite: 845 passed
  (was 841).

  Now pending in the module-system follow-ups: only `pub`
  enforcement and stdlib paths.

- **Per-file error-snippet rendering for imported modules**.
  Errors originating in an imported module now show the
  imported file's source line, not the root file's. Closes
  one of the deliberately-deferred items from the module-
  system MVP.

  Mechanism:
    - `capa.tokens.Pos` gains a `filename: str = ""` field;
      the lexer populates it from its own filename parameter
      so every token (and downstream AST node) carries the
      file it came from.
    - The analyzer takes an optional `sources: dict[str, str]`
      map (filename -> text); `_err` looks up the source for
      the position's filename if the map is set, falling back
      to the analyzer's primary `source` / `filename` for
      single-file inputs and built-in positions.
    - The CLI passes `linked.sources` (already collected by
      the loader) to `analyze()` whenever the loader was
      invoked.

  Before: an error in `utils.capa` rendered against
  `main.capa`'s source, so the snippet was wrong (or empty
  if line numbers were past the root file's length). Now the
  snippet is from `utils.capa` and the filename in the
  diagnostic header points at the right file.

  No new public API; existing callers of `analyze(module,
  source, filename)` keep working unchanged. Two new tests in
  `tests/test_loader.py::TestImportedFileErrorRendering`
  covering the imported-file case + a regression that
  single-file errors still render correctly. Full suite: 841
  passed (was 839).

- **REPL MVP** (`capa repl`). Closes the second of the five
  long-standing known limitations called out in the previous
  release.

  Usage:

  ```
  $ capa repl
  Capa REPL. Type .help for commands, .exit to leave.
  capa> let x = 7
  capa> x * 2
  14
  capa> fun double(n: Int) -> Int
  ...     return n * 2
  ...
  capa> double(5)
  10
  capa> stdio.println("done")
  done
  capa> .exit
  ```

  **Implementation strategy**: each input is bucketed as a
  top-level declaration, a statement, or a bare expression
  (auto-wrapped as `stdio.println("${...}")` so the value is
  shown). All inputs accumulate; on each turn the full
  program is re-assembled, re-lexed, re-parsed, re-analysed,
  re-transpiled, and re-executed as a subprocess. Captured
  stdout is diffed against the previous run so the user
  sees only the *new* output. Wasteful but correct, and
  small enough to fit in a single self-contained module
  (`capa/repl.py`, ~280 lines). The synthesised `main`
  always starts with `stdio.print("")` so the capability
  counts as used (silencing the "declared but never used"
  check) without producing visible output.

  **Meta commands**: `.exit` / `.quit`, `.reset` (clear
  state), `.show` (print accumulated program), `.help`.

  **MVP scope**: only `Stdio` is pre-bound; other built-in
  capabilities (`Fs`, `Net`, `Env`, `Clock`, `Random`,
  `Unsafe`) would trigger the unused-capability check. Users
  needing them declare a function that takes the capability
  and call it.

  **Tests**: 18 in `tests/test_repl.py`. 10 unit tests for
  the helpers (`_is_top_level_form`,
  `_is_bare_expression`, `_is_unit_typed_call`,
  `_ReplState.assemble`) and 8 end-to-end via a `python -m
  capa repl` subprocess with scripted stdin (banner +
  clean exit, bare expression, let-then-use, function
  decl + call, `stdio.println` unwrapped, `.reset` clears
  state, `.show` prints the program, `.help` lists meta,
  error keeps REPL alive).

  Full suite: 839 passed (was 821).

  CLI subcommand dispatch in `capa/cli.py` adds `repl`
  alongside `init` and `lsp`. Roadmap and TODO updates
  reflect MVP-landed; the four remaining known limitations
  are now: package manager / registry, native backend,
  async / await, qualified module access. Down from five.

- **Module system MVP** (`capa/loader.py`, `import foo.bar` now
  works end-to-end). Closes the single-file-only limitation
  that has stood since v0.2.

  **Semantics** (this iteration):
    - `import foo.bar` resolves to
      `<importer-dir>/foo/bar.capa`.
    - All top-level declarations (`fun`, `type`, `trait`,
      `capability`, `impl`, `const`) of the imported module
      become accessible **unqualified** in the importing
      module.
    - Transitive imports are followed depth-first; each file
      is loaded at most once (diamond-import deduplication).
    - Cyclic imports raise a named-cycle error.
    - Name conflicts (two imports defining the same top-level
      name) are detected at link time with both source
      locations.
    - Missing target files produce a clear "cannot resolve"
      diagnostic.

  **Still pending** (P2 follow-ups, deliberately scoped out
  of MVP):
    - Qualified access (`bar.fn(...)`).
    - `pub` visibility enforcement (`KW_PUB` already parses).
    - Stdlib path resolution from a configured root.
    - Per-file source-snippet rendering for errors that
      originate in imported modules.

  Implementation: `capa/loader.py::ModuleLoader.load_root`
  parses the root file, walks Import nodes depth-first, and
  produces a `LinkedModule` (flat AST + `sources` map). The
  CLI invokes the loader instead of `Parser.parse_module`
  whenever analysis is needed (`--check`, `--run`,
  `--manifest`, `--cyclonedx`, `--spdx`, `--vex`,
  `--provenance`, `--doc`, `--transpile`). The
  parse-only path (`--parse`) still uses the raw parser so
  the inspected AST shows imports verbatim.

  10 new tests in `tests/test_loader.py` covering the no-
  imports baseline, single import, transitive chain, dotted-
  path resolution to subdirectory, cycle detection, name-
  conflict reporting, missing-file reporting, diamond
  deduplication, and two end-to-end runs via the CLI. The
  prior `test_import_rejected` analyzer test was rewritten as
  `test_import_silently_accepted_by_direct_analyzer` to
  document the new "loader handles imports; analyzer ignores
  unresolved Imports" contract. Full suite: 821 passed (was
  811).

  The "Known limitations" callouts in `docs/roadmap.html`
  and `TODO.md` were updated to reflect MVP-landed + the
  P2 follow-ups.

- **More stdlib gaps closed**: `List.find`, `List.find_index`,
  `Map.pairs`, `JsonValue.as_number` (alias), `JsonValue.as_int`,
  and **assignment as a single-line match arm body**. All
  surfaced as friction while writing the design-pattern CVE
  case studies and Option/Result tests in this iteration.

  - `List.find(p: T -> Bool) -> Option<T>`: first element
    matching the predicate.
  - `List.find_index(p: T -> Bool) -> Option<Int>`: index of
    the same.
  - `Map.pairs() -> List<(K, V)>`: every entry as a tuple,
    composes cleanly with `for (k, v) in m.pairs()`.
  - `JsonValue.as_number`: alias for `as_num` (both return
    `Option<Float>`); covers users who reach for the longer
    name.
  - `JsonValue.as_int -> Option<Int>`: integer-valued
    extraction; `Some(int(v))` when the underlying float is
    integer-valued (1.0, -7.0), `None` otherwise (3.14).
  - Assignment in single-line match arms:
    `_ -> sum = sum + x` now compiles; previously required
    the multi-line indented form. Parser change in
    `_parse_match_arm` parallels the `return`/`break`/
    `continue` fix shipped earlier in this iteration.

  Registrations in `capa/builtins.py` (List + Map + JsonValue
  rows); runtime implementations on `CapaList` (`find`,
  `find_index`) and `_JsonBase` (`as_number`, `as_int`);
  transpiler lowering for `Map.pairs -> dict.items()`. 8 new
  regression tests in
  `tests/test_transpiler.py::TestStdlibStringsListsMapsJson`
  covering hit / miss / non-integer-float / pairs +
  destructuring / assignment-in-arm. Stdlib reference page
  updated. Full suite: 811 passed (was 803).

- **Five new Option / Result methods**: `Option.filter`,
  `Option.or_else`, `Result.or_else`, `Result.ok`,
  `Result.err`. The Option/Result surface now mirrors the
  standard Rust/Swift/OCaml API more completely:

  | Method | Signature | Behaviour |
  |---|---|---|
  | `Option.filter` | `(T -> Bool) -> Option<T>` | `Some(x)` if predicate passes, else `None` |
  | `Option.or_else` | `(() -> Option<T>) -> Option<T>` | Lazy fallback when `None` |
  | `Result.or_else` | `(E -> Result<T, F>) -> Result<T, F>` | Lazy error recovery, can change `E` to `F` |
  | `Result.ok` | `() -> Option<T>` | `Some(v)` if `Ok(v)`, else `None` |
  | `Result.err` | `() -> Option<E>` | `Some(e)` if `Err(e)`, else `None` |

  Implementations on `Some`, `_NoneType`, `Ok`, `Err` in
  `capa/runtime/_result.py`; registrations in
  `capa/builtins.py`. The transpiler's fall-through emission
  for Option/Result methods already covers these (no
  per-method lowering needed). 6 new analyzer tests in
  `tests/test_analyzer.py::TestFunctionalCombinators`
  covering type checking + a rejected non-Bool predicate +
  error-type-change via `Result.or_else`. Stdlib reference
  page updated. Full suite: 803 passed (was 797).

- **Divergent statements (`return`, `break`, `continue`)
  allowed in single-line match arms**. Previously only the
  multi-line indented arm form accepted divergent statements:

  ```capa
  let v = match r
      Err(_) ->
          return 0 - 1            # was the only way
      Ok(v) -> v
  ```

  The single-line form `Err(_) -> return 0 - 1` parsed as an
  expression and rejected `return` as not-an-expression. Now
  both forms work; the parser promotes a single-line divergent
  statement to a one-statement block, and the analyzer treats
  blocks ending in `return` / `break` / `continue` as
  divergent (their type does not constrain the match's
  result-type unification).

  Surfaced as friction while writing the design-pattern CVE
  case studies; the multi-line workaround was readable but
  verbose. Parser change at
  `capa/parser/_statements.py::_parse_match_arm`; analyzer
  change at
  `capa/analyzer/_expressions.py::_check_match_expr` plus a
  new `_block_diverges` helper. 5 new regression tests in
  `tests/test_transpiler.py::TestMatchArmDivergent` covering
  return / break / continue / multi-line regression / all-
  arms-divergent. Full suite: 797 passed (was 792).

- **Three new String stdlib methods**: `char_at(i: Int) ->
  Option<String>`, `substring(start: Int, end: Int) ->
  String`, `index_of(needle: String) -> Option<Int>`. Fills
  gaps that real Capa programs (the CVE case studies in this
  release) had to work around with `split` + index
  acrobatics. Lowerings:
    - `char_at` returns `Some(s[i])` if `0 <= i < len(s)`
      else `None_`. Mirrors `List.get`'s
      `Option`-on-out-of-range convention.
    - `substring` lowers to a plain Python slice; Python's
      forgiving slice semantics carry through, so
      out-of-range indices clamp.
    - `index_of` lowers to `s.find(needle)` hoisted into a
      one-shot lambda that converts `-1` into `None_` and
      any non-negative result into `Some(i)`.
  Builtin registry: `capa/builtins.py`. Transpiler lowering:
  `capa/transpiler/_methods.py::_emit_string_method`. Tests:
  6 in `tests/test_analyzer.py::TestStringBuiltinMethods`
  (type-checking the three methods + their type errors) + 6
  in `tests/test_transpiler.py::TestTranspileBasic` (runtime
  smoke tests with in-range and out-of-range / found and
  missing cases). Stdlib reference page updated. Full suite:
  792 passed (was 780).

- **CVE case study (design-pattern class): pickle / Java
  ObjectInputStream gadget chains**
  (`examples/cve_pickle.capa` + `docs/cve_pickle.md`). Fourth
  library in the empirical-at-scale arc, completing coverage
  of the four canonical design-pattern bug classes:
  deserialisation-as-codegen (PyYAML), template injection
  (Jinja2), parser-as-fetcher (lxml XXE), and now
  **gadget-chain unserialisation** (pickle, ObjectInputStream,
  BinaryFormatter, Marshal.load, unserialize). The shared
  problem: a deserialiser that produces unbounded runtime
  types (Python object, Java Object, .NET object) must by
  construction have a mechanism to construct any type, and
  that mechanism is indistinguishable from "interpret the
  input as code". Microsoft deprecated `BinaryFormatter` in
  .NET 5 explicitly because the class is *unfixable*. The
  Capa argument: `decode: (String) -> Result<JsonValue,
  DecodeError>` returns a closed algebraic type; the decoder
  cannot produce a `subprocess.Popen` because there is no
  place in the type to put one. With this fourth study the
  arc has covered the four canonical bug classes; subsequent
  case studies are additional data points within the four,
  not new classes. Regression test in
  `tests/test_transpiler.py::test_cve_pickle`. Full suite:
  780 passed.

- **CVE case study (design-pattern class): XXE (XML external
  entity)** (`examples/cve_lxml_xxe.capa` +
  `docs/cve_lxml_xxe.md`). Third library in the empirical-at-
  scale arc, after PyYAML and Jinja2 SSTI. The lxml /
  xml.etree / Java JAXP / .NET XmlReader / PHP libxml /
  Ruby Nokogiri CVE family: XML parsers that by default
  resolve external entity references, turning a "parser" into
  an arbitrary-file-read and SSRF primitive. The Capa parser's
  signature `(String) -> Result<XmlNode, ParseError>` has no
  `Fs` and no `Net`, so resolution of `file://` or `http://`
  entities is structurally impossible. The writeup generalises
  the pattern as "parsers should parse, not fetch" and lists
  other instances (YAML !include, JSON Schema $ref URLs, CSV
  formula evaluation, Markdown !include extensions, config
  loaders). Regression test in
  `tests/test_transpiler.py::test_cve_lxml_xxe`. Full suite:
  779 passed.

- **CVE case study (design-pattern class): Jinja2 SSTI**
  (`examples/cve_jinja2_ssti.capa` +
  `docs/cve_jinja2_ssti.md`). Second library in the
  empirical-at-scale arc, after PyYAML. Server-side template
  injection (SSTI): template engines that allow attribute
  traversal and method calls in the substitution language
  expose arbitrary code execution. The bug class is endemic
  (Jinja2, Mako, Velocity, Freemarker, Smarty, Twig, ERB,
  Handlebars). Capa's template engine has signature `(String,
  Map<String, String>) -> Result<String, RenderError>`, and
  the substitution parser refuses to accept any expression
  containing `.` or `(`. Strictly stronger than Jinja2's
  SandboxedEnvironment: the security boundary is *syntactic*
  (parser-level allow-list) rather than *semantic* (Python
  attribute deny-list), so escape chains cannot apply. The
  writeup includes a comparison table and generalises the
  argument to SQL parameter binding, HTML/CSS escaping, and
  JSON Path / GraphQL field selection. Regression test in
  `tests/test_transpiler.py::test_cve_jinja2_ssti`. Full
  suite: 778 passed.

- **Provenance signing workflow (Capa SLSA L1 to L2)**:
  `deploy/sign-provenance.sh` + `docs/provenance-signing.md`.
  Capa's `--provenance` flag emits a SLSA Build L1 attestation;
  the new shell script and tutorial document the L1-to-L2 path
  via cosign. Three signing modes covered: keypair-based
  (offline / private), Sigstore keyless (public-chain), and
  hosted-build-platform (GitHub Actions with
  `actions/attest-build-provenance` for true SLSA L2). The
  tutorial includes verification recipes for each mode and a
  per-framework mapping showing what each gets you under CRA,
  NIS2, DORA, NIST SSDF, and OWASP SCVS. Capa stays
  independent of any specific signing service; the script is
  example-driven, not bundled. Honest about scope: signing
  alone does not formally lift L1 to L2 (L2 requires a hosted
  build platform); Mode A is documented as "signed L1" rather
  than overclaiming.

- **CVE case study (design-pattern class): PyYAML
  `yaml.load()` arbitrary code execution** (CVE-2017-18342,
  `examples/cve_pyyaml.capa` + `docs/cve_pyyaml.md`). First of
  a new class of case study: design-pattern vulnerabilities,
  where the legitimate library's API is the bug. PyYAML's
  `yaml.load` deserialises arbitrary Python objects, including
  `!!python/object/apply:os.system [...]`, executing code as
  a side effect of "parsing". The bug class is endemic across
  ecosystems: Python's `pickle.loads`, Java's
  `ObjectInputStream`, .NET's `BinaryFormatter`, Ruby's
  `Marshal.load`, Node's `serialize-javascript`. Capa
  structurally rules out the class because `parse_structured:
  (String) -> Result<JsonValue, ParseError>` declares no
  `Unsafe` capability; the body cannot reach `py_invoke` and
  therefore cannot construct arbitrary runtime objects. The
  writeup notes this is *strictly stronger* than PyYAML's
  `safe_load` mitigation (which is opt-in and routinely
  misconfigured per Trail of Bits 2024 audit). Regression test
  in `tests/test_transpiler.py::test_cve_pyyaml`. Distinct
  category from the six supply-chain delivery CVEs already in
  the repo. Full suite: 777 passed.

- **Agda mechanisation skeleton** (`proofs/CapaSyntax.agda`,
  `proofs/CapaSoundness.agda`, `proofs/README.md`). Stage 0 of
  the mechanisation plan described in `docs/semantics.md` § 8.
  States the syntax of λ_cap (types, terms, typing relation,
  small-step reduction, values), then declares four theorems as
  `postulate`: Progress, Preservation, Capability Soundness
  (corollary), Manifest Completeness. The `proofs/README.md`
  documents the staged mechanisation plan (Stages 1-4),
  preferred prover choice (Agda, following PLFA conventions),
  and a status badge tracking which stage is landed. Honestly
  marked as "skeleton, not yet typechecked"; install Agda
  >= 2.6.4 to verify the structure. The artefact is what a
  workshop-paper reviewer expects to see as evidence of intent
  to mechanise; replacing the postulates with proofs is
  workshop-paper-sized future work.

- **Workshop paper draft** (`docs/paper-draft.md`), ~5000
  words, all sections written in first-pass form: abstract,
  introduction, background and related work, three-layer
  discipline, implementation, six-CVE empirical evaluation,
  runtime overhead, SBOM-diff information-gain, regulatory
  mapping, discussion and limitations, conclusion, references,
  two appendices (reproduction + non-claims). Status: working
  draft v1, ready for iteration; convert to LaTeX when
  targeting a specific venue submission. Target venues: PLAS,
  EuroS&P workshops, NDSS workshops. Closes the Tier 3
  workshop-paper-draft item from the May-October plan.

## [0.7.0-alpha], 2026-05-15

The sixth tagged release. **Focus: closing the supply-chain
governance stack.** The compiler now natively emits all four of
the standard governance artefacts (SBOM, VEX, provenance, audit)
at per-function granularity, and a multi-jurisdiction
comparative document maps each artefact onto five frameworks
(CRA, NIS2, DORA, NIST SSDF, OWASP SCVS).

The shipped artefact triangle, all from one source:

- **CycloneDX 1.5 SBOM** (`--cyclonedx`): pre-existing, now
  includes a top-level `vulnerabilities[]` array when any
  `@vex` is present.
- **SPDX 2.3 SBOM** (`--spdx`, new): Linux Foundation companion,
  same per-function metadata via SPDX `annotations[]`.
- **CycloneDX VEX** (`--vex`, new): per-function exploitability
  claims from a new `@vex(cve, status, justification, detail)`
  attribute. Genuinely novel: no other language emits VEX at
  function granularity.
- **SLSA Build L1 provenance** (`--provenance`, new): in-toto
  Statement v1 + SLSA Provenance v1.0 predicate, source
  SHA-256, deterministic invocation ID.

Plus two new auditor-facing programs in Capa:

- **SBOM diff tool** (`examples/sbom_diff.capa`): consumes two
  CycloneDX SBOMs and reports per-function capability
  widenings, narrowings, additions, removals. The alarm bell
  for supplier widening that PURL-only diffs cannot raise.
- **VEX demo** (`examples/vex_demo.capa`): paired with the
  `@vex` attribute, illustrates three flavours of per-function
  exploitability claim.

Plus a consolidated regulatory mapping:

- **`docs/regulatory.md`**: 8-by-5 comparative table (Capa
  artefacts vs CRA/NIS2/DORA/NIST SSDF/OWASP SCVS), with each
  cell classified as direct/indirect/partial/out-of-scope, and
  a per-framework section explaining what Capa contributes and
  what stays organisational. `docs/cra.md` remains as the CRA
  article-by-article deep-dive; the two cross-reference.

Test count: **776** (from 748 at v0.6.0-alpha), across
end-to-end transpiler, lexer, parser, analyzer, formatter,
LSP, attributes (now including 10 VEX + 7 provenance + 11
SPDX), docs, init-project, and Hypothesis property suites.

### Added

- **Consolidated regulatory mapping** (`docs/regulatory.md`).
  Final piece of the Tier 2 plan: a multi-jurisdiction
  comparative document covering five frameworks in one table.
  Rows are the eight Capa artefacts (manifest, CycloneDX SBOM,
  SPDX SBOM, VEX, SLSA provenance, audit pipeline, SBOM diff,
  soundness sketch); columns are CRA + NIS2 + DORA
  (cybersecurity articles only) + NIST SSDF + OWASP SCVS. Each
  cell classifies the fit as direct, indirect, partial, or out
  of scope. Per-framework deeper section then explains what
  Capa contributes specifically and what stays organisational.

  Frameworks **deliberately excluded** with reasoning: ISO
  27001, SOC 2, PCI DSS, HIPAA (management/audit, Capa does
  not deliver compliance); US EO 14028 (subsumed by SSDF); AI
  Act, GDPR (tangential to supply-chain governance); SWID
  (dying format); the business-continuity side of DORA (not
  technical).

  Existing `docs/cra.md` remains as the CRA article-by-
  article deep-dive; both documents cross-reference. Surfaced
  in the README directory tree and the site footer's
  Specification section.

  **Tier 2 of the governance-stack roadmap complete.** The
  supply-chain governance stack now has both the technical
  artefacts (Tier 1: SBOM + SPDX + VEX + SLSA + diff + audit)
  and the regulatory positioning (Tier 2: CRA deep-dive +
  multi-jurisdiction comparative) shipped.

- **SLSA Build L1 provenance attestation** (`capa --provenance
  file.capa`, `capa.manifest.build_provenance`). Final piece of
  the Tier 1 governance-stack work. Emits an `in-toto Statement
  v1` envelope carrying a `SLSA Provenance v1.0` predicate;
  consumable by any SLSA-aware verifier (slsa-verifier, in-toto
  attest, cosign verify-blob). Closes the "where did this SBOM
  come from?" question with an industry-standard format and
  makes the SBOM/VEX/provenance triangle complete.

  Subject is the SHA-256 of the source .capa file. Build
  details fix the build type to
  `https://capa-lang.org/build/transpile-to-python/v1`, with
  the source filename as an external parameter and the Capa
  version + Python target (`python>=3.10`) as internal
  parameters. The invocation ID is deterministic per
  source+filename so reproducible builds get matching IDs.

  L1 scope: provenance is generated and distributed. Signing
  (which lifts to L2) is left to external tooling (cosign,
  sigstore) so Capa stays independent of any specific signing
  service.

  Implementation at `capa/manifest/_provenance.py`; 7 new
  regression tests in `tests/test_attributes.py::TestProvenance`
  covering envelope, subject digest, build/run details,
  deterministic invocation ID, and digest sensitivity to source
  changes. Full suite: 776 passed (was 769).

  **Tier 1 of the governance-stack roadmap complete**: SBOM
  diff, SPDX 2.3 emission, VEX integration, and SLSA L1
  provenance all landed. The next piece (Tier 2) is the
  consolidated `docs/regulatory.md`.

- **VEX (CycloneDX vulnerabilities) emission with per-function
  granularity** (`@vex` attribute, `capa --vex file.capa`,
  embedded in `--cyclonedx`). The genuinely novel piece of the
  Tier 1 governance-stack work. Standard VEX (CycloneDX VEX,
  CSAF VEX) operates at package level: "openssl 3.0.7 has
  CVE-X; our product is/isn't affected because reason Z". Capa
  refines that to per-FUNCTION granularity: "in function
  `parse_user_agent`, CVE-X is `not_affected` because the
  function declares no `Net` and the exploit's network sink
  cannot be reached from this entry point". The capability
  discipline gives the claim a machine-verifiable basis: any
  later edit that adds `Net` to that function would invalidate
  the VEX assertion and the diff would be loud in code review.
  Implementation:
  - New `@vex(cve, status, justification, detail)` attribute,
    validated by the analyzer's schema (unknown keys rejected).
  - `capa.manifest._vex` emits CycloneDX vulnerability entries
    from the parsed attributes; each entry's `affects[]` points
    at the specific function's bom-ref.
  - `--cyclonedx` now includes a top-level `vulnerabilities[]`
    array when any `@vex` is present.
  - `--vex` produces a standalone CycloneDX VEX-only document
    for consumers that prefer that workflow (CSAF-style).
  - Example: `examples/vex_demo.capa` with three @vex
    declarations showing not_affected (with justification),
    in_triage (no justification yet), and a different CVE on a
    different function.
  - Tests: 10 in `tests/test_attributes.py::TestVEX` + a smoke
    test in `tests/test_transpiler.py::test_vex_demo`.
  Full suite: 769 passed (was 759).

- **SPDX 2.3 SBOM emission** (`capa --spdx file.capa`,
  `capa.manifest.build_spdx`). Companion to the existing
  `--cyclonedx` flag: same per-function capability metadata,
  emitted in SPDX 2.3 JSON for tools and pipelines that prefer
  the Linux Foundation ecosystem (OpenChain-conformant
  pipelines, license-compliance tooling). Per-function
  metadata travels via standard SPDX `annotations[]` with a
  `capa:<key>=<value>` payload in the `comment` field;
  capability membership and intra-module calls become explicit
  `DEPENDS_ON` relationships. SPDX IDs are sanitised to match
  the spec's `SPDXRef-[A-Za-z0-9.-]+` constraint (e.g. `Foo::bar`
  becomes `SPDXRef-Fn-file.capa-Foo-bar`). The Linux Foundation
  side of the Tier 1 multi-format SBOM coverage. Second piece
  of the Tier 1 governance-stack work. 11 new regression tests
  in `tests/test_attributes.py::TestSPDX`. Full suite: 759
  passed.

- **SBOM diff tool** (`examples/sbom_diff.capa` +
  `examples/data/demo-sbom-v2.json`). A Capa program that
  consumes two CycloneDX 1.5 SBOMs emitted by `capa
  --cyclonedx` and produces a structured per-function diff:
  added/removed functions, **capability widenings** (alert),
  **capability narrowings** (improvement), and a count of
  unchanged components. Eats its own dogfood: the analyzer
  + audit pipeline + diff tool all consume the same per-
  function `capa:declared_capability` properties. First piece
  of the Tier 1 governance-stack work that complements the
  existing audit pipeline (`sbom_capability_audit.capa`,
  which compares ONE SBOM against a policy; the diff tool
  compares TWO SBOMs against each other). Regression test
  in `tests/test_transpiler.py::test_sbom_diff`.

## [0.6.0-alpha], 2026-05-14

The fifth tagged release. **Thesis-aligned focus**: the release
exists to give the PhD chapter on SBOM Governance under CRA a
coherent set of artefacts that a reviewer can cite and
reproduce.

What lands in this version:

- **Six CVE case studies** (event-stream 2018, eslint-scope
  2018, ua-parser-js 2021, torchtriton 2022, node-ipc 2022,
  xz-utils 2024), each as a paired `examples/cve_*.capa` +
  `docs/cve_*.md`. Four clean wins covering different
  ecosystems (npm, PyPI) and payloads (malicious dependency,
  credential theft, cryptominer + RAT, kernel exfil); two
  honest partial losses (legitimate-authority abuse,
  below-the-language attacks). The thesis experimental section
  has its empirical floor.

- **Runtime-overhead benchmark suite** (`benchmarks/`): three
  paired Capa + hand-Python workloads timed in-process via
  `timeit.repeat`. Headline ratios on CPython 3.14: 1.00x for
  pure compute, 1.20x for list-heavy, 1.45x for
  string-heavy. The thesis chapter on practical overhead can
  cite numbers instead of hand-waving.

- **Article-by-article CRA mapping** (`docs/cra.md`): a focused
  thesis-grade document mapping Capa's machinery onto
  Regulation (EU) 2024/2847. Annex I Part I + Part II
  requirements classified as direct, indirect, partial, or out
  of scope, with explicit narrative on which obligations Capa
  addresses and which remain organisational.

- **Empirical micro-validation** (`docs/empirical_micro.md` +
  `examples/empirical_config*.{capa,py}`): the smallest
  reproducible side-by-side of Python vs Capa for a real-world
  pattern (microservice config loader). Demonstrates that the
  capability-aware SBOM is a strict information gain over a
  PURL-only SBOM.

- **`Range<T>` is now a distinct lazy type from `List<T>`**.
  `0..n` no longer materialises into a CapaList; the iterator
  is lazy. Closes the long-standing performance issue around
  large ranges.

- **Property-based testing extended through phase 3.7**: the
  Hypothesis strategy now generates valid Capa programs with
  four capability flavours (plain, attenuated, via_helper,
  consumed), giving the linear layer direct fuzz coverage.

- **`docs/semantics.md`**: a λ_cap calculus sketch + two
  soundness theorems (Capability Soundness, Manifest
  Completeness). Referee-tractable formal anchor for the
  thesis; the mechanisation in Agda or Coq is the
  workshop-paper budget item that follows.

- **`docs/positioning.md`**: honest comparison vs Pony, Koka,
  Roc, and the Wasm Component Model. Articulates where Capa
  sits in the landscape and what it does *not* claim.

Test count: **747** (from 536 at v0.5.0-alpha), across
end-to-end transpiler, lexer, parser, analyzer, formatter,
LSP, attributes, docs, init-project, and Hypothesis property
suites.

### Added

- **Empirical micro-validation: SBOM diff Python vs Capa**
  (`examples/empirical_config.capa` +
  `examples/empirical_config_naive.py` +
  `docs/empirical_micro.md`). A small, fully reproducible
  comparison of a real-world pattern (microservice config
  loader: disk + environment + remote-flag overrides) in two
  forms. The naive Python version has one
  `load_config(path) -> dict` function conflating three
  capabilities; the Capa version splits the same logic into
  five functions whose signatures declare exactly what each
  needs. The CycloneDX SBOM emitted by `capa --cyclonedx`
  shows per-function declared capabilities (3 pure, 3
  single-capability, 1 composer with `Fs + Env + Net`, 1 main
  with `Stdio`); a PURL-only SBOM for the Python equivalent
  cannot say any of this. The pair is the smallest reproducible
  artefact for the empirical claim in the thesis that
  capability-aware SBOMs are a *strict information gain* over
  PURL-only SBOMs. Closes the "show, don't tell" gap left by
  `docs/cra.md`. Regression test in
  `tests/test_transpiler.py::test_empirical_config`.

- **CRA article-by-article mapping** (`docs/cra.md`). A
  focused thesis-grade document that maps Capa's machinery
  onto the specific articles and annex items of Regulation
  (EU) 2024/2847 (the Cyber Resilience Act). Includes a
  detailed Annex I table (Part I essential cybersecurity
  requirements + Part II vulnerability handling) classifying
  each requirement as **direct**, **indirect**, **partial**,
  or **out of scope** for Capa. The novel-contribution
  section frames the capability-aware SBOM as a strict
  superset of NTIA / CRA minimum SBOM elements (versions and
  PURLs tell you what is in the box; the capability manifest
  tells you what the box can do). The closing section is
  honest about what Capa does *not* solve under CRA
  (vulnerability disclosure, update distribution, incident
  notification, crypto correctness, DoS, hardware-side
  attacks, below-language attacks like xz-utils 2024). The
  thesis chapter on SBOM Governance under CRA can cite this
  document as the technical artefact it argues for.

- **Runtime-overhead benchmark suite** (`benchmarks/`): a small
  set of paired Capa + hand-Python workloads timed in-process
  with `timeit.repeat`. Three workloads cover three regimes
  (pure compute via `fib(25)`, list-heavy via a 1000-element
  scope analyser, string-heavy via 1000-string user-agent
  parsing). Each `.capa` has a matching `_baseline.py` with
  the same algorithm in idiomatic Python; the runner transpiles
  the Capa once, imports both as modules, and reports
  mean/stdev plus the ratio. Headline numbers on CPython 3.14:
  **1.00x for pure compute, 1.20x for list-heavy, 1.45x for
  string-heavy**. The thesis chapter on practical overhead can
  now cite numbers instead of hand-waving. Methodology and a
  detailed breakdown of what is and is not measured live in
  `benchmarks/README.md`.

- **CVE case study: ua-parser-js 2021 (npm account hijack,
  cryptominer + RAT)** (`examples/cve_ua_parser_js.capa` +
  `docs/cve_ua_parser_js.md`). The sixth CVE walkthrough and
  the fourth clean win. On 22 Oct 2021 the maintainer's npm
  account for `ua-parser-js` (about 7-8M weekly downloads) was
  compromised; three malicious versions shipped a `preinstall`
  script that, on Linux, downloaded an XMRig-based
  cryptominer, and on Windows additionally dropped DanaBot, a
  credential-stealing RAT. The case study is in the repo
  specifically to make the **payload-independence** point:
  same attack mechanism as eslint-scope 2018 (account
  hijack), wildly different payload (cryptominer + RAT vs
  npm token theft), and Capa's response is structurally
  identical. `ua-parser-js` also has the *cleanest* possible
  signature of any of the case studies (`(String) ->
  UserAgent`), so the "the declared signature should mention
  `Fs` if the function reads files" argument is at its most
  rhetorically forceful here. Regression test in
  `tests/test_transpiler.py::test_cve_ua_parser_js`. With
  this sixth study the experimental section now covers four
  clean wins (event-stream, eslint-scope, ua-parser-js,
  torchtriton) and two honest partial losses (node-ipc,
  xz-utils) across two ecosystems (npm, PyPI) and seven
  years (2018-2024).

- **CVE case study: torchtriton 2022 (PyPI typosquat)**
  (`examples/cve_torchtriton.capa` +
  `docs/cve_torchtriton.md`). The fifth CVE walkthrough and
  the third clean win, covering the Python / PyPI ecosystem
  (after event-stream and eslint-scope on npm). Recaps the
  attack: between 25-30 Dec 2022 a malicious PyPI package
  named `torchtriton` was installed by anyone running
  PyTorch's nightly build, because pip's default resolution
  preferred public PyPI over the private index. The payload
  walked `$HOME`, captured SSH keys and env vars, and POSTed
  to `*.h4ck.cfd`. The Capa-shaped kernel-launch-planning
  library has zero capabilities; the typosquat's
  `Fs + Net + Env` widening is a loud SBOM diff. With this
  fifth study the experimental section is now balanced: 3
  wins covering different ecosystems / shapes
  (malicious-dependency, credential-theft, typosquat) and
  2 honest partial losses (legitimate-authority-abuse,
  below-the-language). Regression test in
  `tests/test_transpiler.py::test_cve_torchtriton`. The
  full breakdown lives in `docs/cve_torchtriton.md`
  § "The five-case-study summary".

- **CVE case study: xz-utils 2024 / CVE-2024-3094**
  (`examples/cve_xz_utils.capa` + `docs/cve_xz_utils.md`). The
  fourth CVE walkthrough, and the most pessimistic one: a
  multi-year operation by "Jia Tan" against `xz-utils`,
  delivering a backdoor that hijacked
  `RSA_public_decrypt` in sshd via IFUNC dynamic-linker
  indirection. The attack ran beneath the language layer
  entirely: obfuscated payload bytes in test fixture files,
  build-script assembly via `.m4` autotools, and runtime
  symbol replacement at `ld.so` load time. Capa's source-
  level discipline cannot address any of those. The case
  study is in the repo precisely because a thesis that
  claims any supply-chain defence has to acknowledge attacks
  beneath the language layer. The writeup includes a layered
  table of attack surfaces and which ones Capa addresses
  (one row well, one row partially, four rows not at all).
  Pairs with the
  [positioning document](docs/positioning.md)'s "Capa is one
  defence in a stack, not a sufficient defence" claim and
  references reproducible builds, code signing, transparency
  logs as the orthogonal defences the rest of the stack
  needs. Regression test in
  `tests/test_transpiler.py::test_cve_xz_utils`.

- **Property-based testing phase 3.7**: the multi-cap
  strategy `_program_with_caps_advanced` now also samples a
  ``consumed`` flavour. The strategy emits a helper
  ``fun take_{cap}(consume {var}: {Cap}) -> Bool`` that
  takes the capability with the ``consume`` qualifier (so
  the caller cannot use it afterwards), probes it inside
  the helper, and returns. Main calls ``take_{cap}({var})``
  exactly once per consumed capability, satisfying the
  use-after-consume rule by construction (the call is the
  last action on that capability in main's body).

  Programs in the wild now mix four flavours: ``plain``
  (3.5), ``attenuated``, ``via_helper`` (3.6),
  ``consumed`` (3.7). The renamed test method
  `test_runtime_subset_under_advanced_flavours` runs 50
  Hypothesis examples per CI run; sampling typically
  produces programs that mix all four flavours across the
  declared capabilities. All four preserve
  `runtime_classes ⊆ manifest_classes` by construction; the
  test now also catches use-after-consume regressions in
  the analyser's linear layer alongside the structural and
  flow-layer regressions covered by the earlier phases.
  The property-testing arc of the external whitepaper
  review is now closed.

- **Property-based testing phase 3.6**: introduced the
  three-flavour advanced strategy (plain / attenuated /
  via_helper) that phase 3.7 extends. See the entry above.

- **Property-based testing phase 3.5**: the
  `runtime_caps ⊆ manifest_caps` property is now exercised on
  *non-trivial* inclusions. A new Hypothesis strategy
  `_program_with_caps` threads a random subset of
  `{Fs, Net, Env, Clock, Random}` through `main`'s parameter
  list (alongside the mandatory `Stdio`) and emits one
  read-only probe per declared capability so each is exercised
  at least once. The probes are
  `Fs.allows`, `Net.allows`, `Env.allows`, `Clock.now_secs`,
  `Random.float_unit`, each a pure query with no real
  filesystem or network side effect, so the test stays
  self-contained. New test method
  `TestRuntimeSubsetOfManifest.test_runtime_classes_subset_with_multiple_caps`
  runs 50 examples per CI run; sampling typically produces
  10 to 15 distinct main-signature shapes per run. With this
  the citable thesis property has actual fuzz coverage, not
  just a scaffold.

- **Property-based testing phase 3 (minimal)**: the dynamic
  counterpart of Theorem 2 from `docs/semantics.md`. New
  module `capa/runtime/_trace.py` provides an opt-in
  instrumentation that wraps every public method on every
  built-in capability class so each call appends
  `(class_name, op_name)` to a module-level list. The new
  `TestRuntimeSubsetOfManifest` test class in
  `tests/test_properties.py` runs a generated program with
  the trace enabled, then asserts that the set of capability
  classes observed at runtime is a subset of the set
  declared in the manifest emitted from the AST. Phase 3.5
  (still pending) extends the strategy to thread
  Net / Fs / Env through `main` and exercise them so the
  inclusion is non-trivial; today the strategy only uses
  Stdio so the property is `{Stdio} ⊆ {Stdio}`. The
  *scaffold* is the point: the citable property has a place
  to live and a path to broader coverage.

- **Property-based testing phase 2** (syntax-aware Capa
  program generator). Adds one new property to
  `tests/test_properties.py`: every program produced by a
  small Hypothesis composite strategy (a `main(stdio: Stdio)`
  body with 1-4 statements drawn from `let` / `var` /
  `println` / `if` / `for`, using position-indexed unique
  identifiers to avoid duplicate bindings, and integer
  literals only in expressions to avoid scope-tracking
  complexity) is asserted to lex, parse, analyse, transpile,
  and produce syntactically-valid Python. The strategy
  found two real design bugs during its own development
  (capability-must-use violation when `main` was generated
  without a `stdio` reference; duplicate `let` bindings when
  names were sampled from a fixed pool), exactly the kind of
  signal property-based testing exists to surface. 100
  Hypothesis examples per CI run, ~1 second wall clock.
  The phase 3 work (the actual citable property *runtime
  capability set ⊆ manifest declared set*) needs runtime
  instrumentation and a capability-exercising strategy; it
  is tracked in `TODO.md` and corresponds to Theorem 2 of
  `docs/semantics.md`.

- **CVE case study: node-ipc 2022 (protestware)**
  (`examples/cve_node_ipc.capa` + `docs/cve_node_ipc.md`). The
  third CVE walkthrough in the repo, deliberately picked as the
  case where **Capa partially loses**: the package's legitimate
  role (inter-process communication) requires `Net` and `Fs`,
  so a rogue maintainer with legitimate authority can misuse
  those capabilities within the bounds the type system allows.
  The structural discipline that handled event-stream and
  eslint-scope cleanly does not stop this one. The writeup is
  explicit about that, and walks through what Capa still does
  in this regime: the authority surface is SBOM-visible (not
  hand-authored guesses), the caller can attenuate
  (`net.restrict_to`, `fs.restrict_to`) so the blast radius
  shrinks to a single host or directory, and the audit on the
  SBOM flags any future widening of the declared capability.
  Honest scope claim: Capa raises the bar on supply-chain
  attacks; the height matters, but the ceiling above which it
  does not reach (maintainer takeover, author-as-attacker) is
  a scope limit that orthogonal defences (code signing,
  reproducible builds, transparency logs) have to cover.
  Regression test in
  `tests/test_transpiler.py::test_cve_node_ipc`.

- **CVE case study: eslint-scope 2018**
  (`examples/cve_eslint_scope.capa` +
  `docs/cve_eslint_scope.md`). A miniature scope analyser whose
  signature `(List<Decl>) -> List<Binding>` precludes the
  `Fs`-read + `Net`-POST behaviour that the malicious
  `eslint-scope@3.7.2` carried on 12 July 2018. The companion
  writeup walks through the attack (read `~/.npmrc`, exfiltrate
  the `_authToken` to a Pastebin drop, overwrite the malicious
  code with the legitimate version), the analyzer rejection of
  the transliterated attack, the role of `Fs.restrict_to` as
  defence in depth, and the honest limits (capability holder
  with bad intent, the `Unsafe` boundary, Capa is not a
  sandbox). The second CVE case study in the repo; the
  first was the event-stream walkthrough. Both follow the same
  paired-file pattern so a third is mechanical to add. The
  CRA-aligned policy story for an auditor reading the
  resulting SBOM is in
  `examples/sbom_capability_audit.capa`. Regression test in
  `tests/test_transpiler.py::test_cve_eslint_scope`.

- **Property-based test scaffolding** with Hypothesis, in
  `tests/test_properties.py`. Six initial properties that
  exercise the lexer, parser, and formatter over arbitrary
  printable text (~200 examples per property per CI run):
  formatter idempotence (`format(format(s)) == format(s)`),
  formatter fixpoint convergence in one step, formatter
  output satisfies `is_formatted`, lexer terminates on every
  input with either a valid token list or a `LexerError`,
  same for the parser on well-formed token streams. The
  invariants are conservative on purpose, they hold over the
  entire input space, so they make a stable CI floor without
  needing a Capa-grammar generator. The richer
  "runtime capability set ⊆ manifest declared set" property
  needs a syntax-aware program generator and is phase 2.
  Hypothesis is now an optional dev dependency
  (`pip install -e .[test]`).

- **`docs/semantics.md`** is the working sketch of *λ_cap*, a
  minimal lambda calculus that captures Capa's capability
  discipline at a level a paper reviewer can engage with.
  Defines syntax, typing rules (with a split between
  non-linear and linear contexts so the consume discipline
  rides on standard linear-types machinery), and small-step
  operational semantics with a trace recording every
  capability invocation. States two soundness theorems
  with proof sketches: *Capability Soundness* says every
  invocation in the trace has a class drawn from the
  program's initial capability environment, *Manifest
  Completeness* says the manifest is an upper bound on the
  dynamic capability surface. Deferred to the full thesis
  writeup: the branch/loop bookkeeping of the linear layer,
  attenuation completeness as a lattice property, the
  `Unsafe` boundary's relativised soundness, and the
  translation lemma from full Capa to λ_cap. Linked from
  `WHITEPAPER.md` and `docs/positioning.md`. The intended
  next step is mechanising Theorem 1 in Agda or Coq for
  workshop-paper submission.

- **`docs/positioning.md`** captures the honest case for the
  language: what is and is not unique about Capa, which parts of
  the design predate it (capability typing as an idea is decades
  old), which adjacent languages and tools work in the same
  intellectual space (Pony, Koka / Eff / OCaml 5 effect handlers,
  Haskell with phantom types, Roc, the WebAssembly Component
  Model with WIT), and what one-sentence claim Capa stands
  behind when challenged with "you could do this in Python".
  The page is intended for reviewers and contributors. Linked
  from `docs/why.html` and `WHITEPAPER.md`.

- **SBOM ↔ capability-policy audit, written in Capa**
  (`examples/sbom_capability_audit.capa`): the "auditable
  supply chain" pitch made concrete. End-to-end pipeline with
  real file IO: reads both a CycloneDX SBOM and a JSON policy
  file via the `Fs` capability (attenuated to
  `examples/data/` via `Fs.restrict_to` before either file is
  opened, so the auditor cannot exfiltrate anything outside
  its declared input directory), extracts each function's
  declared capabilities from the `capa:declared_capability`
  properties, and checks them against the per-function
  allow-list. Reports a per-function summary plus a numbered
  list of violations. The novel part vs npm / PyPI / cargo
  SBOM tooling: both sides of the comparison are static.
  Capa's type system makes the declared set rigorous, and the
  audit is a syntactic comparison of two finite lists. A diff
  between SBOM and policy is unambiguous, and it travels with
  the build artefact. Sample data at
  `examples/data/demo-sbom.json` +
  `examples/data/demo-policy.json` (the policy deliberately
  omits one function so the audit fires on a single run).
  Regression test in
  `tests/test_transpiler.py::test_sbom_capability_audit`.

- **Missing capability-attenuator methods registered in the
  builtins table**: `Fs.restrict_to`, `Fs.allows`,
  `Env.restrict_to_keys`, `Env.allows`,
  `Clock.restrict_to_after`, `Clock.allows`, and
  `Random.with_seed` are runtime methods on the
  corresponding capability classes but were not listed in
  `capa/builtins.py`. Before the recent capability-method
  strictness change they slipped through as TyUnknown; that
  change exposed the gap. All five attenuators are now
  type-checked properly, including the return type narrowing
  (`Fs.restrict_to(p) -> Fs`, `Env.restrict_to_keys(ks) -> Env`,
  `Clock.restrict_to_after(t) -> Clock`,
  `Random.with_seed(seed) -> Random`).

- **SPDX license-expression parser, written in Capa**
  (`examples/spdx_license_expr.capa`): a recursive-descent
  parser for the SPDX 2.3 Annex D grammar used in every
  `licenseDeclared` / `licenseConcluded` field of every Package
  in an SBOM. Handles the three precedence levels (`OR` <
  `AND` < `WITH`), parenthesised sub-expressions, and the
  `LicenseRef-...` / `DocumentRef-...` identifier shapes.
  The AST is a sum type (`LicenseId` / `LicenseRef` /
  `WithExc` / `AndAll` / `OrAny`) with mutually recursive
  struct payloads, and a precedence-aware renderer round-trips
  the AST back to source: redundant parens are dropped (e.g.
  `(GPL-2.0-only WITH X) OR Apache-2.0` -> `GPL-2.0-only WITH
  X OR Apache-2.0` because WITH binds tighter than OR), but
  load-bearing parens are preserved (`(MIT OR Apache-2.0) AND
  GPL-3.0-only` stays as-is because OR is lower than AND).
  Malformed input surfaces as a structured `Result<_, String>`
  error with positional context. Regression test in
  `tests/test_transpiler.py::test_spdx_license_expr`.

- **SBOM validation in both parsers, referential integrity +
  cycle detection**:
  `validate_spdx(doc: SpdxDocument) -> List<String>` walks the
  document, collects every defined `SPDXID`
  (`SPDXRef-DOCUMENT` + every `Package.SPDXID`) into a
  `Set<String>`, checks that every `Relationship.source` and
  `Relationship.target` points at a known one, and then runs a
  three-colour DFS over the Relationship graph to detect
  cycles. `validate_cyclonedx(doc: CdxDocument) -> List<String>`
  is the symmetric counterpart: collects `bom-ref` from
  `metadata.component` plus every `components[i].bom-ref`,
  checks every `dependencies[i].ref` and every entry in
  `dependsOn[]`, then runs the same DFS over the dependency
  graph. Both validators return a human-readable violation
  list, empty list = the document is internally consistent and
  the graph is a DAG. Each demo prints "Validation: ok (refs
  resolve + acyclic)" or a numbered list of violations.

- **CycloneDX 1.5 JSON parser, written in Capa**
  (`examples/cyclonedx_parser.capa`): the SBOM-of-record
  companion to the SPDX parser. Reads CycloneDX 1.5 documents
  (the format Dependency-Track, OSV-Scanner, syft, and the Capa
  compiler's own `--cyclonedx` output emit) and builds typed
  Capa structs: `CdxDocument`, `CdxComponent`, `CdxHash`,
  `CdxLicense`, `CdxDependency`, `CdxMetadata`. Handles both
  CycloneDX license shapes, `{license: {id|name}}` (a single
  SPDX identifier or a human-readable name) and `{expression:
  ...}` (a full SPDX-license-expression like `MIT OR
  Apache-2.0`), plus the dual `metadata.tools` representation
  (modern `tools.components[]` and the legacy flat
  `tools[]` array). Regression test in
  `tests/test_transpiler.py::test_cyclonedx_parser`.

- **SPDX 2.3 JSON parser, written in Capa**
  (`examples/spdx_parser.capa`): the first real-world SBOM demo
  written in the language. Parses the core SPDX 2.3 fields
  (`spdxVersion`, `dataLicense`, document metadata, `packages`
  with `versionInfo` / `licenseConcluded` / `checksums`, and
  `relationships`) into typed Capa structs
  (`SpdxDocument`, `Package`, `Checksum`, `Relationship`,
  `CreationInfo`). Demonstrates: a user-defined
  `capability SbomReader` marking the trust boundary for any
  function that touches an SBOM, pattern matching on every
  `JsonValue` variant, and `?`-chaining on `Result` so each
  parser function reads top-down without manual match-on-error.
  Optional-field helpers (`string_field_or`, `bool_field_or`)
  cover SPDX's "field may be omitted, fall back to a default"
  semantics. Regression test in
  `tests/test_transpiler.py::test_spdx_parser`.

- **Arity errors include the function signature**: the
  analyzer's `call to 'foo': expected 2 arguments, got 3` now
  appends `(signature: fun(Int, Int) -> Int)` so the reader
  sees the parameter types alongside the count. Applies to both
  free-function and method calls, on both the positional and
  named-argument paths.

- **Top-level keyword-typo hints**: writing `def foo()`,
  `class Foo`, `function bar()`, `func baz()`, `fn quux()`,
  `interface I`, `enum E`, `struct S`, or a bare `let` at the
  top level now produces a targeted parser error pointing at
  the Capa equivalent (`fun`, `type`, `trait`, `type Name =
  ...`, `const`). The most common newcomer-from-Python or
  -from-Rust typos no longer produce the generic "expected
  top-level declaration".

- **Built-in capability method typos are now caught**: calling
  a method that does not exist on one of the built-in
  capabilities (`Stdio`, `Fs`, `Env`, `Net`, `Clock`, `Random`,
  `Unsafe`) was previously silently accepted and returned
  `TyUnknown`. The analyzer now raises a `capability 'Stdio'
  has no method 'prntln'; did you mean 'println'?` with the
  same Levenshtein hint already used for type-method typos.
  User-defined capabilities are unchanged (their method tables
  may be intentionally partial).

- **Formatter intra-line spacing pass (v2)**: outside string
  literals, char literals, and `//` comments, runs of two or
  more spaces in code collapse to a single space, and a
  missing space after `,` is inserted. The pass uses a
  character-by-character state machine, so escaped quotes
  inside literals are handled correctly and trailing commas
  before `)` / `]` / `}` are preserved. Expression re-emission
  from the AST (operator spacing around binary operators,
  brace placement) is still deferred to a future v3 pass that
  needs a `//` comment-preservation design first.

- **One-line install scripts** at [deploy/install.sh](deploy/install.sh)
  (Linux / macOS Apple Silicon) and
  [deploy/install.ps1](deploy/install.ps1) (Windows PowerShell).
  Both download the latest pre-built binary, drop it in
  `~/.local/bin/capa` (or `%LOCALAPPDATA%\capa\capa.exe` on
  Windows), and, on Windows, add that directory to the user
  PATH via `[Environment]::SetEnvironmentVariable("Path", ..., "User")`
  so no admin rights are needed. On Unix the script tells the
  user to add the directory to `PATH` themselves (we do not
  modify shell rc files automatically: too many shells, too
  many opinions). Idempotent on rerun. The bash script also
  strips the macOS Gatekeeper quarantine attribute so the
  binary runs without a Settings detour. README and
  `docs/start.html` lead with the one-liners; the manual
  download path remains documented for users who want to
  verify the asset themselves.

- **`capa --version`**: prints the compiler version and exits.
  Used by the installer scripts to verify a successful download
  but generally useful for "what am I running?".

- **LSP semantic tokens** (`textDocument/semanticTokens/full`):
  type-aware highlighting beyond what a TextMate grammar can
  deliver. The legend uses seven LSP-standard token types
  (`function`, `parameter`, `variable`, `interface`, `type`,
  `enumMember`, `property`) and three modifiers
  (`defaultLibrary` for built-ins, `declaration` for sites that
  introduce a name, `readonly` for `let` bindings and
  constants). Capabilities use `interface`; the built-ins
  (`Stdio`, `Net`, `Fs`, `Env`, `Clock`, `Random`) get the
  `defaultLibrary` modifier so themes can render them with a
  different intensity than user-defined ones. Coverage spans
  reference identifiers (via `result.bindings`), declaration
  sites (via the `name_pos` parser change), `TypeName`
  references inside type annotations (resolved by name in
  `result.global_symbols`), `let` / `var` bindings (with
  `var` getting a new `name_pos` field on the AST), and
  struct fields / sum variants / trait methods at their
  declaration positions. Tokens are sorted by source position
  and relative-encoded into the standard
  `[deltaLine, deltaStart, length, tokenType, tokenModifiers]`
  quintuples expected by the LSP protocol.

- **LSP type-aware method completion after `.`**: when the
  cursor sits in a `receiver.<here>` context, the completion
  list narrows to the methods of the receiver's type, with the
  method's `TyFun` signature rendered in the detail column.
  Built-in types (`String`, `List`, `Map`, `Set`, `Option`,
  `Result`, `JsonValue`) and built-in capabilities (`Stdio`,
  `Net`, `Fs`, `Env`, `Clock`, `Random`) are covered, as are
  user-defined struct and sum types with methods declared via
  `impl`. The receiver may be any expression: an identifier, a
  string literal, a parenthesised sub-expression. Mid-edit
  buffers (a bare trailing `.`) are handled with a
  parse-with-placeholder retry: the source is re-parsed with a
  synthetic identifier inserted at the cursor, which makes the
  surrounding `FieldAccess` / `MethodCall` valid in the AST so
  the receiver's type can be resolved. Methods whose names
  start with `_` are filtered (internal-by-convention).
  Unresolvable receivers return no completions (the dot-trigger
  path never falls back to keywords / built-ins, which would
  be misleading).

- **LSP completion** (`textDocument/completion`): suggests
  Capa identifiers at the cursor. v1 is a two-layer answer.
  The **floor** is always present and is computed without
  parsing: 35 Capa keywords, 7 built-in capabilities (`Stdio`,
  `Fs`, ...), 14 built-in types (`Int`, `Float`, `List`,
  `Option`, `Result`, `Map`, `Set`, ...), 4 common variant
  constructors (`Some`, `None`, `Ok`, `Err`), 10 built-in
  functions (`parse_int`, `new_map`, `parse_json`,
  `py_import`, ...). When the buffer parses cleanly, the
  **module layer** is appended: top-level functions (rendered
  with their `fun(params) -> Ret` signature in the detail
  column), constants (with their declared type), structs, sum
  types and each of their variants surfaced individually,
  user-defined traits and capabilities; plus
  the **local layer**: parameters and `let`/`var` bindings
  visible at the cursor inside the enclosing function. Locals
  whose names start with `_` are filtered out (the convention
  for "intentionally unused"). De-dup by label keeps one entry
  when a user binding collides with a built-in name.

- **LSP rename** (`textDocument/rename` + `textDocument/prepareRename`):
  rewrites every reference and the declaration of the symbol
  under the cursor in a single `WorkspaceEdit`. Builds on the
  existing `compute_references` with `include_declaration=True`,
  so coverage matches find-references exactly (functions, types,
  traits, capabilities, constants, parameters, variants, struct
  fields, method signatures). The new name is validated against
  the lexer's IDENT shape via `str.isidentifier()` plus a
  reserved-keyword check, so renaming to `if`, `fun`, the empty
  string, `1greet`, `say-hi`, or any other non-identifier
  is refused with a human-readable message instead of producing
  a broken source. Built-in symbols (`Stdio`, `Net`, `Result`,
  ...) refuse rename cleanly because they have no source
  declaration to edit. `prepareRename` answers
  "is this position renameable?" so editors can grey out the
  rename UI before the user types a new name.

- **Parser records `name_pos` for declared names**: every
  declaration node (FunDecl, TypeStruct, TypeSum, TraitDecl,
  ConstDecl, Param, Variant, Field, MethodSig) now carries a
  `name_pos: Pos` field separate from the existing `pos`. The
  `pos` of a FunDecl is still the start of the `fun` keyword
  (or the first attribute), but `name_pos` points at the IDENT
  token of the declared name. The analyzer's existing position
  semantics are unchanged; `AnalysisResult` additionally exposes
  `global_symbols: dict[str, Symbol]` so LSP tooling can resolve
  a declaration site to its Symbol without poking at private
  Analyzer state.

- **LSP hover, go-to-definition, find-references on
  declaration sites**: with the parser recording `name_pos`, the
  three cursor-driven LSP features now fire on declarations,
  not just references. Hovering on `foo` in `fun foo(name)`
  shows the function signature; hovering on `name` in the same
  declaration shows `name: T` with the *parameter* label;
  hovering on a struct field, sum variant, or trait method
  signature shows the appropriate detail. Go-to-definition from
  a declaration name is a no-op (lands on the name itself);
  find-references from either side returns the same set, with
  the declaration entry placed at the precise name column rather
  than the start of the `fun` keyword. The mechanism is a small
  `_DeclSite` collector + a `_resolve_decl_symbol` helper that
  maps each declaration kind to the matching Symbol via
  `global_symbols`, sum-type variant tables, struct-field tables,
  trait method-sig tables, or a scan over the function body's
  bindings for parameter sites.

- **LSP code actions (Quick Fix for "did you mean" hints)**:
  `textDocument/codeAction` returns a "Replace with 'X'" Quick
  Fix for every diagnostic whose message ends in
  `; did you mean 'X'?` (the five analyzer error families that
  carry the suggestion: undefined name, undefined type, no
  method on type, no field on struct, unknown variant). The
  replacement range is computed by scanning the source line for
  the misspelled token (matched as a whole word, so a typo like
  `in` does not pick up the `in` inside `println`); when the
  token cannot be located on the line (e.g. the user is mid-edit,
  or the diagnostic position is approximate as for typos inside
  string interpolation), the action is skipped cleanly rather
  than committing to a wrong span. Each action is marked
  `isPreferred=True` so it can be applied with the editor's
  default keyboard shortcut.

- **LSP document symbols**: `textDocument/documentSymbol`
  returns the hierarchical outline of the module. Top-level
  constants, structs (nesting their fields), sum types (nesting
  their variants with payload types in the detail), traits and
  capabilities (nesting their method signatures), top-level
  functions (with `(params) -> Return` rendered as detail), and
  impl blocks (with display names like `impl Greet for Foo` and
  the methods nested under each) appear in source order.
  Editors render this in the outline view, breadcrumb bar, and
  workspace symbol search. The capa-side computation is exposed
  as `compute_document_symbols(source, filename)` returning a
  list of `DocSymbol` dataclasses; the LSP handler maps each to
  the matching `lsp.SymbolKind` (`sum` -> `Enum`, `variant` ->
  `EnumMember`, `capability` -> `Interface`, `impl` -> `Class`,
  etc.).

- **LSP find-references**: `textDocument/references` lists
  every other identifier in the file that resolves to the same
  symbol as the one under the cursor. Reuses the
  `collect_idents` + `AnalysisResult.bindings` machinery from
  hover and go-to-definition; results are ordered by source
  position. The `includeDeclaration` flag from the LSP request
  is honoured: when true and the symbol has a real source
  origin, a location for the declaration line is added; built-in
  symbols are still filtered (they have no file location to
  point at).

- **LSP go-to-definition**: `textDocument/definition` jumps
  from any identifier reference to the position where the
  declaring symbol lives. Functions resolve to the
  `fun name(...)` line; parameters resolve to their slot in
  the parameter list; `let`/`var` bindings resolve to their
  introducing statement; variants resolve to the corresponding
  variant declaration inside the sum type. Built-in symbols
  (`Stdio`, `Net`, `Result`, the implicit `Option`, etc.) carry
  the `Pos(0, 0)` sentinel and are filtered cleanly so the
  editor never jumps to "line 0 of an unknown file". As with
  hover, coverage is limited to identifier references; the
  parser does not yet track end positions on declaration
  nodes, so the jump target is the start of the declaration
  line, which is what every mainstream editor expects.

- **LSP hover**: `textDocument/hover` answers
  "what is this symbol?" for the identifier under the cursor.
  Functions render as a Capa-style signature
  (`fun greet(name: String, age: Int) -> String`); parameters,
  bindings, and constants render as `name: T` plus a kind label;
  variants show the owning sum type; user-defined capabilities
  show the `capability X` head. The hover range covers the
  identifier so editors highlight the exact span. Coverage is
  limited to identifier references in v1 (declaration sites
  store names as strings, not Ident nodes, so they are skipped
  cleanly rather than guessed at). A buffer with parse errors
  returns no hover but never raises.

- **Language server (LSP), v1 diagnostics-only**.
  `python -m capa lsp` starts a stdio server that re-runs the
  full lexer + parser + analyzer pipeline on every didOpen,
  didChange, and didSave, and publishes the resulting errors as
  `textDocument/publishDiagnostics`. Capa's 1-based line/col
  positions are translated to LSP's 0-based positions; severities
  default to Error; the diagnostic `source` field is `capa-lsp`.
  The lexer and parser short-circuit on the first error
  (consistent with the CLI); the analyzer surfaces every error it
  finds in a single pass. `pygls>=2.0` is an optional
  dependency (`pip install -e '.[lsp]'`) so the rest of the
  compiler stays standard-library-only. README ships one-line
  config snippets for Helix and Neovim.

### Changed

- **`Range<T>` is now a distinct type from `List<T>`**. The
  `a..b` and `a..=b` expressions previously typed as
  `List<Int>` and lowered to `CapaList(range(...))`, which
  materialised the full range eagerly (~28 bytes per int
  on CPython, gigabytes for large ranges). Range is now its
  own parametric type registered in `capa/builtins.py` with
  a minimal method surface: `length()`, `contains(T)`,
  `is_empty()`, `to_list()`. The full `List<T>` API
  (`filter`, `fold`, `map`, ...) is reached via explicit
  materialisation: `.to_list().filter(...)`. The runtime
  class `CapaRange` in `capa.runtime._list` wraps Python's
  `range` and implements `__iter__` so bound ranges iterate
  lazily; `CapaRange(0, 1_000_000_000)` constructs in 2µs
  with no allocation. The direct `for x in a..b` form keeps
  its fast path, emitting bare `for x in range(...)` with
  no wrapper around it. Five existing tests migrated to the
  new shape; one new test asserts that calling `.filter`
  directly on a `Range` is now a typed rejection rather
  than silently working. Resolves the deferred follow-up
  to the for-loop materialisation fix from the external
  whitepaper review.

- **`for x in a..b` no longer materialises the full range**.
  The naive lowering was `for x in CapaList(range(a, b)):`,
  which forced Python's `list.__init__` to walk the range
  eagerly (~28 bytes per integer on CPython). `for x in
  0..10_000_000` therefore allocated ~270 MB before doing any
  work. The transpiler now special-cases `ForStmt(iter=
  RangeExpr)` and emits `for x in range(start, stop):`
  directly. The inclusive form `0..=n` lowers to
  `range(0, (n) + 1)`. Bound ranges (`let xs = 0..n; for x in
  xs`) still materialise into a `CapaList` so subsequent
  `List<T>` method calls (`.map`, `.length()`, `.filter`)
  continue to work. Found by an external whitepaper review
  that flagged the memory cost as a blocker for the future
  native backend; the long-term fix (a `Range<Int>` type
  distinct from `List<Int>`) is still pending, but the
  for-iteration case is no longer a footgun.

- **README correction on capability-method typing**. A stale
  paragraph in `README.md` claimed that "capabilities (`Stdio`,
  `Fs`, etc.) have no impls in Capa code, their methods are
  still typed as `TyUnknown` and resolved at runtime against
  the Python runtime implementation." This was true at one
  point but is no longer: every built-in capability method is
  declared in `capa/builtins.py` as a closed table, the
  analyzer dispatches against that table, and unknown methods
  on a built-in capability are rejected with a "did you mean"
  hint rather than typed as `TyUnknown`. Updated the paragraph
  to match reality.

- **WhitePaper held back from the public repo until the
  thesis pre-print is published**. The full design rationale
  document (`Capa-WhitePaper.md`) underpins a PhD thesis on
  SBOM Governance under the EU Cyber Resilience Act and is
  embargoed until the pre-print has a citable DOI. `WHITEPAPER.md`
  replaces it with a one-page stub explaining where the document
  is and how to obtain a copy. References in code comments
  (`// see WhitePaper §4.6`) and in the README / CONTRIBUTING /
  docs site / issue templates all point at the stub for now;
  once the pre-print is up the stub will redirect to the DOI.

- **`?` operator now propagates the inner type**: previously the
  analyzer typed every `expr?` as `TyUnknown`, which silently
  defeated type-aware method dispatch on anything downstream of
  a `?`. The most visible symptom was `Map.get(...)` failing to
  lower into the `Some(m[k]) if k in m else None_` ternary when
  `m` was the result of a `Result`-returning helper, producing a
  runtime `UnboundLocalError` inside the transpiled match-as-
  expression. Now `expr?` unwraps `Result<T, E>` / `Option<T>`
  to `T`; other types (and `TyUnknown` inputs) still degrade to
  `TyUnknown`. Fix also exposed a long-standing test-harness
  hole: `tests/test_transpiler.py::transpile_only` was running
  the lexer + parser without the analyzer, so the transpiler
  saw an empty types map and the same dispatch path silently
  degraded under test. The helper now calls `analyze()` before
  `transpile()`.

- **Internal: every compiler file over ~700 lines is now a
  package**. Following the analyzer split, the same mixin /
  per-topic-module pattern was applied to the parser
  (5 mixins), transpiler (4 mixins), runtime (6 topic modules:
  Result/Option, capabilities, py-interop, list, conversion,
  JSON), manifest (5 topic modules), docgen (4 topic modules),
  capa_ast (6 per-category modules), and lexer (4 mixins). Each
  package's `__init__.py` is either a thin re-export or a small
  composition orchestrator. `cli.py` and `lsp/server.py` were
  evaluated and kept whole because their structure is sequential
  pipeline glue (CLI) or pygls-registration closures (LSP),
  neither of which has the seams that justify a split. No
  user-visible behaviour change, but the surface for future
  contributors is dramatically smaller per concern.

- **"Did you mean?" hints on five common analyzer errors**:
  `undefined name`, `undefined type`, `type X has no method Y`,
  `struct S has no field F`, and `unknown variant V` now append
  `; did you mean 'X'?` when a close candidate exists in scope.
  The matcher is a Levenshtein distance with case-aware
  tie-breaking: same-first-letter and same-case beat raw distance,
  so `Pint` prefers `Point` over `Int` and `reslt` prefers a local
  `result` over the built-in `Result`. Suppressed for needles of
  two characters or fewer, where almost everything is plausibly
  similar. Variant suggestions are scoped to the scrutinee's sum
  type when known.

- **Block-body lambdas inside `(...)`** now raise a targeted parser
  error pointing at the recommended workaround, instead of the
  generic "expected expression, got KW_LET". Same root cause as the
  indent-form match-in-parens case already documented: the lexer
  suppresses NEWLINE/INDENT/DEDENT inside parentheses for implicit
  line continuation, so block-bodied constructs cannot reach their
  layout-driven syntax there. The workaround (bind to `let` first,
  then pass the binding) parses cleanly; single-expression lambdas
  remain unaffected.

### Added

- **`capa init`**, project scaffolding subcommand.
  `python -m capa init [name]` creates a minimal Capa project at the
  given path (defaults to the current directory, which must then be
  empty): `main.capa` is a runnable starter that uses `Stdio` so the
  capability discipline is visible from the first line a user reads,
  `README.md` documents the two commands a user needs (`capa --run`
  and `capa --check`), `.gitignore` covers Python bytecode and
  common editor cruft, and `.capa-version` pins the Capa version
  used at scaffold time. The starter passes `--check` and `--run`
  out of the box and is in canonical `--fmt-check` form.

- **`capa-fmt` (v1, line-level)**: CLI flags `--fmt` (rewrite the
  file in place) and `--fmt-check` (verify, exit 1 if not
  canonical). v1 is a safe, whitespace-only formatter: it
  normalises line endings to LF, replaces leading tabs with four
  spaces each, floors partial space-indents to the nearest lower
  4-space multiple (never deepens nesting), strips trailing
  whitespace, collapses runs of blank lines to a single blank, and
  ensures exactly one final newline. Block-comment interiors
  (`/* ... */` and `/** ... */`) are preserved verbatim so
  Javadoc-style `*` continuation lines survive. Idempotent by
  construction. Intra-line canonicalisation (operator spacing, AST
  round-trip, `//` comment preservation) is deferred to v2.

- **Doc-comment markdown extensions**: `--doc` now renders fenced
  code blocks (triple backticks, with an optional language tag
  emitted as a `class="lang-<name>"` on the inner `<code>`) and
  bulleted lists (lines starting with `- `) inside doc-comment
  bodies. HTML special characters inside code blocks are still
  escaped. Paragraphs and inline `` `code` `` spans continue to
  work as before.

- **Trait section in `--doc`**: plain (non-capability) traits now
  get their own section, listing each method signature and the
  set of types that implement the trait. Capability declarations
  (`capability X`) keep their separate section as before.

### Changed

- **Intel Macs are no longer a release target**. The
  `release-binaries.yml` workflow matrix drops the `macos-13`
  entry; pre-built binaries ship for Linux x86_64, macOS Apple
  Silicon, and Windows x86_64 only. Apple stopped selling Intel
  Macs in 2023 and GitHub's `macos-13` runner pool is unreliable
  (the v0.5.0-alpha Intel job sat queued for over an hour without
  ever picking up a runner). Intel-Mac users install from source
  with Python 3.10+ via `pip install -e .`.

- **Raw string literals**, `r"..."`. No escape processing and no
  `${}` interpolation: every character up to the next `"` is taken
  literally. Useful for Windows paths (`r"C:\Users\..."`) and
  regular-expression patterns (`r"\d+\.\d+"`) where backslashes
  would otherwise need to be doubled. A raw string therefore
  cannot itself contain `"`; for that case use a regular string
  with `\"`. The hash-delimited `r#"..."#` form is not part of
  v1.0. The bare identifier `r` continues to lex as `IDENT`; only
  `r"` triggers the raw-string path.

- **Named arguments**, `f(name: "Ana", age: 30)`. The parser
  accepts an optional `IDENT ":"` prefix on each call argument;
  the analyzer reorders the arguments into parameter order before
  type checking and reports parameter-name typos at the
  offending name; the transpiler emits Python keyword arguments.
  Positional arguments must precede any named argument. Built-in
  methods on `String`, `Map`, `Set`, and on the built-in
  capabilities (`Stdio`, `Net`, `Fs`, ...) reject named arguments
  because their parameter names are not tracked.

### Documentation

- **Indent-based `match` inside parentheses** is now documented as
  a deliberate restriction rather than a known bug. Inside `(...)`
  the lexer suppresses NEWLINE/INDENT/DEDENT to support implicit
  line continuation, so the indent form (`match x` then indented
  arms) cannot be reached. The braced inline form
  (`match x { P1 -> e1, P2 -> e2 }`) works inside a call
  expression and may itself be spread over multiple lines.

## [0.5.0-alpha], 2026-05-12

The fourth tagged release. Focus: independence from Python at
the end-user level, the live HTTPS deployment of the public site,
two new HTML documentation pages, and closing the capability-
attenuation arc.

Users no longer need to install Python to run Capa programs. The
release ships standalone binaries for Linux, macOS Apple Silicon,
and Windows; each bundles the compiler and a Python interpreter
into a single ~8 MB executable. Intel Macs are not shipped as a
pre-built binary (Apple stopped selling Intel Macs in 2023 and
the GitHub Actions Intel runner pool is unreliable); install from
source. The public site is at `https://capa-language.com/` with
HTTPS enforced, HSTS, DNSSEC, full search-engine baseline, and a
per-OS download section on the landing page. The standard library
and language reference docs are now native HTML pages, not bare
markdown. `Random.with_seed` closes the attenuator family so every
built-in capability has one.

### Added

- **Pre-built binaries** for Linux x86_64, macOS Apple Silicon,
  and Windows x86_64. PyInstaller spec at `deploy/capa.spec`
  bundles the compiler and a Python interpreter into a single
  ~8 MB executable, with `.sha256` checksum for verification.
  Built automatically on every version tag by
  `.github/workflows/release-binaries.yml`, a three-platform matrix
  workflow that smoke-tests each binary before uploading to the
  GitHub Release.

- **`Random.with_seed(seed: Int) -> Random`** closes the generic
  attenuation arc. Every built-in capability (`Net`, `Fs`, `Env`,
  `Clock`, `Random`) now has an attenuator. `Random.with_seed`
  returns a deterministic instance whose sequence is a function
  of the integer seed; chained calls re-seed (last wins). Unlike
  the other attenuators there is no denied state, but the audit
  value is in determinism: the manifest's data-flow tracker
  recognises `with_seed` and records it like the `restrict_to*`
  family. Recognised attenuator names are collected in
  `_ATTENUATION_METHODS` for future extensibility.

- **`docs/reference.html` + `docs/stdlib.html`** as native HTML
  pages with the site's chrome, in-page TOC, and tabular method
  references. They replace the broken footer links that
  previously pointed to raw markdown served by GitHub Pages as
  `text/plain`.

- **Download grid on the landing page**, with three clickable
  cards (Linux, macOS, Windows) linking directly to the binary
  in `releases/latest/download/`. The `Get started` page gains
  a per-OS install section with the exact one-liner for each
  platform (curl + chmod for Linux/macOS, Invoke-WebRequest for
  Windows; `xattr -d` for macOS Gatekeeper).

- **SEO + Open Graph metadata** on all ten pages.
  `docs/sitemap.xml` lists every page with realistic lastmod /
  priority; `docs/robots.txt` allows all and points at the
  sitemap. Each page declares page-specific og:title,
  og:description, og:type, og:url, og:image, og:site_name plus
  the matching twitter: equivalents, so links shared on social
  platforms render a structured card with the logo.

- **`community.html` and `brand.html`** site pages, plus the
  hooded-figure logo (header, favicon, hero on landing) and the
  expanded landing-page content (hero code sample, four
  personas, comparison table vs. Python / TypeScript / Rust,
  FAQ with eight questions, release banner).

### Changed

- **`capa --run` executes in-process** via `exec()` rather than
  spawning a subprocess of `sys.executable`. Faster startup, no
  temp-file dance, and survives PyInstaller bundling (the
  subprocess approach assumed `sys.executable` was a generic
  Python interpreter that could run arbitrary `.py` files,
  which fails under PyInstaller). SystemExit propagation
  preserved; runtime tracebacks go to stderr.

- **All in-site `.md` links replaced** with either the matching
  HTML page (Getting started, Tutorial, Reference, Standard
  library) or the rendered GitHub blob URL (white paper, EBNF,
  event-stream demo, SECURITY, CONTRIBUTING). Visitors no
  longer drop onto raw markdown rendered as plain text.

- **Em-dashes removed** from every text file in the repo
  (commit messages, docs, code comments, capa source). Project
  preference is hyphens or commas; the sweep replaced ~430
  occurrences across 63 files.

### Fixed

- `.value-props` and related card grids on the landing/community/
  brand pages now share width equally: added `min-width: 0` so a
  long line in a child `<pre>` triggers `overflow-x: auto`
  rather than stretching the grid column.

- Footer doc links across all eight (now ten) pages no longer
  point at `.md` files served by GitHub Pages as `text/plain`.

### Infrastructure

- **Custom domain `capa-language.com`**, live at HTTPS. DNS
  hosted on Cloudflare with DNSSEC active and the full zone
  reproducible from `deploy/cloudflare-dns.zone`. Cloudflare
  configured with Always Use HTTPS, Full (Strict) SSL/TLS,
  HSTS (max-age six months), Minimum TLS 1.2, and Automatic
  HTTPS Rewrites.

- **`docs/CNAME`** in the repo points GitHub Pages at the
  custom domain.

## [0.4.0-alpha], 2026-05-12

The third tagged release. Focus: closing the audit-artefact loop
and standing the project up on its own domain.

The capability manifest gained a semantic dimension: per-call
data-flow tracking surfaces the actual restriction chain a binding
carries, not just the variable name. The compiler now also emits
HTML documentation generated directly from doc comments, so the
same source produces a machine-readable JSON manifest, a
CycloneDX 1.5 SBOM, and a human-readable doc page. The project
moved off `nelsonduarte.github.io/capa` onto its own DNS at
`capa-language.com`.

### Added

- **Per-call data-flow tracking in the manifest.** Each call site
  in a function's `calls[]` now carries a parallel `args_flow`
  array, the same length as `args`. For arguments that name a
  binding produced by a chain of `.restrict_to*` calls, the entry
  is `{"name": str, "attenuations": [{method, args}, ...]}` in
  source order; for other arguments it is `null`. Example:

  ```
  fun main(net: Net)
      let api = net.restrict_to("api.example.com")
      let narrower = api.restrict_to("v2.api.example.com")
      let ok = fetch_user(narrower, "42")
  ```

  The call record for `fetch_user(narrower, "42")` now reports
  `args_flow[0]` as `narrower` carrying both restrictions, in
  source order. The auditor sees the effective restriction the
  callee received without re-reading the source.

  Scope (v1): only `LetStmt`s with restrict-chain RHSs, only
  intra-function, no scope-awareness (a re-binding inside an `if`
  overwrites the outer one in the map). Method-call resolution
  to a specific `impl` is still out of scope. The syntactic
  `args` field is unchanged; schema_version stays at 1.

- **Doc comments** (`///` line and `/** */` block) attach to the
  next `fun`, `type`, `trait`, or `capability` declaration. The
  block form recognises Javadoc-style `*` left margins and strips
  them, so

      /** line one
       * line two
       */

  reads as `line one\nline two`. Consecutive `///` lines join with
  newlines. `////+` and `/*` (without the second star) remain plain
  comments, dropped by the lexer.

- **`python -m capa --doc`** emits a self-contained HTML page
  documenting every function, type, and user-defined capability in
  a program. Uses the doc comments, capability signatures, and
  attribute metadata already extracted by the analyzer. Inline CSS
  matches the project's dark / accent-purple visual identity. No
  external resources. The human-readable counterpart to the
  machine-readable `--manifest`.

- **Manifest carries doc**: the JSON manifest's per-function and
  per-capability records gain a `doc` field; the CycloneDX output
  surfaces them as `capa:doc` properties on the corresponding
  components.

- **`examples/documented_demo.capa`** uses every form of doc comment
  on a realistic mini-program (capability + impl + factory +
  audited function + CVE-tagged function).

## [0.3.0-alpha], 2026-05-12

The second tagged release. Focus: full CRA alignment of the
capability discipline. The compiler now emits a machine-readable
capability manifest plus a valid CycloneDX 1.5 SBOM with embedded
metadata, and the three remaining built-in capabilities
(`Fs`, `Env`, `Clock`) gained attenuation matching the
`Net.restrict_to` pattern. Function-level audit attributes
(`@security`, `@deprecated`, `@audited`) let authors record CVE
references, deprecation, and audit evidence directly in source.
The website was hardened with a strict Content-Security-Policy
and a Referrer-Policy, and got a proper logo (hooded figure,
purple, with a negative-space C in the body).

### Added

- **Website security hardening.** The static site under `docs/`
  is purely HTML / CSS / SVG (no JavaScript, no external
  resources, no analytics, no fonts off-origin), but the
  defensive headers were missing. All six pages now carry:

  - **Content-Security-Policy** via `<meta http-equiv>`:
    `default-src 'self'; img-src 'self' data:; style-src
    'self'; script-src 'none'; object-src 'none'; base-uri
    'self'; form-action 'self'`. Script execution is denied
    outright; styles must come from the local stylesheet; no
    plugins, no base-tag injection, no form posts off-origin.
  - **Referrer-Policy** `strict-origin-when-cross-origin`, so
    only the origin (not the full path) leaks when a visitor
    clicks an external link.

  To make `style-src 'self'` strict (no `'unsafe-inline'`), the
  seven `style="..."` attributes scattered across the pages were
  refactored into `.section-centered`, `.lead-prose`, and
  `.lead-prose-narrow` classes in `style.css`.

- **`Clock.restrict_to_after(t)` attenuation.** Closes the generic
  attenuation arc started with `Net`, then `Fs` and `Env`. A
  `Clock` can now be narrowed to "active only after time t"
  (seconds since the epoch), the threshold is monotonic across
  chained `restrict_to_after` calls (max wins), and the action
  method `sleep` becomes a silent no-op on a denied Clock
  (fail-closed, consistent with the information-hiding pattern
  used by `Fs.exists` and `Env.get`). Reading the current time
  via `now_secs` / `now_monotonic` stays ungated since it is a
  pure query.

  Example use cases: time-bombed activation, scheduled work that
  is structurally inactive before its window, audit-window
  enforcement.

  `examples/clock_attenuation.capa` demonstrates the pattern with
  one active and one dormant Clock handed to the same helper.

- **Per-call site recording in the manifest.** Each function in
  `--manifest` / `--cyclonedx` output now carries a `calls[]` array
  listing every function and method call in its body, with the
  line:col of the call site and a stringified rendering of the
  argument expressions. An auditor reading the manifest can see,
  for example, that `main` calls `net.restrict_to("api.example.com")`
  on line 5 *before* calling `fetch_user(api, "42")` on line 6 -
  the restriction is visible in the static artefact, no source
  inspection needed.

  Argument expressions are stringified into a Capa-like form
  (literals, identifiers, method chains, field access, struct
  literals, tuple/list literals, etc.) and truncated at 80
  characters with an ellipsis so long literals do not blow up
  the JSON.

  CycloneDX 1.5 output gains `dependencies[]` edges from each
  function to every *function* it calls within the same module.
  Method calls are not yet promoted to edges in v1 because
  resolving `receiver.method` to a specific `impl` requires
  type tracking we have not yet implemented; the call is still
  in `calls[]` of the source function.

- **Generic attenuation: `Fs.restrict_to(prefix)` and
  `Env.restrict_to_keys([...])`.** The `restrict_to` pattern
  established by `Net` now extends to two more built-in
  capabilities. Both narrow monotonically, chaining intersects
  the restriction set, never widens, and both gate every
  operation against the current restriction set *before* any
  system call. Denied operations are information-hiding:
  `Fs.exists` on a denied path returns `False`, and `Env.get`
  on a denied key returns the same `None` as a missing
  variable, so the cap does not leak the existence of resources
  outside its allowed surface.

  Example:

  ```
  fun main(fs: Fs, env: Env, stdio: Stdio)
      let app_fs   = fs.restrict_to("/tmp/myapp/")
      let app_env  = env.restrict_to_keys(["HOME", "APP_TOKEN"])
      do_work(app_fs, app_env, stdio)
  ```

  `do_work` and anything it calls can only touch the filesystem
  under `/tmp/myapp/` and only read the two environment variables,
  no matter what their implementation tries.

- **`examples/fs_env_attenuation.capa`** demonstrating both new
  attenuators and the monotonic-narrowing guarantee.

- **`python -m capa --cyclonedx`**, emits a valid CycloneDX 1.5
  SBOM with the capability manifest embedded as standard
  `properties[]` entries under the `capa:*` namespace. Capa
  programs become first-class citizens of existing SBOM tooling
  (Dependency-Track, OSV-Scanner, syft, sbom-utility) without
  those tools needing to know anything Capa-specific.

  Each function and each user-defined capability becomes a
  `library` sub-component with a deterministic `bom-ref`. The
  call from a function to a user-defined capability is encoded
  both as a `capa:declared_capability` property and as a
  CycloneDX `dependencies[]` edge so dependency-graph tooling
  sees the relation. The serial number is a UUIDv5 derived from
  the filename, so re-running the command produces identical
  output (SBOM diff-friendly across releases of the same file).

- **Function attributes** (`@security`, `@deprecated`, `@audited`) as
  static, source-level metadata. Attributes appear on lines
  immediately before a `fun` declaration (top-level or method inside
  an `impl`), can stack, and accept keyword-style string arguments:

  ```
  @security(cve: "CVE-2024-12345", severity: "high")
  @audited(date: "2026-05-11", by: "Nelson Duarte")
  fun verify_token(token: String, expected: String) -> Bool
      return token == expected
  ```

  The analyzer rejects unknown attribute names, unknown keys, and
  duplicates. The v1 catalogue is fixed: `security`, `deprecated`,
  `audited`.

- **`python -m capa --manifest`**, emits a JSON capability manifest
  describing, for every function in the program: its signature,
  the capabilities it declares, whether it crosses the `Unsafe`
  boundary, and any attached attributes. Module-level entries
  include user-defined capability declarations and their
  implementors, plus a summary count.

  Designed as a CRA-aligned audit artefact: other languages cannot
  emit this because the authority graph is not in their type
  system; in Capa, it falls out of the analyser for free. The
  format is schema-versioned (currently `schema_version: 1`).

- **`examples/manifest_demo.capa`**, a small program showing the
  attribute syntax and a manifest worth reading. Covers a
  user-defined capability and its implementor, an audited method,
  a function with a `@security` annotation, a deprecated function,
  a pure function with no caps, an `Unsafe`-crossing function,
  and a clean entry point.

- **VSCode highlighting** for `@attribute` syntax in the bundled
  extension.

- Repository security hardening: Dependabot vulnerability alerts and
  automated security updates, secret scanning with push protection,
  GitHub private vulnerability reporting, CodeQL workflow
  (security-extended + security-and-quality) on push, PR, and a
  weekly cron, and a `.github/dependabot.yml` that keeps the
  GitHub Actions used by the test workflow up to date.
- `SECURITY.md` describing what counts as a security issue, the
  in-scope / out-of-scope boundary, the private reporting channel,
  supported versions, and the coordinated-disclosure flow.
- `CONTRIBUTING.md` covering dev setup, the compiler architecture
  (lexer → parser → analyzer → transpiler → runtime), what kinds of
  contributions help most, what is currently out of scope, and the
  pull-request conventions.
- `CODE_OF_CONDUCT.md` adopting Contributor Covenant 2.1 by
  reference, with a maintainer contact for reports.
- Issue templates (`bug_report.yml`, `feature_request.yml`) using
  GitHub's YAML issue-form schema with required fields and stage /
  OS dropdowns; a `config.yml` that disables blank issues and links
  to the security advisory channel and Discussions; and a
  `PULL_REQUEST_TEMPLATE.md` with a self-review checklist.

### Changed

- Default `GITHUB_TOKEN` permission in `.github/workflows/tests.yml`
  set to `contents: read`. Any future job that needs broader scope
  must opt in explicitly.

## [0.2.0-alpha], 2026-05-11

First public release. Capa goes from private development to a
public, MIT-licensed, security-hardened repository with a five-page
documentation site, runnable examples, a syntax-highlighting editor
extension, and a comprehensive test suite green on three operating
systems and three Python versions.

### Added

#### Language

- **Capability discipline** enforced at three layers:
  - Structural: capabilities can appear only as function parameters
    (not struct fields, variant payloads, return types, constants,
    locals, or generic args), with a single relaxation for
    cap-bearing structs that implement a user-defined capability.
  - Flow: the same capability cannot be passed as two arguments of
    the same call; declared capability parameters must be used
    (or prefixed with `_`).
  - Linear: the `consume` qualifier marks parameters that take
    ownership, with fork/merge tracking across branches and loops.
- **Seven built-in capabilities**: `Stdio`, `Fs`, `Net`, `Env`,
  `Clock`, `Random`, and `Unsafe` (the explicit escape hatch for
  Python interop).
- **User-defined capabilities** via the `capability X` declaration
  and `impl X for Y` (WhitePaper §4.6). The discipline applies
  uniformly to user-defined and built-in capabilities.
- **First-class attenuation on `Net`**: `Net.restrict_to(host)`
  returns a fresh `Net` whose authority is narrowed to a single
  host. Chaining restrictions intersects allowed-host sets;
  restrictions only narrow, never widen. The runtime check fires
  before any system call.
- **Range expressions**: `a..b` (exclusive) and `a..=b` (inclusive),
  first-class values that can be stored, iterated, and passed.
- **Inline `match` expression form**: `match s { p -> e, p -> e [,] }`
  for one-line matches.
- **`to_int` / `to_float` builtins** for numeric conversion.
- **Types**: `Int`, `Float`, `Bool`, `String`, `Char`, `Unit`,
  tuples, `List`, `Map`, `Set`, `Option`, `Result`, `Fun(...) -> ...`.
- **Generics** with type inference at call sites.
- **Pattern matching** with literal, variant, tuple, and nested
  patterns; exhaustive over covered cases.
- **Closures** as first-class values (`fun (x: Int) -> Int => x * 2`).
- **`?` operator** for `Result` unwrap-or-early-return.
- **String interpolation** with `${...}`.
- **Numeric literals** in decimal, hex (`0x`), octal (`0o`), binary
  (`0b`), with `_` separators.

#### Compiler

- Hand-written four-stage pipeline in pure Python with zero runtime
  dependencies outside the standard library: lexer (with
  significant-indentation handling), recursive-descent parser,
  semantic analyzer (name resolution + types + capability
  discipline), and Python 3.10+ transpiler.
- CLI with five modes: tokenize (default), `--parse`, `--check`,
  `--transpile`, `--run`.
- Programmatic API exposing `Lexer`, `Parser`, `analyze`, and
  `transpile` as a library.
- Module naming convention (`capa_ast.py`, `typesys.py`) chosen to
  avoid colliding with Python stdlib modules under `python -m capa`.

#### Tooling and docs

- **VSCode syntax-highlighting extension** under `vscode/`: TextMate
  grammar covering keywords by category, built-in capabilities
  highlighted distinctly, string interpolation, numeric literals in
  all bases, operators (`..`, `..=`, `=>`, `?`).
- **Event-stream supply-chain demo**: a safe Capa version of the
  `flat_map` function whose JavaScript counterpart shipped a
  Bitcoin-wallet exfiltrator in 2018, plus attack-attempt code
  rejected by the analyzer with source-aligned errors. Lives in
  `examples/demo_event_stream.capa` + `docs/demo-event-stream.md`.
- **Five-page static website** under `docs/` (one stylesheet, no
  JavaScript, no framework, no external fonts): `index.html`,
  `why.html`, `tour.html`, `start.html`, `roadmap.html`. Served by
  GitHub Pages at <https://capa-language.com/>.
- **20 example programs** in `examples/` exercising every major
  language feature.
- **420 tests** (unit + end-to-end) green on Ubuntu, macOS, and
  Windows across Python 3.10, 3.12, and 3.14.
- **White paper** (`WHITEPAPER.md`) and formal **EBNF grammar**
  (`Capa-EBNF.md`) translated to English and synchronised with the
  implementation.

[Unreleased]: https://github.com/nelsonduarte/capa-language/compare/v0.5.0-alpha...HEAD
[0.5.0-alpha]: https://github.com/nelsonduarte/capa-language/releases/tag/v0.5.0-alpha
[0.4.0-alpha]: https://github.com/nelsonduarte/capa-language/releases/tag/v0.4.0-alpha
[0.3.0-alpha]: https://github.com/nelsonduarte/capa-language/releases/tag/v0.3.0-alpha
[0.2.0-alpha]: https://github.com/nelsonduarte/capa-language/releases/tag/v0.2.0-alpha
