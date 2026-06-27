# Reconciling Capa capability attenuation with WASI Preview 2

Status: Proposed / design draft.
Date: 2026-06-27.

Summary: Capa attenuates capabilities dynamically (a restricted value
travels with its restriction and is re-checked on every privileged
call), WASI Preview 2 fixes authority statically at instantiate time,
so this note adopts a hybrid strategy: map a program's static
authority ceiling onto the WASI host configuration (preopens,
env-set, allowed addresses) while keeping the finer in-program
attenuations guest-side, and it states explicitly which of the three
resulting guarantee levels is runtime-enforced versus
compiler-proved.

## 1. Objective and scope

The goal is to reconcile Capa's DYNAMIC attenuation model with the
STATIC capability model of WASI Preview 2 (WASI P2) without losing the
load-bearing claim of the language: that
`provably_excluded_capabilities` in the manifest is a real guarantee,
not merely a guest-side promise the runtime trusts.

This is distinct from, and complementary to, the existing experimental
`--wasi` mode. That mode (documented in `docs/design/wasi_mode.md`)
migrates exactly two capabilities, Random and Clock, off the custom
`capa:host` interfaces and onto canonical WASI P2 interfaces, and only
for their PURE-READER touch-points (`Random.system_seed`,
`Clock.now_secs`, `Clock.now_monotonic`). It deliberately rejects
Clock attenuation (`Clock.restrict_to_after`) and `Clock.sleep` at
compile time, because the `wasi:clocks` interfaces are pure readers
with no host-side handle table on which to enforce a deadline
(`capa/ir/_emit_wasm/_wasi.py:74-93`, the `_validate_wasi_caps`
guard; rationale in the module docstring at
`capa/ir/_emit_wasm/_wasi.py:37-45`). The present document addresses
the harder, general question that the PoC explicitly defers: what
happens to the ATTENUATING capabilities (Fs, Env, Net, Db, Proc, and
the Clock deadline) under a WASI P2 host.

## 2. The Capa attenuation model

This section is factual, grounded in the runtime and analyzer code.

### 2.1 Operations

Every restriction-bearing capability exposes a narrowing operation and
an `allows(...)` query (signatures in `capa/builtins.py:245-304`):

- `Fs.restrict_to(prefix)` (`capa/runtime/_capabilities.py:168-171`)
- `Net.restrict_to(host)` (`capa/runtime/_capabilities.py:565-569`)
- `Db.restrict_to(path)` (`capa/runtime/_capabilities.py:900-906`)
- `Proc.restrict_to(cmd_prefix)`
  (`capa/runtime/_capabilities.py:707-711`)
- `Env.restrict_to_keys(keys)`
  (`capa/runtime/_capabilities.py:355-360`)
- `Clock.restrict_to_after(t)`
  (`capa/runtime/_capabilities.py:400-403`)
- `Random.with_seed(seed)`
  (`capa/runtime/_capabilities.py:478-479`)

### 2.2 Monotonicity

Narrowing never widens. The construction is an immutable, frozen-style
new instance on each call (the classes carry a single private field
and reconstruct rather than mutate):

- Set-valued caps narrow by INTERSECTION with the parent's set:
  `Env.restrict_to_keys` does `new & self._allowed_keys`
  (`capa/runtime/_capabilities.py:357-360`), `Net.restrict_to` does
  `new & self._allowed` (`capa/runtime/_capabilities.py:566-569`),
  `Db.restrict_to` and `Proc.restrict_to` follow the same shape
  (`capa/runtime/_capabilities.py:903-906`,
  `capa/runtime/_capabilities.py:708-711`). `Fs` accumulates
  canonical prefixes by union in `restrict_to`
  (`capa/runtime/_capabilities.py:170-171`) but `allows` requires
  containment in ALL stored prefixes
  (`capa/runtime/_capabilities.py:173-183`), so the EFFECTIVE
  admitted set is the intersection of the prefix containments, which
  is the monotone narrowing the model intends.
- `Clock.restrict_to_after` narrows by MAX of the old and new
  deadline (`capa/runtime/_capabilities.py:400-403`); a later
  not-before threshold is strictly more restrictive.
- `Random.with_seed` returns a fresh seeded instance
  (`capa/runtime/_capabilities.py:478-479`). Random has no "denied"
  state: seeding narrows the SPACE OF POSSIBLE SEQUENCES, not the
  authority to generate (class docstring,
  `capa/runtime/_capabilities.py:432-436`), so it is not an authority
  attenuation in the WASI-relevant sense and is out of scope for the
  reconciliation below.

### 2.3 How attenuation is imposed

On the PYTHON backend the restriction state lives on the capability
object itself, so it travels with the value through every function
call; the privileged method consults `allows(...)` before the syscall
(for example `Net.get` at `capa/runtime/_capabilities.py:574-597`).

On the WASM / Component Model backend a capability has no native value
representation, so restriction state is held in a host-side HANDLE
TABLE (`capa/runtime/_cap_handles.py`, motivation at
`capa/runtime/_cap_handles.py:1-37`). Capabilities are `u32` handles
into a per-instance table; `restrict_*` allocates a fresh CHILD handle
bound to the narrower restriction (delegating to the same cap-class
narrowing methods, so monotonicity and intersection are inherited:
`capa/runtime/_cap_handles.py:129-156`). Every privileged host op
takes the handle as its FIRST parameter, looks the cap up, and
re-checks `allows(...)` before the syscall. See the Component Model
host: `fs_read` at
`capa/runtime/_wasm_component_host.py:335-363`, and the Db ops at
`capa/runtime/_wasm_component_host.py:566-652`. The corresponding WIT
shapes thread `handle: u32` through every op
(`capa/ir/_emit_wit.py:60-198`), and `main`'s root handles are
bootstrapped and dispatched by name in
`capa/runtime/_wasm_component_host.py:767-873`
(root-handle allocation at
`capa/runtime/_cap_handles.py:170-204`).

This handle-table design is itself a fix: before it, the Wasm emitter
inlined `restrict_to(...)` checks at the literal call site, so a
restricted cap lost its restriction the moment it crossed a function
boundary (audit slice 25; history in
`docs/design/wasm-cap-handles.md:1-40`).

### 2.4 Soundness in two layers

The guarantee is the product of two distinct layers.

STATIC layer (the type system, in `capa/analyzer/_discipline.py`):
capabilities flow ONLY through function parameters. They cannot be
hidden in data structures, returned by ordinary functions, or bound
to `let` / `var` slots (`_check_no_capability` at
`capa/analyzer/_discipline.py:213-226`), and a capability cannot be
aliased twice within a single call (`_check_no_aliasing` at
`capa/analyzer/_discipline.py:187-211`). On top of this the manifest
computes `provably_excluded_capabilities` from the function signature
plus a closed-world reachability bound
(`capa/manifest/_funrec.py:475-528`, written out at
`capa/manifest/_funrec.py:607`; reachability map in
`capa/manifest/_reachability.py`). The computation is CONSERVATIVE: it
DOWNGRADES the exclusion claim to the empty list whenever it cannot be
honored, specifically when `Unsafe` is in scope or a `Fun(...)` type
appears in the signature (closures can carry a captured cap the type
system does not track:
`capa/manifest/_funrec.py:470-520`), and it folds in caps reachable
through cap-bearing structs via the per-impl reachability map.

DYNAMIC layer: the concrete restriction travels with the value (the
object on Python, the handle on Wasm) and is enforced per call. There
is no "widen" operation anywhere in the model; every `restrict_*`
returns a strictly-narrower or equal instance.

KEY POINT: the type system guarantees the PRESENCE or ABSENCE of a
capability at a function boundary (whether `main`'s Fs ever reaches a
given function at all). The CONTENT of a concrete restriction (which
prefixes, hosts, or keys it admits) is a RUNTIME value, decided by the
sequence of `restrict_*` calls actually executed. The static layer
proves the shape of the authority graph; the dynamic layer carries the
concrete narrowing.

## 3. The WASI Preview 2 restriction models

This section is standard WASI P2 knowledge, summarised per capability.

- `wasi:cli/environment`: the host injects the environment at
  instantiate time (env-set, or inherit). The guest reads a fixed set
  of variables; there is no runtime narrowing imposed by WASI.
- `wasi:filesystem`: authority is granted through PREOPENS. The host
  pre-opens a set of directories and hands the guest their
  descriptors before `main` runs. A descriptor IS authority over its
  subtree; there is no WASI-imposed runtime narrowing of an open
  descriptor.
- `wasi:sockets` and `wasi:http`: the host decides which addresses or
  address pools the guest may reach (allowed-addresses / outbound
  policy), again at configuration time.
- `wasi:clocks` and `wasi:random`: pure readers, no attenuation
  surface at all.

COMMON PATTERN: in every case the restriction is decided by the HOST
at INSTANTIATE time. There is no dynamic attenuation handle and no
runtime-imposed "narrow midway through the guest". The descriptors and
resource handles a component holds represent authority that has been
GRANTED, ambient within the component, not a self-attenuation the
runtime enforces against the component's own further narrowing.

## 4. The precise tension

The mismatch has three axes.

(a) WHEN it restricts. Capa narrows DYNAMICALLY, anywhere in the code,
as `restrict_*` executes. WASI fixes authority STATICALLY at
instantiate.

(b) WHO imposes it. Capa's runtime re-checks `allows(...)` on EVERY
privileged call. WASI's runtime imposes only the CEILING set at
configuration; everything below that ceiling is ambient inside the
component.

(c) GRANULARITY. Capa enforces per-call. WASI enforces per-instance.

THE CRITICAL POINT: handing the guest the raw WASI capability degrades
Capa's fine internal attenuation from "a guarantee imposed by the
runtime" to "a promise of the guest, verified statically by the
compiler". The compiler still proves the guest only ever narrows; but
under a stock WASI host nothing re-checks that narrowing at the
syscall.

SUB-DISTINCTION by capability. The tension is not uniform. Where WASI
has a host-side ceiling (Fs preopens, Env env-set, Net allowed-addrs),
the INITIAL ceiling IS enforceable by any conformant host. Where the
capability is a pure reader (Clock, Random), there is no ceiling at
all, which is exactly why the current `--wasi` mode already rejects
`Clock.restrict_to_after` and `Clock.sleep` at compile time
(`capa/ir/_emit_wasm/_wasi.py:74-93`).

## 5. Reconciliation options considered

(a) Attenuation entirely guest-side, on top of raw WASI. Keep the
static discipline; emit the `restrict_*` / `allows` logic as guest
code over the raw WASI authority. Trade-off: the enforcement of the
fine attenuation lives in GUEST code. It is correct against a guest
the Capa compiler produced (the compiler proves only-narrowing), but
it is NOT enforced against a tampered or substituted module. The
runtime ceiling is whatever WASI was configured with, not the narrowed
set.

(b) HYBRID (the choice). Map `main`'s static authority CEILING to the
host configuration at instantiate (preopens for Fs, env-set for Env,
allowed-addrs for Net), and keep the dynamic in-program attenuations
guest-side. The runtime imposes the ceiling (hard, on any WASI host);
the internal narrowings stay compiler-proved and, on the Capa host,
runtime-reinforced. Details in sections 7 and 8.

(c) Sub-components / Component Model composition. Attenuation across a
sub-component boundary IS genuinely runtime-imposed (the inner
component only receives the imports the outer one passes). But the
granularity is PER-INSTANCE, not per-call: a sub-component boundary is
established once at composition, it cannot model an Fs that narrows
its prefix on the third call inside a loop. This is a fundamental
granularity mismatch with Capa's per-call model. Reserve it for COARSE
boundaries (sandboxing a plugin or a third-party module), not for fine
attenuation.

(d) Host-side virtualisation by interposition. Shim the WASI
interfaces with an adapter that consults the Capa handle table on
every call. This preserves TOTAL enforcement of the fine attenuation,
but ONLY when the host is the Capa adapter; it forfeits real WASI
portability (a stock `wasmtime`/`jco` host would not run it with the
guarantee intact). Useful as a TRANSITION mode, not as the
destination.

## 6. Decision

Adopt the HYBRID strategy (option b), phased. Map the static authority
ceiling of `main` to the WASI host configuration; keep the dynamic
in-program narrowings guest-side. The choice is driven by section 4:
the ceiling is the part WASI can enforce on any conformant host, and
the fine narrowing is the part that has no WASI runtime home today.

## 7. Stratification of the guarantee

This is the part that preserves the thesis. The reconciliation does
not claim uniform enforcement; it states three explicit levels.

LEVEL 1, the AUTHORITY CEILING. The set passed to `main` (its declared
caps and their initial roots) is mapped to WASI host configuration:
preopens, env-set, allowed-addresses. This is imposed by the RUNTIME
on ANY conformant WASI host. No module, tampered or not, exceeds it.

LEVEL 2, the FINE ATTENUATION, the in-program narrowings below the
ceiling (`restrict_to`, `restrict_to_keys`, the Clock deadline). This
is:
- PROVED by the compiler. `provably_excluded_capabilities` still holds
  unchanged (`capa/manifest/_funrec.py:475-528`); the static
  discipline that makes the proof sound
  (`capa/analyzer/_discipline.py:187-226`) is untouched.
- REINFORCED by the runtime on the CAPA host (the handle table
  re-checks every call:
  `capa/runtime/_wasm_component_host.py:335-363`).
- PROVED-BUT-NOT-REINFORCED under a stock WASI host. The guest only
  ever narrows (compiler-proved), but no stock-host runtime re-checks
  the narrowing at the syscall.

LEVEL 3, MAXIMUM GUARANTEE, the current Capa host. Per-call
attenuation is fully runtime-imposed through the handle table, exactly
as today.

The thesis survives precisely BECAUSE the document is explicit about
this stratification rather than asserting uniform enforcement. It
aligns with the tiers of the trust model: a regulator reads Level 1 as
a hard runtime ceiling and Level 2 as a compiler proof that is
additionally runtime-reinforced on the Capa host. Runtime enforcement
of the FINE attenuation under an ARBITRARY host depends on future WASI
evolution (runtime-enforced descriptor attenuation, or practical
component virtualisation) and is marked as such in section 9.

## 8. Implementation plan, per capability

Phased, easiest mapping first.

PHASE 1, Env and Net. Direct ceiling mapping: `main`'s Env ceiling to
`wasi:cli/environment` env-set, `main`'s Net ceiling to the host's
allowed-addresses. Env additionally closes the leak-by-default AT THE
CEILING: a env-set of exactly the allowed keys means the guest cannot
even observe a variable outside the ceiling, matching the fail-closed
`Env.get` of the Python runtime
(`capa/runtime/_capabilities.py:368-372`). In-program
`restrict_to_keys` / `restrict_to` narrowings below the ceiling stay
guest-side (Level 2).

PHASE 2, Fs via preopens. Map the ceiling of `main`'s Fs root to a set
of preopened directories; in-program `restrict_to` narrowings stay
guest-side. PRE-REQUISITE: the compiler must MATERIALISE the root
ceiling statically (the set of prefixes `main`'s Fs is allowed to
preopen). Where the root prefix is a runtime value the compiler cannot
materialise, degrade THAT PART to guest-side only (Level 2), do not
silently widen the preopen.

CLOCK and RANDOM. Keep the current behaviour: pure readers on
`wasi:clocks` / `wasi:random`, with Clock attenuation
(`restrict_to_after`) and `sleep` REJECTED at compile time under
`--wasi` (`capa/ir/_emit_wasm/_wasi.py:74-93`). There is no ceiling to
map.

SUB-COMPONENTS. Reserved for coarse boundaries (option c), out of the
per-call attenuation path.

## 9. Dependent on future WASI / tooling evolution

Marked clearly as NOT achievable today:

- Runtime enforcement of the FINE attenuation (Level 2) under an
  ARBITRARY WASI host. This needs either runtime-enforced narrowing of
  an already-granted descriptor / resource handle, which WASI P2 does
  not provide, or practical, low-overhead component virtualisation.
- Practical virtualisation of `wasi:filesystem` by sub-component, with
  per-call granularity, as a way to push Level 2 enforcement into a
  portable host.

Until then, maximum-guarantee per-call enforcement of fine attenuation
remains Level 3, the Capa host.

## 10. References

Code:

- `capa/runtime/_capabilities.py` (attenuation semantics:
  Fs:168-183, Env:355-372, Clock:400-417, Net:565-597, Proc:707-744,
  Db:900-929, Random:478-479)
- `capa/runtime/_cap_handles.py` (handle table; `restrict_*`:129-156;
  `bootstrap_root_handles`:170-204)
- `capa/runtime/_wasm_component_host.py` (per-call host enforcement:
  335-363, 566-652; main bootstrap / dispatch: 767-873; WASI recipe
  `add_wasip2`: 97-102)
- `capa/analyzer/_discipline.py` (static discipline:
  `_check_no_aliasing`:187-211, `_check_no_capability`:213-226)
- `capa/manifest/_funrec.py:475-528` and `capa/manifest/_reachability.py`
  (`provably_excluded_capabilities`)
- `capa/builtins.py:245-304` (attenuation method signatures)
- `capa/ir/_emit_wasm/_wasi.py` and `capa/ir/_emit_wit.py:60-198`
  (current `--wasi` mode and WIT with `handle: u32`)

Related design records:

- `docs/design/wasm-cap-handles.md` (handle-table architecture).
- `docs/design/wasi_mode.md` (the experimental `--wasi` PoC).
