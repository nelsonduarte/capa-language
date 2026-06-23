# Execution plan: the native backend, phased and de-risked

> Status: execution plan (2026-06-23). This is the "HOW" document. The
> feasibility study
> ([`llvm-backend-feasibility.md`](llvm-backend-feasibility.md)) already
> answered the "if / when / how much it costs"; it is the parent
> analysis and this plan does not reopen it. What this document is NOT:
> it is not a calendar commitment (no dates, only the relative effort
> bands the feasibility doc records), and it does not re-litigate the
> defer-until-a-driver recommendation. It sequences the work into
> phases, marks which phases are authorised to start, and gates the rest
> on the concrete drivers the feasibility doc already names (section 6).

---

## 1. Strategic decision and inviolable principles

### 1.1 Additive identity

Native performance is a **deployability enabler, not a new value
proposition**. The moat stays exactly where the positioning thesis puts
it: capabilities + IFC + a machine-verifiable SBOM
([`roadmap-security-performance.md`](roadmap-security-performance.md),
"Tese de posicionamento"). The correct framing is:

> Capa delivers capabilities + IFC + a verifiable SBOM WITHOUT making
> you pay for it in performance.

That is, native execution **removes an adoption objection** ("it is
slow"), it is not the thing being sold. This is the same role the
roadmap's Eixo Performance already assigns to performance work: it
"torna a linguagem deployável, removendo o bloqueador de adoção". The
native backend is the axis that makes the security story **deployable**,
not a pivot away from it.

This plan does NOT rewrite the positioning thesis in
`roadmap-security-performance.md`; it references it and frames the
native backend underneath it. **Open item for the owner:** the formal
reconciliation of the positioning thesis with an additive native axis
(how the one-line pitch in the roadmap's closing section absorbs "AOT
binaries of production performance" without diluting the
capabilities+IFC+SBOM headline) is left as an explicit decision for the
project owner, not settled here.

### 1.2 Inviolable principles (structure every phase)

These hold across all phases regardless of how far the work proceeds:

- **(a) Byte-identical parity against the Python oracle is the bar at
  every phase.** The Python transpiler is the correctness oracle
  (feasibility 1.1, 2.6); every backend is held byte-identical to it. A
  native backend is held to the same bar by a `tests/test_ir_llvm_parity.py`
  mirroring `tests/test_ir_wasm_parity.py`: same `_PARITY_PROGRAMS`
  list, same exact-stdout assert, a new runner arm that builds and runs
  the native artifact instead of instantiating wasmtime in-process
  (feasibility 2.6, the parity-harness row in section 3).
- **(b) Never two high-risk fronts at once.** This is the roadmap's
  standing rule ("Nunca duas frentes de risco alto ao mesmo tempo").
  Concretely: the layout-width refactor is taken in isolation before any
  emission work; the GC arc and the host-bridge re-implementation are
  never opened simultaneously.
- **(c) Each phase leaves the suite green.** No phase lands with the
  Wasm parity suite red. The layout refactor in particular must keep
  Wasm parity green throughout (feasibility 2.3, 5.2 risk 2).
- **(d) Wasm remains the enforcement surface.** The Wasm Component Model
  backend stays the surface where capability attenuation is enforced at
  runtime (feasibility 1.3; the handle-table design in
  `wasm-cap-handles.md`). The native backend is additive, never a
  replacement for the sandboxing / SBOM surface.

---

## 2. Gate model

The feasibility doc's recommendation (section 6) is "defer until a
concrete driver appears". This plan refines that into a phased gate:
the de-risking prerequisites and the proof-of-lowering spike are
authorised now, because the feasibility doc itself flags them as "do
independently first, benefits Wasm too" (5.3); everything past the spike
stays gated.

| Phase | Gate to enter |
|---|---|
| Phase 0 (prerequisites) | **Authorised now.** Benefits Wasm independently (feasibility 5.3). |
| Phase 1 (spike) | **Authorised now.** Zero-dependency proof of lowering (feasibility 4.1). |
| Phase 2 (minimal slice) | **Decided after Phase 0+1**, with their results in hand. Not pre-authorised. |
| Phases 3-6 (real backend) | **Gated on one of the three concrete drivers** below. |

The three drivers (feasibility section 6), any one of which unlocks
Phases 3+:

1. A measured perf-bound consumer where profiling shows the Wasm sandbox
   / host-call boundary (not the algorithm) is the bottleneck, and
   Cranelift-via-wasmtime is demonstrably the floor.
2. A hard native-FFI requirement a real consumer needs that the
   Component Model / WIT path cannot serve ergonomically (the most
   plausible trigger).
3. A deployment target with no acceptable Wasm runtime (embedded /
   bare-metal / a platform where shipping wasmtime is disallowed).

---

## 3. The phases

Phases map onto the feasibility scope ladder (section 4) and the
reuse-vs-build table (section 3). Phase 0 and Phase 1 are detailed to an
actionable level; Phases 2-6 are lighter (objective, entry gate, risk,
value-if-you-stop-here).

### Phase 0: Prerequisites (AUTHORISED)

The three prerequisites from feasibility 5.3. These benefit the Wasm
backend independently and take the largest regression risk in
isolation, before any emission code exists.

**Objective.** Make the shared pipeline native-ready without writing a
native emitter: parameterise the layout module, tighten CIR type
resolution, and decide the memory strategy.

**Scope (in).**

- **(i) Refactor `_layout.py` to be parameterised by pointer width and
  alignment.** Today the module bakes in Wasm32's 4-byte pointers and
  i32 addressing (feasibility 2.3): `_size_of` returns 4 for
  struct/sum pointers, the List/Map/Set 16-byte header packs four 4-byte
  words, closures pack `(fn_idx << 32) | env_ptr` into an i64, strings
  pack (ptr, len). The design transfers; the constants do not. Refactor
  into a width-and-alignment-parameterised core that both backends
  consume. This touches `_structs.py`, `_lists.py`, `_maps.py`,
  `_sets.py`, `_closures.py`, `_strings.py` (feasibility 2.3, 5.2 risk
  2): the highest regression surface in the whole effort, which is
  exactly why it is done first and alone.
- **(ii) Tighten CIR type resolution.** Eliminate the `_layout.py`
  "default unknown element type to Int" fallback (feasibility 2.1, 5.3).
  A native ABI cannot rely on that fallback; resolving it may push some
  type precision back into the lowerer or analyzer, a shared cost that
  also benefits Wasm.
- **(iii) Decide the memory-management strategy.** The honest staged
  answer is bump-on-mmap first, then refcounting, then (only if forced)
  tracing GC (feasibility 2.4, 5.3). This phase commits to the staged
  direction; the actual allocator is built in Phase 2.

**Scope (out).** No native emitter. No `.ll` generation. No new
allocator code (only the decision). No host-bridge work.

**Acceptance criterion.** The Wasm parity suite stays byte-identical
green across the entire refactor (every checkpoint, not just the end):
`tests/test_ir_wasm_parity.py` passes unchanged. The layout module is
parameterised such that selecting a 64-bit pointer width is a
configuration, not a code fork. The "unknown -> Int" fallback is gone
and no test regresses.

**Dependencies.** None external. Builds on the existing CIR,
monomorphiser, and layout design (all reused as-is, feasibility section
3).

**Risk.** High regression surface (feasibility 5.2 risk 2): the refactor
touches every collection and closure emitter. Mitigated by isolation
(principle b) and the green-parity gate (principle c).

**Effort band.** Part of the feasibility "minimal useful slice" estimate
of **~4-8 weeks**, which the feasibility doc says is "dominated by the
layout-width refactor" (5.1). This phase is that dominant cost taken up
front and on its own.

### Phase 1: Spike (AUTHORISED)

The proof-of-lowering spike from feasibility 4.1.

**Objective.** Confirm that CIR lowers to native at all, and produce one
byte-identical program against the oracle. The spike's real output is a
**decision**: does the lowering shape hold, and which toolchain to use.

**Scope (in).**

- CIR -> textual `.ll` for a **scalar-only subset**: Int/Bool/Float
  arithmetic, `if`/`while`, function calls (including recursion),
  `println` via a single hand-written `stdio` shim.
- One byte-identical program against the oracle (the feasibility doc
  names "hello / fizzbuzz"); fizzbuzz exercises arithmetic, branching,
  and a loop in one program.

**Scope (out).** No heap, no structs, no collections, no closures, no
capabilities beyond stdout (feasibility 4.1). No allocator. No layout
changes (those are Phase 0).

**Acceptance criterion.** The chosen scalar program runs through the
native binary and its stdout matches the Python oracle byte-for-byte,
asserted by the same shape as `test_ir_wasm_parity.py`. The spike report
records (1) confirmation that the lowering shape is low enough (CIR is
already ANF/SSA-friendly, feasibility 2.1) and (2) a toolchain
recommendation.

**Toolchain: decided by the spike, not on paper.** The feasibility doc
(2.2) weighs textual `.ll` (zero dependency, auditable, recommended for
the spike) vs llvmlite (in-process builder, recommended if it graduates
to a real backend) vs Cranelift-direct (dependency already paid, weaker
optimiser, needs a Rust shim). The spike starts with textual `.ll`
precisely because it keeps the dependency surface at zero and the output
auditable (the oracle-first habit), and the spike's job is to surface
which path the real backend should take. This plan does NOT pre-decide
it.

**Dependencies.** Independent of Phase 0 in principle (scalars need no
layout work), so the two authorised phases can run without a forced
ordering between them; principle (b) still forbids running the
high-risk Phase 0 refactor and any other high-risk front at once, but
the spike is low-risk.

**Risk.** Low. Throwaway-grade code, narrow subset, zero heap.

**Effort band.** **~1-2 weeks** (feasibility 5.1).

### Phase 2: Minimal useful slice (GATED, decided after Phase 0+1)

**Objective.** Scalars + structs to native with the bump-on-mmap
allocator and a native parity harness (feasibility 4.2). Maps onto the
"minimal useful slice" rung of the scope ladder.

**Gate to enter.** Decided after Phase 0+1 with their results in hand
(not pre-authorised). Phase 0's layout refactor must be green and the
spike must have confirmed the lowering shape + toolchain.

**Scope sketch.** Int/Bool/Float + struct construction and field access,
`if`/`while`/`for`, function calls + recursion, `println`; Strings as
(ptr, len); the bump-on-mmap allocator (feasibility 2.4 option 1: same
leak the Wasm bump already has, ships no regression relative to the
status quo); `stdio` and maybe `clock`. Lands `test_ir_llvm_parity.py`
over the scalar/struct subset of `_PARITY_PROGRAMS`.

**Risk.** Native linking/toolchain reliability across platforms
(feasibility 5.2 risk 3, "the last 20% is 80% of the pain").

**Value if you stop here.** A real, auditable native arm exists for the
scalar/struct subset with a parity harness, proving the path end to end.
Note (feasibility 4.2): this slice deliberately does NOT demonstrate
native FFI, the strongest motivation, because FFI lands late.

### Phase 3: Containers and dispatch (GATED on a driver)

**Objective.** Lists/Maps/Sets/closures/trait dispatch (feasibility 4.1
"real backend"). The type-id dispatch header transfers as-is
(feasibility 2.3, section 3). This is where a **native O(1) Map** lands,
the structural cure for the Wasm `Map<K,V>` O(N) / build-O(N^2)
residual the TODO flags (TODO "Known technical residuals"): a real
allocator makes a hash map natural, which a hand-written WAT hash table
in the non-destination backend would not justify.

**Gate to enter.** One of the three drivers (section 2).

**Risk.** Closures and packed strings need a real two-word
representation on 64-bit (feasibility 2.3); breadth of container
emission.

**Value if you stop here.** The native backend covers the common
container-heavy program shape, and closes the Map performance residual
structurally.

### Phase 4: Host bridges (GATED on a driver)

**Objective.** The 10 capability namespaces
(`capa:host/{stdio,panic,clock,env,fs,random,net,db,proc,json}`, ~36 host
functions, ~2050 LOC, feasibility 2.5) plus the attenuation enforcement
that travels with each handle.

**Gate to enter.** One of the three drivers; in practice the FFI /
no-Wasm-runtime drivers, since this is the surface that justifies a
standalone native runtime.

**Open sub-decision (feasibility 2.5).** FFI back to the existing Python
host (one source of truth for enforcement, but reintroduces a Python
dependency) vs re-implement the runtime natively in Rust/C (the honest
standalone story, but duplicates ~2050 LOC of security-critical
enforcement). Left open, to be decided when the driver names the target.

**Risk.** Duplicating security-critical capability enforcement in a
second language is a parity-and-audit liability, not just LOC
(feasibility 5.2 risk 4, the same objection that deferred the Rust Wasm
launcher).

**Value if you stop here.** A native backend that can actually talk to
the OS under capability discipline.

### Phase 5: Memory reclamation (GATED on a driver)

**Objective.** Refcounting over the drop points S1 (linear handles)
already computes (feasibility 2.4 option 2): a refcount header word,
`retain`/`release` at copy/drop sites. Does not collect cycles, which
Capa's value model rarely creates (no arbitrary shared mutability).

**Gate to enter.** A long-running native service that the bump-on-mmap
leak makes untenable (the same pressure P2 addresses on the Wasm side,
roadmap Eixo Performance P2).

**Risk.** Lower than tracing GC; the drop points come partly for free
from S1. Tracing GC is explicitly out of scope until forced (see
anti-scope).

**Value if you stop here.** Native programs that do not leak under
sustained allocation, without a tracing collector.

### Phase 6: Native FFI (GATED, the real motivation)

**Objective.** Direct native FFI: calling C libraries by the C ABI
without the Component Model / WIT marshalling layer (feasibility 1.2).
This is the one capability Wasm genuinely makes awkward and the most
plausible driver of the whole arc.

**Gate to enter.** Driver 2 specifically (a hard native-FFI
requirement).

**Risk.** C ABI surface, safety of the FFI boundary under capability
discipline.

**Value if you stop here.** The native backend delivers the thing Wasm
cannot, which is the only motivation that is uniquely native rather than
"a bit faster / no wasmtime dependency".

---

## 4. Cruxes and mitigations

From feasibility 5.2, carried verbatim in substance:

- **GC (the largest open risk).** Tracing GC with LLVM stack maps is a
  research-grade sub-project; Wasm sidesteps it via the host GC proposal
  (roadmap P2 option 1). **Mitigation:** stage it (bump-on-mmap ->
  refcounting), build a tracing collector only if a long-running native
  service forces it. Refcounting is tractable because S1 supplies the
  drop points (feasibility 2.4).
- **Host-bridge duplication (~2050 LOC of security-critical
  enforcement).** A second implementation of capability attenuation is a
  parity-and-audit liability (feasibility 5.2 risk 4). **Mitigation:**
  keep the FFI-back-to-Python option open as the single-source-of-truth
  path; if re-implementing natively, hold every bridge to the
  Python-vs-native parity bar (principle a).
- **ABI 32->64 representation change (high regression surface).** The
  layout refactor touches every collection/closure emitter and must not
  break Wasm parity (feasibility 5.2 risk 2). **Mitigation:** Phase 0
  takes it in isolation, green-parity gated (principles b, c).
- **Platform / linking.** A working native binary across Windows +
  Linux + macOS (linker, libc, static vs dynamic) is the classic
  last-20%-is-80% pain (feasibility 5.2 risk 3). **Mitigation:** prove
  it on the minimal slice (Phase 2) before scaling breadth.
- **Parity carve-outs.** Float formatting (the Grisu2 port already
  needed for Wasm parity must be shared, not re-derived), integer
  overflow/wrap semantics (the lowerer already handles i64::MIN), and
  Map/Set hash/iteration order must each be re-validated against the
  oracle (feasibility 2.6, 5.2 risk 5). **Mitigation:** share the Grisu2
  path; add each carve-out to `test_ir_llvm_parity.py` explicitly.

---

## 5. Anti-scope (what NOT to do until a driver exists)

Reusing the roadmap's anti-scope ("O que NÃO fazer") and the feasibility
recommendation:

- **No tracing GC.** Until a long-running native service makes it
  unavoidable (feasibility 2.4 option 3). Refcounting first.
- **No complete native re-implementation of the host bridges.** Until a
  driver names the target (Phase 4 is gated); a minimal slice ships
  `stdio` only (feasibility 2.5).
- **No Cranelift-direct or inkwell via Rust** while there is no Rust
  launcher (the P1.2(b) launcher was deferred; feasibility 2.2). A Rust
  component is added only if that arc is funded independently.
- **Do NOT build the backend proper without a driver.** Wasm AOT covers
  90% of the value at 10% of the cost; native is for the case Wasm
  provably cannot reach (roadmap anti-scope; feasibility section 6).

---

## 6. Reassessment points

- **After Phase 0 + Phase 1.** Reassess whether Phase 2 (the minimal
  slice) advances. The spike's toolchain finding and the layout
  refactor's actual cost feed this decision (Decision 2 / gate model
  section 2). If the spike shows the lowering is harder than the
  feasibility doc assumes, or no driver is on the horizon, Phase 2 waits.
- **At each driver gate.** Re-evaluate before entering Phases 3-6:
  confirm a concrete driver (section 2) is actually present, not
  anticipated. The feasibility doc's verdict stands by default ("defer
  until a driver appears", section 6); the burden is on the driver, not
  on the deferral.
