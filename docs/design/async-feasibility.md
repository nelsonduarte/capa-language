# Feasibility study: async / await (concurrency) in Capa

> Status: design spike / feasibility assessment (2026-06-09). This is
> a clear-eyed scoping document, NOT a commitment and NOT an
> implementation plan. It exists so the maintainer can decide
> whether, when, and in what shape to start. The honest headline is
> in Section 8 (Recommendation): **defer until a concrete driver
> exists**, and the crux that makes it expensive is in Section 5
> (IFC / noninterference under concurrency).
>
> Companion to `roadmap-security-performance.md`, which explicitly
> lists async under "O que NÃO fazer (anti-âmbito)": *"Não alargar a
> superfície de linguagem (async, macros, self-hosting) antes de S2 +
> P1/P2 estarem sólidos."* This study does not overturn that line; it
> records WHY, and what would have to change for the line to move.

---

## 0. Confirmed starting point: the current execution model is single-threaded synchronous

Grounded in the code, not assumed:

- **No async surface exists.** There is no `async` / `await` / `spawn`
  keyword in the lexer (`capa/lexer/_tokens.py`, the `KEYWORDS`
  table), no async node in the AST (`capa/capa_ast/`), and no async
  construct in the parser. Every `fun` lowers to an ordinary Python
  `def` (`capa/transpiler/_items.py::_emit_fun`) or an ordinary Wasm
  function.
- **The Python backend runs straight-line.** `_emit_fun` emits
  synchronous `def`; method calls (`capa/transpiler/_methods.py`) and
  expressions (`_expressions.py`) are eager and blocking.
- **The Wasm backend runs one blocking call.** `WasmHost._invoke_main`
  (`capa/runtime/_wasm_host.py:2108`) bootstraps root capability
  handles and then does exactly one synchronous `main(self.store,
  *handle_args)`. The host (`wasmtime.Linker`) provides each
  capability import (`capa:stdio.println`, `fs.read`, `net.get`, ...)
  as a synchronous Python callback that performs the syscall inline
  and returns. There is no event loop, no poll, no host-side
  scheduler. The Component Model host
  (`_wasm_component_host.py`) mirrors this shape.
- **Capabilities are synchronous values.** The runtime cap classes
  (`capa/runtime/_capabilities.py`: `Fs`, `Net`, `Db`, `Proc`, `Env`,
  `Clock`, `Stdio`) expose blocking methods. `Net.get` is a blocking
  HTTP GET; `Db.query` is a blocking SQLite call. Attenuation state
  travels with the handle (`capa/runtime/_cap_handles.py` on Wasm,
  first-class objects on Python).
- **Both soundness proofs are sequential.** λ_cap (capability
  discipline, `docs/semantics.md` Sections 1-8, mechanised in
  `proofs/CapaSoundness.agda`) has a single linear reduction relation
  `(e, τ) → (e', τ)` with one trace. λ_if (noninterference,
  Section 9, `proofs/CapaNoninterference.agda`, Theorems 3-4) is a
  **big-step** semantics `(σ, s) ⇓ (σ', o)` over a single store and a
  single output trace. Neither calculus has a notion of a second
  thread of control, interleaving, or a scheduler. This is the fact
  that makes Section 5 the crux.

Everything below is reasoned against that confirmed baseline.

---

## 1. Motivation and fit

### 1.1 Does async serve Capa's positioning?

Capa's moat (per `roadmap-security-performance.md`) is the
intersection: **capabilities + IFC + a machine-verifiable
supply-chain SBOM that expresses both.** The question for any feature
is not "is it nice" but "does it strengthen or at least not weaken
that claim".

Async/await is, by default, a **general language-surface feature with
weak intrinsic fit** to that moat. It does not, on its own, produce a
new SBOM claim. Capabilities answer "which effects"; IFC answers
"where data flows"; async answers "in what order / overlapped" -
which is a *performance and ergonomics* property, not a
*supply-chain-assurance* property. Nothing a regulator verifies in a
CycloneDX/SPDX/VEX artefact becomes more truthful because the I/O was
concurrent.

That is the candid assessment: async is not a moat feature. It is a
deployability/ergonomics feature with a real cost to the moat
(Section 5).

### 1.2 Concrete use cases it would unlock

There are honest upsides, all I/O-shaped:

- **Async I/O capabilities.** A server or agent that fans out N
  network requests (`Net.get`), or overlaps disk + network, today
  serialises them. An `await`-able `Net` would let one logical task
  issue many in-flight requests on one thread. This matters for the
  LLM-agent and SBOM-watch class of programs the repo already targets
  (`docs/llm-tool-sandbox.md`, the `sbom-watch` downstream demo).
- **Long-running services.** The roadmap's P2 (real GC) is gated on
  "long-running services"; those same services are where blocking-IO
  serialisation hurts. Async is adjacent to that pressure, not to the
  SBOM pitch.
- **Responsiveness under a single event loop** for a future
  interactive/daemon mode.

None of these is a *current* driver. They are latent: they become
real only if Capa grows a server/daemon/agent workload that is
I/O-bound enough to be embarrassed by serial blocking. As of today
the flagship programs are CLI-shaped, short-lived, one-shot (the Wasm
host comment notes "Wasm program lifetime is short, one CLI
invocation in the common case"). For a one-shot CLI, async buys
almost nothing and costs the whole IFC re-proof.

**Verdict on fit: weak-to-neutral now; conditionally real later.**
The honest framing is "async is a deployability feature whose driver
has not arrived", not "async is part of the vision".

---

## 2. The hard design decisions

This section is the core of the study. Three concurrency models, then
the four discipline-interaction analyses.

### 2.1 Concurrency model: three options

**Option A - Cooperative single-threaded (one event loop).**
One OS thread, one event loop. `await` is the only yield point; a
task runs uninterrupted between two `await`s. No preemption, no data
races on shared memory because only one task touches memory at a
time. This is the Python `asyncio` model and the JavaScript model.

**Option B - Structured concurrency with task spawning (still
single-threaded).** Option A plus a `spawn` / nursery / task-group
construct that lets a parent start child tasks, with the structured
guarantee that children complete (or are cancelled) before the parent
scope exits. Still one thread, still cooperative; spawning adds *new
threads of control* but not *new OS threads*. Concurrency, not
parallelism.

**Option C - True parallelism (multiple OS threads / shared
mutable memory).** Real `Thread`/work-stealing, shared heap, data
races possible. This is Rust's `Send`/`Sync`, Go's goroutines on
multiple cores, Pony's actor parallelism.

**Strong analysis: Option A is the only model that does not detonate
Capa's safety guarantees. Option C is categorically out. Option B is
the negotiable middle.**

Why A is least disruptive:

- **No data races by construction.** Linear handles and typestate
  protocols both assume a single owner mutating in a single order. A
  cooperative loop preserves that: between `await` points the running
  task has exclusive access, so a linear handle is never touched by
  two tasks at the same instant. The *only* new hazard is a handle
  being captured by a task that is suspended at an `await` and resumed
  later, which is a sequencing question the linear analysis can
  handle (Section 4), not a race.
- **The IFC story degrades gracefully but does not collapse.**
  Cooperative scheduling still introduces ordering and timing
  channels (Section 5), but it does *not* introduce the
  shared-mutable-state internal channel that true parallelism does.
  The interleaving is coarse-grained (whole runs between awaits) and
  deterministic-ish, which is the difference between "a new proof
  obligation" and "a new research programme".

Why C is out:

- True parallelism breaks the single-store assumption of *both*
  calculi at once. λ_if's `(σ, s) ⇓ (σ', o)` is a function of one
  store; with shared mutable memory and racing writes, low-equivalence
  is no longer preserved by any flow-sensitive type system without a
  full concurrent-IFC apparatus (rely-guarantee or
  observational-determinism style). λ_cap's single-trace `τ` likewise
  loses meaning when two threads append interleaved. Choosing C means
  re-doing both proofs from scratch against a concurrent semantics,
  and adding a `Send`/`Sync`-class type discipline. That is a
  multi-quarter research effort with no SBOM payoff. **Do not.**

Why B is the negotiable middle: structured spawning on one thread is
implementable and keeps the no-race property, but every spawned task
multiplies the IFC obligation (Section 5.3) and the linear-handle
move analysis (Section 4). The recommendation (Section 6) is to ship
A first and treat B as a later, separately-justified slice.

### 2.2 Capabilities under concurrency

The capability discipline (λ_cap, Theorem 1) says: the only way to a
`Cap[c]` value is transitively from `main`'s initial environment;
attenuation only narrows; the dynamic trace's classes are a subset of
the manifest. **Cooperative async (Option A) preserves this almost
for free**, with two specific things to check:

1. **Crossing an `await` point.** A capability held in a local
   variable across `await` is just a value that survives a suspension.
   Theorem 1's invariant ("every free `cap[c, ρ]` in the current term
   has `c ∈ C_init`") is a property of the term, not of timing; a
   suspend/resume does not synthesise a new capability of a new class.
   So *capability soundness* (the manifest-upper-bound claim)
   survives the cooperative model intact. The calculus would need a
   suspension construct added, but the soundness argument is a
   conservative extension: suspension is an administrative reduction
   that touches neither the trace's class set nor attenuation.

2. **Passing a cap into a spawned task (Option B).** A spawned task
   is a new thread of control that closes over capabilities from its
   parent. This is the new leak surface to reason about: a parent
   could `spawn` a task and hand it an *unattenuated* cap while the
   parent itself only ever uses an attenuated one. That is not a new
   *leak* per se (the parent already held the unattenuated authority;
   handing it onward is ordinary delegation, which the discipline
   already permits), but it does mean **the manifest must account for
   capabilities reachable from spawned-task bodies**, exactly as it
   accounts for capabilities reachable from ordinary called functions.
   The reachability analysis (`capa/manifest/_reachability.py`) would
   need to treat a `spawn f(cap)` edge the same way it treats a call
   edge. Mechanical, not deep.

**New leak surface specific to async:** an `await` that hands control
to the scheduler is an observable side effect window. If the
scheduler is itself a capability-mediated thing (a `Task` cap), then
"the ability to spawn / yield" becomes an authority that *should*
appear in the manifest as a new capability class (call it `Task` /
`Async`). That is the clean design: **model the scheduler as a
capability.** A function that can `spawn` must have received the
`Task` cap, so the SBOM gains an honest `can_spawn_tasks` surface.
This is the one genuinely positive interaction with the moat:
concurrency authority becomes a typed, manifested capability rather
than an ambient power. It is small but real.

### 2.3 Linear / typestate under concurrency

Both disciplines are about **single-owner, single-ordered** use:

- A `linear type` value must be consumed exactly once on every path
  (`capa/analyzer/_linear.py`: `_live_linear`, intersection-merge at
  branch joins).
- A typestate value (`Socket[Created] → Connected → Closed`, roadmap
  S3) is linear and transitions by consuming the old state and
  producing the new one (`become`).

What async does to them:

- **A linear handle must not be usable by two tasks.** Under
  Option A (cooperative, no spawn) this is already guaranteed: there
  is only one thread of control, so "two tasks" does not exist yet;
  the existing analysis is sufficient unchanged. Under Option B
  (spawn), it becomes a real obligation: a linear handle captured by a
  spawned task is *moved* into that task; the parent must lose access
  to it (use-after-move), and the spawned task inherits the
  consume-before-drop obligation. This is exactly the
  `Send`/move-semantics problem, but tractable because the existing
  `_consumed` (use-after-consume) and `_live_linear`
  (never-consumed) machinery already models move-on-consume; `spawn`
  is "consume into the child's scope, obligation transfers". The merge
  logic at a `spawn` boundary is the new code, and it is analogous to
  the existing transfer-on-return rule.
- **A typestate protocol across `await` points.** A protocol that
  suspends mid-sequence (`Socket[Connected]` held across `await
  net.get(...)`) is fine under Option A: the state is in a local, the
  suspension does not transition it, and on resume the protocol
  continues. The analyser already threads typestate through ordinary
  control flow (S3.5 receiver-by-state); `await` is one more
  control-flow form to thread it through, with the same
  branch-merge discipline. Under Option B, a typestate value moved
  into a spawned task is the linear-move case above.

**Verdict:** under Option A, linear/typestate need only an `await` as
a new control-flow node in the existing flow analyses (modest). Under
Option B, they need a move-into-task analysis (real, but built on
existing transfer machinery). Nothing here breaks; it is additive.

### 2.4 IFC / noninterference under concurrency (the big one)

Treated in its own section because it is the crux. See Section 5.

### 2.5 Backends and parity

Parity between the Python transpiler and the Wasm/Component-Model
backend is a **core invariant** of the project (every roadmap slice
ends "byte-identical on both backends"). Async threatens this
invariant more than any other interaction, because the two backends
have *completely different* async substrates.

**Python backend.** This is the easy side. `async fun` maps to Python
`async def`; `await e` maps to Python `await`; cooperative scheduling
maps to `asyncio` with the program driven by `asyncio.run(main(...))`.
The cap classes (`Net`, `Db`, ...) would need async variants
(`aiohttp`-style `Net`, an async SQLite). Generators are the
fallback if `asyncio` is deemed too heavy, but `asyncio` is the
idiomatic, well-trodden path. Effort here is moderate and
low-risk: Python *has* the model natively.

**Wasm Component Model backend.** This is the hard side and the
parity risk.

- **The current host has no event loop at all.** `_invoke_main` is
  one blocking `main(...)` call; cap imports are synchronous Python
  callbacks. There is no `poll`, no readiness, no resume.
- **Stackless vs stackful.** The Capa Wasm backend emits *stackless*
  code (ordinary Wasm functions; a bump allocator; no continuation
  capture). Cooperative async needs the ability to *suspend a
  computation mid-function and resume it later*. On Wasm this is not
  free. The two real options are:
  - **Component Model async** (the WASI 0.3 / "async ABI" work:
    `future`, `stream`, `task.wait`, async-lifted exports). This is
    the principled answer and it is what the Component Model is
    actively growing. But as of this writing it is **immature**: the
    async ABI is recent, wasmtime support is evolving, and the
    Python `wasmtime` bindings the host uses
    (`capa/runtime/_wasm_component_host.py`) do not expose a stable
    async-component driver. Betting the backend on it now is betting
    on a moving target.
  - **Asyncify** (a Binaryen pass that rewrites Wasm to be
    suspendable by spilling the stack to linear memory). This works
    today and is backend-agnostic, but it is a whole-module rewrite,
    inflates code size, has a runtime cost, and interacts awkwardly
    with the bump allocator and the cap-handle table. It is a
    stopgap, not a destination.
  - **Stack switching proposal** (typed continuations / `cont`): the
    cleanest long-term Wasm primitive, but not yet stable in the
    engine the project uses.
- **Host event loop.** Whichever lowering, the host
  (`_wasm_host.py` / `_wasm_component_host.py`) must grow an event
  loop that the suspendable module yields into: cap imports become
  *async* (return a pending/future the host resolves), and the host
  drives readiness. This is a substantial host rewrite, not an
  add-on.

**Parity assessment:** for a window of time, async would be **Python
only**. Achieving byte-identical-trace parity for async programs on
Wasm requires either waiting for Component Model async to stabilise or
adopting Asyncify with all its costs. Either way, the project's "both
backends or it does not ship" invariant means async cannot be
declared done until the Wasm side lands - and the Wasm side is the
long pole. **This single fact is most of the effort and most of the
risk.**

---

## 3. What to reuse vs build new

| Layer | Reuse | Build new |
|---|---|---|
| Lexer / parser | token + node infra | `async` / `await` keywords + AST nodes (small) |
| Analyzer - capabilities | λ_cap discipline, reachability | `await` as a control-flow node; model scheduler as a `Task` cap; spawn-edge in reachability (Option B) |
| Analyzer - linear (`_linear.py`) | `_live_linear`, intersection merge, transfer-on-return | `await` as flow node (A); move-into-task merge (B) |
| Analyzer - typestate (S3) | per-state receiver, `become`, branch-threading | `await` as flow node; move-into-task (B) |
| Analyzer - IFC (`_ifc.py`) | label lattice, `pc` machinery, sink rules | **the hard part: scheduling/ordering/timing channel analysis** (Section 5) |
| Proofs (`proofs/`) | λ_cap + λ_if structure, the `--safe` Agda discipline | a concurrent semantics layer + re-proof of the relevant theorem (Section 5.4) |
| CIR (`capa/ir/_lower*`) | the whole lowering pipeline | suspension points in lowering |
| Python emit | `_emit_fun` shape | `async def` / `await` emission; async cap classes |
| Wasm emit | structs/closures/handles | suspension lowering (Asyncify or CM-async); **host event loop** |
| Runtime caps | `Fs`/`Net`/`Db` classes, attenuation, handle table | async cap variants on both hosts |
| SBOM / manifest | the whole manifest pipeline | `can_spawn_tasks` / async-authority surface (the one moat win) |

The reusable surface is large; the genuinely-new surface concentrates
in two places: **the IFC channel analysis** and **the Wasm
suspension + host loop**. Those two are the cost.

---

## 4. Scope options and a recommended minimal first slice

### 4.1 Scope ladder

- **S-0 (do nothing).** Current state. Recommended default until a
  driver arrives (Section 8).
- **S-1 (cooperative async, Python-only, one async cap).**
  `async fun` + `await`, Option A, a single async-capable I/O
  capability (`Net` is the obvious pick: fan-out HTTP is the headline
  use case). Python backend only; Wasm async deferred and explicitly
  documented as "async programs are Python-backend-only for now".
  Scheduler modelled as a `Task` cap so the manifest stays honest.
- **S-2 (cooperative async, both backends).** S-1 plus the Wasm
  suspension lowering + host event loop. This is where the long pole
  lands. Gated on Component Model async maturity or an Asyncify
  decision.
- **S-3 (structured concurrency / spawn).** Option B on top of S-2:
  task groups, move-into-task linear analysis, per-task IFC
  obligation. Separately justified.
- **S-X (true parallelism).** Option C. Out of scope, recommend
  against (Section 2.1).

### 4.2 Recommended minimal first slice, IF proceeding

**S-1: cooperative async on the Python backend with `Net` as the one
async cap, scheduler as a `Task` capability.**

What it *would* guarantee:
- Capability soundness (Theorem 1 analogue) preserved: `await` is an
  administrative reduction, classes still bounded by the manifest; the
  new `Task` authority appears in the SBOM.
- Linear/typestate preserved: `await` is one new control-flow node;
  no spawn, so no move-into-task case yet.
- IFC *explicit-flow* (the default warn tier) preserved unchanged: a
  secret reaching a sink is still caught regardless of interleaving,
  because explicit data-flow labels do not depend on order.

What it would **NOT** guarantee (and must be documented as such):
- **No backend parity.** Async programs run on Python only; the Wasm
  backend rejects `async` until S-2. This is a real, visible hole in
  the project's core invariant and must be stated loudly.
- **No defence against scheduling / ordering / timing channels**
  under `@strict_ifc` (Section 5). The cooperative model *shrinks*
  these channels but does not eliminate them, and the existing
  noninterference proof does not cover them. S-1 would have to either
  (a) scope `@strict_ifc` to forbid `await` under a secret `pc`, or
  (b) explicitly carve async out of the noninterference claim. Either
  is an honesty cost.
- **No spawn.** Single thread of control only; no fan-out *task*, only
  overlapped *awaits* within one logical task (which already covers
  the "many in-flight `Net.get`" case via an `await_all`-style
  combinator that the runtime provides, not user-spawned tasks).

---

## 5. IFC / noninterference under concurrency (the crux)

This is the section that determines the recommendation.

### 5.1 What the current proof guarantees, and why it is sequential

λ_if (Section 9 of `docs/semantics.md`, mechanised in
`proofs/CapaNoninterference.agda`) proves
**termination-insensitive noninterference** for a *single
sequential* big-step semantics. The observer sees PUBLIC variables
and the ordered public output trace `o`. Theorem 3 says: two runs
from low-equivalent stores with different secrets produce identical
public output `o` and low-equivalent final stores. The proof leans
on three sequential facts:

1. **One control flow, one `pc`.** The confinement lemma (Lemma 2)
   says a statement typed under SECRET `pc` emits `o = ε` and changes
   no PUBLIC variable. There is exactly one `pc` because there is
   exactly one thread of control.
2. **One output trace, append-only in program order.** `o_1 = o_2` is
   a statement about a single deterministic emission order.
3. **One store.** Low-equivalence `σ ≈_Γ σ'` is over a single store
   map; `T-While` relies on an in-place monotone fixpoint of *that*
   store's labels.

The proof is honest that it covers neither timing nor termination
(Section 9.6: "the static analyser performs no termination reasoning
whatsoever"). It does not cover *ordering* because in a sequential
program there is only one order.

### 5.2 What concurrency does to it

Concurrency reopens noninterference along axes the proof never
modelled:

- **Scheduling channel.** If the *scheduler's decision* of which task
  to resume can depend on a secret (e.g. a task that `await`s a
  duration computed from a secret, or yields conditionally on a
  secret branch), then the *order* of public outputs from other tasks
  becomes a function of the secret. Two runs with different secrets
  can produce the *same multiset* of public outputs in a *different
  order* - and `o_1 = o_2` (sequence equality) is violated even
  though no secret value was ever in a sink argument. The current
  proof's observation (an ordered trace) is *exactly* the thing a
  scheduling channel attacks.
- **Internal timing / progress channel.** A secret-dependent `await`
  duration leaks via *when* a public output appears relative to
  another, observable to any concurrent task. Cooperative scheduling
  makes this coarser (yields only at `await`) but does not remove it.
- **Ordering channel between tasks sharing state (Option B/C).** Two
  tasks reading/writing the same PUBLIC variable in a secret-dependent
  interleaving leak through the *final* value. Option A (no spawn,
  one task) sidesteps this entirely; it is the reason A is the safe
  model.

### 5.3 How much does the cooperative model (Option A) sidestep?

Substantially, but not completely - this is the load-bearing nuance.

- **Option A with NO spawn (S-1):** there is one thread of control and
  one output trace, in program order, with `await` as the only yield.
  The *explicit-flow* guarantee (secret value in a sink) is untouched:
  it is order-independent. The *implicit-flow* `pc` guarantee is
  untouched *as long as `await` does not itself become an observable
  whose timing depends on a secret*. The residual channel is exactly:
  **a secret-dependent decision to `await` (or how long to `await`)
  observed via the relative timing of public outputs.** With a single
  task and a single observer reading one in-order trace, even this
  largely collapses to the existing termination-insensitivity
  caveat: the proof already declines to reason about *when* outputs
  appear, only *what* they are and *in what program order*. So S-1's
  honest position is: **noninterference over the value-and-order trace
  survives, modulo the same timing carve-out already documented**,
  PROVIDED `@strict_ifc` forbids a secret-conditioned `await` (a small
  extension of the existing `@constant_time` "no secret branch"
  discipline, which already rejects secret-dependent control flow).
- **Option B (spawn):** the scheduling channel and the
  shared-state ordering channel come fully alive. Two tasks, two
  interleaved emission orders, one shared store. `o_1 = o_2` as a
  *sequence* is no longer something a flow-sensitive type system
  delivers without a concurrent-noninterference apparatus
  (observational determinism, or low-determinism á la Zdancewic-Myers
  / Terauchi-Aiken). This is the point where the proof must be
  redone against a concurrent semantics, not extended.

### 5.4 What it would take to recover a guarantee

- **For S-1 (Option A, no spawn):** extend `@strict_ifc` to reject a
  secret-dependent `await` (reuse the `@constant_time` secret-branch
  rejection machinery, `_ct_reject` in `_ifc.py`). Then the existing
  Theorem 3 statement holds for async programs *with the timing
  carve-out already in place*, because the single-task in-order trace
  is preserved. The Agda would need a suspension construct added to
  λ_if and the lock-step induction extended over it - a conservative
  extension, on the order of adding one statement form, NOT a rewrite.
  This is achievable.
- **For S-2/S-3 (parallel emission / spawn):** recover requires a
  *concurrent* noninterference theorem - observational determinism or
  a possibilistic/probabilistic noninterference over interleavings -
  proved against an interleaving small-step semantics. That is a new
  calculus and a new proof, a research-grade undertaking comparable in
  size to the entire existing λ_if development, with a *weaker, harder
  to state* guarantee at the end. This is the honest cost ceiling of
  going past Option A.

### 5.5 The crux, stated plainly

**The single hardest decision is whether async must preserve the
machine-checked noninterference guarantee, and if so, at what
concurrency model the cost becomes prohibitive.** The answer this
study reaches: **Option A (cooperative, no user-visible spawn) keeps
the guarantee recoverable with a conservative proof extension;
anything past it (spawn, parallelism) forces a from-scratch concurrent
noninterference proof for a weaker theorem.** The moment the design
admits two concurrently-emitting tasks, the project's "machine-checked
noninterference" headline either gets a large new asterisk or a large
new proof. That trade is the crux, and it is why the recommendation
caps the ambition at Option A.

---

## 6. Effort and risk

### 6.1 Rough effort (honest, multi-month)

- **S-1 (Python-only cooperative async, one async cap, Task-cap
  modelling, `@strict_ifc` secret-`await` rejection):** ~6-10 slices.
  Parser/AST small; async cap variant small; the IFC `await`-flow node
  + secret-`await` rejection moderate; the λ_if proof extension
  moderate. Call it **1.5-3 months** of focused work, dominated by
  getting the IFC extension and its proof right rather than by the
  surface syntax.
- **S-2 (both backends):** add the Wasm suspension lowering + host
  event loop. This is the long pole. If Component Model async is
  stable enough to lean on, **2-4 months** on top of S-1; if Asyncify
  is used as a stopgap, faster to a working state but with code-size /
  perf debt and a later migration. If the CM-async bet is wrong, this
  can balloon. **High variance.**
- **S-3 (spawn / structured concurrency):** the concurrent
  noninterference proof alone is **research-grade, open-ended**
  (multiple months, uncertain). Recommend not committing without a
  separate study.

Total to a "both-backends, structured-concurrency" end state:
realistically **6-12+ months**, most of it in Wasm-async maturity and
the concurrent IFC proof. This is a major arc, not a feature.

### 6.2 Top risks

1. **Wasm-async immaturity (highest).** Betting S-2 on Component
   Model async that is still moving; or taking on Asyncify debt. This
   risks the parity invariant for an extended window.
2. **Noninterference erosion (highest, tied).** Any slip past
   Option A silently weakens the project's flagship machine-checked
   claim. The SBOM/IFC moat is the whole positioning; eroding it for a
   non-moat feature is the worst trade in the codebase.
3. **Audit-surface explosion.** The roadmap's anti-scope line is
   explicit: every new feature is more surface for the audit campaign.
   Async touches the lexer, parser, every analyzer pass, both
   backends, both hosts, and the proofs. It is the single
   largest-surface feature on any list.
4. **Coloured-function ergonomics.** `async`/`await` colours the
   call graph (async callers, async callees); retrofitting it onto an
   existing synchronous stdlib and existing programs is a known
   ergonomic tax that interacts badly with traits/generics.
5. **Effort overrun.** The IFC proof extension and the Wasm host loop
   are both "looks bounded, is not" candidates.

### 6.3 Prerequisites that should exist first

Per `roadmap-security-performance.md` sequencing, and confirmed by
this study:

- **S2 (IFC) must be solid and stable.** It is. But async *reopens*
  it, so async should not start until there is appetite to re-touch
  the IFC proof.
- **P1 (Wasm AOT) done** (it is) and **P2 (real GC) at least
  scoped** - a long-running async service leaks under the current bump
  allocator, so async without GC delivers a service that cannot
  actually run long. Async's main use case (long-running I/O service)
  is gated on P2. **Async before P2 is a feature whose own use case it
  cannot serve.**
- **A concrete async workload in `~/Desktop/repos/`** that is
  demonstrably I/O-bound and serial-blocked, to anchor the design and
  justify the cost. None exists today.
- **Clarity on Component Model async maturity** in the wasmtime
  version the project pins, before committing to S-2.

---

## 7. Summary table: model vs guarantee

| Guarantee | Sequential (today) | Option A (coop, no spawn) | Option B (spawn) | Option C (parallel) |
|---|---|---|---|---|
| Capability soundness (Thm 1) | proved | preserved (conservative ext.) | preserved + spawn-edge in reachability | preserved but trace re-proof |
| Linear / typestate | enforced | `await` as flow node | + move-into-task | + Send/Sync discipline |
| IFC explicit-flow | enforced | preserved | preserved | needs concurrent IFC |
| IFC implicit / noninterference (Thm 3-4) | machine-checked | recoverable w/ secret-`await` ban + proof ext. | from-scratch concurrent proof, weaker theorem | research-grade, weaker theorem |
| Backend parity | held | **broken until S-2** | broken until S-2 | broken |
| New SBOM surface | - | `Task` cap (moat win) | per-task authority | - |
| Effort | - | 1.5-3 mo | +open-ended proof | do not |

---

## 8. Recommendation

**Defer. Do not start async now. Start only when a concrete driver
arrives, and if it does, cap the ambition at Option A (cooperative,
no user-visible spawn).**

Justification, tied to positioning:

1. **Weak moat fit.** Async produces no new supply-chain-assurance
   claim (Section 1). The one positive interaction - a `Task`
   capability in the SBOM - is small and does not justify the cost.
2. **It reopens the flagship guarantee.** The machine-checked
   noninterference proof is the project's most defensible asset
   (`roadmap-security-performance.md`: "the unique bet"). Async is the
   one feature on the list that *attacks* it, and the safe-but-real
   version (Option A) still costs an IFC proof extension and a
   `@strict_ifc` secret-`await` rule (Section 5.4). Spending the
   moat's proof budget on a non-moat feature is the wrong trade.
3. **It breaks parity for an extended window.** The Wasm-async
   substrate is immature (Section 2.5); shipping async means
   Python-only async for an uncomfortable period, violating the "both
   backends or it does not ship" invariant on a large surface.
4. **Its own use case is gated on prerequisites that are not done.**
   The headline use case (long-running I/O service) needs P2 (real
   GC) first; async before GC is a service that leaks itself to death.
5. **The roadmap already says so.** This study confirms, with
   grounded reasons, the existing anti-scope line.

**The exact driver/condition that would justify starting:** a real,
in-tree, I/O-bound workload (a daemon/server/agent in
`~/Desktop/repos/` whose surface matches what async would change)
that is *demonstrably* bottlenecked on serial blocking I/O, **AND**
P2 (real GC) landed so the workload can actually run long, **AND**
appetite to re-touch the IFC proof. When all three hold, start at
**S-1 (Option A, Python-only, `Net` async, `Task`-cap, secret-`await`
ban under `@strict_ifc`)**, and treat S-2 (Wasm) as a separately-gated
slice contingent on Component Model async maturity. Do not pursue
spawn (S-3) or parallelism (S-X) without a dedicated follow-up study,
because that is where the concurrent-noninterference proof cost goes
from "extension" to "research programme".
