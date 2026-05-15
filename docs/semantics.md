# λ_cap: a small-step calculus for Capa's capability discipline

> **Status: sketch.** This document is the working draft of
> the formal core. It states the syntax, typing rules, and
> small-step semantics of a minimal lambda calculus *λ_cap*
> that captures Capa's three layers of capability discipline,
> and the two soundness theorems the discipline is intended
> to prove. The proofs are sketched, not completed.
>
> Audience: reviewers who want to know there is a path from
> the design-document level to a referee-defensible
> formalisation.

---

## 1. Scope of the calculus

Capa-the-language has more shapes than this document covers
(structs, sum types, traits, pattern matching, attenuation
chains, the `?` operator, generic instantiation, ...). Most of
them are orthogonal to the capability discipline: they are
standard data-shape machinery whose soundness has been worked
out elsewhere. λ_cap focuses on the part where Capa says
something new:

- which terms are allowed to invoke a capability,
- under what static conditions an invocation is sound,
- how the dynamic trace of capability invocations relates to
  the static signature of the program's entry point.

The unmodelled shapes can be reintroduced as standard
extensions to λ_cap with no impact on the soundness arguments.

---

## 2. Syntax

```
e ::=  x                           variable
    |  λx:T. e                     abstraction
    |  e1 e2                       application
    |  let x = e1 in e2            let binding
    |  cap[c]                      capability value of class c
    |  attn(e, ρ)                  attenuate e with restriction ρ
    |  invoke(e, op)               invoke operation op on capability e
    |  consume(e)                  consume capability e (linear use)
    |  ()                          unit value

v ::=  λx:T. e                     lambda value
    |  cap[c, ρ]                   concrete capability, class c, restriction ρ
    |  ()                          unit
```

Each capability class `c` ranges over a fixed finite set
`𝒞 = { Stdio, Fs, Net, Env, Clock, Random, Unsafe }`. A
restriction `ρ ⊆ Σ_c` is a finite subset of the *scope set*
for class `c` (host names for `Net`, path prefixes for `Fs`,
key names for `Env`, etc.). `ρ = ⊤` denotes the unattenuated
authority. The lattice `(𝒫(Σ_c), ⊆)` is the attenuation
ordering: `ρ ⊑ ρ'` iff `ρ ⊆ ρ'`. `attn` produces the
greatest lower bound:

```
attn(cap[c, ρ], ρ')  ≡  cap[c, ρ ∩ ρ']
```

For each class `c` we postulate a fixed set of operations
`Ops(c)`. For `Stdio`, `Ops = { print, println, eprintln,
read_line }`; for `Net`, `Ops = { get, ... }`; and so on.
Every `op ∈ Ops(c)` carries a *scope predicate*
`α_op : Σ_c → Bool` that determines whether a given attenuation
permits the operation. For `Net.get(url)` the predicate is
`α_get(host(url)) ⇔ host(url) ∈ ρ`.

The omitted machinery (numbers, strings, arithmetic, control
flow) is added by the standard rules of a simply-typed lambda
calculus.

---

## 3. Types

```
T ::=  τ                           base type (Int, String, ...)
    |  Cap[c]                      capability type, class c
    |  T1 → T2                     function type
    |  T1 -∘ T2                    linear (consuming) function type
    |  Unit
```

The capability type `Cap[c]` does *not* index the attenuation:
restrictions are runtime values, not types. The static rule
only ensures every `invoke(e, op)` has `e : Cap[c]` for some
class `c` known statically and `op ∈ Ops(c)`.

A linear function type `T1 -∘ T2` represents the *consume*
construct: a parameter of consuming type may be referenced
exactly once on every execution path. The structural and flow
layers use the ordinary arrow `→`.

---

## 4. Typing rules

The judgement is `Γ ⊢ e : T`. The context `Γ` is split into a
non-linear part `Γ_∞` (variables of ordinary type, usable any
number of times) and a linear part `Γ_1` (variables of consuming
type, usable exactly once). Where rules split the context they
split it disjointly: `Γ_1 = Γ_1' ⊎ Γ_1''`.

```
                                           (T-Var)
─────────────────────                      ─────────────────────
Γ_∞, x:T ⊢ x : T                          x:T ⊢ x : T   (linear)


Γ_∞, x:T1; Γ_1 ⊢ e : T2                                 (T-Abs)
────────────────────────────────────
Γ_∞; Γ_1 ⊢ λx:T1. e : T1 → T2


Γ_∞; Γ_1 ⊢ e1 : T1 → T2     Γ_∞; Γ_1' ⊢ e2 : T1         (T-App)
─────────────────────────────────────────────────
Γ_∞; Γ_1 ⊎ Γ_1' ⊢ e1 e2 : T2


Γ_∞; Γ_1 ⊢ e : Cap[c]                                   (T-Attn)
─────────────────────────────────
Γ_∞; Γ_1 ⊢ attn(e, ρ) : Cap[c]


Γ_∞; Γ_1 ⊢ e : Cap[c]      op ∈ Ops(c)                  (T-Invoke)
──────────────────────────────────────────────
Γ_∞; Γ_1 ⊢ invoke(e, op) : Unit


Γ_∞; Γ_1, x:Cap[c] ⊢ e : T   x ∈ FV(e), occurs once     (T-Consume)
──────────────────────────────────────────────────────────
Γ_∞; Γ_1 ⊢ consume(λx:Cap[c]. e) : Cap[c] -∘ T
```

The capability discipline is encoded structurally in `T-Var`
and `T-Invoke`:

- **Structural layer**: `cap[c]` is *not* a term-former in
  source programs. The only way to obtain a `Cap[c]` is via
  `T-Var`: read a variable whose type is `Cap[c]` from the
  context. The only way for that variable to exist in the
  context is for it to have been bound by a `T-Abs` whose
  parameter type was `Cap[c]`. The only way for that
  abstraction to ever be invoked is if a caller supplies a
  `Cap[c]` value, transitively, from the program's initial
  environment. There is no path from a closed program with
  empty initial capability environment to a `Cap[c]` value.

- **Flow layer**: `T-Consume` (and the linear-use side
  condition `occurs once`) materialise the must-use rule and
  the at-most-once rule for consuming parameters. The rest of
  the flow analysis (every capability parameter must be
  referenced on every branch) is enforced by an auxiliary
  pre-pass at the analyser level; it can be folded into a
  more refined `T-Abs` rule but is not load-bearing for the
  soundness theorems below.

- **Linear layer**: the split `Γ_1 ⊎ Γ_1'` in `T-App` is what
  makes linearity work: a linear variable handed to `e1`
  cannot also appear in `e2`. The standard linear-types
  arguments carry over without modification.

---

## 5. Small-step operational semantics

The reduction relation is `(e, τ) → (e', τ')` where `τ` is a
*trace*: a finite sequence of triples `(c, ρ, op)` recording
each capability invocation in execution order. Reductions
through pure expressions leave `τ` unchanged; only `T-Invoke`
appends to it.

```
                                                        (E-AppL)
(e1, τ) → (e1', τ')
─────────────────────────────────────
(e1 e2, τ) → (e1' e2, τ')


(e2, τ) → (e2', τ')                                     (E-AppR)
─────────────────────────────────────
(v1 e2, τ) → (v1 e2', τ')


((λx:T. e) v, τ) → ([v/x] e, τ)                        (E-Beta)


(let x = v in e, τ) → ([v/x] e, τ)                     (E-Let)


(attn(cap[c, ρ], ρ'), τ) → (cap[c, ρ ∩ ρ'], τ)         (E-Attn)


α_op(ρ) holds                                           (E-Invoke-Allow)
──────────────────────────────────────────────────
(invoke(cap[c, ρ], op), τ) → ((), τ · (c, ρ, op))


¬ α_op(ρ) holds                                         (E-Invoke-Deny)
──────────────────────────────────────────────────
(invoke(cap[c, ρ], op), τ) → ((), τ · (c, ρ, deny[op]))


(consume(λx:Cap[c]. e), τ) →                            (E-Consume)
  (λx:Cap[c]. e, τ)
```

The denial rule is what makes attenuation *fail closed*: when
the runtime restriction does not permit the operation, the
operation is recorded as a denial in the trace and execution
continues. This matches what `Fs.exists` on a denied path does
in the runtime (returns `False`) and what `Net.get` on a
denied host does (returns `Err(IoError(...))`).

---

## 6. The two soundness theorems

### Theorem 1 (Capability Soundness)

Let `e` be a closed term well-typed under an initial
environment `Γ_init = { x_1 : Cap[c_1], …, x_n : Cap[c_n] }`
with each `x_i` bound to `cap[c_i, ⊤]` in the initial store.
Let `C_init = { c_1, …, c_n }` be the set of capability
classes accessible to the program. If

```
(e, ε) →* (e', τ)
```

for any final or intermediate state, then every
`(c, ρ, op) ∈ τ` satisfies `c ∈ C_init`.

**Sketch.** By induction on the length of the reduction
sequence, with the inductive invariant *"every free `cap[c, ρ]`
occurrence in the current term has c ∈ C_init"*. The base case
holds because `e` is closed and its only free capabilities are
the substitutions of `x_i` for `cap[c_i, ⊤]`. The inductive
step considers each reduction rule:

- `E-Beta`, `E-Let`, `E-AppL`, `E-AppR`: substitution
  preserves the invariant by the standard lemma (substituting
  a value of type `Cap[c]` for a variable of type `Cap[c]`
  cannot introduce a new class).
- `E-Attn`: produces `cap[c, ρ ∩ ρ']` whose class is the same
  as the source capability, so the invariant is preserved.
- `E-Invoke-Allow` / `E-Invoke-Deny`: appends `(c, ρ, op)` (or
  `(c, ρ, deny[op])`) to the trace where `c` is the class of
  the receiver capability, which by the invariant is in
  `C_init`. So `c ∈ C_init` as required.
- `E-Consume`: the consume operation produces a value of
  function type; no new capability is created.

The structural layer's type system forbids any other path to a
`Cap[c]` value. ∎

### Theorem 2 (Manifest Completeness)

Let `e` be a closed term with initial environment `Γ_init` and
manifest `M(e) = { c | x : Cap[c] ∈ Γ_init }`. Then for every
reduction sequence `(e, ε) →* (e', τ)`, the multiset of
capability classes appearing in `τ` is a subset of `M(e)`.

**Sketch.** Direct corollary of Theorem 1: every `c` in the
trace is in `C_init`, and `C_init = M(e)` by construction. ∎

The interesting direction of Manifest Completeness is the
*non-emptiness* counterpart: if `c ∈ M(e)` then there exists an
execution path in which `c` appears in the trace. This is not a
theorem of the static system; it is a conservative-approximation
property. A reviewer who pushes for it has to accept that "the
manifest is an upper bound on the dynamic capability surface"
is the load-bearing claim, not "the manifest is exactly the
dynamic capability surface".

---

## 7. What is deferred

The sketch above is sufficient to anchor the future paper but
deliberately leaves four things for the full writeup:

1. **The branch / loop discipline** (the fork-merge and
   dry-run-redo rules of the linear layer). These belong in a
   more refined `T-If`, `T-Match`, and `T-While` family of
   rules that lift the linear consume bookkeeping over
   control flow. The implementation in
   [`capa/analyzer/_statements.py`](../capa/analyzer/_statements.py)
   has the algorithmic version; the calculus version is a
   straightforward standard-style adaptation but needs the
   space of a full paper.

2. **Attenuation completeness**. The `attn` operation is
   semantically the intersection of restriction sets. A
   completeness result for attenuation says "given any sound
   attenuation chain that produces `cap[c, ρ]`, the same `ρ`
   is computed by `attn`". This is closer to a property of
   the lattice than a property of the calculus.

3. **The `Unsafe` boundary**. `py_import` and `py_invoke`
   cross out of λ_cap's reasoning by construction. The clean
   way is to type them as `Unsafe → (Args → Result)` and
   *not* model their bodies; the soundness theorem is then
   stated relative to "everything except behaviour past an
   `Unsafe` invocation". The full writeup will state this
   precisely.

4. **The translation from full Capa to λ_cap**. The mapping is
   conservative: data-shape machinery (structs, sums, traits)
   compiles to ordinary terms; the capability surface
   compiles to the rules above. The full writeup contains the
   translation lemma plus the simulation theorem that says
   "if full-Capa typing accepts `e`, then λ_cap typing
   accepts its translation, and the small-step reductions
   agree on the trace".

---

## 8. What this sketch buys

Two things:

- A **referee-tractable target**: any reviewer who asks
  "where's the formal core?" can be pointed at this document.
  It states the calculus, the rules, the theorems, and the
  proof obligations. The proofs themselves are mechanical and
  fit a workshop paper of moderate length.

- A **mechanically-checkable next step**. The reduction rules
  here are small enough to mechanise in Agda or Coq. A
  serious proof would mechanise Theorem 1 and use it as the
  load-bearing artefact in the
  [positioning document](positioning.md)'s claim that "the
  type system is sound, not just convenient". A Stage 0
  skeleton in Agda (syntax + theorem statements as
  `postulate`) lives at [`proofs/`](../proofs/); the
  staged plan to fill in the proofs is documented in
  `proofs/README.md`.

The path from here to "PLAS or EuroS&P submission" is:
(a) fill in the `postulate` declarations at `proofs/CapaSoundness.agda`
to mechanise the calculus and Theorem 1 in Agda;
(b) re-state Theorem 2 as a property over the manifest emitter
in `capa/manifest/__init__.py`;
(c) write the translation lemma from full Capa to λ_cap;
(d) prose around the case studies in
`examples/cve_*.capa` showing the rules in action.

Estimated work: two to three months of focused effort, which
is the workshop-paper budget.

---

## References (placeholder)

- Wadler, *Linear types can change the world*. The linear
  layer here is a textbook special case.
- Maranget, *Compiling pattern matching to good decision
  trees*. For the future treatment of pattern exhaustiveness
  alongside the capability layers.
- Naur-style operational semantics traditions (Plotkin,
  Wright-Felleisen). The progress/preservation framing in
  Theorem 1 is the standard one.
- WebAssembly Component Model and WIT. Adjacent system at
  module rather than function granularity; the comparison
  belongs in the related-work section of the paper.

(Full references list to be assembled when this document
graduates from sketch to publishable writeup.)
