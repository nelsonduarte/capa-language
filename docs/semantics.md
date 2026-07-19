# λ_cap: a small-step calculus for Capa's capability discipline

> **Status: mechanised.** This document specifies the formal
> core of Capa's capability discipline. It states the syntax,
> typing rules, and small-step semantics of a minimal lambda
> calculus *λ_cap* that captures the three layers of the
> discipline, plus the soundness theorems the discipline
> implies. The proofs are mechanised in Agda at
> [`proofs/CapaSoundness.agda`](../proofs/CapaSoundness.agda)
> with no `postulate` remaining; CI typechecks them on every
> change to [`proofs/`](../proofs/).
>
> **The mechanisation covers a strict subset of this document.**
> Progress, Preservation, Capability Soundness and Manifest
> Completeness are genuinely machine-checked over all ten
> capability classes. The attenuation lattice of Section 2, the
> operation-parameterised `invoke`, and the restriction component
> of `cap[c, ρ]` are **specified here but absent from the Agda**;
> attenuation is modelled as the identity. Section 6.1 states the
> boundary exactly. Read it before citing this document.
>
> Audience: reviewers who want a reference-quality account of
> the discipline plus a mechanised soundness argument they can
> re-check independently.

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

Each capability class `c` ranges over a fixed finite set of the
ten built-in classes
`𝒞 = { Stdio, Fs, Net, Env, Clock, Random, Proc, Db, Serve,
Unsafe }`, whose single source of truth in the compiler is
`BUILTIN_CAPS` in
[`capa/ir/_capa_types.py`](../capa/ir/_capa_types.py) and which the
Agda `Cap` datatype enumerates constructor for constructor (a test
guard fails if the two drift). A
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

## 6.1 Mechanisation coverage: what the Agda contains

The λ_cap mechanisation covers a **strict subset** of the prose in
Sections 2 to 5. This subsection says which subset, in the same
voice as the λ_if deviations D1 to D3 (Section 9.8 and
[`proofs/README.md`](../proofs/README.md)), so a referee opening
the artefact knows before reading it which parts of this document
are backed by a machine and which are specification only.

**Mechanised, under `--safe`, with no `postulate` remaining**
([`proofs/CapaSyntax.agda`](../proofs/CapaSyntax.agda),
[`proofs/CapaSoundness.agda`](../proofs/CapaSoundness.agda),
[`proofs/CapaManifestExact.agda`](../proofs/CapaManifestExact.agda)):
the term syntax, the typing relation, the small-step reduction
relation, PLFA-style parallel renaming and substitution, Progress,
Preservation, Theorem 1 (Capability Soundness) in its single-step
form, Theorem 2 (Manifest Completeness) in its multi-step form,
and literal-introduction confinement for the gated variant. All of
these quantify over the full ten-element `𝒞`: every theorem is
parametric in the capability tag, so the class set is a genuine
universal quantifier and not a modelled sample. Theorem 2 is an
**upper bound**, not an exactness result, and
[`proofs/CapaSoundness.agda`](../proofs/CapaSoundness.agda)
explains why the exactness version is false in general (a program
may declare a capability parameter and never use it).

**Specified above but NOT mechanised.** Three gaps, all of them
consequences of one modelling decision:

- **M1 (attenuation is modelled as the identity).** Section 2
  specifies the attenuation lattice `(𝒫(Σ_c), ⊆)` and the
  greatest-lower-bound equation
  `attn(cap[c, ρ], ρ') ≡ cap[c, ρ ∩ ρ']`. The Agda has none of
  it. `restrict : Cap -> Tm -> Tm` takes **no restriction
  argument at all**, and the rule `R-Restrict` reduces
  `restrict c (cap c)` to `cap c`. Attenuation in the
  mechanisation is therefore the identity on capability values,
  and the development proves nothing whatsoever about narrowing.
  Nothing in the Agda rules out a "restricted" capability
  reaching authority its restriction excludes; that property is
  simply not stated there. This gap is not specific to any one
  class: it affects `Net` host sets and `Fs` path prefixes
  exactly as much as anything newer, and it has been present
  since the first version of the mechanisation.

- **M2 (`invoke` is not operation-parameterised).** Sections 2
  and 3 give `invoke(e, op)` with a per-class operation set
  `Ops(c)` and a scope predicate `α_op : Σ_c → Bool` deciding
  whether an attenuation permits the operation. The Agda's
  `use : Cap -> Tm -> Tm` carries only the class tag. The
  mechanisation therefore tracks *which class* a term exercises
  and never *which operation*, and no scope predicate is
  evaluated anywhere in it.

- **M3 (capability values carry no restriction).** Section 2's
  value form is `cap[c, ρ]`. The Agda constructor is
  `cap : Cap -> Tm`, a bare class tag. This is a corollary of
  M1 rather than an independent gap, but it is worth stating
  separately because it means the restriction component has no
  representation in the model at all, not even an inert one.

**What this costs, stated precisely.** The mechanised theorems are
about the *class-level* capability footprint: which of the ten
classes a program can exercise. That is exactly the granularity
the manifest declares, so Theorems 1 and 2 are meaningful, and
re-checkable, as stated. What is *not* machine-backed is any claim
about attenuation: that `restrict_to` narrows authority, that
narrowing is monotone, or that a restricted handle cannot exceed
its restriction. Read the attenuation content of this document as
specification awaiting mechanisation.

**This is a scheduled decision, not an oversight.** Building real
attenuation semantics into λ_cap (restriction-carrying capability
values, a lattice-valued `restrict`, and a monotonicity theorem)
is deliberately held out of the present work and tracked as its
own project. Note that item 2 of Section 7 below, "attenuation
completeness", presumes the lattice is already in the model; until
M1 is closed, that item is a second step rather than the next one.

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

## 8. What this calculus buys

Two things:

- A **referee-tractable target**: any reviewer who asks
  "where's the formal core?" can be pointed at this document.
  It states the calculus, the rules, the theorems, and the
  proof obligations.

- A **mechanically-checked soundness argument**. The
  reduction rules are mechanised in
  [`proofs/CapaSoundness.agda`](../proofs/CapaSoundness.agda)
  (with the syntax layer in
  [`proofs/CapaSyntax.agda`](../proofs/CapaSyntax.agda)).
  Progress, Preservation, Capability Soundness, and a
  multi-step Manifest Completeness theorem are stated as
  real Agda definitions with no `postulate` declarations
  remaining. CI typechecks the proofs on every change to
  [`proofs/`](../proofs/), so the positioning document's
  claim that "the type system is sound, not just convenient"
  is independently re-checkable rather than aspirational.

What still belongs in a future writeup:
- the translation lemma from full Capa (structs, sum types,
  attenuation chains, the `?` operator, generic instantiation)
  down to λ_cap, with the simulation theorem;
- prose around the case studies in
  `examples/cve_*.capa` showing the rules block specific
  classes of CVE.

These are the workshop-paper deliverables; the underlying
mechanisation they would cite is already in tree.

---

## 9. Noninterference (information-flow soundness)

> **Status: machine-checked.** Section 9 is now mechanised in Agda
> ([`proofs/CapaIF.agda`](../proofs/CapaIF.agda) and
> [`proofs/CapaNoninterference.agda`](../proofs/CapaNoninterference.agda),
> under `--safe`, no postulates): Lemma 1, Lemma 2, Theorem 3 (the
> declassify-free fragment) AND Theorem 4 (delimited release, with
> `declassify`) are all proved and typechecked in CI. Sections 1
> to 8 above describe the capability calculus λ_cap, whose
> soundness is mechanised in the same directory. Section 9 is a
> *different* property about a *different* calculus:
> termination-insensitive noninterference for a store-based
> imperative core λ_if that models Capa's information-flow control
> (the analyser in
> [`capa/analyzer/_ifc.py`](../capa/analyzer/_ifc.py) over the
> two-point lattice in [`capa/_labels.py`](../capa/_labels.py)).
> The prose below states the rules and proofs; the Agda is the
> artefact a referee re-checks. It uses the same honesty
> conventions as [`proofs/README.md`](../proofs/README.md): the
> *calculus* is what is proved sound; fidelity between λ_if and the
> Python analyser is argued informally (Section 9.8), and we do
> **not** claim the Python analyser is verified. Three encoding
> deviations (D1 total stores, D2 inductive big-step semantics, D3
> the release-log form of the Theorem 4 agreement hypothesis) are
> documented in `proofs/README.md` and inline in the Agda.

The result is the standard Volpano-Smith / Sabelfeld-Myers
noninterference theorem for a flow-sensitive type system,
specialised to Capa's two-point lattice and extended with an
explicit declassification primitive (delimited release in the
Sabelfeld-Sands sense). The lineage is cited in the references;
nothing here is novel as a *theorem*. What is load-bearing is
that the rules of λ_if are a faithful core of what
[`capa/analyzer/_ifc.py`](../capa/analyzer/_ifc.py) actually
does, so that a referee reading "Capa's IFC is sound" has a
precise statement to check.

### 9.1 Syntax of λ_if

λ_if is a small imperative language: pure expressions, and
statements over a mutable store, with one secret *source*
(`env_get`), one explicit *downgrade* (`declassify`), and one
public *observable* (`sink`).

```
e ::=  n                            integer / base literal
    |  x                            variable
    |  e1 ⊕ e2                      binary operation (⊕ ranges over a fixed set)
    |  env_get()                    the single secret source
    |  declassify(e)                explicit downgrade to PUBLIC

s ::=  skip                         no-op
    |  x := e                       assignment
    |  s1 ; s2                      sequencing
    |  if e then s1 else s2         conditional
    |  while e do s                 loop
    |  sink(e)                      the single public observable
```

A *store* `σ : Var ⇀ Val` is a finite partial map from variables
to values. A *public output trace* `o : List Val` records, in
order, the values emitted by `sink`. The only modelled base type
is integers (Booleans encoded as `0` / non-`0`); adding strings
and further base types is orthogonal and changes none of the
arguments.

`env_get()` abstracts the analyser's single modelled secret
source `("Env", "get")` (the `_SECRET_SOURCES` set in
`_ifc.py`). `sink(e)` abstracts the public-exfiltration sinks
`_PUBLIC_SINKS` (`Stdio.println` / `print` / `eprintln`,
`Net.get` / `post`, `Fs.write`, `Db.exec` / `query`). `e1 ⊕ e2`
abstracts every label-joining expression form in `_compute_label`
(BinOp, interpolation, indexing, aggregate literals, pure call
results): each is a join of operand labels, so a single n-ary
join former is representative.

### 9.2 Lattice and labels

The lattice is exactly the two-point lattice of
[`capa/_labels.py`](../capa/_labels.py):

```
PUBLIC ⊑ SECRET          (PUBLIC is bottom, SECRET is top)
```

with join `⊔` = least upper bound. Writing `L` for `{PUBLIC,
SECRET}` and ranking `rank(PUBLIC) = 0`, `rank(SECRET) = 1`:

```
ℓ1 ⊔ ℓ2  =  the ℓi with the larger rank        (L.join)
ℓ1 ⊑ ℓ2  ⇔  rank(ℓ1) ≤ rank(ℓ2)                (L.flows_to)
```

`⊔` is commutative, associative, idempotent, with PUBLIC as
unit; `(L, ⊑)` is a two-element bounded lattice. These are the
algebraic facts the proofs use; they are immediate from the
rank table and mirror `join` / `join_all` / `flows_to` in
`_labels.py`.

A *label environment* `Γ : Var ⇀ L` assigns a security label to
each variable. It is *flow-sensitive*: statement typing updates
`Γ` as it goes (mirroring `Symbol.label` being raised in place
by `_label_binding`, `_ifc_field_store`,
`_check_ifc_container_mutation`). A distinguished *program-counter
label* `pc ∈ L` tracks the confidentiality of the control-flow
context (the analyser's `self._pc_label`, raised by `_pc_raise`).

### 9.3 Expression labelling

The judgement `Γ ⊢ e : ℓ` reads "under `Γ`, expression `e` has
security label `ℓ`". The rules are exactly `_compute_label`:

```
                                        (L-Lit)
─────────────────
Γ ⊢ n : PUBLIC


Γ(x) = ℓ                                (L-Var)
─────────────────
Γ ⊢ x : ℓ


Γ ⊢ e1 : ℓ1     Γ ⊢ e2 : ℓ2            (L-Op)
─────────────────────────────────
Γ ⊢ e1 ⊕ e2 : ℓ1 ⊔ ℓ2


                                        (L-Env)
─────────────────────
Γ ⊢ env_get() : SECRET


Γ ⊢ e : ℓ                               (L-Declassify)
─────────────────────────
Γ ⊢ declassify(e) : PUBLIC
```

`L-Lit` is the literal case of `_compute_label`; `L-Var` is the
`A.Ident` case reading `Symbol.label`; `L-Op` is the
join-of-operands core shared by BinOp / interpolation / index /
aggregate / pure-call; `L-Env` is the `_SECRET_SOURCES` case;
`L-Declassify` is the `_is_declassify_call` override that returns
`PUBLIC` regardless of the argument's label (`_compute_label`,
the declassify branch). Labelling is deterministic and total: a
unique `ℓ` exists for every `e` under a `Γ` defined on `e`'s free
variables (immediate by structural induction).

### 9.4 Statement typing

The judgement `pc ⊢ Γ { s } Γ'` reads "under program-counter
label `pc`, statement `s` transforms label environment `Γ` into
`Γ'`". It is flow-sensitive (`Γ` may change) and carries `pc`.

```
                                        (T-Skip)
──────────────────────
pc ⊢ Γ { skip } Γ


Γ ⊢ e : ℓ                               (T-Assign)
──────────────────────────────────────────────
pc ⊢ Γ { x := e } Γ[x ↦ ℓ ⊔ pc]


pc ⊢ Γ { s1 } Γ1     pc ⊢ Γ1 { s2 } Γ2  (T-Seq)
──────────────────────────────────────────────
pc ⊢ Γ { s1 ; s2 } Γ2


Γ ⊢ e : ℓ
(pc ⊔ ℓ) ⊢ Γ { s1 } Γ1
(pc ⊔ ℓ) ⊢ Γ { s2 } Γ2                  (T-If)
──────────────────────────────────────────────
pc ⊢ Γ { if e then s1 else s2 } (Γ1 ⊔ Γ2)


Γ ⊢ e : ℓ     (pc ⊔ ℓ) ⊢ Γ { s } Γ
Γ a fixpoint of the body                (T-While)
──────────────────────────────────────────────
pc ⊢ Γ { while e do s } Γ


Γ ⊢ e : ℓ     ℓ ⊔ pc ⊑ PUBLIC           (T-Sink)
──────────────────────────────────────────────
pc ⊢ Γ { sink(e) } Γ
```

Notes on the rules and their analyser counterparts:

- **T-Assign** sets `Γ(x) := label(e) ⊔ pc`. The `⊔ pc`
  conjunct is the implicit-flow guard: a public expression
  assigned under a secret `pc` still yields a SECRET variable.
  The explicit-flow half is the label join of the RHS value
  (`_join_decl_and_value_label` at a `let` / `var` binding, the
  reassignment branch of `_check_assign` for `x = e`, and
  `_ifc_field_store` for a `p.f = e` field store). The `⊔ pc`
  implicit-flow half is `_join_pc_if_strict`, the single helper
  every one of those three assignment sites routes its result
  through, which joins the current `_pc_label` into the assigned
  label. This `⊔ pc` join is the `@strict_ifc` regime that λ_if
  models: `_join_pc_if_strict` is a no-op unless `@strict_ifc` is
  active, so the default warn tier deliberately does not fold the
  pc into assigned labels and therefore does not enforce this
  implicit flow (Section 9.8, item 6).

- **T-If / T-While** check the body under `pc' = pc ⊔ ℓ` where
  `ℓ` is the condition's label. This is exactly `_pc_raise`,
  which joins the condition labels into `self._pc_label` for the
  duration of the guarded body and restores it afterwards.
  `_check_if` raises the pc over each branch by the conditions
  that select it, and `_check_while` / `_check_for` raise it over
  the loop body by the controlling condition / iterated
  collection (`_pc_raise(s.cond)` and `_pc_raise(s.iter)`
  respectively, restored in a `finally` so the raise scopes to
  the body only). The raised pc only becomes an enforced
  *rejection* under `@strict_ifc`, via the implicit-flow clause
  of T-Sink below; this is the regime λ_if models.

- **T-While** requires `Γ` to be a *fixpoint* of the body: the
  body, checked from `Γ`, must return `Γ` unchanged. This is the
  monotone-join-to-fixpoint that `_ifc.py` realises by raising
  labels *in place* with monotonic joins (the same `Symbol`
  object is carried across iterations, and labels only ever
  rise), so a loop's post-environment is the least fixpoint
  above its entry environment. Existence is guaranteed because
  `L` has finite height (2) and the body transfer function is
  monotone, so iterating from the entry `Γ` reaches a fixpoint
  in finitely many steps; in the rule we take that fixpoint as
  the typing `Γ`.

- **T-If** joins the two branch environments pointwise
  (`(Γ1 ⊔ Γ2)(x) = Γ1(x) ⊔ Γ2(x)`). This is the post-branch
  merge of the in-place monotonic raises across the two arms.

- **T-Sink** is well-typed only if `label(e) ⊔ pc ⊑ PUBLIC`,
  i.e. both the argument and the control-flow context are
  PUBLIC. The `label(e) ⊑ PUBLIC` half is `_check_ifc_sink`'s
  explicit-flow rule (a SECRET argument to a sink position is a
  violation); the `pc ⊑ PUBLIC` half is the `@strict_ifc`
  implicit-flow clause in `_check_ifc_sink` (a sink running
  under a SECRET `pc` is a violation). λ_if models the
  `@strict_ifc` regime, where both are hard errors; the default
  warn-only tier of the analyser is a deliberate usability
  relaxation discussed in Section 9.8.

A program `s` is *well-typed* (under `Γ_0`) if `PUBLIC ⊢ Γ_0 { s }
Γ'` for some `Γ'`, i.e. it type-checks from the public initial
`pc`.

### 9.5 Operational semantics

Big-step over configurations `(σ, s)`, producing a final store
and an output trace. The judgement `(σ, s) ⇓ (σ', o)` reads
"from store `σ`, statement `s` terminates in store `σ'` emitting
output trace `o`". Expression evaluation `σ ⊢ e ⇓ v` is the
obvious total function on a store defined over `e`'s free
variables, with the two nonstandard cases:

```
σ ⊢ env_get() ⇓ κ          (κ the ambient secret value)
σ ⊢ declassify(e) ⇓ v       if σ ⊢ e ⇓ v   (identity on the value)
```

`declassify` is the identity on values; it changes only the
*label*, never the value, matching `_check_declassify` ("declassify
is identity on the value; only its security label changes"). The
secret value read by `env_get()` is an ambient parameter `κ` of
the run; two runs may differ in `κ` (this is precisely what
noninterference quantifies over).

```
                                        (E-Skip)
─────────────────────────
(σ, skip) ⇓ (σ, ε)


σ ⊢ e ⇓ v                               (E-Assign)
─────────────────────────────────
(σ, x := e) ⇓ (σ[x ↦ v], ε)


(σ, s1) ⇓ (σ1, o1)   (σ1, s2) ⇓ (σ2, o2)  (E-Seq)
──────────────────────────────────────────────────
(σ, s1 ; s2) ⇓ (σ2, o1 · o2)


σ ⊢ e ⇓ v   v ≠ 0   (σ, s1) ⇓ (σ', o)   (E-IfT)
──────────────────────────────────────────────────
(σ, if e then s1 else s2) ⇓ (σ', o)


σ ⊢ e ⇓ v   v = 0   (σ, s2) ⇓ (σ', o)   (E-IfF)
──────────────────────────────────────────────────
(σ, if e then s1 else s2) ⇓ (σ', o)


σ ⊢ e ⇓ v   v = 0                       (E-WhileF)
──────────────────────────────────────────────────
(σ, while e do s) ⇓ (σ, ε)


σ ⊢ e ⇓ v   v ≠ 0
(σ, s) ⇓ (σ1, o1)
(σ1, while e do s) ⇓ (σ2, o2)           (E-WhileT)
──────────────────────────────────────────────────
(σ, while e do s) ⇓ (σ2, o1 · o2)


σ ⊢ e ⇓ v                               (E-Sink)
─────────────────────────────────
(σ, sink(e)) ⇓ (σ, [v])
```

`ε` is the empty trace and `·` is trace concatenation. `sink(e)`
appends the value of `e` to the public output trace; nothing
else affects it. The semantics is termination-insensitive by
construction: `⇓` is only defined for terminating runs, and the
theorem below quantifies only over runs that do converge.

### 9.6 Low-equivalence and the noninterference theorem

The observer sees PUBLIC-labelled variables and the public
output trace. Low-equivalence is taken *with respect to a label
environment* `Γ`.

> **Definition (low-equivalence of stores).** For label
> environment `Γ`, two stores `σ` and `σ'` are *low-equivalent*,
> written `σ ≈_Γ σ'`, iff for every variable `x` with `Γ(x) =
> PUBLIC` and `x ∈ dom(σ) ∩ dom(σ')` we have `σ(x) = σ'(x)`.

SECRET-labelled variables may differ freely; PUBLIC-labelled
variables must agree.

> **Theorem 3 (Noninterference, declassify-free fragment).**
> Let `s` be a well-typed statement of λ_if that contains no
> `declassify`, with `PUBLIC ⊢ Γ_0 { s } Γ'`. Let `σ_1 ≈_{Γ_0}
> σ_2` be two low-equivalent initial stores. Fix two arbitrary
> secret source values `κ_1`, `κ_2` for the two runs. If both
> runs converge,
>
> ```
> (σ_1, s) ⇓ (σ_1', o_1)   and   (σ_2, s) ⇓ (σ_2', o_2),
> ```
>
> then the final stores are low-equivalent at the final
> environment, `σ_1' ≈_{Γ'} σ_2'`, and the public output traces
> are identical, `o_1 = o_2`.

In words: a well-typed declassify-free program reveals nothing
about the secret source `κ` (nor about the initial values of
SECRET variables) through either its PUBLIC variables or its
public output. The quantification over arbitrary `κ_1 ≠ κ_2` is
what makes this a confidentiality statement about `env_get()`.

**Termination-insensitivity is the honest match.** The theorem
says nothing about runs that diverge, and a SECRET-conditioned
`while` can diverge on one `κ` and converge on the other. This
is deliberate and faithful: the static analyser in `_ifc.py`
performs no termination reasoning whatsoever (it has no progress
measure, no ranking functions, it only raises labels), so it
cannot and does not rule out the termination channel. Claiming
termination-*sensitive* noninterference would over-state what
the implementation enforces. Termination-insensitive
noninterference is exactly the guarantee a Volpano-Smith-style
flow type system delivers, and exactly what Capa's analyser
delivers. The progress / timing channels are out of scope here
and are partially addressed by the separate `@constant_time`
discipline (`_ct_reject`, `_check_ct_index`, `_check_ct_arith`
in `_ifc.py`), which is *not* modelled by λ_if.

### 9.7 Proof

The proof is the textbook two-lemma structure: an expression
soundness lemma for the explicit-flow case, and a confinement
lemma for the implicit-flow (high-`pc`) case. Both are stated so
they transcribe directly to Agda (structural induction on the
labelling derivation and on the typing derivation respectively).

> **Lemma 1 (Expression label soundness).** If `Γ ⊢ e : PUBLIC`
> and `σ_1 ≈_Γ σ_2`, and both `σ_1 ⊢ e ⇓ v_1` and `σ_2 ⊢ e ⇓
> v_2` (with the same ambient secret values for whichever
> `env_get` occurrences appear), then `v_1 = v_2`. Here the
> declassify-free restriction is in force, so `e` contains no
> `declassify`.

*Proof.* Induction on the derivation of `Γ ⊢ e : PUBLIC`.

- `L-Lit`: `e = n`. Then `v_1 = n = v_2`.
- `L-Var`: `e = x` and `Γ(x) = PUBLIC`. By `σ_1 ≈_Γ σ_2`,
  `σ_1(x) = σ_2(x)`, so `v_1 = v_2`.
- `L-Op`: `e = e1 ⊕ e2 : PUBLIC`. By `L-Op` the label is `ℓ1 ⊔
  ℓ2 = PUBLIC`, and since PUBLIC is the bottom and `⊔` is a
  least upper bound, `ℓ1 = ℓ2 = PUBLIC`. The IH applies to `e1`
  and `e2`, giving equal sub-values; `⊕` is a (pure,
  deterministic) function, so the results are equal.
- `L-Env`: cannot occur, since `L-Env` gives label SECRET, not
  PUBLIC.
- `L-Declassify`: cannot occur in the declassify-free fragment.

∎

> **Lemma 2 (Confinement / high-pc).** If `SECRET ⊢ Γ { s } Γ'`
> (the statement is typed under a SECRET program-counter) and
> `(σ, s) ⇓ (σ', o)`, then:
> (i) `o = ε` (the run emits no public output); and
> (ii) for every `x` with `Γ(x) = PUBLIC`, `σ'(x) = σ(x)` and
> moreover `Γ'(x) = PUBLIC ⟹ Γ(x) = PUBLIC` with the value
> unchanged. Equivalently, a statement typed under SECRET `pc`
> assigns only to variables whose resulting label is SECRET, and
> emits nothing.

*Proof.* Induction on the derivation of `(σ, s) ⇓ (σ', o)`,
inverting the typing derivation `SECRET ⊢ Γ { s } Γ'` at each
step.

- **E-Skip** (`s = skip`, `T-Skip`): `σ' = σ`, `o = ε`. Both
  parts hold trivially.
- **E-Assign** (`s = x := e`, `T-Assign`): `o = ε`, discharging
  (i). For (ii), `Γ' = Γ[x ↦ ℓ ⊔ pc]` with `pc = SECRET`, so
  `Γ'(x) = ℓ ⊔ SECRET = SECRET`. Thus the *only* variable whose
  value changed, `x`, has `Γ'(x) = SECRET`, not PUBLIC. Every
  PUBLIC-labelled variable under `Γ'` is `≠ x`, hence unchanged
  in the store and already PUBLIC under `Γ`.
- **E-Seq** (`T-Seq` with `SECRET ⊢ Γ { s1 } Γ1` and `SECRET ⊢
  Γ1 { s2 } Γ2`): apply the IH to each sub-derivation. The first
  gives `o1 = ε` and that no PUBLIC variable changed value
  through `s1`, with each surviving-PUBLIC variable still PUBLIC
  in `Γ1`; the second gives `o2 = ε` likewise from `Γ1`.
  Composing, `o = o1 · o2 = ε`, and no PUBLIC variable changed
  across the sequence.
- **E-IfT / E-IfF** (`T-If`): the chosen branch `si` is typed
  under `(pc ⊔ ℓ)` with `pc = SECRET`, so under SECRET. The IH
  on the branch's evaluation gives `o = ε` and no PUBLIC change
  for that branch; the post-environment is `Γ1 ⊔ Γ2` and a
  variable PUBLIC there is PUBLIC in both `Γ1` and `Γ2`, hence
  (by the IH applied to whichever branch ran) unchanged.
- **E-WhileF** (`T-While`): zero iterations, `σ' = σ`, `o = ε`.
- **E-WhileT** (`T-While`): the body is typed under `(pc ⊔ ℓ) =
  SECRET` and the loop is a fixpoint (`Γ` in, `Γ` out). The IH
  on the body gives `o1 = ε` and no PUBLIC value change; the IH
  on the recursive while-evaluation (same SECRET typing, same
  fixpoint `Γ`) gives `o2 = ε` and no PUBLIC change. Compose.
- **E-Sink** (`s = sink(e)`, `T-Sink`): `T-Sink` requires
  `label(e) ⊔ pc ⊑ PUBLIC`. With `pc = SECRET` this demands
  `SECRET ⊑ PUBLIC`, which is false. So `sink(e)` is **not**
  typable under SECRET `pc`; this case is vacuous. (This is the
  one place confinement leans on the `pc` conjunct of T-Sink,
  i.e. the `@strict_ifc` implicit-flow clause.)

∎

> **Theorem 3 (restated) and its proof.**

*Proof of Theorem 3.* We prove the stronger statement by
induction on the *shape of the two evaluation derivations run in
lock-step*, generalised over the typing `pc ⊢ Γ { s } Γ'` and
the invariant: for low-equivalent inputs `σ_1 ≈_Γ σ_2`, if both
runs converge then `σ_1' ≈_{Γ'} σ_2'` and `o_1 = o_2`. The
top-level theorem is the `pc = PUBLIC`, `Γ = Γ_0` instance.

Proceed by induction on the first run's derivation `(σ_1, s) ⇓
(σ_1', o_1)`, case-splitting on whether `pc = PUBLIC` or `pc =
SECRET` where the cases need it.

- **skip**: both runs use E-Skip; stores unchanged, both traces
  `ε`. `σ_1 ≈_Γ σ_2` and `Γ' = Γ` close it.

- **x := e** (`T-Assign`, `Γ' = Γ[x ↦ ℓ ⊔ pc]`): both runs use
  E-Assign, no output, so `o_1 = o_2 = ε`. For low-equivalence
  at `Γ'`, take any `y` with `Γ'(y) = PUBLIC`.
  - If `y ≠ x`: `Γ'(y) = Γ(y) = PUBLIC` and the store value of
    `y` is unchanged in both runs, so `σ_1'(y) = σ_1(y) =
    σ_2(y) = σ_2'(y)` by the hypothesis `σ_1 ≈_Γ σ_2`.
  - If `y = x`: `Γ'(x) = ℓ ⊔ pc = PUBLIC` forces `ℓ = PUBLIC`
    *and* `pc = PUBLIC`. Then `Γ ⊢ e : PUBLIC`, and by Lemma 1
    (using `σ_1 ≈_Γ σ_2`) the assigned values agree: `σ_1'(x) =
    σ_2'(x)`.

- **s1 ; s2** (`T-Seq`): IH on `s1` from `σ_1 ≈_Γ σ_2` gives
  `σ_{1,1} ≈_{Γ1} σ_{2,1}` and equal first outputs; IH on `s2`
  from there gives `σ_1' ≈_{Γ2} σ_2'` and equal second outputs.
  Concatenated outputs are equal.

- **if e then s1 else s2** (`T-If`, condition label `ℓ`,
  `Γ' = Γ1 ⊔ Γ2`). Two sub-cases on `ℓ`.
  - **`ℓ = PUBLIC` (low branch).** By Lemma 1 the condition
    evaluates equally in both runs, so both take the *same*
    branch `si`. That branch is typed under `pc ⊔ ℓ = pc`. Apply
    the IH to `si` from `σ_1 ≈_Γ σ_2`: equal outputs, and
    `σ_1' ≈_{Γi} σ_2'`. Since `Γ' = Γ1 ⊔ Γ2` and a variable
    PUBLIC in `Γ'` is PUBLIC in `Γi`, low-equivalence lifts from
    `Γi` to `Γ'`.
  - **`ℓ = SECRET` (high branch).** The two runs may take
    different branches. But each branch is typed under `pc ⊔ ℓ =
    SECRET`. Apply Confinement (Lemma 2) to whichever branch run
    each side took: each emits `o = ε` (so `o_1 = ε = o_2`,
    equal) and changes no PUBLIC-at-`Γ'` variable's value (a
    variable PUBLIC in `Γ' = Γ1 ⊔ Γ2` is PUBLIC in both `Γ1` and
    `Γ2`, hence within scope of Lemma 2(ii) for whichever branch
    ran). Therefore each run's PUBLIC variables equal their
    initial values, which agreed by `σ_1 ≈_Γ σ_2`; so
    `σ_1' ≈_{Γ'} σ_2'`. (Note this high case can only arise when
    `pc = PUBLIC` at entry but `ℓ = SECRET` raises it; when `pc`
    is already SECRET the whole statement is governed by Lemma 2
    directly and the theorem's conclusion is immediate.)

- **while e do s** (`T-While`, fixpoint `Γ`, `Γ' = Γ`). Sub-case
  on the condition label `ℓ`.
  - **`ℓ = PUBLIC`.** By Lemma 1 the guard evaluates equally in
    both runs, so both take the same number of iterations and
    in lock-step (a standard induction on the number of
    iterations, using the IH on the body, which is typed under
    `pc ⊔ ℓ = pc` and returns the same fixpoint `Γ`). Each
    iteration preserves `σ_1 ≈_Γ σ_2` and equal accumulated
    output; the result follows.
  - **`ℓ = SECRET`.** The body is typed under `pc ⊔ ℓ = SECRET`,
    and the two runs may iterate different numbers of times.
    Apply Confinement (Lemma 2) to each iteration of each run:
    every iteration emits `ε` and changes no PUBLIC variable's
    value. Hence both whole loops emit `ε` (equal) and leave
    every PUBLIC variable at its initial, agreeing value, so
    `σ_1' ≈_Γ σ_2'`. (Termination-insensitivity is used exactly
    here: if one run loops forever it has no `⇓` derivation and
    is outside the theorem's hypothesis; we only relate runs
    that both converge.)

- **sink(e)** (`T-Sink`, requires `label(e) ⊔ pc ⊑ PUBLIC`).
  Well-typedness forces `label(e) = PUBLIC` and `pc = PUBLIC`.
  By Lemma 1 the emitted value agrees: `v_1 = v_2`, so `o_1 =
  [v_1] = [v_2] = o_2`. The store is unchanged, preserving
  `σ_1 ≈_Γ σ_2 = σ_1' ≈_{Γ'} σ_2'`.

Every case preserves both conjuncts; the induction closes. ∎

### 9.7.1 Declassify-relaxed form (delimited release)

With `declassify` reintroduced, strict noninterference is by
design false: `declassify` *is* a deliberate downgrade. The
honest statement is *delimited release* / *relaxed
noninterference* in the Sabelfeld-Sands sense: the program
leaks nothing *beyond the values it explicitly declassifies*.

Let `D(s)` be the (multiset of) sub-expressions appearing inside
`declassify(·)` positions in `s`. Given a run, write `⟦D(s)⟧_σ^κ`
for the tuple of values those declassified expressions evaluate
to during that run.

> **Theorem 4 (Relaxed noninterference, delimited release).**
> Let `s` be well-typed with `PUBLIC ⊢ Γ_0 { s } Γ'`. Let
> `σ_1 ≈_{Γ_0} σ_2` with ambient secrets `κ_1`, `κ_2`. If both
> runs converge and additionally the two runs *agree on every
> declassified value*, i.e.
>
> ```
> ⟦D(s)⟧_{σ_1}^{κ_1}  =  ⟦D(s)⟧_{σ_2}^{κ_2},
> ```
>
> then `σ_1' ≈_{Γ'} σ_2'` and `o_1 = o_2`.

*Proof.* Identical to the proof of Theorem 3, with one extra
labelling case to discharge in Lemma 1:

- `L-Declassify`: `e = declassify(e_0) : PUBLIC`. We must show
  the two runs assign it equal values. By the *hypothesis* of
  Theorem 4, the two runs agree on every declassified value, and
  `e_0 ∈ D(s)`; therefore `v_1 = ⟦e_0⟧_{σ_1}^{κ_1} =
  ⟦e_0⟧_{σ_2}^{κ_2} = v_2` directly. (We do *not* recurse into
  `e_0`; the agreement is assumed, which is precisely what
  "released modulo the declassified expressions" means.)

Every other case of Lemma 1, and of the main induction, is
unchanged. The escape hatch is contained to `L-Declassify`: a
SECRET value can become PUBLIC only by passing through a
`declassify`, and the theorem then relates only those runs that
already agree on what was released. ∎

> **Mechanisation note (encoding of the agreement hypothesis,
> deviation D3).** Theorems 3 and 4 are now machine-checked in
> Agda ([`proofs/CapaNoninterference.agda`](../proofs/CapaNoninterference.agda),
> `noninterference` and `theorem4`, under `--safe`, no postulates).
> The Agda development encodes the agreement hypothesis
> `⟦D(s)⟧_{σ_1}^{κ_1} = ⟦D(s)⟧_{σ_2}^{κ_2}` not as one flat
> multiset equality but in two structural forms (in
> [`proofs/CapaIF.agda`](../proofs/CapaIF.agda)): `EAgree` on
> expressions ("the two runs agree on every declassified value
> inside `e`") and `Agree` on the two big-step derivations
> ("...along the actual execution paths"). A concrete per-
> expression *release log* `releases κ σ e` is also defined (the
> sequence of declassified values an expression produces, the
> `declassify` analogue of the `sink` output trace `o`), and
> `EAgree` is proved EQUIVALENT to release-log equality
> `releases κ_1 σ_1 e = releases κ_2 σ_2 e` (`eagree->releq` /
> `releq->eagree`). So the Agda hypothesis IS the release-set
> agreement above, only phrased per declassify position so the
> `L-Op` and `L-Declassify` cases decompose without list-append
> reasoning. The derivation-indexed `Agree` is the faithful
> operational reading of `⟦D(s)⟧` evaluated at the store each
> declassify is actually reached in; where the two runs diverge
> under a SECRET guard it demands agreement only on the guard's
> releases, since the divergent declassifies are confined by
> Lemma 2 exactly as in the proof above. This keeps the hypothesis
> non-vacuous: a worked example in the Agda file
> (`sink(declassify(env_get))`) is covered by Theorem 4 but
> excluded from Theorem 3, and its agreement hypothesis reduces to
> secret equality `κ_1 = κ_2`, so Theorem 4 does not collapse into
> Theorem 3.

This matches the analyser's `declassify(value, reason: "...")`:
the label drops to PUBLIC (`_compute_label`), the value is
unchanged (`_check_declassify`), and the `reason` string is the
audit record that, in the deployed system, is what an auditor
inspects to decide whether the released values were appropriate.
λ_if models the *flow* effect of declassify; the SBOM audit
trail is orthogonal and not part of the calculus.

### 9.8 Model-versus-implementation gap

λ_if is a faithful *core*, not a transcription, of
[`capa/analyzer/_ifc.py`](../capa/analyzer/_ifc.py). The
fidelity between λ_if and the analyser is argued informally; in
the honesty convention of [`proofs/README.md`](../proofs/README.md),
**the calculus is what is proved, and we do not claim the Python
analyser is verified.** What λ_if deliberately abstracts away:

1. **Per-field struct precision and escape analysis.** The
   analyser tracks a per-field label map per struct binding
   (`_record_field_map`, `_precise_field_label`,
   `_ifc_field_store`) plus an escape set
   (`_escaped_struct_syms`, `_mark_struct_escape`) so a public
   field of a struct that also holds a secret is not
   over-tainted. λ_if has only scalar variables. The analyser's
   per-field map is a *precision* refinement that always falls
   back to the sound whole-value join on escape / aliasing /
   unknown shape, so λ_if's whole-value treatment is the sound
   over-approximation the analyser degrades to. λ_if does not
   prove the per-field refinement itself sound; the analyser's
   own comments record two known false negatives there that
   remain abstracted away (cross-function self-mutation, and
   embed-then-mutate staleness of an embedded struct binding).
   The implicit-flow case (a public field assigned under a secret
   pc) is *not* among them under `@strict_ifc`: `_ifc_field_store`
   folds the pc into the stored field's label via
   `_join_pc_if_strict` (the struct analogue of the scalar
   implicit-assign rule of T-Assign), so the strict tier λ_if
   models enforces it.

2. **Mutable-container taint and reference aliasing.**
   `_check_ifc_container_mutation` (List.push / Set.add /
   Map.set) and `_ifc_alias_link` / `_struct_aliases` model
   secrets injected into mutable containers and shared through
   reference aliases. λ_if's single n-ary join expression
   (`L-Op`) and scalar store abstract these as the same
   join-of-operands rule; the aliasing bookkeeping is not in the
   calculus.

3. **Cross-function summaries.** `_ifc_summary`,
   `_check_ifc_call_summary`, `_check_ifc_method_call_summary`
   compute, to a fixpoint, which parameters of each function /
   method reach a sink, including a sound union over dynamic
   (trait / capability) dispatch. λ_if is intra-procedural: it
   has no function calls at the statement level; `e1 ⊕ e2`
   stands in for the join-of-arguments rule a pure call uses.

4. **Constant-time / timing channels.** `_ct_reject`,
   `_check_ct_index`, `_check_ct_method_index`, `_check_ct_arith`
   enforce a separate `@constant_time` discipline (no secret
   branch conditions, no secret indices, no variable-time
   arithmetic on secrets). This is a *timing* property, distinct
   from noninterference over the value/trace observation that
   λ_if models, and it is not part of λ_if. The
   termination-insensitivity of Theorem 3 is the matching
   statement: λ_if proves nothing about timing or progress.

5. **The real AST and type system.** λ_if has integers and one
   binary-op former; Capa has the full type system of
   Sections 1 to 4, interpolated strings, pattern matching
   (`_label_pattern_binds`), the `?` operator (`A.Try`), and so
   on. Each maps to an `L-Op`-style join in the analyser; λ_if
   takes the representative case.

6. **Warn-then-enforce tiering.** The analyser emits IFC
   findings as non-fatal *warnings* by default and as hard
   *errors* only under `@strict_ifc` (`_check_ifc_sink`,
   `_emit_ifc_call_leak`). λ_if models the `@strict_ifc` regime,
   where T-Sink is a hard typing requirement. Under the default
   tier a program that violates T-Sink still compiles (with a
   warning), so Theorem 3 characterises the guarantee of
   `@strict_ifc` code specifically, not of every program the
   compiler accepts.

**Mechanisation status.** Section 9 is now mechanised. The Agda
development for λ_if parallels
[`proofs/CapaSoundness.agda`](../proofs/CapaSoundness.agda):
[`proofs/CapaIF.agda`](../proofs/CapaIF.agda) has the syntax, the
labelling and statement-typing relations, the big-step semantics,
and the release-log machinery; and
[`proofs/CapaNoninterference.agda`](../proofs/CapaNoninterference.agda)
has Lemmas 1 and 2 and Theorems 3 and 4. The two-point lattice,
finite loop-fixpoint, and lock-step induction made it a PLFA-scale
development comparable to the existing capability proof. The
noninterference claim is therefore now a *machine-checked* result
(under `--safe`, no postulates), not a hand proof.

---

### 9.9 Fidelity evidence (differential harness)

Section 9.8 argues the λ_if-versus-analyser fidelity *informally*.
[`tests/test_ifc_fidelity.py`](../tests/test_ifc_fidelity.py) adds
**machine-run evidence** for it: a differential, property-based
harness that cross-checks the real analyser
([`capa/analyzer/_ifc.py`](../capa/analyzer/_ifc.py)) against an
*independent, executable* model of λ_if
([`tests/_lambda_if_ref.py`](../tests/_lambda_if_ref.py)) on the
fragment λ_if models.

The reference module is a hand transcription of
[`proofs/CapaIF.agda`](../proofs/CapaIF.agda) - the two-point
lattice, the expression labelling judgement (`L-Lit` / `L-Var` /
`L-Op` / `L-Env` / `L-Declassify`), the flow-sensitive, pc-carrying
statement typing (`T-Skip` / `T-Assign` / `T-Seq` / `T-If` /
`T-While` / `T-Sink`, with the `T-Sink` side condition
`(l ⊔ pc) flows PUBLIC` as the single hard constraint of the
`@strict_ifc` regime), and the big-step semantics with a public
output trace. The value carrier is the one implementation choice
Section 9 leaves open (CapaIF.agda takes `op` as "any deterministic
binary function"): the harness fixes it to **strings** with `op` =
concatenation, so `env-get` maps onto `env.get(...).unwrap_or(...)`
with no parsing glue and the model trace is byte-comparable with
`stdio.println` output. Every IFC-relevant rule is transcribed
unchanged; only the carrier is chosen.

A Hypothesis generator emits small λ_if-fragment programs (scalar
variables, `env-get` as the secret source, `declassify`, assignment,
sequencing, `if` / `while`, `sink`) in both well-typed and ill-typed
(leaky) shapes, a renderer turns each into the equivalent
`@strict_ifc` Capa program 1:1, and two differential checks run:

- **Typing agreement.** The reference's well-typed verdict must
  equal the analyser's "accepts under `@strict_ifc`" verdict on every
  program. Because the Agda proof guarantees the λ_if verdict
  enforces noninterference, a disagreement is a fidelity finding - an
  analyser soundness gap (it accepts what λ_if rejects) or an
  over-restriction (it rejects what λ_if accepts).
- **Runtime agreement.** For every well-typed program, the analyser-
  backed Capa runtime and the λ_if reference interpreter must produce
  the same public output trace on the same secret input; run twice
  with differing secrets, a well-typed program's trace must also be
  independent of the secret (excluding `declassify`, which reveals by
  design - there the model and Capa still *agree* on the revealed
  value). A mismatch is a semantics-fidelity finding.

The harness reports non-vacuity counters confirming both the accept
and the reject branches are reached and that runtime agreement runs
on real (non-discarded) programs. The counters also confirm the
*confinement frontier* is exercised: a SECRET-guarded `if` / `while`
whose body assigns but sinks nothing (pc raised, assignment tainted,
nothing released) is well-typed in λ_if by confinement and the
analyser must - and does - accept it, so this is the case where the
reference and analyser reason most differently yet must reach the
same verdict.

**Honest caveats.** This is *evidence, not proof*, and it does **not
close the model-versus-implementation gap of Section 9.8**:

- it is **coverage-bounded** - Hypothesis *sampling*, not an
  exhaustive check of all programs;
- it is **fragment-only** - it covers exactly what λ_if models
  (scalar variables, `env-get`, `declassify`, assign, seq, `if`,
  `while`, `sink`) and *not* the analyser features Section 9.8 lists
  as abstracted away (per-field struct precision and escape analysis,
  mutable-container taint and reference aliasing, cross-function
  summaries, constant-time / timing, the full AST and type system);
- it shares the same *value carrier choice* as a deliberate
  simplification, so it tests the IFC verdict and the value/trace
  observation, not Capa's full value semantics.

What it does buy: independent, re-runnable confirmation that on the
modelled fragment the analyser's accept/reject decisions and runtime
traces *match the proven-safe calculus*, narrowing the informal gap
to the explicitly-listed unmodelled features.

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
- Volpano, Smith, Irvine, *A sound type system for secure flow
  analysis*. The flow type system and the
  termination-insensitive noninterference theorem of Section 9
  are this lineage.
- Sabelfeld, Myers, *Language-based information-flow security*.
  The survey framing for the lattice, low-equivalence, and
  noninterference statement used in Section 9.
- Sabelfeld, Sands, *Declassification: dimensions and
  principles*, and Sabelfeld, Myers, *A model for delimited
  release*. The relaxed-noninterference / delimited-release
  treatment of `declassify` in Section 9.7.1.

(Full references list to be assembled in the workshop-paper
submission.)
