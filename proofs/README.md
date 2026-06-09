# Capa formal mechanisation: status and plan

[![agda](https://github.com/nelsonduarte/capa-language/actions/workflows/agda.yml/badge.svg)](https://github.com/nelsonduarte/capa-language/actions/workflows/agda.yml)

> **Status (2026-06-09): all four capability soundness theorems
> proved, PLUS Lemma 1, Lemma 2, the declassify-free
> noninterference theorem (Theorem 3) AND the delimited-release
> theorem (Theorem 4) for λ_if; mechanically typechecked in CI; no
> postulates remain.** This directory holds two formalisations in
> Agda. (1) The λ_cap capability calculus: syntax, typing,
> reduction, PLFA-style parallel substitution, the inductive
> `_∈caps_` relation, and the reflexive-transitive closure
> `_==>*_`; Progress, Preservation, Capability Soundness, and
> Manifest Completeness ([`docs/semantics.md`](../docs/semantics.md)
> Theorems 1 and 2) are proved. (2) The λ_if information-flow
> calculus ([`docs/semantics.md`](../docs/semantics.md) Section 9):
> the two-point security lattice, expression labelling,
> flow-sensitive statement typing, an inductive big-step
> semantics, low-equivalence, the noninterference theorem
> (Theorem 3) with its two supporting lemmas, AND the
> delimited-release / relaxed-noninterference theorem (Theorem 4)
> for the full calculus WITH `declassify`. The noninterference
> modules typecheck under Agda's `--safe` flag, which mechanically
> forbids postulates, `trustMe`, and unsafe pragmas.

## What this directory is for

The paper draft and the design documents claim two soundness
properties for the Capa capability discipline:

- **Theorem 1 (Capability Soundness)**: a well-typed Capa
  program does not exercise capabilities it does not declare.
- **Theorem 2 (Manifest Completeness)**: the manifest emitted
  by `--manifest` declares exactly the capability footprint a
  well-typed program can exercise.

The proof sketches in [`docs/semantics.md`](../docs/semantics.md)
are pen-and-paper. A workshop or journal reviewer reasonably
asks for a mechanised version. This directory contains that
mechanisation: the capability soundness theorems and the
`lambda_if` noninterference theorems (Theorems 3 and 4) are
machine-checked Agda, with the noninterference modules passing
under `--safe`. The status table below tracks each landed stage.

## Why Agda (and not Coq, Lean, Isabelle)

The choice is partly preference and partly ecosystem fit:

- **Agda**: dependently-typed, propositions-as-types, reads
  like ordinary functional code. Best fit for syntactic
  Wright-Felleisen soundness proofs (which is what the
  semantics document does). [Programming Language Foundations
  in Agda (PLFA)](https://plfa.github.io/) is the canonical
  tutorial for exactly this style of proof.
- Coq, Lean, Isabelle would all work. Agda was chosen
  because the proofs are short enough that the dependently-
  typed-functional flavour reads cleanly and the PLFA
  template is directly applicable.

If a future contributor prefers another prover, the syntax
and reduction relations transfer mechanically; only the proof
tactics differ.

## What is in here

- `CapaSyntax.agda`: syntax of λ_cap. Types (base, function,
  capability), terms (variables, lambdas, applications,
  capability uses, attenuation, consume), contexts, typing
  relation, small-step reduction relation, values.

- `CapaSoundness.agda`: Progress, Preservation, Capability
  Soundness, and Manifest Completeness for λ_cap, proved by
  induction on the typing / reduction derivations in the
  Wright-Felleisen style (same shape as PLFA chapter
  "Properties"). No postulates remain.

- `CapaIF.agda`: the λ_if information-flow calculus
  ([`docs/semantics.md`](../docs/semantics.md) Section 9). Syntax
  of expressions and statements, the two-point security lattice
  (`PUBLIC`/`SECRET` with join and flows-to), expression
  labelling `_|-e_~>_`, flow-sensitive statement typing
  `_,_|-s_~>_` (carrying a program-counter label), and the
  big-step operational semantics `_,_,_=>_,_` with a public
  output trace. Two encoding choices are documented inline as
  deviations D1 / D2 (total-function stores instead of partial
  maps; the big-step semantics as an inductive relation rather
  than a recursive function, which is the standard
  termination-insensitive encoding the while rule needs).

- `CapaNoninterference.agda`: the noninterference development.
  Lemma 1 (expression label soundness, `lemma1`), Lemma 2
  (confinement / high-pc, `confinement`), Theorem 3
  (termination-insensitive noninterference for the
  declassify-free fragment, `noninterference`), and Theorem 4
  (delimited release / relaxed noninterference for the full
  calculus with `declassify`, `theorem4`). Two supporting lemmas
  the paper proof uses implicitly are made explicit and proved:
  `mono-secret` (a SECRET-pc statement never lowers a label to
  PUBLIC) and `while-high-conf` (a SECRET-guarded loop emits
  nothing and touches no PUBLIC variable). Theorem 4 reuses
  `lemma1-decl` (Lemma 1 re-admitting `declassify`, discharged in
  the L-Declassify case by the agreement hypothesis) and the
  release-log machinery from `CapaIF.agda`. The whole module is
  checked under `--safe`. A small worked example at the foot of
  the module (`example-prog = sink(declassify(env-get))`) shows a
  declassify-and-sink program that is covered by Theorem 4 but
  EXCLUDED from Theorem 3 (it has no `DFStmt` derivation), and
  proves the agreement hypothesis for it is exactly secret
  equality `k1 == k2`, so Theorem 4 does not collapse into
  Theorem 3.

## How to typecheck

The skeleton declares its own `Nat` / `Bool` / `==`, so
agda-stdlib is not needed. Any Agda `>= 2.6.4` is enough.

```bash
# Install Agda. On Debian / Ubuntu (or WSL):
sudo apt install agda
# Or via cabal / nix / Homebrew on macOS.

# Typecheck (from this directory):
agda CapaSyntax.agda
agda CapaSoundness.agda
agda CapaIF.agda
agda CapaNoninterference.agda   # checks under --safe too
```

CI typechecks all four files on every push that touches
`proofs/` (see `.github/workflows/agda.yml`).

## Mechanisation stages (all landed)

The mechanisation proceeded in the stages below; all are now
complete (see the status table at the end):

1. **Stage 0 (done)**: syntax + theorem statements +
   postulates. The reviewer can read the file and see that
   the formalisation is well-typed in intent.

2. **Stage 1 (done)**: prove Progress. For every well-typed
   closed term `t` of type `A`, either `t` is a value or
   there exists `t'` with `t -> t'`. Structural induction on
   the typing derivation; two canonical-forms lemmas
   discharge the cases where a reduction rule needs to see a
   specific value shape.

3. **Stage 2 (done)**: prove Preservation. If `t : A` and
   `t -> t'`, then `t' : A`. Structural induction on the
   reduction derivation, supported by PLFA-style parallel
   renaming / substitution lemmas (`rename-pres`,
   `subst-pres`, `subst-zero`). The `R-Beta` rule now does
   real de Bruijn substitution; the elided form used by
   Stage 1 is gone.

4. **Stage 3 (done)**: prove Capability Soundness. If
   `t ==> t'` then every cap that appears syntactically in
   `t'` already appeared in `t`. Mechanised against the
   inductive relation `_∈caps_`, with two side lemmas:
   `rename-∈caps` (renaming preserves the relation) and
   `subst-∈caps-bounded` (caps in a substituted term either
   come from the original term or from the substitution image,
   bounded by a predicate). The Bool-indicator `caps-of`
   remains defined for downstream Stage 4 work.

5. **Stage 4 (done)**: prove Manifest Completeness. If
   `t ==>* t'` then every cap appearing syntactically in `t'`
   already appeared in `t`. Iterated form of Stage 3,
   composed with Stage 2 (preservation carries the typing
   through each step so Stage 3 can re-fire on the witness).
   The reflexive-transitive closure `_==>*_` is defined in
   CapaSyntax.agda. **Note**: the original skeleton postulate
   was `declared-caps t == caps-of-reachable t` with
   `declared-caps` defined as the lam-prefix Cap-typed
   parameter list. That equation is false in general (a
   function value can declare a cap parameter and never use
   it). The mechanised statement above is the
   honestly-provable claim and still captures the manifest's
   role: the cap set advertised by the program is a sound
   upper bound on the runtime trace.

Each stage is a few hundred lines of Agda in the PLFA style.
The total is workshop-paper-sized: roughly 1500 to 2500 lines
of mechanised Agda.

## Out of scope (deliberate)

- **Mechanising the translation from full Capa to λ_cap.**
  The translation is sketched informally in `docs/semantics.md`
  § 7.4. Mechanising it would close the soundness story for
  the production language, not just the calculus.
  Out of workshop-paper budget; out of scope here.
- **Mechanising the runtime trace correspondence**. The Capa
  runtime has an opt-in trace
  (`capa/runtime/_trace.py`) that records each capability
  invocation; Hypothesis property-tests assert
  `runtime_classes ⊆ manifest_classes`. Lifting that property
  into the calculus would require modelling the dynamic
  semantics of the Python target, which is well beyond a
  workshop paper.

## Status badge

Honest tracking:

| Stage | Status |
|---|---|
| Stage 0: skeleton + theorem statements | landed |
| Stage 1: Progress | landed |
| Stage 2: Preservation | landed |
| Stage 3: Capability Soundness | landed |
| Stage 4: Manifest Completeness | landed |
| λ_if: syntax + lattice + typing + big-step semantics | landed |
| λ_if Lemma 1: expression label soundness | landed |
| λ_if Lemma 2: confinement / high-pc | landed |
| λ_if Theorem 3: declassify-free noninterference | landed |
| λ_if Theorem 4: delimited release | landed (machine-checked, `--safe`) |

The four capability soundness theorems and BOTH λ_if
noninterference theorems (Theorem 3 for the declassify-free
fragment and Theorem 4, delimited release, for the full calculus
with `declassify`, with Lemmas 1 and 2) are machine-verified; the
noninterference modules pass under `--safe`. The paper can cite
them as such; the Agda source in this directory is the artefact a
referee opens. No future-item gap remains in the λ_if
development.

## λ_if: deviations from the Section 9 paper proof

The mechanisation is faithful to
[`docs/semantics.md`](../docs/semantics.md) Section 9 rule for
rule. Three encoding choices differ from the prose, all documented
inline in `CapaIF.agda` and none weakening the theorem:

- **D1 (total stores).** Stores and label environments are total
  functions `Var -> Nat` / `Var -> L` rather than finite partial
  maps. This is the standard PLFA store encoding; it removes the
  "x in dom" side condition from low-equivalence, which becomes
  the clean pointwise "agree on every PUBLIC variable".

- **D2 (inductive big-step semantics).** The big-step relation is
  a `data` type, not a recursive function. The `while` rule is not
  structurally terminating as a function (its recursive call is
  not on a subterm) -- exactly the termination-insensitivity the
  paper flags. As an inductive relation the derivations are finite
  objects to induct over, the textbook encoding of a
  termination-insensitive semantics, and the noninterference proof
  relates only runs for which both derivations exist (both
  converge), matching the theorem's hypothesis.

- **D3 (release-log agreement for Theorem 4).** Section 9.7.1
  writes the delimited-release hypothesis as equality of the
  multiset/tuple of declassified values,
  `[| D(s) |]_{σ1}^{κ1} == [| D(s) |]_{σ2}^{κ2}`. The Agda
  encoding uses two structural forms (in `CapaIF.agda`):
  `EAgree` on expressions ("the two runs agree on every
  declassified value inside `e`") and `Agree` on the two big-step
  derivations ("...along the actual execution paths"). `EAgree` is
  proved EQUIVALENT to equality of the expression release logs
  `releases k1 s1 e == releases k2 s2 e` (`eagree<->releq`:
  `eagree->releq` and `releq->eagree` in
  `CapaNoninterference.agda`), where `releases` is the concrete
  per-expression release log -- declassify's analogue of the `sink`
  output trace. So the hypothesis IS release-log equality, phrased
  per-position so the L-Op / L-Declassify cases decompose without
  list-append surgery. The derivation-indexed `Agree` is the
  faithful operational reading of `[| D(s) |]` evaluated at the
  store each declassify is actually reached in: where the two runs
  diverge under a SECRET guard it demands agreement only on the
  guard releases (the divergent declassifies are confined by
  Lemma 2, exactly as the paper proof handles them), so the
  hypothesis is a real, non-vacuous condition on the low-context
  declassifies and Theorem 4 does NOT collapse into Theorem 3.

The proof also makes explicit two facts the paper proof uses
silently: `mono-secret` (under SECRET pc, no rule manufactures a
fresh PUBLIC label) and `while-high-conf` (a SECRET-guarded loop
is confined per-iteration). Both are proved, not assumed.

As in the capability development, **the calculus is what is
proved sound; fidelity between λ_if and the Python analyser is
argued informally** in `docs/semantics.md` Section 9.8, and we do
not claim the analyser itself is verified.
