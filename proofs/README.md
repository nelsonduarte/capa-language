# Capa formal mechanisation: status and plan

> **Status (2026-05-15): skeleton, not yet typechecked.** This
> directory holds a working sketch of the λ_cap formalisation
> in Agda syntax. The files state the syntax, typing rules,
> reduction relation, and the two soundness theorems
> ([`docs/semantics.md`](../docs/semantics.md) Theorems 1 and 2)
> as `postulate` declarations. Filling in the proofs is the
> workshop-paper-sized task referenced in
> `docs/semantics.md` § 8.

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
asks for a mechanised version. This directory is the
mechanisation skeleton.

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

- `CapaSoundness.agda`: statements of the two theorems as
  `postulate` declarations. Each comes with a comment block
  describing the expected proof structure (the proof technique
  is induction on the typing derivation, in the Wright-
  Felleisen style; same shape as PLFA chapter "Properties").

## How to typecheck

```bash
# Install Agda (>= 2.6.4 recommended) and stdlib v2.0.
# On Linux:
sudo apt install agda
# Or via cabal / nix / your package manager of choice.

# Typecheck (from this directory):
agda CapaSyntax.agda
agda CapaSoundness.agda
```

If the files fail to typecheck, the most likely cause is a
minor syntactic drift between Agda versions. The intent of
each declaration is described in the comments above it, so a
contributor can fix the syntax without losing the meaning.

## Mechanisation plan (incremental)

The path from this skeleton to a fully-verified soundness
proof:

1. **Stage 0 (current)**: syntax + theorem statements +
   postulates. The reviewer can read the file and see that
   the formalisation is well-typed in intent, even if the
   proofs are not yet filled in.

2. **Stage 1**: prove Progress. For every well-typed closed
   term `t` of type `A`, either `t` is a value or there
   exists `t'` with `t -> t'`. Standard structural induction
   on the typing derivation.

3. **Stage 2**: prove Preservation. If `t : A` and `t -> t'`,
   then `t' : A`. Standard structural induction.

4. **Stage 3**: derive Capability Soundness as a corollary.
   The reduction relation tracks which capability is being
   used at each step; the typing context bounds the set of
   capabilities; preservation gives the rest.

5. **Stage 4**: prove Manifest Completeness. This is a
   separate result about the manifest extraction function.
   Likely a structural induction on the typing derivation,
   reading off the capability set from each rule.

Each stage is a few hundred lines of Agda in the PLFA style.
The total is workshop-paper-sized: roughly 1500 to 2500 lines
of mechanised Agda when complete.

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
| Stage 0: skeleton + theorem statements | **landed** (this commit) |
| Stage 1: Progress | not started |
| Stage 2: Preservation | not started |
| Stage 3: Capability Soundness corollary | not started |
| Stage 4: Manifest Completeness | not started |

The paper claims sketched proofs, not mechanised proofs. This
directory is the next step toward the latter; do not cite the
soundness theorems as machine-verified yet.
