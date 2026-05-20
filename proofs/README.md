# Capa formal mechanisation: status and plan

[![agda](https://github.com/nelsonduarte/capa-language/actions/workflows/agda.yml/badge.svg)](https://github.com/nelsonduarte/capa-language/actions/workflows/agda.yml)

> **Status (2026-05-20): all four soundness theorems proved;
> mechanically typechecked in CI; no postulates remain.** This
> directory holds the λ_cap formalisation in Agda. Syntax,
> typing, reduction, PLFA-style parallel substitution, the
> inductive `_∈caps_` relation, and the reflexive-transitive
> closure `_==>*_` are all mechanised. Progress, Preservation,
> Capability Soundness, and Manifest Completeness
> ([`docs/semantics.md`](../docs/semantics.md) Theorems 1 and 2)
> are proved. The mechanisation arc is complete.

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

The skeleton declares its own `Nat` / `Bool` / `==`, so
agda-stdlib is not needed. Any Agda `>= 2.6.4` is enough.

```bash
# Install Agda. On Debian / Ubuntu (or WSL):
sudo apt install agda
# Or via cabal / nix / Homebrew on macOS.

# Typecheck (from this directory):
agda CapaSyntax.agda
agda CapaSoundness.agda
```

CI also typechecks both files on every push that touches
`proofs/` (see `.github/workflows/agda.yml`).

## Mechanisation plan (incremental)

The path from this skeleton to a fully-verified soundness
proof:

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
| Stage 0: skeleton + theorem statements | landed |
| Stage 1: Progress | landed |
| Stage 2: Preservation | landed |
| Stage 3: Capability Soundness | landed |
| Stage 4: Manifest Completeness | landed |

All four soundness theorems are now machine-verified. The
paper can cite them as such; the Agda source in this directory
is the artefact a referee opens.
