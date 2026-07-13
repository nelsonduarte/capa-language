{-# OPTIONS --safe #-}
------------------------------------------------------------------
-- CapaManifestExact.agda
--
-- Phase 1 of closing the "Capa-vs-lambda_cap gap" (docs/paper-draft.md
-- around lines 512-528, proofs/README.md). This file introduces a
-- GATED refinement of CapaSyntax's typing relation that models Capa's
-- top-level discipline: capability *literals* may only be introduced
-- at the program's top level (where `main` receives the runtime-
-- supplied capabilities). Inside any lambda body, capabilities are
-- always *variables* bound by the enclosing top-level lambda, never
-- fresh literals.
--
-- The gate is a boolean index on the typing judgement:
--   true  = "at the top level"    (capability literals admitted)
--   false = "under a binder"      (capability literals forbidden)
--
-- We prove two structural lemmas and NOTHING else in this phase (no
-- preservation, no exactness theorem yet):
--
--   * weaken-top  (Lemma A): a term typed under the FALSE flag is
--     also typed under the TRUE flag. TRUE is strictly more
--     permissive (it additionally admits the capability-literal
--     rule), so a restrictive derivation is trivially a permissive
--     one. This is the lemma that will later rescue substitution /
--     preservation when a top-typed capability value is substituted
--     into a non-top body -- but that is future work.
--
--   * forget-flag (Lemma B): a term typed in the gated judgement
--     (under EITHER flag) is typed in CapaSyntax's ORIGINAL ungated
--     `_|-_!_`. So the gated calculus is a strict RESTRICTION of the
--     original: every already-proved theorem (progress, preservation,
--     capability-soundness, manifest-completeness) applies to gated-
--     typed programs for free, and nothing in the existing metatheory
--     is disturbed.
--
-- STATUS: intended to typecheck on Agda >= 2.6.4 under --safe.
-- Verified in CI (see .github/workflows/agda.yml).
--
-- Everything below reuses CapaSyntax verbatim (Bool, Cap, Ty, Var,
-- Tm, Ctx, `_>>_!_`, the original `_|-_!_`, reduction, values,
-- CapSet, ...). Nothing already defined there is restated.
------------------------------------------------------------------

module CapaManifestExact where

open import CapaSyntax

------------------------------------------------------------------
-- Gated typing relation.
--
-- G |-[ b ] t ! A reads "in context G, at gate b, term t has
-- type A". The gate b : Bool records whether we are still at the
-- top level (true) or have descended under a binder (false).
--
-- Gating semantics, rule by rule:
--
--   G-Var       : allowed under ANY gate value.
--   G-Lam       : conclusion holds under ANY gate; the body is
--                 typed with the gate forced to FALSE (going under
--                 a binder leaves the top level).
--   G-App       : the SAME gate is threaded to both sub-derivations
--                 and the conclusion (a top-level application has
--                 its parts at the top -- the `main`-applied-to-
--                 capabilities spine; an application under a binder
--                 has non-top parts).
--   G-Int/G-Unit: allowed under ANY gate value.
--   G-Cap       : admissible ONLY at gate TRUE. This is the whole
--                 point: no capability literal can be conjured
--                 under a binder.
--   G-Use /
--   G-Restrict /
--   G-Consume   : thread the gate unchanged to sub-derivation(s)
--                 and conclusion.
------------------------------------------------------------------

data _|-[_]_!_ : Ctx -> Bool -> Tm -> Ty -> Set where

  G-Var : forall {G b v A}
        -> G >> v ! A
        -> G |-[ b ] var v ! A

  G-Lam : forall {G b A B t}
        -> ((G , A)) |-[ false ] t ! B
        -> G |-[ b ] lam A t ! (A => B)

  G-App : forall {G b t1 t2 A B}
        -> G |-[ b ] t1 ! (A => B)
        -> G |-[ b ] t2 ! A
        -> G |-[ b ] app t1 t2 ! B

  G-Int : forall {G b n}
        -> G |-[ b ] i n ! TyInt

  G-Unit : forall {G b}
         -> G |-[ b ] unit ! TyUnit

  G-Cap : forall {G c}
        -> G |-[ true ] cap c ! TyCap c

  G-Use : forall {G b c t}
        -> G |-[ b ] t ! TyCap c
        -> G |-[ b ] use c t ! TyUnit

  G-Restrict : forall {G b c t}
             -> G |-[ b ] t ! TyCap c
             -> G |-[ b ] restrict c t ! TyCap c

  G-Consume : forall {G b t A}
            -> G |-[ b ] t ! A
            -> G |-[ b ] consume t ! A

infix 4 _|-[_]_!_

------------------------------------------------------------------
-- Lemma A: weaken-top.
--
-- Any term well-typed under the FALSE gate is also well-typed under
-- the TRUE gate (same context, same term, same type). TRUE only ADDS
-- the capability-literal rule G-Cap, so every FALSE derivation is
-- already a TRUE one.
--
-- Structural induction on the gated derivation. The G-Cap case does
-- not arise: G-Cap concludes at gate `true`, which cannot unify with
-- the input gate `false`, so Agda's coverage checker excludes it
-- automatically (as with the absurd `()` canonical-forms cases in
-- CapaSoundness.agda). Every remaining constructor is either atomic
-- (returned unchanged at gate true) or threads the gate through its
-- premises via the induction hypothesis.
--
-- Note the G-Lam case: its body premise is ALWAYS at gate false
-- regardless of the conclusion gate, so the sub-derivation is reused
-- verbatim; only the conclusion gate flips from false to true.
------------------------------------------------------------------

weaken-top : forall {G t A}
           -> G |-[ false ] t ! A
           -> G |-[ true ]  t ! A
weaken-top (G-Var x)      = G-Var x
weaken-top (G-Lam d)      = G-Lam d
weaken-top (G-App d1 d2)  = G-App (weaken-top d1) (weaken-top d2)
weaken-top G-Int          = G-Int
weaken-top G-Unit         = G-Unit
weaken-top (G-Use d)      = G-Use (weaken-top d)
weaken-top (G-Restrict d) = G-Restrict (weaken-top d)
weaken-top (G-Consume d)  = G-Consume (weaken-top d)

------------------------------------------------------------------
-- Lemma B: forget-flag.
--
-- Any term well-typed in the gated judgement (under EITHER gate
-- value b) is well-typed in CapaSyntax's ORIGINAL ungated `_|-_!_`
-- (same context / term / type). Erasing the gate maps each gated
-- rule to its ungated namesake; the gate value is irrelevant to the
-- image, so the same clause serves both b = true and b = false.
--
-- Structural induction on the gated derivation. This exhibits the
-- gated calculus as a strict restriction of the original, so the
-- existing metatheory carries over unchanged.
------------------------------------------------------------------

forget-flag : forall {G b t A}
            -> G |-[ b ] t ! A
            -> G |- t ! A
forget-flag (G-Var x)      = T-Var x
forget-flag (G-Lam d)      = T-Lam (forget-flag d)
forget-flag (G-App d1 d2)  = T-App (forget-flag d1) (forget-flag d2)
forget-flag G-Int          = T-Int
forget-flag G-Unit         = T-Unit
forget-flag G-Cap          = T-Cap
forget-flag (G-Use d)      = T-Use (forget-flag d)
forget-flag (G-Restrict d) = T-Restrict (forget-flag d)
forget-flag (G-Consume d)  = T-Consume (forget-flag d)

------------------------------------------------------------------
-- That is Phase 1. The gated judgement `_|-[_]_!_` refines
-- CapaSyntax's `_|-_!_` with a top-level gate on capability
-- literals; weaken-top and forget-flag are real, total, --safe
-- definitions by structural induction. Preservation for the gated
-- judgement and the manifest-exactness theorem are deferred to a
-- later phase.
------------------------------------------------------------------
