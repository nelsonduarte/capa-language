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
--   * weaken-top  (Lemma A): a term typed under the FALSE gate is
--     also typed under the TRUE gate. TRUE is strictly more
--     permissive (it additionally admits the capability-literal
--     rule G-Cap), so a restrictive (false-gate) derivation is
--     trivially a permissive (true-gate) one. This is exactly the
--     permissive-direction structural weakening `false => true`;
--     its precise role in later phases is TBD. (It is NOT the
--     direction preservation would want: substituting a true-gate
--     capability value into a false-gate body would need
--     `true => false`, which is inadmissible BY DESIGN -- that
--     inadmissibility is the whole point of the gate, and is why
--     gated preservation is false; see the counterexample near the
--     end of this file. weaken-top does not, and cannot, rescue it.)
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
-- already a TRUE one. This is a plain permissive-direction weakening
-- (`false => true`); it makes NO claim about preservation, and its
-- precise use in later phases is left open.
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
-- Sanity anchors and the preservation counterexample.
--
-- These are permanent, machine-checked definitions that pin down the
-- meaning of the gated judgement so it cannot silently rot:
--
--   * `positive` witnesses NON-VACUITY: a genuine top-level program
--     (main takes a Net capability and uses it) types at gate true,
--     with the cap appearing as a VARIABLE inside the body (never a
--     literal), exactly as Capa's discipline intends.
--
--   * `prog` / `prog-typed` / `prog-step` / `reduct-untypable`
--     together REFUTE gated preservation: a gate-true program steps
--     (by beta, substituting a cap LITERAL argument into the body) to
--     a term that is untypable at EVERY gate. So `t ==> t'` does not
--     preserve gated typing. This is deliberate -- it is the machine
--     evidence that the manifest-exactness theorem must NOT be routed
--     through a gated preservation lemma, and instead be established
--     as a SOURCE-level property of the initial program (via
--     forget-flag, below).
------------------------------------------------------------------

-- Empty type (no constructors), for the untypability half. CapaSyntax
-- exports no such type, so we declare a local one.
data Empty : Set where

-- Non-vacuity: a real top-level main, capability used as a bound
-- variable inside the (gate-false) body.
positive : empty |-[ true ] lam (TyCap Net) (use Net (var vzero)) ! (TyCap Net => TyUnit)
positive = G-Lam (G-Use (G-Var here))

-- A gate-true program: (\ (n : Net) -> \ (_ : Unit) -> use Net n) applied
-- to the capability LITERAL `cap Net`.
prog : Tm
prog = app (lam (TyCap Net) (lam TyUnit (use Net (var (vsuc vzero))))) (cap Net)

prog-typed : empty |-[ true ] prog ! (TyUnit => TyUnit)
prog-typed = G-App (G-Lam (G-Lam (G-Use (G-Var (there here))))) G-Cap

-- One beta step substitutes the literal `cap Net` for the outer
-- binder, producing a lambda whose body now contains a cap LITERAL.
prog-step : prog ==> lam TyUnit (use Net (cap Net))
prog-step = R-Beta V-Cap

-- The reduct is untypable at EVERY gate: inverting G-Lam then G-Use
-- exposes the premise `(empty , TyUnit) |-[ false ] cap Net ! TyCap Net`,
-- and no constructor types a cap literal at gate false (only G-Cap
-- could, and it pins gate true, which cannot unify with false). The
-- `()` therefore lands on that cap-at-false premise.
reduct-untypable : forall {b}
                 -> empty |-[ b ] lam TyUnit (use Net (cap Net)) ! (TyUnit => TyUnit)
                 -> Empty
reduct-untypable (G-Lam (G-Use ()))

------------------------------------------------------------------
-- That is Phase 1. The gated judgement `_|-[_]_!_` refines
-- CapaSyntax's `_|-_!_` with a top-level gate on capability
-- literals; weaken-top and forget-flag are real, total, --safe
-- definitions by structural induction.
--
-- Gated preservation is FALSE (the counterexample above), so the
-- eventual manifest-exactness theorem will be proven as a SOURCE-
-- level property of the initial program: forget-flag hands a gated-
-- typed program off to CapaSyntax / CapaSoundness, and the already-
-- proven multi-step manifest-completeness there supplies the runtime
-- capability bound. It will NOT be obtained by re-deriving
-- preservation under the gate.
------------------------------------------------------------------
