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
-- Phase 3 reuses the already-proven runtime metatheory. CapaSoundness
-- itself `open import CapaSyntax`s (without `public`), so it does not
-- re-export CapaSyntax names; there is no clash with our own direct
-- import above. We use `manifest-completeness` and `_∈caps_` from it.
open import CapaSoundness

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

data _|-[_]_!_ {Req : Set} : Ctx -> Bool -> Tm Req -> Ty -> Set where

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

  G-Bool : forall {G b v}
         -> G |-[ b ] bool v ! TyBool

  G-Unit : forall {G b}
         -> G |-[ b ] unit ! TyUnit

  G-Cap : forall {G c res}
        -> G |-[ true ] cap c res ! TyCap c

  G-Use : forall {G b c x t}
        -> G |-[ b ] t ! TyCap c
        -> G |-[ b ] use c x t ! TyBool

  G-Restrict : forall {G b c res t}
             -> G |-[ b ] t ! TyCap c
             -> G |-[ b ] restrict c res t ! TyCap c

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

weaken-top : forall {Req} {G} {t : Tm Req} {A}
           -> G |-[ false ] t ! A
           -> G |-[ true ]  t ! A
weaken-top (G-Var x)      = G-Var x
weaken-top (G-Lam d)      = G-Lam d
weaken-top (G-App d1 d2)  = G-App (weaken-top d1) (weaken-top d2)
weaken-top G-Int          = G-Int
weaken-top G-Bool         = G-Bool
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

forget-flag : forall {Req} {G b} {t : Tm Req} {A}
            -> G |-[ b ] t ! A
            -> G |- t ! A
forget-flag (G-Var x)      = T-Var x
forget-flag (G-Lam d)      = T-Lam (forget-flag d)
forget-flag (G-App d1 d2)  = T-App (forget-flag d1) (forget-flag d2)
forget-flag G-Int          = T-Int
forget-flag G-Bool         = T-Bool
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
positive : empty |-[ true ] lam (TyCap Net) (use Net zero (var vzero))
                             ! (TyCap Net => TyBool)
positive = G-Lam (G-Use (G-Var here))

-- A gate-true program: (\ (n : Net) -> \ (_ : Unit) -> use Net n) applied
-- to the capability LITERAL `cap Net`.
prog : Tm Nat
prog = app (lam (TyCap Net) (lam TyUnit (use Net zero (var (vsuc vzero)))))
           (cap Net unrestricted)

prog-typed : empty |-[ true ] prog ! (TyUnit => TyBool)
prog-typed = G-App (G-Lam (G-Lam (G-Use (G-Var (there here))))) G-Cap

-- One beta step substitutes the literal `cap Net` for the outer
-- binder, producing a lambda whose body now contains a cap LITERAL.
prog-step : prog ==> lam TyUnit (use Net zero (cap Net unrestricted))
prog-step = R-Beta V-Cap

-- The reduct is untypable at EVERY gate: inverting G-Lam then G-Use
-- exposes the premise `(empty , TyUnit) |-[ false ] cap Net ! TyCap Net`,
-- and no constructor types a cap literal at gate false (only G-Cap
-- could, and it pins gate true, which cannot unify with false). The
-- `()` therefore lands on that cap-at-false premise.
reduct-untypable : forall {b}
                 -> empty |-[ b ] lam TyUnit (use Net zero (cap Net unrestricted))
                                  ! (TyUnit => TyBool)
                 -> Empty
reduct-untypable (G-Lam (G-Use ()))

------------------------------------------------------------------
-- Phase 2: literal-only occurrence, and "no cap literal under a
-- binder".
--
-- The gate exists to guarantee ONE precise source-level fact: a
-- capability LITERAL `cap c` is never conjured under a binder. This
-- section formalizes and proves exactly that; it is the load-bearing
-- lemma for Phase 3's introduction-confinement result (capability
-- literals are introduced only at the top level, never under a
-- binder).
--
-- We need a LITERAL-ONLY occurrence relation, distinct from
-- CapaSyntax's `_∈caps_`. `_∈caps_` also counts the TAG on `use c t`
-- / `restrict c t` (via its `here-use-tag` / `here-restrict-tag`
-- constructors). Here we deliberately DROP those: a `use Net n` whose
-- subject `n` is a variable is a legitimate exercise of a declared
-- capability, not a conjured literal. So `_∈lit_` has a single
-- introduction (`lit-here` at `cap c`) plus pure congruence descents;
-- it has NO tag "here" cases and NO cases at var / i / unit.
------------------------------------------------------------------

data _∈lit_ {Req : Set} : Cap -> Tm Req -> Set where
  lit-here     : forall {c res}      -> c ∈lit (cap c res)
  lit-lam      : forall {c A t}      -> c ∈lit t  -> c ∈lit (lam A t)
  lit-app-l    : forall {c t1 t2}    -> c ∈lit t1 -> c ∈lit (app t1 t2)
  lit-app-r    : forall {c t1 t2}    -> c ∈lit t2 -> c ∈lit (app t1 t2)
  lit-use      : forall {c c' x t}   -> c ∈lit t  -> c ∈lit (use c' x t)
  lit-restrict : forall {c c' res t} -> c ∈lit t  -> c ∈lit (restrict c' res t)
  lit-consume  : forall {c t}        -> c ∈lit t  -> c ∈lit (consume t)

infix 4 _∈lit_

------------------------------------------------------------------
-- Core Phase-2 lemma: a term well-typed at gate FALSE contains no
-- capability literal. Structural induction on the gated typing
-- derivation, mirroring the shape of `capability-soundness` in
-- CapaSoundness.agda.
--
-- The G-Cap case does NOT arise: G-Cap concludes at gate `true`,
-- which cannot unify with the input gate `false`, so the coverage
-- checker excludes it (same mechanism as `weaken-top`). That single
-- exclusion is the entire content of the theorem -- with G-Cap gone,
-- no literal can be introduced, and every remaining rule either has
-- an empty occurrence relation (var / i / unit, discharged by `()`)
-- or only descends into an already-false sub-derivation (recurse).
------------------------------------------------------------------

no-cap-literal-under-false : forall {Req} {G} {t : Tm Req} {A c}
                           -> G |-[ false ] t ! A
                           -> c ∈lit t
                           -> Empty
no-cap-literal-under-false (G-Var _)      ()
no-cap-literal-under-false (G-Lam d)      (lit-lam h)      = no-cap-literal-under-false d h
no-cap-literal-under-false (G-App d1 d2)  (lit-app-l h)    = no-cap-literal-under-false d1 h
no-cap-literal-under-false (G-App d1 d2)  (lit-app-r h)    = no-cap-literal-under-false d2 h
no-cap-literal-under-false G-Int          ()
no-cap-literal-under-false G-Bool         ()
no-cap-literal-under-false G-Unit         ()
no-cap-literal-under-false (G-Use d)      (lit-use h)      = no-cap-literal-under-false d h
no-cap-literal-under-false (G-Restrict d) (lit-restrict h) = no-cap-literal-under-false d h
no-cap-literal-under-false (G-Consume d)  (lit-consume h)  = no-cap-literal-under-false d h

------------------------------------------------------------------
-- Non-vacuity anchor for `_∈lit_`: the relation really does pick out
-- the top-level literal. `prog` (from Phase 1) has `cap Net` as the
-- argument of its top-level application, so the occurrence descends
-- through the `app` (right) to `lit-here`.
------------------------------------------------------------------

prog-has-lit : Net ∈lit prog
prog-has-lit = lit-app-r lit-here

------------------------------------------------------------------
-- Phase 3: literal confinement (the payoff), and the runtime bound.
--
-- Phase 2 proved no capability literal appears under a binder. Phase 3
-- lifts that to the whole program: in a gate-TRUE well-typed program,
-- every capability literal occurs at the TOP LEVEL (outside all lambda
-- binders) -- the precise formal content of "capabilities are only
-- introduced at the top, where the runtime supplies them". This closes
-- the Capa-vs-lambda_cap gap on the INTRODUCTION dimension.
--
-- `_spine-lit_` is `_∈lit_` MINUS the lambda-descent case: a spine
-- occurrence is a literal reachable without crossing any binder. The
-- omission of a `lam` constructor is the whole point.
------------------------------------------------------------------

data _spine-lit_ {Req : Set} : Cap -> Tm Req -> Set where
  spine-here     : forall {c res}   -> c spine-lit (cap c res)
  spine-app-l    : forall {c t1 t2} -> c spine-lit t1 -> c spine-lit (app t1 t2)
  spine-app-r    : forall {c t1 t2} -> c spine-lit t2 -> c spine-lit (app t1 t2)
  spine-use      : forall {c c' x t}
                 -> c spine-lit t  -> c spine-lit (use c' x t)
  spine-restrict : forall {c c' res t}
                 -> c spine-lit t  -> c spine-lit (restrict c' res t)
  spine-consume  : forall {c t}     -> c spine-lit t  -> c spine-lit (consume t)

infix 4 _spine-lit_

-- Ex-falso for the local Empty (no constructors, so the argument is
-- absurd). Used to discharge the lam case of confinement.
Empty-elim : forall {A : Set} -> Empty -> A
Empty-elim ()

------------------------------------------------------------------
-- Confinement theorem: every literal occurrence in a gate-true term
-- is a spine (non-under-binder) occurrence.
--
-- Induction matching the `_∈lit_` witness against the gated typing
-- derivation. The lam case (`G-Lam d` with `lit-lam h`) is the crux:
-- the body is gate `false`, so `no-cap-literal-under-false d h`
-- (Phase 2) yields `Empty`, discharged by ex-falso -- an under-binder
-- literal simply cannot exist in a well-typed term. Every other case
-- is a congruence: recurse into the matching gate-true sub-derivation
-- and re-wrap with the corresponding spine constructor. The var / i /
-- unit cases have an empty `_∈lit_` and are discharged by `()`.
------------------------------------------------------------------

confine : forall {Req} {G} {e : Tm Req} {A c}
        -> G |-[ true ] e ! A
        -> c ∈lit e
        -> c spine-lit e
confine (G-Var _)      ()
confine (G-Lam d)      (lit-lam h)      = Empty-elim (no-cap-literal-under-false d h)
confine (G-App d1 d2)  (lit-app-l h)    = spine-app-l (confine d1 h)
confine (G-App d1 d2)  (lit-app-r h)    = spine-app-r (confine d2 h)
confine G-Int          ()
confine G-Bool         ()
confine G-Unit         ()
confine G-Cap          lit-here         = spine-here
confine (G-Use d)      (lit-use h)      = spine-use (confine d h)
confine (G-Restrict d) (lit-restrict h) = spine-restrict (confine d h)
confine (G-Consume d)  (lit-consume h)  = spine-consume (confine d h)

------------------------------------------------------------------
-- The pre-existing multi-step runtime bound, restricted to gated
-- programs. This is NOT a new guarantee earned by the gate: it is
-- CapaSoundness's already-proven `manifest-completeness` composed with
-- forget-flag, i.e. the SAME bound restricted (via gate-typability) to
-- a subset of programs, hence strictly WEAKER than the existing
-- theorem. It is recorded only to note that gate-typable programs
-- inherit that bound; the one genuinely new result of this file is
-- `confine` (introduction confinement), not this corollary.
-- (`manifest-completeness` takes the capability as an EXPLICIT
-- argument; we let Agda infer it via `_`.)
------------------------------------------------------------------

gated-runtime-bound : forall {Req} {e e' : Tm Req} {A c}
                    -> empty |-[ true ] e ! A
                    -> e ==>* e'
                    -> c ∈caps e'
                    -> c ∈caps e
gated-runtime-bound d r h = manifest-completeness (forget-flag d) r _ h

------------------------------------------------------------------
-- Machine-checked anchors.
--
-- `prog-confined` confirms the confinement theorem on the Phase-1
-- program; `prog-confined-explicit` is the hand-written witness, and
-- the two agree by construction (confine computes exactly this shape).
-- `prog-runtime-bound` exercises the runtime bound: the reduct of
-- `prog` exercises Net (as `use Net (cap Net)` under a lambda), and
-- the bound pulls that back to `Net ∈caps prog`.
------------------------------------------------------------------

prog-confined : Net spine-lit prog
prog-confined = confine prog-typed prog-has-lit

prog-confined-explicit : Net spine-lit prog
prog-confined-explicit = spine-app-r spine-here

prog-runtime-bound : Net ∈caps prog
prog-runtime-bound = gated-runtime-bound prog-typed (step* prog-step done*) (inside-lam here-use-tag)

------------------------------------------------------------------
-- Divergence witness: `_spine-lit_` is STRICTLY contained in
-- `_∈lit_`, so `confine` is non-trivial and its gate-true hypothesis
-- is load-bearing. On `lam TyUnit (cap Net)` the literal DOES occur
-- (under the binder), yet there is NO spine occurrence; and the term
-- is not gate-typable at any gate, so `confine` never applies to it --
-- exactly as it must, since `confine`'s conclusion would be false
-- here. Together these show the gap between the two relations is real
-- and that gate-typability is precisely what rules the bad term out.
------------------------------------------------------------------

-- ∈lit holds: the literal cap Net occurs, but under a lambda binder.
witness-lit : Net ∈lit (lam TyUnit (cap Net (unrestricted {Nat})))
witness-lit = lit-lam lit-here

-- spine-lit FAILS on the same term: no spine-lit constructor targets a lam.
witness-not-spine : Net spine-lit (lam TyUnit (cap Net (unrestricted {Nat})))
                  -> Empty
witness-not-spine ()

-- The gate hypothesis is load-bearing: this term is not gate-typable
-- at any gate (its body would need `cap Net` typed at gate false).
witness-untypable : forall {b A}
                  -> empty |-[ b ] lam TyUnit (cap Net (unrestricted {Nat})) ! A
                  -> Empty
witness-untypable (G-Lam ())

------------------------------------------------------------------
-- That is Phases 1-3. The gated judgement `_|-[_]_!_` refines
-- CapaSyntax's `_|-_!_` with a top-level gate on capability literals.
-- Phase 1 (weaken-top, forget-flag) relates the gate to the original
-- calculus; Phase 2 (`_∈lit_`, no-cap-literal-under-false) shows no
-- literal appears under a binder; Phase 3 (`_spine-lit_`, confine)
-- lifts that to the whole program -- in a gate-true well-typed program
-- EVERY capability literal occurs OUTSIDE all lambda binders. This is
-- INTRODUCTION CONFINEMENT, and it closes the Capa-vs-lambda_cap gap on
-- the INTRODUCTION dimension. gated-runtime-bound is NOT a new result:
-- it merely records that CapaSoundness's pre-existing multi-step bound
-- still applies to gate-typable programs (via forget-flag).
--
-- WHAT `confine` DOES AND DOES NOT SAY. It proves literals are
-- introduced only at the top level, never under a binder. It does NOT
-- prove that those top-level literals equal `decl(e_0)`, the cap-typed
-- PARAMETER list of the leading lambda prefix: `spine-lit` ("not under
-- a binder") is strictly broader than "is a runtime-supplied parameter
-- of the main lambda". For instance `use Net (cap Net)` is gate-true
-- typable (G-Use G-Cap) and its literal is a spine occurrence, yet it
-- declares no cap parameter -- the capability is exercised directly at
-- top level, not passed in as an argument to a `main` lambda.
-- INFORMALLY, in the intended whole-program shape `app main (cap c)`
-- the top-level literals are exactly what the runtime supplies, but
-- that correspondence is not what `confine` establishes.
--
-- HONEST SCOPE. We do NOT claim full `∈caps` equality. The use /
-- restrict TAGS of a dead nested cap-lambda survive in `∈caps` (the
-- known declared-but-unused caveat), so the footprint can strictly
-- exceed what the program exercises. The manifest remains a SOUND
-- UPPER BOUND, and is TIGHT on introduction: literal capabilities
-- enter only at the top. Gated preservation is FALSE (the Phase-1
-- counterexample), which is exactly why the runtime bound is routed
-- through forget-flag + the source program's footprint rather than a
-- gated preservation lemma.
--
-- NOT MECHANIZED. The translation from Capa's surface syntax to gate-
-- true-typable lambda_cap is not formalized here: `confine` is
-- conditional on gated typability, matching the informal calculus-vs-
-- analyser fidelity that proofs/README.md already flags. What is proved
-- is that the gated CALCULUS has the confinement property -- not, on
-- its own, that "Capa closes the gap".
------------------------------------------------------------------
