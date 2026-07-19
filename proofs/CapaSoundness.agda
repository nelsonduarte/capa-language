{-# OPTIONS --safe #-}
------------------------------------------------------------------
-- CapaSoundness.agda
--
-- Soundness theorems for lambda_cap. Progress, Preservation,
-- Capability Soundness, and Manifest Completeness are all
-- proved as of Stages 1, 2, 3, and 4 of the mechanisation plan.
-- No postulates remain (see proofs/README.md).
--
-- STATUS: Typechecks on Agda >= 2.6.4. Verified in CI (see
-- .github/workflows/agda.yml).
--
-- Proof technique: structural induction on the typing derivation
-- in the Wright-Felleisen style. The shape matches PLFA chapter
-- "Properties":
--   1. progress is induction on _|-_!_ (Stage 1, done)
--   2. preservation is induction on _==>_ given the typing,
--      supported by PLFA-style parallel renaming / substitution
--      lemmas (Stage 2, done)
--   3. capability soundness is induction on _==>_ given the
--      inductive relation `_∈caps_` (Stage 3, done)
--   4. manifest completeness is iterated capability-soundness
--      over the reflexive-transitive closure ==>* (Stage 4, done)
--
-- These four theorems are about the CLASS-level footprint: which
-- of the ten capability classes a program can exercise. They say
-- nothing about how far a capability's authority has been
-- narrowed; that is the subject of CapaAttenuation.agda, and the
-- two developments are independent (nothing here inspects a
-- restriction, and nothing there weakens anything here).
------------------------------------------------------------------

module CapaSoundness where

open import CapaSyntax

------------------------------------------------------------------
-- Theorem 1: Progress.
--
-- Every well-typed closed term either is a value or can step.
-- Proof below by induction on the typing derivation, using two
-- canonical-forms lemmas (lambdas at function types, cap
-- constants at capability types) to discharge the cases where a
-- reduction rule needs to see a specific value shape.
------------------------------------------------------------------

data Progress {Req : Set} (t : Tm Req) : Set where
  step : forall {t'} -> t ==> t' -> Progress t
  done : Value t                 -> Progress t

-- Canonical Forms: at a function type, the only value shape is
-- a lambda; at a capability type, the only value shape is a cap
-- constant carrying SOME restriction. Each absurd case below
-- pattern-matches on the typing derivation: the value form forces
-- a specific term shape, and no constructor of _|-_!_ types that
-- shape at the expected return type.
--
-- `CapForm` replaces what used to be an equation `t == cap c`.
-- Now that a capability value carries a restriction, the canonical
-- form is existential in that restriction, so it is packaged as a
-- one-constructor datatype in the same style as `LamForm`.

data LamForm {Req : Set} : Tm Req -> Set where
  isLam : (A : Ty) (t : Tm Req) -> LamForm (lam A t)

data CapForm {Req : Set} (c : Cap) : Tm Req -> Set where
  isCap : (res : Restriction Req) -> CapForm c (cap c res)

canonical-Lam : forall {Req} {t : Tm Req} {A B}
              -> Value t
              -> empty |- t ! (A => B)
              -> LamForm t
canonical-Lam V-Lam  (T-Lam _) = isLam _ _
canonical-Lam V-Int  ()
canonical-Lam V-Bool ()
canonical-Lam V-Unit ()
canonical-Lam V-Cap  ()

canonical-Cap : forall {Req} {t : Tm Req} {c}
              -> Value t
              -> empty |- t ! TyCap c
              -> CapForm c t
canonical-Cap V-Cap  T-Cap = isCap _
canonical-Cap V-Lam  ()
canonical-Cap V-Int  ()
canonical-Cap V-Bool ()
canonical-Cap V-Unit ()

-- Stage 1: Progress.
--
-- Pattern-match on the typing derivation. T-Var is vacuous in
-- the empty context; the five "atomic" rules (T-Lam, T-Int,
-- T-Bool, T-Unit, T-Cap) yield values directly; T-App, T-Use,
-- T-Restrict, T-Consume recurse via the induction hypothesis
-- on their subderivations and use canonical forms where the
-- step rule needs to see a specific value shape.
--
-- Every recursive call is on a strict structural subderivation;
-- the termination checker accepts without an explicit measure.

progress : forall {Req} {t : Tm Req} {A} -> empty |- t ! A -> Progress t
progress (T-Var ())
progress (T-Lam _)             = done V-Lam
progress T-Int                 = done V-Int
progress T-Bool                = done V-Bool
progress T-Unit                = done V-Unit
progress T-Cap                 = done V-Cap
progress (T-App d1 d2) with progress d1
... | step s1                  = step (R-AppLeft s1)
... | done v1 with progress d2
...           | step s2        = step (R-AppRight v1 s2)
...           | done v2 with canonical-Lam v1 d1
...                     | isLam _ _ = step (R-Beta v2)
progress (T-Use d) with progress d
... | step s                   = step (R-UseStep s)
... | done v with canonical-Cap v d
...          | isCap _         = step R-Use
progress (T-Restrict d) with progress d
... | step s                   = step (R-RestrictStep s)
... | done v with canonical-Cap v d
...          | isCap _         = step R-Restrict
progress (T-Consume d) with progress d
... | step s                   = step (R-ConsumeStep s)
... | done v                   = step (R-Consume v)

------------------------------------------------------------------
-- Renaming preserves typing.
--
-- The standard PLFA lemma. If rho maps every (x : A) in G to
-- (rho x : A) in G', then for every well-typed G |- t ! A the
-- renamed term is well-typed in G': G' |- rename rho t ! A.
-- This is the inner core that the substitution lemma below
-- relies on (via exts, which under a binder lifts using
-- `rename vsuc` on the existing substitution image).
------------------------------------------------------------------

ext-pres : forall {G G' B} {rho : Var -> Var}
         -> (forall {x A} -> G >> x ! A -> G' >> rho x ! A)
         -> (forall {x A} -> (G , B) >> x ! A -> (G' , B) >> ext rho x ! A)
ext-pres rho-ok here      = here
ext-pres rho-ok (there d) = there (rho-ok d)

rename-pres : forall {Req} {G G'} {t : Tm Req} {A} {rho : Var -> Var}
            -> (forall {x B} -> G >> x ! B -> G' >> rho x ! B)
            -> G  |- t ! A
            -> G' |- rename rho t ! A
rename-pres rho-ok (T-Var x)      = T-Var (rho-ok x)
rename-pres rho-ok (T-Lam d)      = T-Lam (rename-pres (ext-pres rho-ok) d)
rename-pres rho-ok (T-App d1 d2)  = T-App (rename-pres rho-ok d1) (rename-pres rho-ok d2)
rename-pres rho-ok T-Int          = T-Int
rename-pres rho-ok T-Bool         = T-Bool
rename-pres rho-ok T-Unit         = T-Unit
rename-pres rho-ok T-Cap          = T-Cap
rename-pres rho-ok (T-Use d)      = T-Use (rename-pres rho-ok d)
rename-pres rho-ok (T-Restrict d) = T-Restrict (rename-pres rho-ok d)
rename-pres rho-ok (T-Consume d)  = T-Consume (rename-pres rho-ok d)

------------------------------------------------------------------
-- Substitution preserves typing (parallel form).
--
-- If sigma maps every variable (x : A) in G to a term sigma x of
-- type A in G', then for every G |- t ! A we have
-- G' |- subst sigma t ! A. The exts-pres helper lifts the
-- condition under a new binding: at index vzero return T-Var here
-- (the fresh variable); at (vsuc x) appeal to rename-pres with
-- the `there` renaming on the IH for the original index.
------------------------------------------------------------------

exts-pres : forall {Req} {G G' B} {sigma : Var -> Tm Req}
          -> (forall {x A} -> G >> x ! A -> G' |- sigma x ! A)
          -> (forall {x A} -> (G , B) >> x ! A -> (G' , B) |- exts sigma x ! A)
exts-pres sigma-ok here      = T-Var here
exts-pres sigma-ok (there d) = rename-pres there (sigma-ok d)

subst-pres : forall {Req} {G G'} {t : Tm Req} {A} {sigma : Var -> Tm Req}
           -> (forall {x B} -> G >> x ! B -> G' |- sigma x ! B)
           -> G  |- t ! A
           -> G' |- subst sigma t ! A
subst-pres sigma-ok (T-Var x)      = sigma-ok x
subst-pres sigma-ok (T-Lam d)      = T-Lam (subst-pres (exts-pres sigma-ok) d)
subst-pres sigma-ok (T-App d1 d2)  = T-App (subst-pres sigma-ok d1) (subst-pres sigma-ok d2)
subst-pres sigma-ok T-Int          = T-Int
subst-pres sigma-ok T-Bool         = T-Bool
subst-pres sigma-ok T-Unit         = T-Unit
subst-pres sigma-ok T-Cap          = T-Cap
subst-pres sigma-ok (T-Use d)      = T-Use (subst-pres sigma-ok d)
subst-pres sigma-ok (T-Restrict d) = T-Restrict (subst-pres sigma-ok d)
subst-pres sigma-ok (T-Consume d)  = T-Consume (subst-pres sigma-ok d)

------------------------------------------------------------------
-- Single-substitution corollary. If v has type A in G and t has
-- type B in G , A, then t [ v ] has type B in G. This is the
-- form needed at the R-Beta case of preservation.
------------------------------------------------------------------

sub-zero-pres : forall {Req} {G} {v : Tm Req} {A}
              -> G |- v ! A
              -> (forall {x B} -> (G , A) >> x ! B -> G |- sub-zero v x ! B)
sub-zero-pres dv here      = dv
sub-zero-pres dv (there d) = T-Var d

subst-zero : forall {Req} {G} {v t : Tm Req} {A B}
           -> (G , A) |- t ! B
           -> G       |- v ! A
           -> G       |- t [ v ] ! B
subst-zero dt dv = subst-pres (sub-zero-pres dv) dt

------------------------------------------------------------------
-- Theorem 2: Preservation.
--
-- Reduction preserves the type. Proof by induction on the
-- reduction derivation. The congruence cases recurse on the
-- subderivation; R-Beta uses subst-zero (the lambda body's
-- typing in the extended context combines with the argument's
-- typing in the outer context to yield the substituted body's
-- typing); R-Use returns T-Bool (the reduct is the boolean the
-- receiver's restriction assigns to the request) and R-Restrict
-- returns T-Cap; R-Consume returns the inner derivation unchanged
-- because consume is a no-op at the type level.
------------------------------------------------------------------

preservation : forall {Req} {G} {t t' : Tm Req} {A}
             -> G |- t ! A
             -> t ==> t'
             -> G |- t' ! A
preservation (T-App d1 d2)         (R-AppLeft s1)     = T-App (preservation d1 s1) d2
preservation (T-App d1 d2)         (R-AppRight _ s2)  = T-App d1 (preservation d2 s2)
preservation (T-App (T-Lam db) dv) (R-Beta _)         = subst-zero db dv
preservation (T-Use d)             (R-UseStep s)      = T-Use (preservation d s)
preservation (T-Use _)             R-Use              = T-Bool
preservation (T-Restrict d)        (R-RestrictStep s) = T-Restrict (preservation d s)
preservation (T-Restrict _)        R-Restrict         = T-Cap
preservation (T-Consume d)         (R-ConsumeStep s)  = T-Consume (preservation d s)
preservation (T-Consume d)         (R-Consume _)      = d

------------------------------------------------------------------
-- Theorem 3: Capability Soundness.
--
-- For a well-typed closed term t : A, every reduction step
-- t ==> t' satisfies caps-of(t') subset-of caps-of(t). In words:
-- reduction can only drop capabilities from the syntactic
-- surface, never introduce new ones. The single-step formulation
-- below extends to the reflexive-transitive closure by iteration.
--
-- This file mechanises the relational form of the theorem: every
-- cap that appears syntactically in t' already appeared in t.
-- The relation `c ∈caps t` has one constructor per place a cap
-- can appear in a Tm (cap-introductions, use / restrict syntactic
-- tags, and propagation through lam / app / use / restrict /
-- consume). Pattern matching on this inductive relation
-- sidesteps the higher-order unification issues that the Bool-
-- indicator formulation (`caps-of : Tm -> CapSet` defined below)
-- would force at every union-decomposition step.
--
-- caps-of stays defined as a Bool indicator function so future
-- stages (Manifest Completeness compares Bool functions
-- pointwise) and the README narrative still have a concrete
-- "set of capabilities appearing in t" reference. The theorem
-- proper consumes `_∈caps_` and never inspects caps-of.
--
-- Both are blind to restrictions: the footprint is a set of
-- CLASSES, which is exactly what a manifest declares. How narrow
-- each of those classes' authority is, is CapaAttenuation.agda's
-- subject.
------------------------------------------------------------------

caps-of : forall {Req} -> Tm Req -> CapSet
caps-of (var _)          = emptyCS
caps-of (lam _ t)        = caps-of t
caps-of (app t1 t2)      = caps-of t1 ∪ caps-of t2
caps-of (i _)            = emptyCS
caps-of (bool _)         = emptyCS
caps-of unit             = emptyCS
caps-of (cap c _)        = singletonCS c
caps-of (use c _ t)      = singletonCS c ∪ caps-of t
caps-of (restrict c _ t) = singletonCS c ∪ caps-of t
caps-of (consume t)      = caps-of t

------------------------------------------------------------------
-- Disjunction (sum type), used by the substitution-caps lemma.
------------------------------------------------------------------

data _⊎_ (A B : Set) : Set where
  inl : A -> A ⊎ B
  inr : B -> A ⊎ B

infixr 1 _⊎_

------------------------------------------------------------------
-- The "c appears syntactically in t" judgement. Each constructor
-- corresponds to one Tm shape and one place inside that shape
-- where c can show up; the lam / app / use / restrict / consume
-- "inside-" constructors propagate through subterms; here-cap,
-- here-use-tag, here-restrict-tag are the leaves where a cap is
-- actually introduced.
------------------------------------------------------------------

data _∈caps_ {Req : Set} : Cap -> Tm Req -> Set where
  here-cap          : forall {c res}       -> c ∈caps (cap c res)
  here-use-tag      : forall {c x t}       -> c ∈caps (use c x t)
  here-restrict-tag : forall {c res t}     -> c ∈caps (restrict c res t)
  inside-lam        : forall {c A t}       -> c ∈caps t  -> c ∈caps (lam A t)
  inside-app-l      : forall {c t1 t2}     -> c ∈caps t1 -> c ∈caps (app t1 t2)
  inside-app-r      : forall {c t1 t2}     -> c ∈caps t2 -> c ∈caps (app t1 t2)
  inside-use        : forall {c c' x t}    -> c ∈caps t  -> c ∈caps (use c' x t)
  inside-restrict   : forall {c c' res t}  -> c ∈caps t  -> c ∈caps (restrict c' res t)
  inside-consume    : forall {c t}         -> c ∈caps t  -> c ∈caps (consume t)

infix 4 _∈caps_

------------------------------------------------------------------
-- Renaming preserves the "cap appears" judgement: if c appears
-- in (rename rho t), then it already appeared in t. Renaming
-- only changes variable indices; the cap-introduction and tag
-- positions are preserved verbatim. Proved by recursion on the
-- term so Agda can compute `rename rho t` and the proof's outer
-- constructor becomes available for pattern matching.
------------------------------------------------------------------

rename-∈caps : forall {Req} {c rho} (t : Tm Req)
             -> c ∈caps (rename rho t)
             -> c ∈caps t
rename-∈caps (var _)          ()
rename-∈caps (lam _ t)        (inside-lam h)      = inside-lam (rename-∈caps t h)
rename-∈caps (app t1 t2)      (inside-app-l h)    = inside-app-l (rename-∈caps t1 h)
rename-∈caps (app t1 t2)      (inside-app-r h)    = inside-app-r (rename-∈caps t2 h)
rename-∈caps (i _)            ()
rename-∈caps (bool _)         ()
rename-∈caps unit             ()
rename-∈caps (cap _ _)        here-cap            = here-cap
rename-∈caps (use _ _ _)      here-use-tag        = here-use-tag
rename-∈caps (use _ _ t)      (inside-use h)      = inside-use (rename-∈caps t h)
rename-∈caps (restrict _ _ _) here-restrict-tag   = here-restrict-tag
rename-∈caps (restrict _ _ t) (inside-restrict h) = inside-restrict (rename-∈caps t h)
rename-∈caps (consume t)      (inside-consume h)  = inside-consume (rename-∈caps t h)

------------------------------------------------------------------
-- Substitution-caps lemma: if every term in the image of sigma
-- has its caps bounded by a predicate P : Cap -> Set, then the
-- caps appearing in (subst sigma t) come either from t itself or
-- from P. The bounded form factors the lam case via the
-- rename-∈caps lemma applied at exts sigma.
------------------------------------------------------------------

sigma-∈bounded : forall {Req} -> (Var -> Tm Req) -> (Cap -> Set) -> Set
sigma-∈bounded sigma P = (x : Var) (c : Cap)
                       -> c ∈caps (sigma x) -> P c

exts-∈bounded : forall {Req} {P} (sigma : Var -> Tm Req)
              -> sigma-∈bounded sigma P
              -> sigma-∈bounded (exts sigma) P
exts-∈bounded sigma sb vzero    c ()
exts-∈bounded sigma sb (vsuc x) c h = sb x c (rename-∈caps (sigma x) h)

subst-∈caps-bounded : forall {Req} {P} (sigma : Var -> Tm Req) (t : Tm Req) (c : Cap)
                    -> sigma-∈bounded sigma P
                    -> c ∈caps (subst sigma t)
                    -> c ∈caps t ⊎ P c
subst-∈caps-bounded sigma (var x) c sb h = inr (sb x c h)
subst-∈caps-bounded sigma (lam _ t) c sb (inside-lam h)
  with subst-∈caps-bounded (exts sigma) t c (exts-∈bounded sigma sb) h
... | inl ht = inl (inside-lam ht)
... | inr p  = inr p
subst-∈caps-bounded sigma (app t1 t2) c sb (inside-app-l h)
  with subst-∈caps-bounded sigma t1 c sb h
... | inl ht = inl (inside-app-l ht)
... | inr p  = inr p
subst-∈caps-bounded sigma (app t1 t2) c sb (inside-app-r h)
  with subst-∈caps-bounded sigma t2 c sb h
... | inl ht = inl (inside-app-r ht)
... | inr p  = inr p
subst-∈caps-bounded sigma (i _)    c sb ()
subst-∈caps-bounded sigma (bool _) c sb ()
subst-∈caps-bounded sigma unit     c sb ()
subst-∈caps-bounded sigma (cap _ _) c sb here-cap = inl here-cap
subst-∈caps-bounded sigma (use _ _ _) c sb here-use-tag = inl here-use-tag
subst-∈caps-bounded sigma (use _ _ t) c sb (inside-use h)
  with subst-∈caps-bounded sigma t c sb h
... | inl ht = inl (inside-use ht)
... | inr p  = inr p
subst-∈caps-bounded sigma (restrict _ _ _) c sb here-restrict-tag = inl here-restrict-tag
subst-∈caps-bounded sigma (restrict _ _ t) c sb (inside-restrict h)
  with subst-∈caps-bounded sigma t c sb h
... | inl ht = inl (inside-restrict ht)
... | inr p  = inr p
subst-∈caps-bounded sigma (consume t) c sb (inside-consume h)
  with subst-∈caps-bounded sigma t c sb h
... | inl ht = inl (inside-consume ht)
... | inr p  = inr p

sub-zero-∈bounded : forall {Req} (v : Tm Req)
                  -> sigma-∈bounded (sub-zero v) (\ c -> c ∈caps v)
sub-zero-∈bounded v vzero    c h = h
sub-zero-∈bounded v (vsuc _) c ()

subst-zero-∈caps : forall {Req} (t : Tm Req) {v : Tm Req} (c : Cap)
                 -> c ∈caps (t [ v ])
                 -> c ∈caps t ⊎ c ∈caps v
subst-zero-∈caps t {v} c h
  = subst-∈caps-bounded (sub-zero v) t c (sub-zero-∈bounded v) h

------------------------------------------------------------------
-- Capability Soundness theorem. Induction on the reduction
-- derivation, pattern-matching on the `c ∈caps t'` proof of the
-- reduct to determine which subterm of t' the cap came from,
-- then reconstructing the corresponding witness in t.
--
-- R-Beta is the only nontrivial case: the reduct body [ v ]
-- decomposes via subst-zero-∈caps into "cap was in body" or
-- "cap was in v"; in the source `app (lam A body) v` these map
-- to inside-app-l (inside-lam _) and inside-app-r _ respectively.
-- R-Use's reduct is a boolean literal whose ∈caps relation is
-- empty; the hypothesis is absurd. R-Restrict's reduct
-- `cap c0 (res ∩R res')` is inhabited only by here-cap, and the
-- source `restrict c0 res' (...)` has the matching
-- here-restrict-tag witness.
------------------------------------------------------------------

capability-soundness
  : forall {Req} {t t' : Tm Req} {A}
  -> empty |- t ! A
  -> t ==> t'
  -> (c : Cap)
  -> c ∈caps t'
  -> c ∈caps t
capability-soundness (T-App d1 d2) (R-AppLeft s1) c (inside-app-l h)
  = inside-app-l (capability-soundness d1 s1 c h)
capability-soundness (T-App d1 d2) (R-AppLeft s1) c (inside-app-r h)
  = inside-app-r h
capability-soundness (T-App d1 d2) (R-AppRight _ s2) c (inside-app-l h)
  = inside-app-l h
capability-soundness (T-App d1 d2) (R-AppRight _ s2) c (inside-app-r h)
  = inside-app-r (capability-soundness d2 s2 c h)
capability-soundness (T-App (T-Lam _) _) (R-Beta {t = body} {v = v} _) c h
  with subst-zero-∈caps body c h
... | inl ht = inside-app-l (inside-lam ht)
... | inr hv = inside-app-r hv
capability-soundness (T-Use d) (R-UseStep s) c here-use-tag = here-use-tag
capability-soundness (T-Use d) (R-UseStep s) c (inside-use h)
  = inside-use (capability-soundness d s c h)
capability-soundness (T-Use _) R-Use c ()
capability-soundness (T-Restrict d) (R-RestrictStep s) c here-restrict-tag = here-restrict-tag
capability-soundness (T-Restrict d) (R-RestrictStep s) c (inside-restrict h)
  = inside-restrict (capability-soundness d s c h)
capability-soundness (T-Restrict _) R-Restrict c here-cap = here-restrict-tag
capability-soundness (T-Consume d) (R-ConsumeStep s) c (inside-consume h)
  = inside-consume (capability-soundness d s c h)
capability-soundness (T-Consume _) (R-Consume _) c h = inside-consume h

------------------------------------------------------------------
-- Theorem 4: Manifest Completeness (multi-step soundness).
--
-- The capability set of a closed term is an upper bound on the
-- capabilities that can ever appear in any term reachable by
-- reduction. In words: reduction never invents capabilities; the
-- syntactic surface of t is everything its runtime trace can
-- exercise.
--
-- The statement is multi-step capability soundness: if
-- t ==>* t' and c appears in t', then c appears in t.
-- This is the iterated form of Theorem 3 (capability-soundness)
-- composed with Theorem 2 (preservation): preservation lets us
-- carry the typing through each step so capability-soundness can
-- be re-applied; capability-soundness then walks each cap-witness
-- back through the step.
--
-- Note on the original skeleton statement. An earlier draft
-- postulated `declared-caps t == caps-of-reachable t`, with
-- `declared-caps` defined as the lam-prefix Cap-typed parameter
-- list. That equation is false in general (declared but unused
-- caps): a function value `lam (TyCap Net) (i 0)` declares Net
-- yet never exercises it, so the two sides disagree. The
-- multi-step soundness above is the honestly-provable claim and
-- still captures the manifest's role: the cap set advertised
-- by the program is a sound upper bound on the run-time trace.
------------------------------------------------------------------

manifest-completeness : forall {Req} {t t' : Tm Req} {A}
                      -> empty |- t ! A
                      -> t ==>* t'
                      -> (c : Cap)
                      -> c ∈caps t'
                      -> c ∈caps t
manifest-completeness d done*           c h = h
manifest-completeness d (step* s rest)  c h
  = capability-soundness d s c (manifest-completeness (preservation d s) rest c h)

------------------------------------------------------------------
-- That is the full statement set. `progress`, `preservation`,
-- `capability-soundness`, and `manifest-completeness` are all
-- real definitions (Stages 1, 2, 3, 4). No postulates remain.
------------------------------------------------------------------
