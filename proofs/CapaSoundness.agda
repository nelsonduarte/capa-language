------------------------------------------------------------------
-- CapaSoundness.agda
--
-- Soundness theorems for lambda_cap. Progress and Preservation
-- are proved as of Stages 1 and 2 of the mechanisation plan;
-- Capability Soundness and Manifest Completeness remain as
-- postulates pending Stages 3 and 4 (see proofs/README.md).
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
--   3. capability soundness is a corollary (Stage 3, postulate)
--   4. manifest completeness is a separate structural induction
--      (Stage 4, postulate)
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

data Progress (t : Tm) : Set where
  step : forall {t'} -> t ==> t' -> Progress t
  done : Value t                 -> Progress t

-- Canonical Forms: at a function type, the only value shape is
-- a lambda; at a capability type, the only value shape is the
-- cap constant. Each absurd case below pattern-matches on the
-- typing derivation: the value form forces a specific term
-- shape, and no constructor of _|-_!_ types that shape at the
-- expected return type.

data LamForm : Tm -> Set where
  isLam : (A : Ty) (t : Tm) -> LamForm (lam A t)

canonical-Lam : forall {t A B}
              -> Value t
              -> empty |- t ! (A => B)
              -> LamForm t
canonical-Lam V-Lam  (T-Lam _) = isLam _ _
canonical-Lam V-Int  ()
canonical-Lam V-Unit ()
canonical-Lam V-Cap  ()

canonical-Cap : forall {t c}
              -> Value t
              -> empty |- t ! TyCap c
              -> t == cap c
canonical-Cap V-Cap  T-Cap = refl
canonical-Cap V-Lam  ()
canonical-Cap V-Int  ()
canonical-Cap V-Unit ()

-- Stage 1: Progress.
--
-- Pattern-match on the typing derivation. T-Var is vacuous in
-- the empty context; the four "atomic" rules (T-Lam, T-Int,
-- T-Unit, T-Cap) yield values directly; T-App, T-Use,
-- T-Restrict, T-Consume recurse via the induction hypothesis
-- on their subderivations and use canonical forms where the
-- step rule needs to see a specific value shape.
--
-- Every recursive call is on a strict structural subderivation;
-- the termination checker accepts without an explicit measure.

progress : forall {t A} -> empty |- t ! A -> Progress t
progress (T-Var ())
progress (T-Lam _)             = done V-Lam
progress T-Int                 = done V-Int
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
...          | refl            = step R-Use
progress (T-Restrict d) with progress d
... | step s                   = step (R-RestrictStep s)
... | done v with canonical-Cap v d
...          | refl            = step R-Restrict
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

rename-pres : forall {G G' t A} {rho : Var -> Var}
            -> (forall {x B} -> G >> x ! B -> G' >> rho x ! B)
            -> G  |- t ! A
            -> G' |- rename rho t ! A
rename-pres rho-ok (T-Var x)      = T-Var (rho-ok x)
rename-pres rho-ok (T-Lam d)      = T-Lam (rename-pres (ext-pres rho-ok) d)
rename-pres rho-ok (T-App d1 d2)  = T-App (rename-pres rho-ok d1) (rename-pres rho-ok d2)
rename-pres rho-ok T-Int          = T-Int
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

exts-pres : forall {G G' B} {sigma : Var -> Tm}
          -> (forall {x A} -> G >> x ! A -> G' |- sigma x ! A)
          -> (forall {x A} -> (G , B) >> x ! A -> (G' , B) |- exts sigma x ! A)
exts-pres sigma-ok here      = T-Var here
exts-pres sigma-ok (there d) = rename-pres there (sigma-ok d)

subst-pres : forall {G G' t A} {sigma : Var -> Tm}
           -> (forall {x B} -> G >> x ! B -> G' |- sigma x ! B)
           -> G  |- t ! A
           -> G' |- subst sigma t ! A
subst-pres sigma-ok (T-Var x)      = sigma-ok x
subst-pres sigma-ok (T-Lam d)      = T-Lam (subst-pres (exts-pres sigma-ok) d)
subst-pres sigma-ok (T-App d1 d2)  = T-App (subst-pres sigma-ok d1) (subst-pres sigma-ok d2)
subst-pres sigma-ok T-Int          = T-Int
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

sub-zero-pres : forall {G v A}
              -> G |- v ! A
              -> (forall {x B} -> (G , A) >> x ! B -> G |- sub-zero v x ! B)
sub-zero-pres dv here      = dv
sub-zero-pres dv (there d) = T-Var d

subst-zero : forall {G v t A B}
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
-- typing); R-Use and R-Restrict return T-Unit / T-Cap directly;
-- R-Consume returns the inner derivation unchanged because
-- consume is a no-op at the type level.
------------------------------------------------------------------

preservation : forall {G t t' A}
             -> G |- t ! A
             -> t ==> t'
             -> G |- t' ! A
preservation (T-App d1 d2)         (R-AppLeft s1)     = T-App (preservation d1 s1) d2
preservation (T-App d1 d2)         (R-AppRight _ s2)  = T-App d1 (preservation d2 s2)
preservation (T-App (T-Lam db) dv) (R-Beta _)         = subst-zero db dv
preservation (T-Use d)             (R-UseStep s)      = T-Use (preservation d s)
preservation (T-Use _)             R-Use              = T-Unit
preservation (T-Restrict d)        (R-RestrictStep s) = T-Restrict (preservation d s)
preservation (T-Restrict _)        R-Restrict         = T-Cap
preservation (T-Consume d)         (R-ConsumeStep s)  = T-Consume (preservation d s)
preservation (T-Consume d)         (R-Consume _)      = d

------------------------------------------------------------------
-- Theorem 3 (Corollary): Capability Soundness.
--
-- A well-typed closed term cannot, via any number of reduction
-- steps, exercise a capability it does not contain in its
-- syntactic surface.
--
-- More precisely: define caps-of(t) as the set of Cap tags
-- appearing in any cap-introduction or use-c subterm of t. For a
-- well-typed closed term t : A, every reachable t' satisfies
-- caps-of(t') is contained in caps-of(t).
--
-- Proof: by repeated application of preservation; each reduction
-- step either (a) does not affect the set of capabilities (beta,
-- left/right-step rules) or (b) discharges one (R-Use:
-- use c (cap c) -> unit drops c from the syntactic surface).
-- Restriction (R-Restrict) preserves the set.
--
-- The corollary is stated as a postulate here; the proof would
-- be a relatively short follow-on to preservation.
------------------------------------------------------------------

postulate
  caps-of : Tm -> CapSet

postulate
  capability-soundness
    : forall {t t' A}
    -> empty |- t ! A
    -> t ==> t'
    -> (c : Cap)
    -> caps-of t' c == true
    -> caps-of t  c == true

------------------------------------------------------------------
-- Theorem 4: Manifest Completeness.
--
-- The manifest emitted by `capa --manifest` for a top-level
-- function declares exactly the capability set the function can
-- exercise (in the sense of caps-of-reachable above).
--
-- Formal statement: define
--
--   declared-caps(t) = the capability parameters in the surface
--                      signature of t (the analyzer reads these
--                      directly from the AST).
--
-- Then for any well-typed closed function value v : Cap1 => ...
-- => Cap_n => Ret, declared-caps(v) equals caps-of-reachable(v).
--
-- Proof sketch: the typing rule T-Use is the only way a Cap-typed
-- expression can be exercised, and T-Use requires the cap-typed
-- argument to be in scope. The only way a cap-typed value enters
-- scope is via a parameter (or via cap-introduction, which the
-- surface language restricts to main). Therefore every Cap
-- exercised somewhere reachable from v has been declared in
-- some parameter on the path; collecting those gives exactly
-- declared-caps.
--
-- This is the property the runtime trace test in
-- tests/test_properties.py asserts dynamically (runtime_classes
-- subset of manifest_classes); the mechanised version would
-- close it statically for the calculus.
------------------------------------------------------------------

postulate
  declared-caps : Tm -> CapSet
  caps-of-reachable : Tm -> CapSet

postulate
  manifest-completeness
    : forall {t A}
    -> empty |- t ! A
    -> (c : Cap)
    -> declared-caps t c == caps-of-reachable t c

------------------------------------------------------------------
-- That is the full statement set. `progress` and `preservation`
-- are now real definitions (Stages 1 and 2). The remaining
-- postulates are `caps-of` + `capability-soundness` (Stage 3),
-- and `declared-caps` + `caps-of-reachable` +
-- `manifest-completeness` (Stage 4).
------------------------------------------------------------------
