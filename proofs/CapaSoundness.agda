------------------------------------------------------------------
-- CapaSoundness.agda
--
-- Soundness theorems for lambda_cap. Progress is proved as of
-- Stage 1 of the mechanisation plan; Preservation, Capability
-- Soundness, and Manifest Completeness remain as postulates
-- pending Stages 2 to 4 (see proofs/README.md).
--
-- STATUS: Typechecks on Agda >= 2.6.4. Verified in CI (see
-- .github/workflows/agda.yml).
--
-- Proof technique: structural induction on the typing derivation
-- in the Wright-Felleisen style. The shape matches PLFA chapter
-- "Properties":
--   1. progress is induction on _|-_!_ (Stage 1, done)
--   2. preservation is induction on _==>_ given the typing
--      (Stage 2, postulate)
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
-- Theorem 2: Preservation.
--
-- Reduction preserves the type.
--
-- Proof sketch: induction on the reduction derivation, using a
-- substitution lemma:
--
--   subst-lemma : G , A |- t : B
--               -> G |- v : A
--               -> G |- t[v/0] : B
--
-- which is itself a structural induction on the typing of t.
--
-- The capability-specific rules need no special handling: R-Use
-- and R-Restrict consume a TyCap-typed value and return TyUnit or
-- TyCap c, both of which are correctly typed at the redex.
------------------------------------------------------------------

postulate
  preservation : forall {G t t' A}
               -> G |- t ! A
               -> t ==> t'
               -> G |- t' ! A

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
-- That is the full statement set. `progress` is now a real
-- definition (Stage 1, this commit). The remaining postulates
-- are `preservation` (Stage 2), `caps-of` +
-- `capability-soundness` (Stage 3), and `declared-caps` +
-- `caps-of-reachable` + `manifest-completeness` (Stage 4).
------------------------------------------------------------------
