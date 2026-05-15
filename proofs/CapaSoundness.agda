------------------------------------------------------------------
-- CapaSoundness.agda
--
-- Statements of the two soundness theorems for lambda_cap. The
-- proofs are postulated; filling them in is the workshop-paper-
-- sized task referenced in docs/semantics.md section 8.
--
-- STATUS: Skeleton. Has not been typechecked by Agda locally.
-- Install Agda >= 2.6.4 and run `agda CapaSoundness.agda` to
-- verify the structure. The `postulate` declarations stand in
-- for the actual proofs and will need to be replaced.
--
-- Proof technique (for the contributor who picks this up):
-- structural induction on the typing derivation in the Wright-
-- Felleisen style. The shape matches PLFA chapter "Properties":
--   1. progress is induction on _|-_!_
--   2. preservation is induction on _==>_ given the typing
--   3. capability soundness is a corollary
------------------------------------------------------------------

module CapaSoundness where

open import CapaSyntax

------------------------------------------------------------------
-- Theorem 1: Progress.
--
-- Every well-typed closed term either is a value or can step.
--
-- Proof sketch: induction on the typing derivation. Cases:
--
--   T-Var: vacuous, the context is empty so there is no variable.
--   T-Lam: lam is a value.
--   T-App: by IH on t1; if value, by IH on t2; if value, apply
--          beta (R-Beta).
--   T-Int, T-Unit, T-Cap: values.
--   T-Use: by IH on the cap-typed subterm. If value, that value
--          must be cap c (by the canonical-forms lemma), apply
--          R-Use.
--   T-Restrict: dual to T-Use, ends in R-Restrict.
--   T-Consume: by IH on the subterm. If value, apply R-Consume;
--              otherwise R-ConsumeStep.
------------------------------------------------------------------

data Progress (t : Tm) : Set where
  step : forall {t'} -> t ==> t' -> Progress t
  done : Value t                 -> Progress t

postulate
  progress : forall {t A} -> empty |- t ! A -> Progress t

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
-- That is the full statement set. The five `postulate`
-- declarations (progress, preservation, caps-of,
-- capability-soundness, declared-caps + caps-of-reachable +
-- manifest-completeness) are the bricks that turn into actual
-- proofs in subsequent stages.
--
-- Stage 1 fills `progress`. Stage 2 fills `preservation`.
-- Stage 3 fills `caps-of` and `capability-soundness`. Stage 4
-- fills `declared-caps`, `caps-of-reachable`, and
-- `manifest-completeness`.
------------------------------------------------------------------
