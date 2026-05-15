------------------------------------------------------------------
-- CapaSyntax.agda
--
-- Syntax, typing relation, and small-step reduction for the
-- lambda_cap calculus described in docs/semantics.md.
--
-- STATUS: Skeleton. Has not been typechecked by Agda locally.
-- Install Agda >= 2.6.4 and run `agda CapaSyntax.agda` to verify.
-- Minor syntactic adjustments may be required across Agda versions.
--
-- The conventions follow Programming Language Foundations in Agda
-- (PLFA), Wadler/Kokke/Siek, which is the canonical reference for
-- this Wright-Felleisen style.
------------------------------------------------------------------

module CapaSyntax where

------------------------------------------------------------------
-- Basic library types we depend on.
------------------------------------------------------------------

data Nat : Set where
  zero : Nat
  suc  : Nat -> Nat

data Bool : Set where
  true  : Bool
  false : Bool

data _==_ {A : Set} (x : A) : A -> Set where
  refl : x == x

infix 4 _==_

------------------------------------------------------------------
-- Capabilities.
--
-- The capability tags are an enumerated set. The constructors
-- match the built-in capabilities Capa ships (capa/runtime/
-- _capabilities.py). User-defined capabilities are handled in
-- the full language but not modelled in lambda_cap.
------------------------------------------------------------------

data Cap : Set where
  Stdio   : Cap
  Fs      : Cap
  Net     : Cap
  Env     : Cap
  Clock   : Cap
  Random  : Cap
  Unsafe  : Cap

------------------------------------------------------------------
-- Types.
--
-- The types of lambda_cap: base types (Int, Bool, Unit), function
-- types, and capability types (one per Cap tag).
------------------------------------------------------------------

data Ty : Set where
  TyInt   : Ty
  TyBool  : Ty
  TyUnit  : Ty
  _=>_    : Ty -> Ty -> Ty                          -- function
  TyCap   : Cap -> Ty                               -- capability type

infixr 7 _=>_

------------------------------------------------------------------
-- Variables (de Bruijn indices).
------------------------------------------------------------------

data Var : Set where
  vzero : Var
  vsuc  : Var -> Var

------------------------------------------------------------------
-- Terms.
--
-- Variables, lambdas, applications, integer literals, the unit
-- value, capability constants (introduced at main), method calls
-- on capabilities (`use`), restrict_to-style attenuation
-- (`restrict`), and the consume-style move (`consume`).
------------------------------------------------------------------

data Tm : Set where
  var      : Var -> Tm
  lam      : Ty -> Tm -> Tm
  app      : Tm -> Tm -> Tm
  i        : Nat -> Tm                              -- integer literal
  unit     : Tm
  cap      : Cap -> Tm                              -- capability constant
  use      : Cap -> Tm -> Tm                        -- exercise a cap
  restrict : Cap -> Tm -> Tm                        -- attenuate a cap
  consume  : Tm -> Tm                               -- linear move

------------------------------------------------------------------
-- Typing contexts.
--
-- A context is a finite list of types. We use the standard
-- snoc-list representation: empty, or (ctx , T).
------------------------------------------------------------------

data Ctx : Set where
  empty : Ctx
  _,_   : Ctx -> Ty -> Ctx

infixl 5 _,_

------------------------------------------------------------------
-- Variable lookup judgment.
--
-- Index x in context G has type A. de Bruijn-style.
------------------------------------------------------------------

data _>>_!_ : Ctx -> Var -> Ty -> Set where
  here  : forall {G A}     -> ((G , A)) >> vzero    ! A
  there : forall {G A B v} -> G >> v ! A -> ((G , B)) >> (vsuc v) ! A

infix 4 _>>_!_

------------------------------------------------------------------
-- Capability footprint: the set of capabilities a typing context
-- makes available. Represented as a Cap -> Bool characteristic
-- function.
------------------------------------------------------------------

CapSet : Set
CapSet = Cap -> Bool

emptyCS : CapSet
emptyCS _ = false

singletonCS : Cap -> CapSet
singletonCS c c' = ?               -- decidable equality on Cap

------------------------------------------------------------------
-- Typing relation.
--
-- G |- t : T meaning "in context G, term t has type T". The
-- capability rules are:
--
--   - cap c   has type TyCap c, unconditionally (introduction
--             at main is the only way to obtain one in practice;
--             in the calculus we admit it as a literal).
--   - use c t requires t : TyCap c and produces TyUnit.
--   - restrict c t requires t : TyCap c and produces TyCap c.
--   - consume t reads t at any type and produces the same type;
--             the linear-tracking happens at the operational
--             semantics layer, not in the typing rules.
------------------------------------------------------------------

data _|-_!_ : Ctx -> Tm -> Ty -> Set where

  T-Var : forall {G v A}
        -> G >> v ! A
        -> G |- var v ! A

  T-Lam : forall {G A B t}
        -> ((G , A)) |- t ! B
        -> G |- lam A t ! (A => B)

  T-App : forall {G t1 t2 A B}
        -> G |- t1 ! (A => B)
        -> G |- t2 ! A
        -> G |- app t1 t2 ! B

  T-Int : forall {G n}
        -> G |- i n ! TyInt

  T-Unit : forall {G}
         -> G |- unit ! TyUnit

  T-Cap : forall {G c}
        -> G |- cap c ! TyCap c

  T-Use : forall {G c t}
        -> G |- t ! TyCap c
        -> G |- use c t ! TyUnit

  T-Restrict : forall {G c t}
             -> G |- t ! TyCap c
             -> G |- restrict c t ! TyCap c

  T-Consume : forall {G t A}
            -> G |- t ! A
            -> G |- consume t ! A

infix 4 _|-_!_

------------------------------------------------------------------
-- Values.
--
-- Lambdas, integer literals, unit, and capability constants are
-- values. `use`, `app`, `restrict`, and `consume` reduce further.
------------------------------------------------------------------

data Value : Tm -> Set where
  V-Lam  : forall {A t} -> Value (lam A t)
  V-Int  : forall {n}   -> Value (i n)
  V-Unit : Value unit
  V-Cap  : forall {c}   -> Value (cap c)

------------------------------------------------------------------
-- Small-step reduction.
--
-- Standard call-by-value beta. The capability-specific rules:
--
--   - R-Use: use c (cap c)  -> unit
--            (exercising a capability returns unit, the runtime
--            effect is modelled by the labelled-transition system
--            in CapaSoundness.agda)
--   - R-Restrict: restrict c (cap c) -> cap c
--            (attenuation produces a capability of the same tag;
--            the narrowing is tracked in the trace, not in the
--            syntax)
--   - R-Consume: consume v -> v   when Value v
--            (linear move; the operational invariant is that the
--            original binding is no longer accessible, which the
--            full language enforces via the consume keyword and
--            the analyzer's use-after-consume bookkeeping)
------------------------------------------------------------------

data _==>_ : Tm -> Tm -> Set where

  R-AppLeft  : forall {t1 t1' t2}
             -> t1 ==> t1'
             -> app t1 t2 ==> app t1' t2

  R-AppRight : forall {v t2 t2'}
             -> Value v
             -> t2 ==> t2'
             -> app v t2 ==> app v t2'

  R-Beta     : forall {A t v}
             -> Value v
             -> app (lam A t) v ==> t                -- substitution elided

  R-Use      : forall {c}
             -> use c (cap c) ==> unit

  R-UseStep  : forall {c t t'}
             -> t ==> t'
             -> use c t ==> use c t'

  R-Restrict : forall {c}
             -> restrict c (cap c) ==> cap c

  R-RestrictStep : forall {c t t'}
                 -> t ==> t'
                 -> restrict c t ==> restrict c t'

  R-Consume      : forall {v}
                 -> Value v
                 -> consume v ==> v

  R-ConsumeStep  : forall {t t'}
                 -> t ==> t'
                 -> consume t ==> consume t'

infix 4 _==>_

------------------------------------------------------------------
-- That is the syntax. The two theorems (Progress + Preservation,
-- composing into Capability Soundness, plus Manifest Completeness)
-- are stated in CapaSoundness.agda.
------------------------------------------------------------------
