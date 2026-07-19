{-# OPTIONS --safe #-}
------------------------------------------------------------------
-- CapaSyntax.agda
--
-- Syntax, typing relation, and small-step reduction for the
-- lambda_cap calculus described in docs/semantics.md. Includes
-- PLFA-style parallel renaming / substitution (used by R-Beta
-- and by the preservation proof in CapaSoundness.agda).
--
-- STATUS: Typechecks on Agda >= 2.6.4. Verified in CI (see
-- .github/workflows/agda.yml).
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

_||_ : Bool -> Bool -> Bool
true  || _ = true
false || y = y

infixr 5 _||_

_&&_ : Bool -> Bool -> Bool
true  && y = y
false && _ = false

infixr 6 _&&_

data _==_ {A : Set} (x : A) : A -> Set where
  refl : x == x

infix 4 _==_

{-# BUILTIN EQUALITY _==_ #-}

------------------------------------------------------------------
-- Capabilities.
--
-- The capability tags are an enumerated set. The constructors
-- match the ten built-in capabilities Capa ships, whose single
-- source of truth is BUILTIN_CAPS in capa/ir/_capa_types.py.
-- The test TestCapabilityRegistry in tests/test_cap_handles.py
-- parses this datatype and fails if the two lists drift apart.
-- User-defined capabilities are handled in the full language but
-- not modelled in lambda_cap.
--
-- Every theorem in CapaSoundness.agda, CapaAttenuation.agda and
-- CapaManifestExact.agda is parametric in the capability tag: the
-- proofs induct on the typing or reduction derivation and on the
-- `_∈caps_` witness, never on WHICH capability a tag is. Adding a
-- constructor here therefore costs exactly one new diagonal line
-- in `singletonCS` below and no new proof case anywhere.
------------------------------------------------------------------

data Cap : Set where
  Stdio   : Cap
  Fs      : Cap
  Net     : Cap
  Env     : Cap
  Clock   : Cap
  Random  : Cap
  Proc    : Cap
  Db      : Cap
  Serve   : Cap
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
-- Restrictions: the attenuation lattice of docs/semantics.md
-- Section 2.
--
-- The prose fixes, per capability class c, a SCOPE SET `Sigma_c`
-- (host names for Net, path prefixes for Fs, variable names for
-- Env, (address, port) pairs for Serve, ...) and takes a
-- restriction to be a subset `rho` of it, ordered by inclusion.
-- `attn(cap[c, rho], rho') = cap[c, rho ∩ rho']` is the greatest
-- lower bound in `(P(Sigma_c), ⊆)`.
--
-- Here `Req` is that scope set, left ABSTRACT: everything below,
-- and every theorem in CapaAttenuation.agda, is universally
-- quantified over it, so the results hold for each class's own
-- scope set by instantiation (Req := Sigma_Net gives the Net
-- theory, Req := Sigma_Serve the Serve theory, and so on). A
-- restriction is the characteristic function of a subset. Using
-- ONE abstract domain rather than a per-class family `Cap -> Set`
-- is a deliberate choice; see the note at the end of this section.
--
-- The runtime is what this models. `capa/runtime/_capabilities.py`
-- stores a restriction as either "unrestricted" or a frozen set,
-- and every attenuator narrows:
--
--   Net / Env / Proc / Db  intersect the stored set outright
--   Fs / Serve             ACCUMULATE rules by union and permit a
--                          request only if EVERY rule passes, which
--                          is the intersection of the per-rule
--                          permitted sets (proved as `meetAll-snoc`
--                          in CapaAttenuation.agda)
--   Clock                  raises a not-before threshold via max,
--                          the intersection of two up-sets
--
-- so `_∩R_` below is the common content of all of them.
--
-- WHY ONE ABSTRACT `Req` AND NOT A FAMILY `Cap -> Set`. A
-- per-class family was tried first and rejected on inference
-- grounds, not on modelling grounds: with `Tm (Req : Cap -> Set)`
-- a restriction has type `Req c -> Bool`, and recovering `Req`
-- from `Req c` is a higher-order unification problem Agda cannot
-- solve, so every constructor application leaves the domain an
-- unsolved metavariable. The cost of the uniform choice is that a
-- single term draws all its restrictions from one scope set, so
-- the model cannot express a program whose Fs restriction and Net
-- restriction range over genuinely different sets at once. No
-- theorem below relates two classes' restrictions, so nothing
-- stated here is weakened by the identification; what is lost is
-- only the ability to state a cross-class theorem, and there is
-- none to state.
------------------------------------------------------------------

Restriction : Set -> Set
Restriction Req = Req -> Bool

-- Top of the lattice: the unattenuated authority `rho = ⊤` of the
-- prose, the `None` a fresh runtime capability carries.
unrestricted : forall {Req} -> Restriction Req
unrestricted _ = true

-- Bottom of the lattice: permits nothing. This is what the runtime
-- produces from a restriction spec that does not parse
-- (`_SERVE_DENY_ALL_RULE`): attenuation cannot report an error, so
-- a malformed spec must deny rather than be dropped, since dropping
-- it would silently WIDEN authority.
denyAll : forall {Req} -> Restriction Req
denyAll _ = false

-- Meet: `rho ∩ rho'`, the greatest lower bound.
_∩R_ : forall {Req} -> Restriction Req -> Restriction Req -> Restriction Req
(p ∩R q) x = p x && q x

infixr 6 _∩R_

-- The attenuation ordering `rho ⊑ rho'` of the prose, pointwise:
-- everything p permits, q permits. "p is at least as narrow as q".
_⊑R_ : forall {Req} -> Restriction Req -> Restriction Req -> Set
_⊑R_ {Req} p q = (x : Req) -> p x == true -> q x == true

infix 4 _⊑R_

-- Pointwise (extensional) equivalence of restrictions. Restrictions
-- are functions, and function extensionality is not available under
-- --safe, so the lattice laws in CapaAttenuation.agda are stated
-- with this rather than with `_==_`.
_≈R_ : forall {Req} -> Restriction Req -> Restriction Req -> Set
_≈R_ {Req} p q = (x : Req) -> p x == q x

infix 4 _≈R_

------------------------------------------------------------------
-- Terms.
--
-- Variables, lambdas, applications, integer and boolean literals,
-- the unit value, capability constants (introduced at main),
-- invocation of a capability on a request (`use`), restrict_to-
-- style attenuation (`restrict`), and the consume-style move
-- (`consume`).
--
-- `Tm` is indexed by the scope set `Req` the term's restrictions
-- and requests are drawn from.
--
--   cap c rho        the value `cap[c, rho]` of the prose: a
--                    capability of class c carrying restriction rho
--   use c x t        `invoke(t, ...)` on request x; it reduces to
--                    the BOOLEAN the receiver's restriction assigns
--                    to x, so a denied invocation is observably
--                    different from a permitted one
--   restrict c rho t `attn(t, rho)`
------------------------------------------------------------------

data Tm (Req : Set) : Set where
  var      : Var -> Tm Req
  lam      : Ty -> Tm Req -> Tm Req
  app      : Tm Req -> Tm Req -> Tm Req
  i        : Nat -> Tm Req                          -- integer literal
  bool     : Bool -> Tm Req                         -- boolean literal
  unit     : Tm Req
  cap      : Cap -> Restriction Req -> Tm Req       -- capability value
  use      : Cap -> Req -> Tm Req -> Tm Req         -- exercise a cap
  restrict : Cap -> Restriction Req -> Tm Req -> Tm Req  -- attenuate
  consume  : Tm Req -> Tm Req                       -- linear move

------------------------------------------------------------------
-- Renamings and substitutions (PLFA-style parallel).
--
-- A renaming is a function Var -> Var; a substitution is a
-- function Var -> Tm. `ext` lifts a renaming under a binder
-- (the new vzero stays put, every existing index shifts up by
-- one via the underlying renaming); `exts` does the same for a
-- substitution but the existing indices are first renamed via
-- `rename vsuc` to skip the new binding. `rename` and `subst`
-- then recurse over a term applying the lifted renaming or
-- substitution at each occurrence.
--
-- Restrictions and requests are not terms, so they ride through
-- both traversals untouched.
--
-- Termination: `rename` and `subst` are structurally recursive
-- on the Tm argument, so Agda accepts them without pragma.
-- There is no mutual recursion: `ext` -> `rename` -> `exts` ->
-- `subst`.
------------------------------------------------------------------

ext : (Var -> Var) -> (Var -> Var)
ext rho vzero    = vzero
ext rho (vsuc x) = vsuc (rho x)

rename : forall {Req} -> (Var -> Var) -> Tm Req -> Tm Req
rename rho (var x)            = var (rho x)
rename rho (lam A t)          = lam A (rename (ext rho) t)
rename rho (app t1 t2)        = app (rename rho t1) (rename rho t2)
rename rho (i n)              = i n
rename rho (bool v)           = bool v
rename rho unit               = unit
rename rho (cap c res)        = cap c res
rename rho (use c x t)        = use c x (rename rho t)
rename rho (restrict c res t) = restrict c res (rename rho t)
rename rho (consume t)        = consume (rename rho t)

exts : forall {Req} -> (Var -> Tm Req) -> (Var -> Tm Req)
exts sigma vzero    = var vzero
exts sigma (vsuc x) = rename vsuc (sigma x)

subst : forall {Req} -> (Var -> Tm Req) -> Tm Req -> Tm Req
subst sigma (var x)            = sigma x
subst sigma (lam A t)          = lam A (subst (exts sigma) t)
subst sigma (app t1 t2)        = app (subst sigma t1) (subst sigma t2)
subst sigma (i n)              = i n
subst sigma (bool v)           = bool v
subst sigma unit               = unit
subst sigma (cap c res)        = cap c res
subst sigma (use c x t)        = use c x (subst sigma t)
subst sigma (restrict c res t) = restrict c res (subst sigma t)
subst sigma (consume t)        = consume (subst sigma t)

-- Single-variable substitution: `t [ v ]` replaces the zero
-- index in t with v, leaving every other index unshifted.

sub-zero : forall {Req} -> Tm Req -> (Var -> Tm Req)
sub-zero v vzero    = v
sub-zero v (vsuc x) = var x

_[_] : forall {Req} -> Tm Req -> Tm Req -> Tm Req
t [ v ] = subst (sub-zero v) t

infix 6 _[_]

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
singletonCS Stdio  Stdio  = true
singletonCS Fs     Fs     = true
singletonCS Net    Net    = true
singletonCS Env    Env    = true
singletonCS Clock  Clock  = true
singletonCS Random Random = true
singletonCS Proc   Proc   = true
singletonCS Db     Db     = true
singletonCS Serve  Serve  = true
singletonCS Unsafe Unsafe = true
singletonCS _      _      = false

_∪_ : CapSet -> CapSet -> CapSet
(S ∪ T) c = S c || T c

infixr 5 _∪_

------------------------------------------------------------------
-- Typing relation.
--
-- G |- t : T meaning "in context G, term t has type T". The
-- capability rules are:
--
--   - cap c res has type TyCap c, unconditionally (introduction
--             at main is the only way to obtain one in practice;
--             in the calculus we admit it as a literal). The
--             restriction is a runtime value and is NOT reflected
--             in the type, matching Section 3 of the prose:
--             "the capability type Cap[c] does not index the
--             attenuation".
--   - use c x t requires t : TyCap c and produces TyBool: the
--             boolean is whether the receiver's restriction
--             permits the request x.
--   - restrict c res t requires t : TyCap c and produces TyCap c.
--   - consume t reads t at any type and produces the same type;
--             the linear-tracking happens at the operational
--             semantics layer, not in the typing rules.
------------------------------------------------------------------

data _|-_!_ {Req : Set} : Ctx -> Tm Req -> Ty -> Set where

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

  T-Bool : forall {G v}
         -> G |- bool v ! TyBool

  T-Unit : forall {G}
         -> G |- unit ! TyUnit

  T-Cap : forall {G c res}
        -> G |- cap c res ! TyCap c

  T-Use : forall {G c x t}
        -> G |- t ! TyCap c
        -> G |- use c x t ! TyBool

  T-Restrict : forall {G c res t}
             -> G |- t ! TyCap c
             -> G |- restrict c res t ! TyCap c

  T-Consume : forall {G t A}
            -> G |- t ! A
            -> G |- consume t ! A

infix 4 _|-_!_

------------------------------------------------------------------
-- Values.
--
-- Lambdas, integer and boolean literals, unit, and capability
-- constants are values. `use`, `app`, `restrict`, and `consume`
-- reduce further.
------------------------------------------------------------------

data Value {Req : Set} : Tm Req -> Set where
  V-Lam  : forall {A t} -> Value (lam A t)
  V-Int  : forall {n}   -> Value (i n)
  V-Bool : forall {v}   -> Value (bool v)
  V-Unit : Value unit
  V-Cap  : forall {c res} -> Value (cap c res)

------------------------------------------------------------------
-- Small-step reduction.
--
-- Standard call-by-value beta. The capability-specific rules:
--
--   - R-Use: use c x (cap c res)  ->  bool (res x)
--            Invoking a capability on request x yields whether the
--            receiver's restriction PERMITS x. This is the prose's
--            E-Invoke-Allow / E-Invoke-Deny pair collapsed into one
--            rule whose reduct records which of the two fired, and
--            it is what makes the restriction operationally
--            load-bearing rather than an inert decoration: a
--            narrower capability produces an observably different
--            answer. It mirrors the runtime `allows` predicate
--            (`Net.allows(host)`, `Fs.allows(path)`,
--            `Serve.allows(addr, port)`), which is exactly the
--            gate every IO method consults before acting.
--   - R-Restrict: restrict c res' (cap c res) -> cap c (res ∩R res')
--            The prose's E-Attn, verbatim: attenuation returns a
--            capability of the same class whose restriction is the
--            MEET of the old one and the requested one. It is not
--            the identity, and CapaAttenuation.agda proves both
--            that it can only narrow and (by machine-checked
--            witness) that it sometimes strictly does.
--   - R-Consume: consume v -> v   when Value v
--            (linear move; the operational invariant is that the
--            original binding is no longer accessible, which the
--            full language enforces via the consume keyword and
--            the analyzer's use-after-consume bookkeeping)
------------------------------------------------------------------

data _==>_ {Req : Set} : Tm Req -> Tm Req -> Set where

  R-AppLeft  : forall {t1 t1' t2}
             -> t1 ==> t1'
             -> app t1 t2 ==> app t1' t2

  R-AppRight : forall {v t2 t2'}
             -> Value v
             -> t2 ==> t2'
             -> app v t2 ==> app v t2'

  R-Beta     : forall {A t v}
             -> Value v
             -> app (lam A t) v ==> t [ v ]

  R-Use      : forall {c x res}
             -> use c x (cap c res) ==> bool (res x)

  R-UseStep  : forall {c x t t'}
             -> t ==> t'
             -> use c x t ==> use c x t'

  R-Restrict : forall {c res res'}
             -> restrict c res' (cap c res) ==> cap c (res ∩R res')

  R-RestrictStep : forall {c res t t'}
                 -> t ==> t'
                 -> restrict c res t ==> restrict c res t'

  R-Consume      : forall {v}
                 -> Value v
                 -> consume v ==> v

  R-ConsumeStep  : forall {t t'}
                 -> t ==> t'
                 -> consume t ==> consume t'

infix 4 _==>_

------------------------------------------------------------------
-- Reflexive-transitive closure of small-step reduction. Read
-- t ==>* t' as "t reduces to t' in zero or more steps". Used by
-- the Manifest Completeness theorem in CapaSoundness.agda to
-- bound the capabilities reachable via any number of reduction
-- steps, and by the attenuation-tower theorem in
-- CapaAttenuation.agda.
------------------------------------------------------------------

data _==>*_ {Req : Set} : Tm Req -> Tm Req -> Set where
  done* : forall {t} -> t ==>* t
  step* : forall {t t' t''} -> t ==> t' -> t' ==>* t'' -> t ==>* t''

infix 4 _==>*_

------------------------------------------------------------------
-- That is the syntax. The four soundness theorems (Progress +
-- Preservation, composing into Capability Soundness and Manifest
-- Completeness) are stated and proved in CapaSoundness.agda; the
-- attenuation metatheory is in CapaAttenuation.agda.
------------------------------------------------------------------
