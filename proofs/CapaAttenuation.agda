{-# OPTIONS --safe #-}
------------------------------------------------------------------
-- CapaAttenuation.agda
--
-- The attenuation metatheory of lambda_cap: the lattice of
-- Section 2 of docs/semantics.md, the rule E-Attn of Section 5,
-- and the guarantee the whole capability story rests on, namely
-- that attenuating a capability can only ever NARROW its
-- authority and never widen it.
--
-- STATUS: Typechecks on Agda >= 2.6.4 under --safe, with no
-- postulate. Verified in CI (see .github/workflows/agda.yml).
--
-- WHAT THIS FILE ADDS OVER CapaSoundness.agda. The four theorems
-- there are about the CLASS-level footprint: which of the ten
-- capability classes a program can exercise. They are blind to
-- restrictions. This file is about the other axis: given that a
-- program holds class c, how much of Sigma_c can it reach, and
-- what can reduction do to that quantity. Nothing here weakens
-- anything there; the two developments share the syntax and are
-- otherwise independent.
--
-- THE DEGENERACY TRAP, and how it is closed. A monotonicity
-- theorem is worthless if attenuation happens to be the identity,
-- because "restricting only narrows" is then vacuously true. Two
-- things rule that out here, both machine-checked:
--
--   * a restriction is OPERATIONALLY LOAD-BEARING. `use c x t`
--     reduces to the boolean the receiver's restriction assigns
--     to the request x, so a narrower capability produces a
--     different observable answer. A restriction is not a
--     decoration that no rule reads.
--   * the STRICT-NARROWING witnesses at the end of this file
--     exhibit a concrete capability, a concrete attenuation, and
--     a concrete request that the capability permits BEFORE
--     attenuation and is denied AFTER it, plus a refutation of
--     the claim that the two restrictions are equivalent.
--
-- If someone were to weaken R-Restrict back to the identity
-- `restrict c res' (cap c res) ==> cap c res`, those witnesses
-- would stop typechecking. That is the intended tripwire.
------------------------------------------------------------------

module CapaAttenuation where

open import CapaSyntax
-- `_⊎_` / `inl` / `inr` and `preservation` are reused from the
-- soundness development rather than restated. CapaSoundness does
-- not re-export CapaSyntax, so there is no clash with the direct
-- import above.
open import CapaSoundness

------------------------------------------------------------------
-- Equality plumbing. CapaSyntax declares `_==_` (and registers it
-- as BUILTIN EQUALITY) but exports no eliminators, so the three
-- standard ones are given here.
------------------------------------------------------------------

symEq : forall {A : Set} {x y : A} -> x == y -> y == x
symEq refl = refl

transEq : forall {A : Set} {x y z : A} -> x == y -> y == z -> x == z
transEq refl q = q

congEq : forall {A B : Set} {x y : A} (f : A -> B) -> x == y -> f x == f y
congEq f refl = refl

substEq : forall {A : Set} {x y : A} (P : A -> Set) -> x == y -> P x -> P y
substEq P refl px = px

data Empty : Set where

true-not-false : true == false -> Empty
true-not-false ()

false-not-true : false == true -> Empty
false-not-true ()

------------------------------------------------------------------
-- Boolean conjunction lemmas. `_&&_` in CapaSyntax matches on its
-- LEFT argument only, so most of these need a case split on that
-- argument alone.
------------------------------------------------------------------

&&-elim-l : (u v : Bool) -> (u && v) == true -> u == true
&&-elim-l true  v h = refl
&&-elim-l false v ()

&&-elim-r : (u v : Bool) -> (u && v) == true -> v == true
&&-elim-r true  v h = h
&&-elim-r false v ()

&&-intro : {u v : Bool} -> u == true -> v == true -> (u && v) == true
&&-intro refl h2 = h2

&&-assoc : (u v w : Bool) -> ((u && v) && w) == (u && (v && w))
&&-assoc true  v w = refl
&&-assoc false v w = refl

&&-comm : (u v : Bool) -> (u && v) == (v && u)
&&-comm true  true  = refl
&&-comm true  false = refl
&&-comm false true  = refl
&&-comm false false = refl

&&-idem : (u : Bool) -> (u && u) == u
&&-idem true  = refl
&&-idem false = refl

&&-true-r : (u : Bool) -> (u && true) == u
&&-true-r true  = refl
&&-true-r false = refl

&&-false-r : (u : Bool) -> (u && false) == false
&&-false-r true  = refl
&&-false-r false = refl

------------------------------------------------------------------
-- PART 1: the attenuation lattice.
--
-- docs/semantics.md Section 2 specifies `(P(Sigma_c), ⊆)` with
-- `attn` producing the greatest lower bound. `_⊑R_` is that order
-- and `_∩R_` that meet, both defined in CapaSyntax. This part
-- proves they behave as advertised.
--
-- Everything is stated pointwise: restrictions are functions, and
-- function extensionality is unavailable under --safe, so
-- equalities between restrictions are `_≈R_` (pointwise equality)
-- rather than `_==_`. Nothing below needs more than that.
------------------------------------------------------------------

-- `_⊑R_` is a preorder.

⊑R-refl : forall {Req} (p : Restriction Req) -> p ⊑R p
⊑R-refl p x h = h

⊑R-trans : forall {Req} {p q s : Restriction Req}
         -> p ⊑R q -> q ⊑R s -> p ⊑R s
⊑R-trans pq qs x h = qs x (pq x h)

-- `_≈R_` is an equivalence, and it implies the order both ways.

≈R-refl : forall {Req} (p : Restriction Req) -> p ≈R p
≈R-refl p x = refl

≈R-sym : forall {Req} {p q : Restriction Req} -> p ≈R q -> q ≈R p
≈R-sym pq x = symEq (pq x)

≈R-trans : forall {Req} {p q s : Restriction Req}
         -> p ≈R q -> q ≈R s -> p ≈R s
≈R-trans pq qs x = transEq (pq x) (qs x)

≈R-to-⊑R : forall {Req} {p q : Restriction Req} -> p ≈R q -> p ⊑R q
≈R-to-⊑R pq x h = substEq (\ z -> z == true) (pq x) h

-- `_∩R_` is the greatest lower bound: below both arguments, and
-- above anything else that is below both. This is the equation
-- `attn(cap[c, rho], rho') = cap[c, rho ∩ rho']` of Section 2,
-- stated as a lattice property.

∩R-lower-l : forall {Req} (p q : Restriction Req) -> (p ∩R q) ⊑R p
∩R-lower-l p q x h = &&-elim-l (p x) (q x) h

∩R-lower-r : forall {Req} (p q : Restriction Req) -> (p ∩R q) ⊑R q
∩R-lower-r p q x h = &&-elim-r (p x) (q x) h

∩R-greatest : forall {Req} {p q s : Restriction Req}
            -> s ⊑R p -> s ⊑R q -> s ⊑R (p ∩R q)
∩R-greatest sp sq x h = &&-intro (sp x h) (sq x h)

-- The usual meet laws.

∩R-assoc : forall {Req} (p q s : Restriction Req)
         -> ((p ∩R q) ∩R s) ≈R (p ∩R (q ∩R s))
∩R-assoc p q s x = &&-assoc (p x) (q x) (s x)

∩R-comm : forall {Req} (p q : Restriction Req) -> (p ∩R q) ≈R (q ∩R p)
∩R-comm p q x = &&-comm (p x) (q x)

∩R-idem : forall {Req} (p : Restriction Req) -> (p ∩R p) ≈R p
∩R-idem p x = &&-idem (p x)

-- `unrestricted` is the top element and the unit of the meet.
-- CONSEQUENCE, and it is the point: attenuating an ALREADY
-- narrowed capability by the top element gives back exactly the
-- narrowed one. `serve.restrict_to("*:*")` on a cap already
-- confined to 127.0.0.1:8080 restores nothing.

∩R-unrestricted-r : forall {Req} (p : Restriction Req)
                  -> (p ∩R unrestricted) ≈R p
∩R-unrestricted-r p x = &&-true-r (p x)

∩R-unrestricted-l : forall {Req} (p : Restriction Req)
                  -> (unrestricted ∩R p) ≈R p
∩R-unrestricted-l p x = refl

⊑R-unrestricted : forall {Req} (p : Restriction Req) -> p ⊑R unrestricted
⊑R-unrestricted p x h = refl

-- `denyAll` is the bottom element and absorbs the meet. This is
-- the runtime's fail-closed handling of a restriction spec that
-- does not parse (`_SERVE_DENY_ALL_RULE`): the malformed spec
-- becomes a rule nothing satisfies, and no later attenuation can
-- recover from it.

∩R-denyAll-r : forall {Req} (p : Restriction Req) -> (p ∩R denyAll) ≈R denyAll
∩R-denyAll-r p x = &&-false-r (p x)

∩R-denyAll-l : forall {Req} (p : Restriction Req) -> (denyAll ∩R p) ≈R denyAll
∩R-denyAll-l p x = refl

denyAll-⊑R : forall {Req} (p : Restriction Req) -> denyAll ⊑R p
denyAll-⊑R p x ()

------------------------------------------------------------------
-- PART 2: attenuation on terms, one step.
--
-- `attn-is-meet` pins the reduct of E-Attn exactly, and
-- `attn-narrows` is the single-step form of the headline claim.
------------------------------------------------------------------

-- E-Attn produces the meet, and nothing else can happen to
-- `restrict c res' (cap c res)`: pattern-matching the step forces
-- the reduct.

attn-is-meet : forall {Req} (c : Cap) (res res' : Restriction Req) {t : Tm Req}
             -> restrict c res' (cap c res) ==> t
             -> t == cap c (res ∩R res')
attn-is-meet c res res' R-Restrict = refl

-- Attenuation narrows: the restriction of the reduct is below the
-- restriction of the source. Never widens.

attn-narrows : forall {Req} (res res' : Restriction Req)
             -> (res ∩R res') ⊑R res
attn-narrows res res' = ∩R-lower-l res res'

-- The OPERATIONAL form, which is the one a reader should care
-- about, because it is stated over the reduction relation rather
-- than over the lattice: every invocation an ATTENUATED
-- capability permits, the ORIGINAL capability already permitted.
-- Contrapositively, attenuation can never unlock a request that
-- was previously denied.

attn-use-never-widens
  : forall {Req} {c : Cap} (res res' : Restriction Req) (x : Req) {v : Bool}
  -> use c x (cap c (res ∩R res')) ==> bool v
  -> v == true
  -> use c x (cap c res) ==> bool true
attn-use-never-widens {Req} {c} res res' x R-Use h
  = substEq (\ z -> use c x (cap c res) ==> bool z)
            (&&-elim-l (res x) (res' x) h)
            R-Use

------------------------------------------------------------------
-- PART 3: towers of attenuation.
--
-- Real Capa code attenuates repeatedly: `net.restrict_to(a)`
-- then `.restrict_to(b)` then `.restrict_to(c)`. This part shows
-- such a chain reduces to a SINGLE capability whose restriction
-- is the meet of every restriction applied, in any length, and
-- that this meet is below the starting restriction.
------------------------------------------------------------------

data List (A : Set) : Set where
  []   : List A
  _::_ : A -> List A -> List A

infixr 5 _::_

_++_ : forall {A : Set} -> List A -> List A -> List A
[]        ++ ys = ys
(x :: xs) ++ ys = x :: (xs ++ ys)

infixr 5 _++_

-- `restricts c (r1 :: r2 :: []) t` is `restrict c r2 (restrict c r1 t)`:
-- the head of the list is the attenuation applied FIRST.
restricts : forall {Req} -> Cap -> List (Restriction Req) -> Tm Req -> Tm Req
restricts c []          t = t
restricts c (q :: rest) t = restricts c rest (restrict c q t)

-- The restriction such a chain accumulates, folded left.
meets : forall {Req} -> Restriction Req -> List (Restriction Req) -> Restriction Req
meets p []          = p
meets p (q :: rest) = meets (p ∩R q) rest

-- The meet of a list on its own, folded right from the top.
meetAll : forall {Req} -> List (Restriction Req) -> Restriction Req
meetAll []          = unrestricted
meetAll (q :: rest) = q ∩R meetAll rest

-- A step inside a tower is a step of the whole tower.
restricts-cong : forall {Req} (c : Cap) (rs : List (Restriction Req))
                 {t t' : Tm Req}
               -> t ==> t'
               -> restricts c rs t ==> restricts c rs t'
restricts-cong c []          s = s
restricts-cong c (q :: rest) s = restricts-cong c rest (R-RestrictStep s)

-- A tower of attenuations over a capability value reduces to a
-- single capability value carrying the accumulated meet.
attn-tower : forall {Req} (c : Cap) (rs : List (Restriction Req))
             (p : Restriction Req)
           -> restricts c rs (cap c p) ==>* cap c (meets p rs)
attn-tower c []          p = done*
attn-tower c (q :: rest) p
  = step* (restricts-cong c rest R-Restrict) (attn-tower c rest (p ∩R q))

-- However long the chain, the result is below where it started.
tower-narrows : forall {Req} (p : Restriction Req) (rs : List (Restriction Req))
              -> meets p rs ⊑R p
tower-narrows p []          = ⊑R-refl p
tower-narrows p (q :: rest)
  = ⊑R-trans (tower-narrows (p ∩R q) rest) (∩R-lower-l p q)

-- Repeated attenuation COMPOSES AS INTERSECTION: a chain of n
-- attenuations is equivalent to the single attenuation by the meet
-- of all n. So the order they are applied in does not matter, and
-- nothing is gained or lost by splitting or merging a chain.
tower-is-one-meet : forall {Req} (p : Restriction Req) (rs : List (Restriction Req))
                  -> meets p rs ≈R (p ∩R meetAll rs)
tower-is-one-meet p []          x = symEq (&&-true-r (p x))
tower-is-one-meet p (q :: rest) x
  = transEq (tower-is-one-meet (p ∩R q) rest x)
            (&&-assoc (p x) (q x) (meetAll rest x))

-- RUNTIME BRIDGE. `Fs` and `Serve` do not store a permitted set;
-- they store a SET OF RULES which `restrict_to` grows by union,
-- and permit a request only if EVERY rule passes (see
-- `Serve.allows` and `Fs.allows` in capa/runtime/_capabilities.py).
-- This lemma is the reason that implementation IS the intersection
-- the model uses: appending one more rule to the accumulated list
-- is exactly meeting the permitted set with that rule.
meetAll-snoc : forall {Req} (rs : List (Restriction Req)) (q : Restriction Req)
             -> meetAll (rs ++ (q :: [])) ≈R (meetAll rs ∩R q)
meetAll-snoc []          q x = &&-true-r (q x)
meetAll-snoc (p :: rest) q x
  = transEq (congEq (\ z -> p x && z) (meetAll-snoc rest q x))
            (symEq (&&-assoc (p x) (meetAll rest x) (q x)))

------------------------------------------------------------------
-- PART 4: the whole-calculus theorem.
--
-- Parts 2 and 3 are about the attenuation rule in isolation. This
-- part is the statement over ARBITRARY reduction: no matter what a
-- well-typed program does, no capability value it ever reaches
-- carries authority exceeding that of a capability value already
-- present in the source. Beta reduction can duplicate a capability
-- but not widen it; `restrict` narrows it; nothing else touches it.
--
-- `Auth c res t` is the occurrence relation for capability VALUES,
-- carrying the restriction. It is deliberately separate from
-- CapaSoundness's `_∈caps_`, which also counts the syntactic tags
-- on `use` and `restrict` (those are not capability values and
-- have no authority of their own).
------------------------------------------------------------------

data Auth {Req : Set} (c : Cap) (res : Restriction Req) : Tm Req -> Set where
  auth-here     : Auth c res (cap c res)
  auth-lam      : forall {A t}      -> Auth c res t -> Auth c res (lam A t)
  auth-app-l    : forall {t1 t2}    -> Auth c res t1 -> Auth c res (app t1 t2)
  auth-app-r    : forall {t1 t2}    -> Auth c res t2 -> Auth c res (app t1 t2)
  auth-use      : forall {c' x t}   -> Auth c res t -> Auth c res (use c' x t)
  auth-restrict : forall {c' q t}   -> Auth c res t -> Auth c res (restrict c' q t)
  auth-consume  : forall {t}        -> Auth c res t -> Auth c res (consume t)

-- "the authority res' found in t' is bounded by some authority
-- already in t".
data Narrowed {Req : Set} (c : Cap) (res' : Restriction Req) (t : Tm Req) : Set where
  narrowed : (res : Restriction Req)
           -> Auth c res t
           -> res' ⊑R res
           -> Narrowed c res' t

------------------------------------------------------------------
-- Renaming and substitution lemmas for `Auth`, mirroring the
-- `_∈caps_` versions in CapaSoundness. Restrictions ride through
-- both traversals untouched, so an occurrence in the traversed
-- term comes from the original term or from the substituted
-- values, with the SAME restriction in either case.
------------------------------------------------------------------

rename-Auth : forall {Req} {c res} {rho : Var -> Var} (t : Tm Req)
            -> Auth c res (rename rho t)
            -> Auth c res t
rename-Auth (var _)          ()
rename-Auth (lam _ t)        (auth-lam h)      = auth-lam (rename-Auth t h)
rename-Auth (app t1 t2)      (auth-app-l h)    = auth-app-l (rename-Auth t1 h)
rename-Auth (app t1 t2)      (auth-app-r h)    = auth-app-r (rename-Auth t2 h)
rename-Auth (i _)            ()
rename-Auth (bool _)         ()
rename-Auth unit             ()
rename-Auth (cap _ _)        auth-here         = auth-here
rename-Auth (use _ _ t)      (auth-use h)      = auth-use (rename-Auth t h)
rename-Auth (restrict _ _ t) (auth-restrict h) = auth-restrict (rename-Auth t h)
rename-Auth (consume t)      (auth-consume h)  = auth-consume (rename-Auth t h)

sigma-Auth-bounded : forall {Req} -> (Var -> Tm Req)
                   -> (Cap -> Restriction Req -> Set) -> Set
sigma-Auth-bounded {Req} sigma P
  = (x : Var) (c : Cap) (res : Restriction Req) -> Auth c res (sigma x) -> P c res

exts-Auth-bounded : forall {Req} {P} (sigma : Var -> Tm Req)
                  -> sigma-Auth-bounded sigma P
                  -> sigma-Auth-bounded (exts sigma) P
exts-Auth-bounded sigma sb vzero    c res ()
exts-Auth-bounded sigma sb (vsuc x) c res h = sb x c res (rename-Auth (sigma x) h)

subst-Auth-bounded : forall {Req} {P} (sigma : Var -> Tm Req) (t : Tm Req)
                     (c : Cap) (res : Restriction Req)
                   -> sigma-Auth-bounded sigma P
                   -> Auth c res (subst sigma t)
                   -> Auth c res t ⊎ P c res
subst-Auth-bounded sigma (var x) c res sb h = inr (sb x c res h)
subst-Auth-bounded sigma (lam _ t) c res sb (auth-lam h)
  with subst-Auth-bounded (exts sigma) t c res (exts-Auth-bounded sigma sb) h
... | inl ht = inl (auth-lam ht)
... | inr p  = inr p
subst-Auth-bounded sigma (app t1 t2) c res sb (auth-app-l h)
  with subst-Auth-bounded sigma t1 c res sb h
... | inl ht = inl (auth-app-l ht)
... | inr p  = inr p
subst-Auth-bounded sigma (app t1 t2) c res sb (auth-app-r h)
  with subst-Auth-bounded sigma t2 c res sb h
... | inl ht = inl (auth-app-r ht)
... | inr p  = inr p
subst-Auth-bounded sigma (i _)    c res sb ()
subst-Auth-bounded sigma (bool _) c res sb ()
subst-Auth-bounded sigma unit     c res sb ()
subst-Auth-bounded sigma (cap _ _) c res sb auth-here = inl auth-here
subst-Auth-bounded sigma (use _ _ t) c res sb (auth-use h)
  with subst-Auth-bounded sigma t c res sb h
... | inl ht = inl (auth-use ht)
... | inr p  = inr p
subst-Auth-bounded sigma (restrict _ _ t) c res sb (auth-restrict h)
  with subst-Auth-bounded sigma t c res sb h
... | inl ht = inl (auth-restrict ht)
... | inr p  = inr p
subst-Auth-bounded sigma (consume t) c res sb (auth-consume h)
  with subst-Auth-bounded sigma t c res sb h
... | inl ht = inl (auth-consume ht)
... | inr p  = inr p

sub-zero-Auth-bounded : forall {Req} (v : Tm Req)
                      -> sigma-Auth-bounded (sub-zero v)
                                            (\ c res -> Auth c res v)
sub-zero-Auth-bounded v vzero    c res h = h
sub-zero-Auth-bounded v (vsuc _) c res ()

subst-zero-Auth : forall {Req} (t : Tm Req) {v : Tm Req}
                  (c : Cap) (res : Restriction Req)
                -> Auth c res (t [ v ])
                -> Auth c res t ⊎ Auth c res v
subst-zero-Auth t {v} c res h
  = subst-Auth-bounded (sub-zero v) t c res (sub-zero-Auth-bounded v) h

------------------------------------------------------------------
-- Theorem (single-step attenuation soundness).
--
-- For a well-typed closed term t, if t ==> t' and a capability of
-- class c carrying restriction res' occurs in t', then some
-- capability of class c occurs in t carrying a restriction res
-- with res' ⊑R res. Reduction never widens authority.
--
-- The crux is the R-Restrict case: the reduct carries
-- `res ∩R res'` and the source carries `res`, discharged by
-- ∩R-lower-l. Every other case reproduces the SAME restriction,
-- so ⊑R-refl suffices; R-Beta routes through subst-zero-Auth to
-- decide whether the occurrence came from the lambda body or from
-- the substituted argument. R-Use is absurd: its reduct is a
-- boolean literal, in which no capability value occurs.
------------------------------------------------------------------

attenuation-soundness
  : forall {Req} {t t' : Tm Req} {A} {c : Cap} {res' : Restriction Req}
  -> empty |- t ! A
  -> t ==> t'
  -> Auth c res' t'
  -> Narrowed c res' t
attenuation-soundness (T-App d1 d2) (R-AppLeft s1) (auth-app-l h)
  with attenuation-soundness d1 s1 h
... | narrowed res occ le = narrowed res (auth-app-l occ) le
attenuation-soundness (T-App d1 d2) (R-AppLeft s1) (auth-app-r h)
  = narrowed _ (auth-app-r h) (⊑R-refl _)
attenuation-soundness (T-App d1 d2) (R-AppRight _ s2) (auth-app-l h)
  = narrowed _ (auth-app-l h) (⊑R-refl _)
attenuation-soundness (T-App d1 d2) (R-AppRight _ s2) (auth-app-r h)
  with attenuation-soundness d2 s2 h
... | narrowed res occ le = narrowed res (auth-app-r occ) le
attenuation-soundness {c = c} {res' = res'}
                      (T-App (T-Lam _) _) (R-Beta {t = body} _) h
  with subst-zero-Auth body c res' h
... | inl hb = narrowed _ (auth-app-l (auth-lam hb)) (⊑R-refl _)
... | inr hv = narrowed _ (auth-app-r hv) (⊑R-refl _)
attenuation-soundness (T-Use d) (R-UseStep s) (auth-use h)
  with attenuation-soundness d s h
... | narrowed res occ le = narrowed res (auth-use occ) le
attenuation-soundness (T-Use _) R-Use ()
attenuation-soundness (T-Restrict d) (R-RestrictStep s) (auth-restrict h)
  with attenuation-soundness d s h
... | narrowed res occ le = narrowed res (auth-restrict occ) le
attenuation-soundness (T-Restrict _) (R-Restrict {res = res} {res' = res'}) auth-here
  = narrowed res (auth-restrict auth-here) (∩R-lower-l res res')
attenuation-soundness (T-Consume d) (R-ConsumeStep s) (auth-consume h)
  with attenuation-soundness d s h
... | narrowed res occ le = narrowed res (auth-consume occ) le
attenuation-soundness (T-Consume _) (R-Consume _) h
  = narrowed _ (auth-consume h) (⊑R-refl _)

------------------------------------------------------------------
-- Theorem (attenuation monotonicity, multi-step).
--
-- The same statement over any number of reduction steps: whatever
-- a well-typed program computes, every capability value it can
-- ever hold is bounded by a capability value in its source. This
-- is the attenuation counterpart of manifest-completeness: that
-- one bounds WHICH CLASSES appear, this one bounds HOW MUCH
-- AUTHORITY any of them carries.
--
-- Iterated attenuation-soundness, carrying the typing forward with
-- preservation and composing the bounds with ⊑R-trans.
------------------------------------------------------------------

attenuation-monotonicity
  : forall {Req} {t t' : Tm Req} {A} {c : Cap} {res' : Restriction Req}
  -> empty |- t ! A
  -> t ==>* t'
  -> Auth c res' t'
  -> Narrowed c res' t
attenuation-monotonicity d done* h = narrowed _ h (⊑R-refl _)
attenuation-monotonicity d (step* s rest) h
  with attenuation-monotonicity (preservation d s) rest h
... | narrowed res occ le with attenuation-soundness d s occ
...   | narrowed res0 occ0 le0 = narrowed res0 occ0 (⊑R-trans le le0)

------------------------------------------------------------------
-- Corollary, in the vocabulary a security reader wants: if any
-- capability reachable from a well-typed program permits a
-- request, then some capability in the SOURCE already permitted
-- that same request. Reduction cannot manufacture reach.
------------------------------------------------------------------

data Permits {Req : Set} (c : Cap) (x : Req) (t : Tm Req) : Set where
  permits : (res : Restriction Req)
          -> Auth c res t
          -> res x == true
          -> Permits c x t

authority-bounded
  : forall {Req} {t t' : Tm Req} {A} {c : Cap} {res' : Restriction Req}
  -> empty |- t ! A
  -> t ==>* t'
  -> Auth c res' t'
  -> (x : Req)
  -> res' x == true
  -> Permits c x t
authority-bounded d r h x hx with attenuation-monotonicity d r h
... | narrowed res occ le = permits res occ (le x hx)

------------------------------------------------------------------
-- PART 5: non-degeneracy.
--
-- Everything above would also hold if `restrict` were the
-- identity, because "narrower or equal" is satisfied by "equal".
-- These witnesses rule that reading out. They instantiate the
-- abstract scope set at Nat and take the restriction "the request
-- is zero", which is as small a concrete attenuation as it is
-- possible to write.
--
-- Read them as: the SAME request, on the SAME capability class,
-- answered `true` before attenuation and `false` after it.
------------------------------------------------------------------

isZero : Nat -> Bool
isZero zero    = true
isZero (suc _) = false

one : Nat
one = suc zero

-- An unattenuated Net capability permits request 1.
unattenuated-permits : use Net one (cap Net unrestricted) ==>* bool true
unattenuated-permits = step* R-Use done*

-- Attenuating it by `isZero` and then making the SAME request
-- gets `false`. Two steps: E-Attn under the `use`, then E-Invoke.
attenuated-denies : use Net one (restrict Net isZero (cap Net unrestricted))
                    ==>* bool false
attenuated-denies = step* (R-UseStep R-Restrict) (step* R-Use done*)

-- Attenuation is NOT the identity on restrictions: the source and
-- the attenuated restriction are not even pointwise equal.
attn-not-identity : (unrestricted {Nat} ≈R (unrestricted {Nat} ∩R isZero)) -> Empty
attn-not-identity eq = true-not-false (eq one)

-- The containment `⊑R` proved above is therefore STRICT here: the
-- attenuated restriction is below the original and the original is
-- not below it.
attn-strict : ((unrestricted {Nat}) ⊑R (unrestricted {Nat} ∩R isZero)) -> Empty
attn-strict le = false-not-true (le one refl)

-- Fail-closed: a capability carrying the bottom restriction denies
-- every request. This is what the runtime produces from a
-- restriction spec that does not parse.
denyAll-denies : forall {Req} (c : Cap) (x : Req)
               -> use c x (cap c denyAll) ==> bool false
denyAll-denies c x = R-Use

-- And no later attenuation can undo it, not even by the top
-- element: `denyAll ∩R p` is still `denyAll`.
denyAll-is-final : forall {Req} (p : Restriction Req)
                 -> (denyAll ∩R p) ≈R denyAll
denyAll-is-final p = ∩R-denyAll-l p

------------------------------------------------------------------
-- That is the attenuation development. `attn-is-meet`,
-- `attn-narrows` and `attn-use-never-widens` cover one step;
-- `attn-tower`, `tower-narrows` and `tower-is-one-meet` cover
-- chains; `attenuation-soundness`, `attenuation-monotonicity` and
-- `authority-bounded` cover arbitrary reduction of any well-typed
-- program; Part 5 shows none of it is vacuous. No postulates.
------------------------------------------------------------------
