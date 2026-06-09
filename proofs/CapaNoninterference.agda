{-# OPTIONS --safe #-}
------------------------------------------------------------------
-- CapaNoninterference.agda
--
-- Machine-checked termination-insensitive noninterference for the
-- lambda_if information-flow calculus of docs/semantics.md
-- Section 9 (the Volpano-Smith / Sabelfeld-Myers theorem for
-- Capa's two-point lattice under the @strict_ifc regime).
--
-- Mechanises, with NO postulates and NO holes on the key results:
--   * Lemma 1  (expression label soundness)        : lemma1
--   * Lemma 2  (confinement / high-pc)             : confinement
--   * Theorem 3 (declassify-free noninterference)  : noninterference
--
-- Theorem 4 (delimited release for declassify) is NOT mechanised
-- in this pass. It is left as a clearly-marked future item with a
-- precise statement below; it is NOT postulated. See the closing
-- comment and proofs/README.md for the honest status.
--
-- STATUS: Typechecks on Agda >= 2.6.4 (developed and checked
-- locally on Agda 2.7.0.1; CI pins 2.6.4.3). Verified in CI (see
-- .github/workflows/agda.yml).
--
-- Proof technique (faithful to Section 9.7): the textbook
-- two-lemma structure. Lemma 1 is induction on the expression
-- labelling derivation; Lemma 2 is induction on the big-step
-- evaluation derivation inverting the SECRET-pc typing; Theorem 3
-- is induction on the FIRST run's evaluation derivation, run in
-- lock-step with the second run, splitting each guard on whether
-- pc join (guard label) is PUBLIC (low, use Lemma 1 to force the
-- same control-flow choice) or SECRET (high, use Lemma 2 to
-- confine both arms). Two supporting lemmas the paper proof uses
-- implicitly are made explicit: `mono-secret` (a statement typed
-- under SECRET pc never lowers a label to PUBLIC) and
-- `while-high-conf` (a SECRET-guarded loop emits nothing and
-- touches no PUBLIC variable), both proved here without holes.
------------------------------------------------------------------

module CapaNoninterference where

open import CapaIF

------------------------------------------------------------------
-- Products and sums (self-contained, no agda-stdlib).
------------------------------------------------------------------

record _×_ (A B : Set) : Set where
  constructor _,_
  field
    fst : A
    snd : B

open _×_ public

infixr 2 _×_

------------------------------------------------------------------
-- Low-equivalence of stores at a label environment (Section 9.6).
-- Two stores agree on every PUBLIC-labelled variable. With total
-- stores (deviation D1 in CapaIF.agda) the "x in dom" side
-- condition of the paper definition disappears.
------------------------------------------------------------------

LowEq : Env -> Store -> Store -> Set
LowEq g s1 s2 = (x : Var) -> g x == PUBLIC -> s1 x == s2 x

------------------------------------------------------------------
-- Lemma 1 (Expression label soundness, Section 9.7).
--
-- If e is declassify-free, labelled PUBLIC under g, and the two
-- stores are low-equivalent at g, then e evaluates to the same
-- value in both runs -- EVEN THOUGH the two runs may use different
-- ambient secrets kappa1, kappa2, because a PUBLIC declassify-free
-- expression cannot mention env-get (that would force label
-- SECRET).
--
-- The derivation is taken at an arbitrary label l together with a
-- proof l == PUBLIC, which lets the L-Op case decompose the join
-- and the L-Env case be discharged as absurd (SECRET != PUBLIC).
-- L-Declassify is impossible under the DFExpr hypothesis.
--
-- Induction on the labelling derivation. No holes, no postulates.
------------------------------------------------------------------

lemma1 : forall {g e l k1 k2 s1 s2}
       -> g |-e e ~> l
       -> DFExpr e
       -> l == PUBLIC
       -> LowEq g s1 s2
       -> eval k1 s1 e == eval k2 s2 e
lemma1 L-Lit df-lit p leq = refl
lemma1 (L-Var {x = x}) df-evar p leq = leq x p
lemma1 (L-Op d1 d2) (df-op f1 f2) p leq
  = cong2 _+N_
      (lemma1 d1 f1 (join-public-l p) leq)
      (lemma1 d2 f2 (join-public-r p) leq)
lemma1 L-Env df-env ()
-- L-Declassify cannot occur: DFExpr has no constructor for a
-- declassify term, so the DFExpr argument is uninhabited here.
lemma1 (L-Declassify _) () _ _

------------------------------------------------------------------
-- SECRET-pc monotonicity. A statement typed under a SECRET
-- program-counter never produces a PUBLIC label that was not
-- already PUBLIC on entry. (Under SECRET pc every assignment sets
-- the target to SECRET, so labels can only stay or rise; no rule
-- manufactures a fresh PUBLIC.) This is the fact the paper's
-- confinement and the high cases of Theorem 3 use silently when
-- they say "a variable PUBLIC in the output env was PUBLIC on
-- entry".
--
-- Induction on the typing derivation. T-Sink under SECRET pc is
-- impossible (it would need SECRET flows PUBLIC), discharged via
-- the flows relation.
------------------------------------------------------------------

-- Helper: an update that stores a SECRET-valued label cannot make
-- a variable PUBLIC. The var-eq case split is kept INSIDE this
-- lemma, where the env-update reduces, so the caller never gets a
-- stuck `(g [ a :> v ]) x` redex.
update-secret-pub : forall (g : Env) (a x : Var) (v : L)
                  -> v == SECRET
                  -> (g [ a :> v ]) x == PUBLIC
                  -> g x == PUBLIC
update-secret-pub g a x v vsec h with var-eq a x
... | yes _ = absurd (sec-not-pub (trans (sym vsec) h))
  where sec-not-pub : SECRET == PUBLIC -> Empty
        sec-not-pub ()
... | no  _ = h

mono-secret : forall {g g' s}
            -> SECRET , g |-s s ~> g'
            -> (x : Var) -> g' x == PUBLIC -> g x == PUBLIC
mono-secret T-Skip x px = px
mono-secret {g = g} (T-Assign {x = a} {l = l} _) x px
  = update-secret-pub g a x (l join SECRET) (join-secret-r l) px
mono-secret (T-Seq d1 d2) x px = mono-secret d1 x (mono-secret d2 x px)
-- branches typed at SECRET join l, which reduces to SECRET; the
-- output env is g1 envjoin g2, so g'(x) = g1 x join g2 x = PUBLIC
-- forces g1 x = PUBLIC, and mono-secret on the first branch closes it
mono-secret (T-If _ d1 _) x px = mono-secret d1 x (join-public-l px)
mono-secret (T-While _ _) x px = px
mono-secret (T-Sink {l = l} _ fl) x px
  = absurd (secret-flows-public (transport-flows (join-secret-r l) fl))
  where transport-flows : forall {a b} -> a == SECRET -> a flows b -> SECRET flows b
        transport-flows refl h = h
        secret-flows-public : SECRET flows PUBLIC -> Empty
        secret-flows-public ()

------------------------------------------------------------------
-- Helper: if storing a SECRET-valued label at a left a variable
-- PUBLIC, then that variable is not a (so the parallel store
-- update did not touch its value). Returns the disequality, kept
-- with the var-eq split internal so the env-update reduces.
------------------------------------------------------------------

secret-pub-neq : forall (g : Env) (a x : Var) (v : L)
               -> v == SECRET
               -> (g [ a :> v ]) x == PUBLIC
               -> a == x -> Empty
secret-pub-neq g a x v vsec h with var-eq a x
... | yes _ = \ _ -> sec-not-pub (trans (sym vsec) h)
  where sec-not-pub : SECRET == PUBLIC -> Empty
        sec-not-pub ()
... | no  q = q

------------------------------------------------------------------
-- Lemma 2 (Confinement / high-pc, Section 9.7).
--
-- A statement typed under a SECRET program-counter, when it
-- terminates, (i) emits the empty trace and (ii) leaves every
-- variable that is PUBLIC in its OUTPUT environment with its store
-- value unchanged.
--
-- Induction on the big-step evaluation derivation, inverting the
-- SECRET-pc typing at each step. The sink case is vacuous (T-Sink
-- cannot be typed under SECRET pc); the assign case uses that the
-- assigned label becomes SECRET, so a PUBLIC-output variable is
-- never the assigned one; seq / if / while compose the IH,
-- pulling PUBLIC-ness of an output variable back through
-- mono-secret where the paper says "still PUBLIC in the earlier
-- environment". No holes, no postulates.
------------------------------------------------------------------

confinement : forall {k g g' s sigma sigma' o}
            -> SECRET , g |-s s ~> g'
            -> k , s , sigma => sigma' , o
            -> (o == []) × ((x : Var) -> g' x == PUBLIC -> sigma' x == sigma x)
confinement T-Skip E-Skip = refl , \ x px -> refl
confinement {sigma = sigma} (T-Assign {x = a} {l = l} _) E-Assign
  = refl , conf
  where
    conf : (x : Var) -> _ -> _
    conf x px = update-miss sigma a x _
                  (secret-pub-neq _ a x (l join SECRET) (join-secret-r l) px)
confinement (T-Seq d1 d2) (E-Seq e1 e2)
  with confinement d1 e1 | confinement d2 e2
... | (o1eq , c1) | (o2eq , c2)
  = trans (cong2 _++_ o1eq o2eq) refl
  , \ x px -> trans (c2 x px) (c1 x (mono-secret d2 x px))
confinement (T-If _ d1 _) (E-IfT _ e1)
  with confinement d1 e1
... | (o1eq , c1) = o1eq , \ x px -> c1 x (join-public-l px)
confinement (T-If _ _ d2) (E-IfF _ e2)
  with confinement d2 e2
... | (o2eq , c2) = o2eq , \ x px -> c2 x (join-public-r px)
confinement (T-While _ _) (E-WhileF _) = refl , \ x px -> refl
confinement (T-While de db) (E-WhileT _ ebody ewhile)
  with confinement db ebody | confinement (T-While de db) ewhile
... | (o1eq , c1) | (o2eq , c2)
  = trans (cong2 _++_ o1eq o2eq) refl
  , \ x px -> trans (c2 x px) (c1 x px)
confinement (T-Sink {l = l} _ fl) E-Sink
  = absurd (secret-flows-public (transport-flows (join-secret-r l) fl))
  where transport-flows : forall {a b} -> a == SECRET -> a flows b -> SECRET flows b
        transport-flows refl h = h
        secret-flows-public : SECRET flows PUBLIC -> Empty
        secret-flows-public ()

------------------------------------------------------------------
-- High-while confinement. A while loop whose body is typed under
-- SECRET pc with the loop's fixpoint environment g as both entry
-- and exit, when it terminates, emits the empty trace and leaves
-- every g-PUBLIC variable unchanged -- regardless of how many
-- times it iterates. This is exactly the per-iteration argument
-- the paper makes for the SECRET-guarded loop case of Theorem 3.
--
-- Note: the whole `swhile e b` is typed at the OUTER pc (which may
-- be PUBLIC) in Theorem 3; only the BODY is at SECRET. So we
-- cannot reuse `confinement` on the whole loop; we induct on the
-- while evaluation derivation, applying `confinement` to each body
-- run. No holes, no postulates.
------------------------------------------------------------------

while-high-conf : forall {k g e b sigma sigma' o}
                -> SECRET , g |-s b ~> g
                -> k , swhile e b , sigma => sigma' , o
                -> (o == []) × ((x : Var) -> g x == PUBLIC -> sigma' x == sigma x)
while-high-conf db (E-WhileF _) = refl , \ x px -> refl
while-high-conf db (E-WhileT _ ebody ewhile)
  with confinement db ebody | while-high-conf db ewhile
... | (o1eq , c1) | (o2eq , c2)
  = trans (cong2 _++_ o1eq o2eq) refl
  , \ x px -> trans (c2 x px) (c1 x px)

------------------------------------------------------------------
-- General transport (subst) and the pc-transport for typing
-- derivations. In the SECRET-guarded if / while cases the branch
-- / body is typed at `pc join l` which equals SECRET (by
-- join-secret-r) but not definitionally when pc is a variable, so
-- we move the derivation across that equality.
------------------------------------------------------------------

subst-eq : forall {A : Set} (P : A -> Set) {x y : A} -> x == y -> P x -> P y
subst-eq P refl px = px

retype-pc : forall {pc pc' g s g'}
          -> pc == pc'
          -> pc  , g |-s s ~> g'
          -> pc' , g |-s s ~> g'
retype-pc {g = g} {s = s} {g' = g'} eq d
  = subst-eq (\ p -> p , g |-s s ~> g') eq d

------------------------------------------------------------------
-- Trace value mismatch is impossible across guards: zero and
-- suc v cannot be equal. Used to rule out the cross-branch /
-- cross-iteration eval-derivation pairings in the low cases,
-- where Lemma 1 forces the two guards to evaluate identically.
------------------------------------------------------------------

zero-not-suc : forall {v} -> zero == suc v -> Empty
zero-not-suc ()

------------------------------------------------------------------
-- Theorem 3 (Noninterference, declassify-free fragment,
-- Section 9.6 / 9.7).
--
-- For a well-typed declassify-free statement s with
-- PUBLIC |- Gamma_0 { s } Gamma', any two low-equivalent initial
-- stores, and ANY two ambient secret values, if both runs
-- converge then the final stores are low-equivalent at Gamma' and
-- the public output traces are identical.
--
-- We prove the generalised statement over an arbitrary pc and
-- entry environment g (the theorem is the pc = PUBLIC, g = Gamma_0
-- instance). Induction is on the FIRST run's evaluation
-- derivation, run in lock-step with the second; the guard cases
-- split on the guard label l:
--   * l = PUBLIC (low): Lemma 1 forces both runs down the SAME
--     control-flow path; recurse with the IH and lift
--     low-equivalence through the branch-merge / loop fixpoint.
--   * l = SECRET (high): the branch / body is typed under SECRET
--     pc; Lemma 2 (confinement) / while-high-conf confine both
--     runs to the empty trace and to no PUBLIC-variable change.
-- No holes, no postulates on this result.
------------------------------------------------------------------

noninterference
  : forall {pc g g' s k1 k2 sigma1 sigma2 sigma1' sigma2' o1 o2}
  -> DFStmt s
  -> pc , g |-s s ~> g'
  -> k1 , s , sigma1 => sigma1' , o1
  -> k2 , s , sigma2 => sigma2' , o2
  -> LowEq g sigma1 sigma2
  -> LowEq g' sigma1' sigma2' × (o1 == o2)

-- skip
noninterference df-skip T-Skip E-Skip E-Skip leq = leq , refl

-- assignment
noninterference {pc = pc} {k1 = k1} {k2 = k2} {sigma1 = s1} {sigma2 = s2}
  (df-assign dfe) (T-Assign {x = a} {e = e} {l = l} de) E-Assign E-Assign leq
  = leqOut , refl
  where
    leqOut : LowEq _ _ _
    leqOut y py with var-eq a y
    -- y == a: g'(a) = l join pc = PUBLIC forces l = PUBLIC and
    -- pc = PUBLIC; Lemma 1 makes the assigned values agree
    ... | yes refl =
      let lpub : l == PUBLIC
          lpub = join-public-l (trans (sym (env-hit _ a (l join pc))) py)
      in trans (update-hit s1 a (eval k1 s1 e))
           (trans (lemma1 de dfe lpub leq)
                  (sym (update-hit s2 a (eval k2 s2 e))))
    -- y /= a: value untouched in both runs; agree by hypothesis
    ... | no q =
      let gy : _ == PUBLIC
          gy = trans (sym (env-miss _ a y (l join pc) q)) py
      in trans (update-miss s1 a y (eval k1 s1 e) q)
           (trans (leq y gy) (sym (update-miss s2 a y (eval k2 s2 e) q)))

-- sequencing
noninterference (df-seq df1 df2) (T-Seq d1 d2) (E-Seq e1a e1b) (E-Seq e2a e2b) leq
  with noninterference df1 d1 e1a e2a leq
... | (leq1 , oeq1) with noninterference df2 d2 e1b e2b leq1
...   | (leq2 , oeq2) = leq2 , cong2 _++_ oeq1 oeq2

-- conditional, low guard (l = PUBLIC): same branch in both runs
noninterference (df-if {e = e} dfe df1 df2)
  (T-If {l = PUBLIC} de d1 d2) (E-IfT ev1 b1) (E-IfT ev2 b2) leq
  with noninterference df1 d1 b1 b2 leq
... | (leqB , oeqB) = liftMerge leqB , oeqB
  where liftMerge : LowEq _ _ _ -> LowEq _ _ _
        liftMerge lb y py = lb y (join-public-l py)
noninterference (df-if {e = e} dfe df1 df2)
  (T-If {l = PUBLIC} de d1 d2) (E-IfF ev1 b1) (E-IfF ev2 b2) leq
  with noninterference df2 d2 b1 b2 leq
... | (leqB , oeqB) = liftMerge leqB , oeqB
  where liftMerge : LowEq _ _ _ -> LowEq _ _ _
        liftMerge lb y py = lb y (join-public-r py)
-- the cross cases (the two runs take different branches) are ruled
-- out: Lemma 1 forces equal guard evaluation, so zero = suc v
noninterference (df-if dfe df1 df2)
  (T-If {l = PUBLIC} de d1 d2) (E-IfT ev1 b1) (E-IfF ev2 b2) leq
  = absurd (zero-not-suc (trans (sym ev2) (trans (sym (lemma1 de dfe refl leq)) ev1)))
noninterference (df-if dfe df1 df2)
  (T-If {l = PUBLIC} de d1 d2) (E-IfF ev1 b1) (E-IfT ev2 b2) leq
  = absurd (zero-not-suc (trans (sym ev1) (trans (lemma1 de dfe refl leq) ev2)))

-- conditional, high guard (l = SECRET): the two runs may take
-- different branches, but each branch is typed under SECRET pc, so
-- confinement confines both. Four clauses for the four branch
-- pairings. The merged output env g1 envjoin g2 is PUBLIC at y
-- only if both g1 y and g2 y are PUBLIC (join-public-l / -r),
-- which feeds confinement on whichever branch each run took;
-- g(y) = PUBLIC comes via mono-secret on a branch output.
noninterference (df-if dfe df1 df2)
  (T-If {pc = pc} {l = SECRET} de d1 d2) (E-IfT _ b1) (E-IfT _ b2) leq
  = (\ y py -> let g1p = join-public-l py
               in trans (snd c1 y g1p) (trans (leq y (mono-secret dd1 y g1p)) (sym (snd c2 y g1p))))
  , trans (fst c1) (sym (fst c2))
  where dd1 = retype-pc (join-secret-r pc) d1
        c1 = confinement dd1 b1
        c2 = confinement dd1 b2
noninterference (df-if dfe df1 df2)
  (T-If {pc = pc} {l = SECRET} de d1 d2) (E-IfT _ b1) (E-IfF _ b2) leq
  = (\ y py -> let g1p = join-public-l py ; g2p = join-public-r py
               in trans (snd c1 y g1p) (trans (leq y (mono-secret dd1 y g1p)) (sym (snd c2 y g2p))))
  , trans (fst c1) (sym (fst c2))
  where dd1 = retype-pc (join-secret-r pc) d1
        dd2 = retype-pc (join-secret-r pc) d2
        c1 = confinement dd1 b1
        c2 = confinement dd2 b2
noninterference (df-if dfe df1 df2)
  (T-If {pc = pc} {l = SECRET} de d1 d2) (E-IfF _ b1) (E-IfT _ b2) leq
  = (\ y py -> let g1p = join-public-l py ; g2p = join-public-r py
               in trans (snd c1 y g2p) (trans (leq y (mono-secret dd2 y g2p)) (sym (snd c2 y g1p))))
  , trans (fst c1) (sym (fst c2))
  where dd1 = retype-pc (join-secret-r pc) d1
        dd2 = retype-pc (join-secret-r pc) d2
        c1 = confinement dd2 b1
        c2 = confinement dd1 b2
noninterference (df-if dfe df1 df2)
  (T-If {pc = pc} {l = SECRET} de d1 d2) (E-IfF _ b1) (E-IfF _ b2) leq
  = (\ y py -> let g2p = join-public-r py
               in trans (snd c1 y g2p) (trans (leq y (mono-secret dd2 y g2p)) (sym (snd c2 y g2p))))
  , trans (fst c1) (sym (fst c2))
  where dd2 = retype-pc (join-secret-r pc) d2
        c1 = confinement dd2 b1
        c2 = confinement dd2 b2

-- while, low guard (l = PUBLIC): lock-step iteration
noninterference (df-while {e = e} dfe dfb)
  (T-While {l = PUBLIC} de db) (E-WhileF ev1) (E-WhileF ev2) leq
  = leq , refl
noninterference (df-while dfe dfb)
  (T-While {l = PUBLIC} de db) (E-WhileT ev1 body1 rest1) (E-WhileT ev2 body2 rest2) leq
  with noninterference dfb db body1 body2 leq
... | (leqBody , oeqBody)
  with noninterference (df-while dfe dfb) (T-While de db) rest1 rest2 leqBody
... | (leqRest , oeqRest) = leqRest , cong2 _++_ oeqBody oeqRest
-- mismatched iteration counts are ruled out by Lemma 1
noninterference (df-while dfe dfb)
  (T-While {l = PUBLIC} de db) (E-WhileF ev1) (E-WhileT ev2 _ _) leq
  = absurd (zero-not-suc (trans (sym ev1) (trans (lemma1 de dfe refl leq) ev2)))
noninterference (df-while dfe dfb)
  (T-While {l = PUBLIC} de db) (E-WhileT ev1 _ _) (E-WhileF ev2) leq
  = absurd (zero-not-suc (trans (sym ev2) (trans (sym (lemma1 de dfe refl leq)) ev1)))

-- while, high guard (l = SECRET): confine both loops
noninterference (df-while dfe dfb)
  (T-While {pc = pc} {l = SECRET} de db) ev1 ev2 leq
  = leqOut , trans (fst conf1) (sym (fst conf2))
  where
    dbS : SECRET , _ |-s _ ~> _
    dbS = retype-pc (join-secret-r pc) db
    conf1 = while-high-conf dbS ev1
    conf2 = while-high-conf dbS ev2
    leqOut : LowEq _ _ _
    leqOut y py =
      trans (snd conf1 y py) (trans (leq y py) (sym (snd conf2 y py)))

-- sink
noninterference {k1 = k1} {k2 = k2} {sigma1 = s1} {sigma2 = s2}
  (df-sink dfe) (T-Sink {e = e} {l = l} de fl) E-Sink E-Sink leq
  = leq , cong (\ v -> v :: []) valeq
  where
    lpub : l == PUBLIC
    lpub = join-public-l (flows-public-is-public fl)
    valeq : eval k1 s1 e == eval k2 s2 e
    valeq = lemma1 de dfe lpub leq

------------------------------------------------------------------
-- Theorem 4 (Relaxed noninterference / delimited release,
-- Section 9.7.1): STATUS = NOT MECHANISED in this pass.
--
-- This is an HONEST gap, NOT a postulate. There is deliberately no
-- Agda term for Theorem 4 below: faking it with a `postulate`
-- would defeat the purpose of a machine-checked artefact, and the
-- module is checked under --safe precisely so that no such cheat
-- can sneak in.
--
-- The precise statement it WOULD have, transcribing Section 9.7.1,
-- is recorded here as a comment so a future contributor has the
-- exact obligation:
--
--   Let D(s) be the multiset of sub-expressions sitting directly
--   inside declassify(.) positions of s, and let [| D(s) |]_sigma^k
--   be the tuple of values they evaluate to in a given run. Then
--   for s well-typed with PUBLIC , Gamma_0 |-s s ~> Gamma', for
--   low-equivalent sigma1 ~[Gamma_0] sigma2 with ambient secrets
--   k1, k2, IF both runs converge AND the two runs agree on every
--   declassified value, i.e. [| D(s) |]_{sigma1}^{k1} ==
--   [| D(s) |]_{sigma2}^{k2}, then sigma1' ~[Gamma'] sigma2' and
--   o1 == o2.
--
-- The paper proof (Section 9.7.1) is "identical to Theorem 3 with
-- one extra Lemma-1 case for L-Declassify, discharged directly by
-- the agreement hypothesis". The mechanisation work it needs that
-- this pass does not do:
--   1. drop the DFExpr / DFStmt restriction from the inputs of
--      lemma1 and noninterference (re-admitting declassify);
--   2. define the released-values tuple [| D(s) |] as a function
--      of (s, k, sigma) and thread the run-agreement hypothesis
--      through the L-Declassify case of lemma1 and the assign /
--      sink cases of noninterference;
--   3. handle that, under declassify, a sub-expression's run-to-run
--      agreement is an ASSUMPTION rather than a consequence, so the
--      generalised induction's invariant must carry the agreement
--      witness for the declassified positions reached so far.
--
-- Step 2's bookkeeping (a faithful [| D(s) |] over the big-step
-- relation, aligned across two runs that may take different
-- control-flow paths) is the bulk of the work and is left for a
-- follow-up. Theorem 3 above is fully mechanised and checked under
-- --safe; Theorem 4 is future work, tracked in proofs/README.md.
------------------------------------------------------------------

