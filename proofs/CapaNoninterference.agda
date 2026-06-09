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
--   * Lemma 1 with declassify                      : lemma1-decl
--   * Theorem 4 (delimited release / relaxed       : theorem4
--                noninterference for declassify)
--
-- Theorem 4 is the delimited-release statement of Section 9.7.1:
-- declassify is re-admitted (no declassify-free restriction), and
-- the conclusion holds modulo an agreement hypothesis on the
-- declassified values (see `Agree` / `EAgree` in CapaIF.agda and
-- the encoding note at the foot of this file). It is a real proof,
-- not a postulate; the module is checked under --safe.
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
-- The non-dependent product `_×_` (with fst / snd) is defined in
-- CapaIF.agda and re-exported here via `open import CapaIF`.
------------------------------------------------------------------

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
-- Section 9.7.1): MECHANISED below, with NO postulates and NO
-- holes, checked under --safe.
--
-- Encoding of the agreement hypothesis (deviation D3, documented
-- in proofs/README.md and docs/semantics.md Section 9.7.1). The
-- paper writes the hypothesis as `[| D(s) |]_{s1}^{k1} ==
-- [| D(s) |]_{s2}^{k2}`, equality of the multiset/tuple of
-- declassified values. We use the per-position structural form
-- `EAgree` on expressions and `Agree` on the two big-step
-- derivations (both in CapaIF.agda):
--
--   * `EAgree k1 s1 k2 s2 e` -- the two runs agree on every
--     declassified value inside expression `e`. We prove it is
--     EQUIVALENT to equality of the expression release logs
--     `releases k1 s1 e == releases k2 s2 e` (`eagree->releq` and
--     `releq->eagree` below), so adopting it does not weaken the
--     hypothesis: it IS release-log equality, phrased so the
--     L-Op / L-Declassify cases decompose without list-append
--     surgery.
--
--   * `Agree d1 d2` -- the run-level form, threaded along the two
--     ACTUAL execution paths. This is the faithful operational
--     reading of `[| D(s) |]` evaluated at the stores each
--     declassify is really reached in. Where the two runs diverge
--     (a SECRET guard) only the guard releases must agree; the
--     divergent declassifies are confined by Lemma 2, exactly as
--     in the paper proof, so demanding cross-run agreement on them
--     would be spurious. This is why Theorem 4 does NOT collapse
--     into Theorem 3: the hypothesis is a real, non-vacuous
--     condition on the low-context declassifies.
--
-- The proof is "Theorem 3 plus one Lemma-1 case for L-Declassify,
-- discharged by the agreement hypothesis" (Section 9.7.1), with
-- the run-level agreement supplying the per-site witnesses.
------------------------------------------------------------------

------------------------------------------------------------------
-- Release-log machinery: `EAgree` is equivalent to equality of
-- the expression release logs. This justifies calling `EAgree`
-- "the two release logs agree".
------------------------------------------------------------------

-- length of a trace, and the syntactic declassify-node count of an
-- expression. The release-log length is store-independent: it is
-- exactly the number of declassify nodes (`releases-length`),
-- which is what lets equal release logs be split at op nodes.

len : Trace -> Nat
len []        = zero
len (_ :: xs) = suc (len xs)

dcount : Expr -> Nat
dcount (lit n)        = zero
dcount (evar x)       = zero
dcount (op a b)       = dcount a +N dcount b
dcount env-get        = zero
dcount (declassify e) = suc (dcount e)

len-++ : forall (xs ys : Trace) -> len (xs ++ ys) == (len xs +N len ys)
len-++ []        ys = refl
len-++ (x :: xs) ys = cong suc (len-++ xs ys)

releases-length : forall (k : Nat) (s : Store) (e : Expr)
                -> len (releases k s e) == dcount e
releases-length k s (lit n)        = refl
releases-length k s (evar x)       = refl
releases-length k s (op a b)
  = trans (len-++ (releases k s a) (releases k s b))
          (cong2 _+N_ (releases-length k s a) (releases-length k s b))
releases-length k s env-get        = refl
releases-length k s (declassify e)
  = trans (len-++ (releases k s e) (eval k s e :: []))
          (trans (cong (\ n -> n +N suc zero) (releases-length k s e))
                 (n+1 (dcount e)))
  where
    n+1 : forall (n : Nat) -> (n +N suc zero) == suc n
    n+1 zero    = refl
    n+1 (suc m) = cong suc (n+1 m)

-- cons injectivity for traces.
cons-head : forall {a b : Nat} {as bs} -> (a :: as) == (b :: bs) -> a == b
cons-head refl = refl

cons-tail : forall {a b : Nat} {as bs} -> (a :: as) == (b :: bs) -> as == bs
cons-tail refl = refl

-- append cancellation when the two prefixes have equal length.
++-cancel : forall (xs1 xs2 ys1 ys2 : Trace)
          -> len xs1 == len xs2
          -> (xs1 ++ ys1) == (xs2 ++ ys2)
          -> (xs1 == xs2) × (ys1 == ys2)
++-cancel [] [] ys1 ys2 _ eq = refl , eq
++-cancel [] (x2 :: xs2) ys1 ys2 () _
++-cancel (x1 :: xs1) [] ys1 ys2 () _
++-cancel (x1 :: xs1) (x2 :: xs2) ys1 ys2 leq eq
  with ++-cancel xs1 xs2 ys1 ys2 (suc-inj leq) (cons-tail eq)
... | (ts , us) = cong2 _::_ (cons-head eq) ts , us

-- forward: EAgree implies the release logs are equal.
eagree->releq : forall {k1 s1 k2 s2 e}
              -> EAgree k1 s1 k2 s2 e
              -> releases k1 s1 e == releases k2 s2 e
eagree->releq ea-lit = refl
eagree->releq ea-var = refl
eagree->releq (ea-op a b) = cong2 _++_ (eagree->releq a) (eagree->releq b)
eagree->releq ea-env = refl
eagree->releq {k1 = k1} {s1 = s1} {k2 = k2} {s2 = s2} (ea-decl {e = e} a veq)
  = cong2 _++_ (eagree->releq a) (cong (\ v -> v :: []) veq)

-- backward: equal release logs imply EAgree. Uses releases-length
-- to split the op case and the declassify case. This closes the
-- equivalence, so EAgree IS release-log equality.
releq->eagree : forall {k1 s1 k2 s2} (e : Expr)
              -> releases k1 s1 e == releases k2 s2 e
              -> EAgree k1 s1 k2 s2 e
releq->eagree (lit n)  eq = ea-lit
releq->eagree (evar x) eq = ea-var
releq->eagree {k1 = k1} {s1 = s1} {k2 = k2} {s2 = s2} (op a b) eq
  with ++-cancel (releases k1 s1 a) (releases k2 s2 a)
                 (releases k1 s1 b) (releases k2 s2 b)
                 (trans (releases-length k1 s1 a) (sym (releases-length k2 s2 a)))
                 eq
... | aeq , beq = ea-op (releq->eagree a aeq) (releq->eagree b beq)
releq->eagree env-get  eq = ea-env
releq->eagree {k1 = k1} {s1 = s1} {k2 = k2} {s2 = s2} (declassify e) eq
  with ++-cancel (releases k1 s1 e) (releases k2 s2 e)
                 (eval k1 s1 e :: []) (eval k2 s2 e :: [])
                 (trans (releases-length k1 s1 e) (sym (releases-length k2 s2 e)))
                 eq
... | eeq , veq = ea-decl (releq->eagree e eeq) (cons-head veq)

------------------------------------------------------------------
-- Lemma 1 with declassify (Section 9.7.1).
--
-- Like `lemma1`, but admitting `declassify`: a PUBLIC-labelled
-- expression evaluates equally in two low-equivalent runs PROVIDED
-- the two runs agree on its declassified values (`EAgree`). The
-- only new case beyond `lemma1` is L-Declassify, discharged
-- directly by the `ea-decl` agreement witness -- exactly the
-- paper's one-line extra case. No DFExpr restriction. No holes.
------------------------------------------------------------------

lemma1-decl : forall {g e l k1 k2 s1 s2}
            -> g |-e e ~> l
            -> l == PUBLIC
            -> LowEq g s1 s2
            -> EAgree k1 s1 k2 s2 e
            -> eval k1 s1 e == eval k2 s2 e
lemma1-decl L-Lit p leq ea-lit = refl
lemma1-decl (L-Var {x = x}) p leq ea-var = leq x p
lemma1-decl (L-Op d1 d2) p leq (ea-op a1 a2)
  = cong2 _+N_
      (lemma1-decl d1 (join-public-l p) leq a1)
      (lemma1-decl d2 (join-public-r p) leq a2)
lemma1-decl L-Env () leq ea-env
-- declassify: eval (declassify e0) = eval e0, and the agreement
-- witness IS the equality of those two values across runs.
lemma1-decl (L-Declassify _) p leq (ea-decl _ veq) = veq

------------------------------------------------------------------
-- Theorem 4 (Relaxed noninterference / delimited release,
-- Section 9.7.1).
--
-- For a well-typed statement s (NO declassify-free restriction:
-- DFStmt is gone), two runs from low-equivalent stores that
-- additionally AGREE on every declassified value reached along
-- their execution paths (`Agree ev1 ev2`), the final stores are
-- low-equivalent at the final environment and the public output
-- traces are identical.
--
-- The proof mirrors `noninterference` (Theorem 3) clause for
-- clause; the only changes are:
--   * the DFStmt argument and the DFExpr arguments are dropped;
--   * every appeal to `lemma1` becomes an appeal to `lemma1-decl`,
--     fed the per-site `EAgree` witness pulled out of `Agree`;
--   * the SECRET (high) cases are byte-for-byte the Theorem 3
--     argument: they use confinement only and never touch the
--     agreement, since declassifies under SECRET pc are confined.
-- No holes, no postulates on this result.
------------------------------------------------------------------

theorem4
  : forall {pc g g' s k1 k2 sigma1 sigma2 sigma1' sigma2' o1 o2}
  -> pc , g |-s s ~> g'
  -> (ev1 : k1 , s , sigma1 => sigma1' , o1)
  -> (ev2 : k2 , s , sigma2 => sigma2' , o2)
  -> LowEq g sigma1 sigma2
  -> Agree ev1 ev2
  -> LowEq g' sigma1' sigma2' × (o1 == o2)

-- skip
theorem4 T-Skip E-Skip E-Skip leq ag = leq , refl

-- assignment
theorem4 {pc = pc} {k1 = k1} {k2 = k2} {sigma1 = s1} {sigma2 = s2}
  (T-Assign {x = a} {e = e} {l = l} de) E-Assign E-Assign leq ag
  = leqOut , refl
  where
    leqOut : LowEq _ _ _
    leqOut y py with var-eq a y
    ... | yes refl =
      let lpub : l == PUBLIC
          lpub = join-public-l (trans (sym (env-hit _ a (l join pc))) py)
      in trans (update-hit s1 a (eval k1 s1 e))
           (trans (lemma1-decl de lpub leq ag)
                  (sym (update-hit s2 a (eval k2 s2 e))))
    ... | no q =
      let gy : _ == PUBLIC
          gy = trans (sym (env-miss _ a y (l join pc) q)) py
      in trans (update-miss s1 a y (eval k1 s1 e) q)
           (trans (leq y gy) (sym (update-miss s2 a y (eval k2 s2 e) q)))

-- sequencing
theorem4 (T-Seq d1 d2) (E-Seq e1a e1b) (E-Seq e2a e2b) leq ag
  with theorem4 d1 e1a e2a leq (fst ag)
... | (leq1 , oeq1) with theorem4 d2 e1b e2b leq1 (snd ag)
...   | (leq2 , oeq2) = leq2 , cong2 _++_ oeq1 oeq2

-- conditional, low guard (l = PUBLIC): same branch in both runs
theorem4 (T-If {l = PUBLIC} de d1 d2) (E-IfT ev1 b1) (E-IfT ev2 b2) leq ag
  with theorem4 d1 b1 b2 leq (snd ag)
... | (leqB , oeqB) = (\ y py -> leqB y (join-public-l py)) , oeqB
theorem4 (T-If {l = PUBLIC} de d1 d2) (E-IfF ev1 b1) (E-IfF ev2 b2) leq ag
  with theorem4 d2 b1 b2 leq (snd ag)
... | (leqB , oeqB) = (\ y py -> leqB y (join-public-r py)) , oeqB
-- cross cases ruled out: Lemma 1 (with declassify) forces equal
-- guard evaluation, using the guard's release agreement
theorem4 (T-If {l = PUBLIC} de d1 d2) (E-IfT ev1 b1) (E-IfF ev2 b2) leq ag
  = absurd (zero-not-suc (trans (sym ev2) (trans (sym (lemma1-decl de refl leq ag)) ev1)))
theorem4 (T-If {l = PUBLIC} de d1 d2) (E-IfF ev1 b1) (E-IfT ev2 b2) leq ag
  = absurd (zero-not-suc (trans (sym ev1) (trans (lemma1-decl de refl leq ag) ev2)))

-- conditional, high guard (l = SECRET): confinement, identical to
-- Theorem 3; the agreement is not consulted (declassifies under
-- SECRET pc are confined).
theorem4 (T-If {pc = pc} {l = SECRET} de d1 d2) (E-IfT _ b1) (E-IfT _ b2) leq ag
  = (\ y py -> let g1p = join-public-l py
               in trans (snd c1 y g1p) (trans (leq y (mono-secret dd1 y g1p)) (sym (snd c2 y g1p))))
  , trans (fst c1) (sym (fst c2))
  where dd1 = retype-pc (join-secret-r pc) d1
        c1 = confinement dd1 b1
        c2 = confinement dd1 b2
theorem4 (T-If {pc = pc} {l = SECRET} de d1 d2) (E-IfT _ b1) (E-IfF _ b2) leq ag
  = (\ y py -> let g1p = join-public-l py ; g2p = join-public-r py
               in trans (snd c1 y g1p) (trans (leq y (mono-secret dd1 y g1p)) (sym (snd c2 y g2p))))
  , trans (fst c1) (sym (fst c2))
  where dd1 = retype-pc (join-secret-r pc) d1
        dd2 = retype-pc (join-secret-r pc) d2
        c1 = confinement dd1 b1
        c2 = confinement dd2 b2
theorem4 (T-If {pc = pc} {l = SECRET} de d1 d2) (E-IfF _ b1) (E-IfT _ b2) leq ag
  = (\ y py -> let g1p = join-public-l py ; g2p = join-public-r py
               in trans (snd c1 y g2p) (trans (leq y (mono-secret dd2 y g2p)) (sym (snd c2 y g1p))))
  , trans (fst c1) (sym (fst c2))
  where dd1 = retype-pc (join-secret-r pc) d1
        dd2 = retype-pc (join-secret-r pc) d2
        c1 = confinement dd2 b1
        c2 = confinement dd1 b2
theorem4 (T-If {pc = pc} {l = SECRET} de d1 d2) (E-IfF _ b1) (E-IfF _ b2) leq ag
  = (\ y py -> let g2p = join-public-r py
               in trans (snd c1 y g2p) (trans (leq y (mono-secret dd2 y g2p)) (sym (snd c2 y g2p))))
  , trans (fst c1) (sym (fst c2))
  where dd2 = retype-pc (join-secret-r pc) d2
        c1 = confinement dd2 b1
        c2 = confinement dd2 b2

-- while, low guard (l = PUBLIC): lock-step iteration
theorem4 (T-While {l = PUBLIC} de db) (E-WhileF ev1) (E-WhileF ev2) leq ag
  = leq , refl
theorem4 (T-While {l = PUBLIC} de db)
  (E-WhileT ev1 body1 rest1) (E-WhileT ev2 body2 rest2) leq ag
  with theorem4 db body1 body2 leq (fst (snd ag))
... | (leqBody , oeqBody)
  with theorem4 (T-While de db) rest1 rest2 leqBody (snd (snd ag))
... | (leqRest , oeqRest) = leqRest , cong2 _++_ oeqBody oeqRest
-- mismatched iteration counts ruled out by Lemma 1 (with declassify)
theorem4 (T-While {l = PUBLIC} de db) (E-WhileF ev1) (E-WhileT ev2 _ _) leq ag
  = absurd (zero-not-suc (trans (sym ev1) (trans (lemma1-decl de refl leq ag) ev2)))
theorem4 (T-While {l = PUBLIC} de db) (E-WhileT ev1 _ _) (E-WhileF ev2) leq ag
  = absurd (zero-not-suc (trans (sym ev2) (trans (sym (lemma1-decl de refl leq ag)) ev1)))

-- while, high guard (l = SECRET): confine both loops (Theorem 3
-- argument verbatim; agreement not consulted)
theorem4 (T-While {pc = pc} {l = SECRET} de db) ev1 ev2 leq ag
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
theorem4 {k1 = k1} {k2 = k2} {sigma1 = s1} {sigma2 = s2}
  (T-Sink {e = e} {l = l} de fl) E-Sink E-Sink leq ag
  = leq , cong (\ v -> v :: []) valeq
  where
    lpub : l == PUBLIC
    lpub = join-public-l (flows-public-is-public fl)
    valeq : eval k1 s1 e == eval k2 s2 e
    valeq = lemma1-decl de lpub leq ag

------------------------------------------------------------------
-- Non-vacuity witness (Section 9.7.1).
--
-- A concrete declassify-and-sink program that is (a) well-typed,
-- (b) evaluable, (c) covered by Theorem 4, and (d) EXCLUDED from
-- Theorem 3 (it contains declassify, so no DFStmt holds for it).
--
-- The program is   sink(declassify(env-get))   under PUBLIC pc and
-- the all-PUBLIC environment. It declassifies the secret and sinks
-- it -- exactly the pattern Theorem 3 forbids. Theorem 4 covers it
-- and, crucially, its conclusion DEPENDS on the agreement
-- hypothesis: the sunk value is the declassified secret, so two
-- runs with DIFFERENT secrets produce DIFFERENT public output
-- unless they agree on the declassified value. The agreement
-- `EAgree k1 s1 k2 s2 (declassify env-get)` for this program is
-- precisely `k1 == k2` (the released value is the secret itself),
-- a genuinely non-trivial condition. Hence Theorem 4 does not
-- collapse into Theorem 3.
------------------------------------------------------------------

-- the program is well-typed under PUBLIC pc in the all-PUBLIC env
example-prog : Stmt
example-prog = sink (declassify env-get)

example-env : Env
example-env _ = PUBLIC

example-typed : PUBLIC , example-env |-s example-prog ~> example-env
example-typed = T-Sink (L-Declassify L-Env) pub-flows

-- it evaluates from any store, emitting the secret as public output
example-eval : forall (k : Nat) (s : Store)
             -> k , example-prog , s => s , (k :: [])
example-eval k s = E-Sink

-- the agreement hypothesis for this program is exactly k1 == k2:
-- the released value is the secret, so agreement IS secret-equality
example-agree-is-keq : forall {k1 k2 s1 s2}
                     -> k1 == k2
                     -> Agree (example-eval k1 s1) (example-eval k2 s2)
example-agree-is-keq keq = ea-decl ea-env keq

-- WITHOUT agreement the public outputs differ: two runs with
-- distinct secrets emit distinct traces. This shows the hypothesis
-- is NECESSARY (the conclusion o1 == o2 fails when k1 /= k2),
-- so Theorem 4 genuinely depends on it.
example-needs-agreement : forall {k1 k2 : Nat}
                        -> (k1 :: []) == (k2 :: [])
                        -> k1 == k2
example-needs-agreement refl = refl

-- Theorem 4 applied to the example: low-equivalent stores plus the
-- agreement (here k1 == k2) give equal public output.
example-theorem4 : forall {k1 k2 s1 s2}
                 -> LowEq example-env s1 s2
                 -> k1 == k2
                 -> ((k1 :: []) == (k2 :: []))
example-theorem4 {s1 = s1} {s2 = s2} leq keq
  = snd (theorem4 example-typed (example-eval _ s1) (example-eval _ s2)
                  leq (example-agree-is-keq keq))

