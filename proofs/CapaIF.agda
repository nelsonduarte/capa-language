{-# OPTIONS --safe #-}
------------------------------------------------------------------
-- CapaIF.agda
--
-- Syntax, two-point security lattice, expression labelling,
-- flow-sensitive statement typing, and big-step operational
-- semantics for the lambda_if information-flow calculus described
-- in docs/semantics.md Section 9. This is the syntax/semantics
-- layer; the noninterference theorems are in
-- CapaNoninterference.agda.
--
-- STATUS: Typechecks on Agda >= 2.6.4 (developed and checked
-- locally on Agda 2.7.0.1; CI pins 2.6.4.3). Verified in CI (see
-- .github/workflows/agda.yml).
--
-- Conventions follow CapaSyntax.agda / CapaSoundness.agda and
-- Programming Language Foundations in Agda (PLFA): the module is
-- self-contained and declares its own Nat / Bool / equality, so
-- agda-stdlib is not a dependency.
--
-- Faithfulness to the Section 9 blueprint, and the two places the
-- Agda encoding deviates for tractability, are documented inline
-- and summarised in proofs/README.md:
--
--   (D1) Stores and label environments are TOTAL functions
--        Var -> Nat and Var -> L, rather than finite partial maps.
--        Section 9 uses partial maps with a "x in dom" side
--        condition in low-equivalence; with total functions the
--        side condition disappears and low-equivalence is the
--        clean pointwise statement "agree on every PUBLIC var".
--        This is the standard PLFA store encoding and loses no
--        generality for the theorem.
--
--   (D2) The big-step evaluation of statements is encoded as an
--        INDUCTIVE relation `_,_=>_,_` (a data type), not a
--        recursive function. The while rule is not structurally
--        terminating as a function (the recursive while call is
--        not on a subterm), exactly the termination-insensitivity
--        the paper flags. As an inductive relation the
--        derivations are finite objects we induct over, which is
--        the textbook encoding of a termination-insensitive
--        big-step semantics and matches Section 9.5 rule-for-rule.
------------------------------------------------------------------

module CapaIF where

------------------------------------------------------------------
-- Basic library types (self-contained, no agda-stdlib).
------------------------------------------------------------------

data Nat : Set where
  zero : Nat
  suc  : Nat -> Nat

{-# BUILTIN NATURAL Nat #-}

data Bool : Set where
  true  : Bool
  false : Bool

data _==_ {A : Set} (x : A) : A -> Set where
  refl : x == x

infix 4 _==_

{-# BUILTIN EQUALITY _==_ #-}

-- Symmetry / transitivity / congruence (the only equality
-- plumbing the proofs need).

sym : forall {A : Set} {x y : A} -> x == y -> y == x
sym refl = refl

trans : forall {A : Set} {x y z : A} -> x == y -> y == z -> x == z
trans refl q = q

cong : forall {A B : Set} (f : A -> B) {x y : A} -> x == y -> f x == f y
cong f refl = refl

cong2 : forall {A B C : Set} (f : A -> B -> C) {x x' : A} {y y' : B}
      -> x == x' -> y == y' -> f x y == f x' y'
cong2 f refl refl = refl

-- The empty type and negation (used for the absurd label cases).

data Empty : Set where

absurd : forall {A : Set} -> Empty -> A
absurd ()

------------------------------------------------------------------
-- Variables (de Bruijn-style natural-number names).
------------------------------------------------------------------

Var : Set
Var = Nat

-- Decidable equality on variables: returns true / false plus a
-- proof reflecting the result, so a store update can branch on
-- "is this the assigned variable?" and the proofs can recover the
-- equality / disequality fact.

data VarEq (x y : Var) : Set where
  yes : x == y -> VarEq x y
  no  : (x == y -> Empty) -> VarEq x y

suc-inj : forall {x y : Nat} -> suc x == suc y -> x == y
suc-inj refl = refl

var-eq : (x y : Var) -> VarEq x y
var-eq zero    zero    = yes refl
var-eq zero    (suc _) = no (\ ())
var-eq (suc _) zero    = no (\ ())
var-eq (suc x) (suc y) with var-eq x y
... | yes p = yes (cong suc p)
... | no  q = no  (\ e -> q (suc-inj e))

------------------------------------------------------------------
-- The two-point security lattice (docs/semantics.md Section 9.2,
-- mirroring capa/_labels.py). PUBLIC is bottom, SECRET is top.
------------------------------------------------------------------

data L : Set where
  PUBLIC : L
  SECRET : L

-- Join = least upper bound. SECRET is absorbing, PUBLIC is unit.
-- This is the rank-max table of _labels.py L.join.

_join_ : L -> L -> L
PUBLIC join b = b
SECRET join _ = SECRET

infixl 6 _join_

-- flows-to as a relation. PUBLIC flows everywhere; SECRET flows
-- only to SECRET. (_labels.py L.flows_to: rank l1 <= rank l2.)

data _flows_ : L -> L -> Set where
  pub-flows : forall {l} -> PUBLIC flows l
  sec-flows : SECRET flows SECRET

infix 4 _flows_

-- The handful of lattice facts the proofs use. All are immediate
-- from the two-element rank table.

join-public-unit-r : forall l -> (l join PUBLIC) == l
join-public-unit-r PUBLIC = refl
join-public-unit-r SECRET = refl

-- If a join is PUBLIC then both operands are PUBLIC. This is the
-- "PUBLIC is bottom" fact Lemma 1's L-Op case and Theorem 3's
-- assign case lean on.

join-public-l : forall {a b} -> (a join b) == PUBLIC -> a == PUBLIC
join-public-l {PUBLIC} {b} _ = refl
join-public-l {SECRET} {b} ()

join-public-r : forall {a b} -> (a join b) == PUBLIC -> b == PUBLIC
join-public-r {PUBLIC} {b} p = p
join-public-r {SECRET} {b} ()

-- Joining SECRET on either side yields SECRET (the implicit-flow
-- fact Lemma 2's assign case uses: under SECRET pc the assigned
-- label is SECRET).

join-secret-r : forall l -> (l join SECRET) == SECRET
join-secret-r PUBLIC = refl
join-secret-r SECRET = refl

-- "label l flows to PUBLIC" forces l = PUBLIC (the T-Sink
-- well-typedness fact: a sink under SECRET pc is untypable).

flows-public-is-public : forall {l} -> l flows PUBLIC -> l == PUBLIC
flows-public-is-public pub-flows = refl

------------------------------------------------------------------
-- Expressions (Section 9.1 / 9.3). One label-joining binary op
-- former (op) stands for the whole join-of-operands family; one
-- secret source (env-get); one downgrade (declassify).
------------------------------------------------------------------

data Expr : Set where
  lit        : Nat -> Expr               -- integer literal
  evar       : Var -> Expr               -- variable read
  op         : Expr -> Expr -> Expr      -- label-joining binary op
  env-get    : Expr                      -- the single secret source
  declassify : Expr -> Expr              -- downgrade to PUBLIC

-- declassify-freeness, as an inductive predicate. Theorem 3 is
-- stated for the declassify-free fragment; Theorem 4 drops this.

data DFExpr : Expr -> Set where
  df-lit  : forall {n}     -> DFExpr (lit n)
  df-evar : forall {x}     -> DFExpr (evar x)
  df-op   : forall {a b}   -> DFExpr a -> DFExpr b -> DFExpr (op a b)
  df-env  :                   DFExpr env-get

------------------------------------------------------------------
-- Statements (Section 9.1).
------------------------------------------------------------------

data Stmt : Set where
  skip   : Stmt
  assign : Var -> Expr -> Stmt
  seq    : Stmt -> Stmt -> Stmt
  sif    : Expr -> Stmt -> Stmt -> Stmt
  swhile : Expr -> Stmt -> Stmt
  sink   : Expr -> Stmt

-- declassify-freeness lifted to statements.

data DFStmt : Stmt -> Set where
  df-skip   : DFStmt skip
  df-assign : forall {x e}     -> DFExpr e -> DFStmt (assign x e)
  df-seq    : forall {s1 s2}   -> DFStmt s1 -> DFStmt s2 -> DFStmt (seq s1 s2)
  df-if     : forall {e s1 s2} -> DFExpr e -> DFStmt s1 -> DFStmt s2 -> DFStmt (sif e s1 s2)
  df-while  : forall {e s}     -> DFExpr e -> DFStmt s -> DFStmt (swhile e s)
  df-sink   : forall {e}       -> DFExpr e -> DFStmt (sink e)

------------------------------------------------------------------
-- Stores and label environments as TOTAL functions (deviation
-- D1). A store maps each variable to its current value; a label
-- environment maps each variable to its current security label.
------------------------------------------------------------------

Store : Set
Store = Var -> Nat

Env : Set
Env = Var -> L

-- Pointwise store update and label-environment update.

_[_:=_] : Store -> Var -> Nat -> Store
(s [ x := v ]) y with var-eq x y
... | yes _ = v
... | no  _ = s y

_[_:>_] : Env -> Var -> L -> Env
(g [ x :> l ]) y with var-eq x y
... | yes _ = l
... | no  _ = g y

-- Pointwise join of two label environments (the T-If merge).

_envjoin_ : Env -> Env -> Env
(g1 envjoin g2) y = g1 y join g2 y

-- Update lookup facts (computed by var-eq).

update-hit : forall (s : Store) (x : Var) (v : Nat) -> (s [ x := v ]) x == v
update-hit s x v with var-eq x x
... | yes _ = refl
... | no  q = absurd (q refl)

update-miss : forall (s : Store) (x y : Var) (v : Nat)
            -> (x == y -> Empty) -> (s [ x := v ]) y == s y
update-miss s x y v neq with var-eq x y
... | yes p = absurd (neq p)
... | no  _ = refl

env-hit : forall (g : Env) (x : Var) (l : L) -> (g [ x :> l ]) x == l
env-hit g x l with var-eq x x
... | yes _ = refl
... | no  q = absurd (q refl)

env-miss : forall (g : Env) (x y : Var) (l : L)
         -> (x == y -> Empty) -> (g [ x :> l ]) y == g y
env-miss g x y l neq with var-eq x y
... | yes p = absurd (neq p)
... | no  _ = refl

------------------------------------------------------------------
-- Expression evaluation (Section 9.5). A total function on a
-- store, parameterised by the ambient secret value kappa that
-- env-get reads. declassify is the identity on the value (it
-- changes only the label, never the value). The binary op is a
-- fixed pure deterministic function; we take addition as the
-- representative (any total binary function would do, since the
-- proofs only use determinism of the op, never its algebra).
------------------------------------------------------------------

_+N_ : Nat -> Nat -> Nat
zero  +N b = b
suc a +N b = suc (a +N b)

eval : Nat -> Store -> Expr -> Nat
eval kappa s (lit n)        = n
eval kappa s (evar x)       = s x
eval kappa s (op a b)       = eval kappa s a +N eval kappa s b
eval kappa s env-get        = kappa
eval kappa s (declassify e) = eval kappa s e

------------------------------------------------------------------
-- Expression labelling judgement (Section 9.3). Deterministic and
-- total; encoded as a relation so the proofs induct on it.
------------------------------------------------------------------

data _|-e_~>_ (g : Env) : Expr -> L -> Set where

  L-Lit : forall {n}
        -> g |-e lit n ~> PUBLIC

  L-Var : forall {x}
        -> g |-e evar x ~> g x

  L-Op  : forall {a b l1 l2}
        -> g |-e a ~> l1
        -> g |-e b ~> l2
        -> g |-e op a b ~> (l1 join l2)

  L-Env : g |-e env-get ~> SECRET

  L-Declassify : forall {e l}
               -> g |-e e ~> l
               -> g |-e declassify e ~> PUBLIC

infix 4 _|-e_~>_

------------------------------------------------------------------
-- Output traces (Section 9.5): a list of emitted values. The only
-- operations needed are the empty trace, the singleton, and
-- concatenation.
------------------------------------------------------------------

data Trace : Set where
  []   : Trace
  _::_ : Nat -> Trace -> Trace

infixr 5 _::_

_++_ : Trace -> Trace -> Trace
[]        ++ ys = ys
(x :: xs) ++ ys = x :: (xs ++ ys)

infixr 5 _++_

------------------------------------------------------------------
-- Statement typing (Section 9.4): read `pc , g |-s s ~> g'` as
-- the paper's `pc |- g { s } g'`. Flow-sensitive (g may change)
-- and pc-carrying. T-While takes the body fixpoint as the typing
-- environment, exactly as the paper rule states (the analyser
-- realises it by monotone in-place label raising to a least
-- fixpoint over the height-2 lattice).
------------------------------------------------------------------

data _,_|-s_~>_ : L -> Env -> Stmt -> Env -> Set where

  T-Skip : forall {pc g}
         -> pc , g |-s skip ~> g

  T-Assign : forall {pc g x e l}
           -> g |-e e ~> l
           -> pc , g |-s assign x e ~> (g [ x :> (l join pc) ])

  T-Seq : forall {pc g g1 g2 s1 s2}
        -> pc , g  |-s s1 ~> g1
        -> pc , g1 |-s s2 ~> g2
        -> pc , g  |-s seq s1 s2 ~> g2

  T-If : forall {pc g g1 g2 e l s1 s2}
       -> g |-e e ~> l
       -> (pc join l) , g |-s s1 ~> g1
       -> (pc join l) , g |-s s2 ~> g2
       -> pc , g |-s sif e s1 s2 ~> (g1 envjoin g2)

  T-While : forall {pc g e l s}
          -> g |-e e ~> l
          -> (pc join l) , g |-s s ~> g
          -> pc , g |-s swhile e s ~> g

  T-Sink : forall {pc g e l}
         -> g |-e e ~> l
         -> (l join pc) flows PUBLIC
         -> pc , g |-s sink e ~> g

infix 4 _,_|-s_~>_

------------------------------------------------------------------
-- Big-step operational semantics (Section 9.5), encoded as an
-- inductive relation (deviation D2). Read `kappa , s , sigma =>
-- sigma' , o` as "with ambient secret kappa, from store sigma,
-- statement s terminates in store sigma' emitting trace o". The
-- secret kappa is fixed for a whole run (the rules thread it
-- unchanged through every premise).
------------------------------------------------------------------

data _,_,_=>_,_ (kappa : Nat) : Stmt -> Store -> Store -> Trace -> Set where

  E-Skip : forall {s}
         -> kappa , skip , s => s , []

  E-Assign : forall {s x e}
           -> kappa , assign x e , s => (s [ x := eval kappa s e ]) , []

  E-Seq : forall {s s1 s2 s' s'' o1 o2}
        -> kappa , s1 , s  => s'  , o1
        -> kappa , s2 , s' => s'' , o2
        -> kappa , seq s1 s2 , s => s'' , (o1 ++ o2)

  -- guard non-zero (true) takes the then-branch
  E-IfT : forall {s s' e s1 s2 o v}
        -> eval kappa s e == suc v
        -> kappa , s1 , s => s' , o
        -> kappa , sif e s1 s2 , s => s' , o

  -- guard zero (false) takes the else-branch
  E-IfF : forall {s s' e s1 s2 o}
        -> eval kappa s e == zero
        -> kappa , s2 , s => s' , o
        -> kappa , sif e s1 s2 , s => s' , o

  E-WhileF : forall {s e b}
           -> eval kappa s e == zero
           -> kappa , swhile e b , s => s , []

  E-WhileT : forall {s s1 s2 e b o1 o2 v}
           -> eval kappa s e == suc v
           -> kappa , b , s => s1 , o1
           -> kappa , swhile e b , s1 => s2 , o2
           -> kappa , swhile e b , s => s2 , (o1 ++ o2)

  E-Sink : forall {s e}
         -> kappa , sink e , s => s , (eval kappa s e :: [])

infix 4 _,_,_=>_,_

------------------------------------------------------------------
-- That is the syntax + semantics. Lemma 1, Lemma 2, Theorem 3,
-- and the Theorem 4 status are in CapaNoninterference.agda.
------------------------------------------------------------------
