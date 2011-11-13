{-# LANGUAGE
    TypeOperators
  , DeriveFunctor
  , MultiParamTypeClasses
  , FlexibleInstances
  , OverlappingInstances
  , NoMonomorphismRestriction
  , OverloadedStrings
  , UndecidableInstances
  , FlexibleContexts
  #-}

module Types where

import Data.Set (Set)
import qualified Data.Set as S
import GHC.Exts

import Exponential



{-
class Term t where
  type V :: * -> *
  eval   :: t (T a) -> t (T a)
  fv     :: t (T a) -> Set (V a)
  --subst  :: t a -> v -> t1 -> t t1
-}

infixr  :+:
data (f :+: g ) a = Inl (f a) | Inr (g a)

instance (Functor f,Functor g) => Functor (f :+: g) where
    fmap f (Inr r) = Inr (fmap f  r)
    fmap f (Inl l) = Inl (fmap f  l)

instance (ExpFunctor f,ExpFunctor g) => ExpFunctor (f :+: g) where
    xmap f g (Inr r) = Inr (xmap f g r )
    xmap f g (Inl l) = Inl (xmap f g l)

instance Functor f => ExpFunctor f where
    xmap = const . fmap

class (ExpFunctor sub, ExpFunctor sup) => sub :<: sup where
    inj :: sub a -> sup a

instance ExpFunctor f => (:<:) f f where
    inj = id
instance (ExpFunctor f , ExpFunctor g) => (:<:) f (f :+: g) where
    inj = Inl
instance (ExpFunctor f , ExpFunctor g, ExpFunctor h, f :<: g) => (:<:) f (h :+: g) where
    inj = Inr . inj


inject :: (sub :<: sup) => sub (Elim sup a) -> Elim sup a
inject = roll . inj


data Lam a = Lam (a -> a)


lam  = inject . Lam

instance ExpFunctor Lam where
    xmap f g (Lam k) = Lam (f . k . g)


data App t = App t t
    deriving Functor
app t1 t2 = inject $ App t1 t2


class EvalAlg f where
    evalAlg :: f (Val a) -> Val a

instance EvalAlg Lam where
    evalAlg (Lam k) = L k

instance EvalAlg App where
    evalAlg (App (L k) v2) = k v2

instance (EvalAlg f,EvalAlg g) => EvalAlg (f :+: g) where
    evalAlg (Inl e) = evalAlg e
    evalAlg (Inr e) = evalAlg e

data Val a = L (Val a -> Val a) | ZV | SV (Val a)

instance Show (Val a) where
    show ZV = "0"
    show (SV x) = "S ("++show x++")"
    show (L _) = "<func>"

data Z a = Z
 deriving Functor

zero = inject Z

data S a = S a
 deriving Functor
suck = inject . S

instance EvalAlg Z where
    evalAlg = const ZV

instance EvalAlg S where
    evalAlg (S a) = (SV a)

data Fix a = Fix (a -> a)

instance ExpFunctor Fix where
    xmap f g (Fix k) = Fix $ f . k . g

instance EvalAlg Fix where
    evalAlg (Fix k) = k $ evalAlg $ Fix k

fix = inject . Fix

data Case a = Case a a (a -> a)

instance ExpFunctor Case where
    xmap f g (Case x y k) = Case (f x) (f y) (f . k . g)

instance EvalAlg Case where
    evalAlg (Case ZV x _) = x
    evalAlg (Case (SV n) _ k) = k n

caseT x f g = inject $ Case x f g

type Term = App :+: Lam :+: Z :+: S :+: Fix :+: Case
-- type Expr = ForAll Term

-- eval :: ForAll Term -> Val ()
eval = cata evalAlg . safe


--test :: ((App :+: Lam) :<: t) => Elim t a
test = app (lam id) (lam id)

--test2 :: (Term :<: t) => Elim t a
test2 = app (lam (suck . suck .suck)) (suck zero)

--cataTerm :: (Term :<: t) => Elim t a
cataTerm = lam $ \f -> lam $ \g -> fix $ \h ->
             lam $ \x -> caseT x g (\y -> app f (app h y))

--plusTerm :: (Term :<: t) => Elim t a
plusTerm = lam $ app (app (app cataTerm f) g) where
    f = lam $ \g -> lam $ \x -> suck (app g x)
    g = lam id

--multTerm :: (Term :<: t) => Elim t a
multTerm = lam $ app (app (app cataTerm f) g) where
    f = lam $ \x -> lam $ \b -> app (app plusTerm b) (app x b)
    g = lam $ \x -> zero

--facTerm :: (Term :<: t) => Elim t a
facTerm = fix $ \f -> lam $ \x -> caseT x (suck zero) (app (app multTerm x) . app f)

toInt ZV = 0
toInt (SV n) = succ $ toInt n

fromInt 0 = ZV
fromInt n = SV $ fromInt $ pred n

debug f = toInt . f . fromInt

data Plus a = Plus a a
 deriving Functor
data Mult a = Mult a a
 deriving Functor
data Pred a = Pred a
 deriving Functor

plus a b = inject $ Plus a b
mult a b = inject $ Mult a b
prad = inject . Pred

instance EvalAlg Plus where
    evalAlg (Plus y x) = plusVal x y

instance EvalAlg Mult where
    evalAlg (Mult y x) = multVal x y

instance EvalAlg Pred where
    evalAlg (Pred ZV) = ZV
    evalAlg (Pred (SV x)) = x

plusVal ZV v = v
plusVal (SV x) y = SV $ plusVal x y


multVal ZV v = ZV
multVal (SV x) y = plusVal y $ multVal x y

fact' =  fix $ \f -> lam $ \x -> caseT x (suck zero) (mult x . app f)