{-# LANGUAGE
    TypeOperators
  , DeriveFunctor
  , MultiParamTypeClasses
  , FlexibleInstances
  , OverlappingInstances
  , NoMonomorphismRestriction
  , OverloadedStrings
  #-}

module Types where

import Data.Set (Set)
import qualified Data.Set as S
import GHC.Exts

{-
class Term t where
  type V :: * -> *
  eval   :: t (T a) -> t (T a)
  fv     :: t (T a) -> Set (V a)
  --subst  :: t a -> v -> t1 -> t t1
-}

infixr :+:
data (f :+: g ) a = Inl (f a) | Inr (g a)
    deriving Functor
newtype Fix f = In {out :: f (Fix f)}

class (Functor sub, Functor sup) => sub :<: sup where
    inj :: sub a -> sup a

instance Functor f => (:<:) f f where
    inj = id
instance (Functor f , Functor g) => (:<:) f (f :+: g) where
    inj = Inl
instance (Functor f , Functor g, Functor h, f :<: g) => (:<:) f (h :+: g) where
    inj = Inr . inj

inject = In . inj

cata phi = phi . fmap (cata phi) . out

type VarE = Var ()

class Term  t where
    fvAlg    :: t (Set VarE) -> Set VarE
--    substAlg :: (t :<: t1) => t a -> t1 a -> VarE -> t1

 --   evalAlg :: t Vf -> V

instance (Term f,Term g) => Term (f :+: g) where
    fvAlg (Inl x) = fvAlg x
    fvAlg (Inr x) = fvAlg x

data Var a = Var String Int
    deriving (Functor,Ord,Eq)

var x n = inject $ Var x n
castVar :: Var a -> Var b
castVar (Var x n) = Var x n

instance Show (Var v)  where
    show (Var v n) = v ++ show n

instance IsString (Var v) where
    fromString x = Var "x" 0

instance Term Var where
    fvAlg = S.singleton . castVar
  --  substAlg v t w | castVar v == w = t
  --  substAlg (Var x n) _ _ = var x n

data Lam a = Lam VarE a
    deriving Functor
lam x t = inject $ Lam x t

instance Term Lam  where
    fvAlg (Lam v s) = (castVar v) `S.delete` s

data App t = App t t
    deriving Functor
app t1 t2 = inject $ App t1 t2

instance Term App where
    fvAlg (App s1 s2) = s1 `S.union` s2
    -- substAlg (App t t2) v r = app (substAlg t v r) (substAlg t2 v r)

type Expr = Fix (Var :+: App :+: Lam )

test :: Expr
test = let x0 = var "x" 0
           y0 = var "y" 0
       in app (lam (Var "x" 0) x0) y0

fv = cata fvAlg
