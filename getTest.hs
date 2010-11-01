{-# LANGUAGE TemplateHaskell, NoMonomorphismRestriction, DeriveDataTypeable #-}

import Language.Haskell.TH.Syntax
import Language.Haskell.TH
import Language.Haskell.TH.Quote
import Data.Data
import Control.Monad

import GetFunctor

data Nat = Z |S Nat
--  deriving (Data,Type

data List a = Nil | Cons a (List a)
data Tree a = L | T a (Tree a) (Tree a)


$(mkCata ''Nat)
-- $(mkCata ''List)
-- $(mkCata ''Tree)
$(mkCata ''Maybe)
$(mkCata ''Bool)

-- main = return ()
