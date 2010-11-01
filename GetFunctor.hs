{-# LANGUAGE TemplateHaskell, NoMonomorphismRestriction, DeriveDataTypeable #-}

module GetFunctor where

import Language.Haskell.TH.Syntax
import Language.Haskell.TH
import Language.Haskell.TH.Quote
import Data.Data
import Control.Monad



-- $(mkCata ''Nat)

--mkCata t = do

{-
mkFunctor :: Name -> Q [Dec]
mkFunctor t = do
  TyConI (DataD _ n ns cs _) <- reify t
  n' <- newName $ nameBase n
  return $ [DataD [] (mkName $ nameBase n ++ "F") (ns) (toFunctor n' cs) []]

toFunctor n = foldr1 mkEither . map (\(NormalC _ ts) -> f . map snd $ ts) where
    f  =  undefined
    mkEither = undefined
    mkPair = undefined
-}

-- make cata from polynomial functor
mkCata :: Name -> Q [Dec]
mkCata t = do
  TyConI (DataD _ n ns cs _) <- reify t
  args <- replicateM (length cs) (newName "f")
  und <- varE $ mkName "undefined"
  let cataName = mkName $ "cata" ++ nameBase n
      argsP = map varP args
      rec v = foldl appE (varE cataName) . map varE $ v : args
  clauses <- zipWithM (mkClause rec n argsP) (reverse args) cs
  return $ [FunD cataName clauses]



mkClause rec name argsP v t@(NormalC n as) = do
  vars <-replicateM (length as) (newName "x")
  let  body = foldl appE (varE v) .  zipWith (mkBody rec name) vars $ map snd as
  clause (n `conP` (map varP vars):argsP) (normalB body) []
mkClause _ _ _ _ _ = error "Cant handle such types"

mkBody rec name v (ConT n) | n == name = rec v
mkBody _ _ v (ConT _) = varE v
mkBody _ _ v (VarT _) = varE v
mkBody _ _ _ _ = error "Cant handle such types"

{-
[FunD cata [Clause [VarP f_6,VarP g_7,LitP (IntegerL 0)] (NormalB (VarE g_7)) [],
            Clause [VarP f_8,VarP g_9,VarP n_10] (NormalB (AppE (VarE f_8) (AppE (AppE (AppE (VarE cata) (VarE f_8)) (VarE g_9)) (InfixE (Just (VarE n_10)) (VarE GHC.Num.-) (Just (LitE (IntegerL 1))))))) []]]
-}