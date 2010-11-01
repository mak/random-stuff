{-# LANGUAGE NoMonomorphismRestriction #-}
module Main where

import Data.List (partition)
import Control.Arrow
import System.Environment(getArgs)
import Control.DeepSeq
import Criterion.Main

data N  = Z | S N deriving Show

one = S Z

cataN Z _ b = b
cataN (S n) f b = f $ cataN n f b

paraN Z _ b = b
paraN (S n) f b = f n $ paraN n f b

hyloN f g s p a | p a = f $ hyloN f g s p $ s a
hyloN _ g _ _ _ = g

cataN' n f b = hyloN f b id isZero n
anaN' n s p = hyloN S Z s p n
-- paraN' n f b = hyloN f b (id &&& id) isZero n


isZero Z = True
isZero (S _) = False

add = \n -> cataN n S
mul = \n m -> cataN n (add m) Z
fac = \n -> paraN n (\n m -> S n `mul` m) one

fromInt 0 = Z
fromInt (n+1) = S $ fromInt n

toInt = \x -> cataN x succ 0

{-# INLINE (><) #-}
f >< g = \(x,y) -> (f x, g y)

{-# RULES "cataTree/anaTree -> hyloTree"
  forall f g s p a. cataTree f g (anaTree s p a) = hyloTree f g s p a
  #-}

hyloTree f g s p a | p a = f . ( id >< (hyloTree f g s p >< hyloTree f g s p))  $ s a
hyloTree _ g _ _ _ = g

treeSort = hyloTree flatten [] part (not . null) where
    flatten (x,(y,z)) = y ++ (x:z)
    part (x:xs) = (x,partition (<x) xs)

data T a = L | N (a,(T a,T a))

cataTree _ g L = g
cataTree f g (N x) = f $ id >< (cataTree f g >< cataTree f g) $ x

anaTree s p a | p a = N $ (id >< (anaTree s p >< anaTree s p)) $ s a
anaTree _ _ _ = L

treeSort' = cataTree flatten [] . anaTree part (not . null) where
    flatten (x,(y,z)) = y ++ (x:z)
    part (x:xs) = (x,partition (<x) xs)


qSort [] = []
qSort (x:xs) = qSort ys ++ (x:qSort zs) where
    (ys,zs) = partition (<x) xs

main = do
  let n = 2000
      listRev = [n,n-1..1] :: [Int]
      list    = [1..n] :: [Int]
  listRev `deepseq` return ()
  list `deepseq` return ()
  defaultMain [
        bench "treeSort reverserd" $ nf treeSort listRev
       ,bench "qSort reverserd" $ nf qSort listRev
       ,bench "treeSort' reverserd" $ nf treeSort' listRev
       ,bench "treeSort " $ nf treeSort list
       ,bench "treeSort' " $ nf treeSort' list
       ,bench "qSort" $ nf qSort list

       ]