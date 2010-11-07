{-# LANGUAGE RankNTypes, DeriveFunctor, NoMonomorphismRestriction, ViewPatterns #-}

import Control.Arrow ((&&&))
import System.Random
import Criterion.Main
import Data.Monoid



newtype Fix f  = In {out :: f (Fix f) }

-- haskell use biggest fix point
type CoFix f  = Fix f

newtype Fx f a x = Fx {unFx :: (a,f x)}
    deriving Functor

outl = fst . unFx . out
outr = snd . unFx . out

type Fv f a = CoFix (Fx f a)

data N a = Z | S a
    deriving Functor
type Nat = Fix N

data T a x = L a | T x x
    deriving Functor
type Tree a = Fix (T a)

forkFx :: (a -> b) -> (a -> f x) -> a -> Fx f b x
forkFx f g = Fx . (f &&& g)

-- data L =

cata phi = phi . fmap (cata phi) . out
ana psi = In . fmap (ana psi) . psi
hylo phi psi = phi . fmap (hylo phi psi) . psi

histo, histo2 :: Functor f => (f (CoFix (Fx f a)) -> a) -> Fix f -> a
histo phi = phi . fmap (ana $ forkFx (histo phi) out ) . out

histo2 phi = outl . cata (In . forkFx phi id)


histoNat f g=  head . go where
    go 0 = [g]
    go n = let xs = go $ pred n in  f xs : xs

fib,fib1,fib2,fib3,fib3',fib4,fib5 :: Int -> Int
fib = (fibs !! ) where
    fibs = 1 : 1 : zipWith (+) (tail fibs) fibs

fib1 = snd . cata phi . fromInt where
    phi Z = (1,1)
    phi (S n) = snd &&& uncurry (+) $ n

getN 1 mem = outl mem
getN n mem = case outr mem of
                Z -> Nothing
                S m -> getN (n-1) m

fib2 =  getSum . maybe undefined id . histo phi . fromInt where
    phi Z = Just $ Sum 1
    phi (S x) = getN 1 x `mappend` getN 2 x

fib3 = histo2 phi . fromInt where
    phi Z = 1
    phi (S x) = case outr x of
                  Z -> 1
                  S y -> outl x + outl y

fib3' = getSum . maybe undefined id . histo2 phi . fromInt where
    phi Z = Just $ Sum 1
    phi (S x) = getN 1 x `mappend` getN 2 x

fib4 = hylo phi psi where
    psi 0 = L 1
    psi 1 = L 1
    psi n = T (n-1) (n-2)
    phi (L a) = a
    phi (T a b) = a + b

fib5 = histoNat phi 1 where
    phi [1]  = 1
    phi (n1:n2:_) = n1 + n2

toInt = cata phi where
    phi Z = 0
    phi (S n) = succ n

testInt f = f . fromInt


z = In Z
s = In .S
fromInt 0 = z
fromInt n = s $ fromInt $ pred n

main = do
  k <- randomRIO (0,300)
  putStrLn $  "fib( " ++ show k ++ ")"
  defaultMain $ map ($k) [
                   bench "fib - basic zipWith def" . nf fib
                  ,bench "fib1 - catamorphic pair-endoding" .  nf fib1
                  ,bench "fib2 - histo - straighforwad def" . nf fib2
                  ,bench "fib3 - histo - catamophic def"  . nf fib3
                  ,bench "fib3' - histo - catamophic def - nice api" .nf fib3'
                  ,bench "fib4 - hylomorpic definition on leaf-trees" .nf fib4
                  ,bench "fib5 - direct nat hylomorhism with explicite list based memoization" . nf fib5
                  ]