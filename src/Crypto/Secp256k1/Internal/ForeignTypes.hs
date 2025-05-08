-- |
-- Module      : Crypto.Secp256k1.Internal.ForeignTypes
-- License     : UNLICENSE
-- Maintainer  : Jean-Pierre Rupp <jprupp@protonmail.ch>
-- Stability   : experimental
-- Portability : POSIX
--
-- The API for this module may change at any time. This is an internal module only
-- exposed for hacking and experimentation.
module Crypto.Secp256k1.Internal.ForeignTypes where

import Foreign (Ptr)
import Foreign.C (CInt (..), CUChar, CUInt (..))

data LCtx

data PubKey64

data Msg32

data Sig64

data Seed32

data Compact64

data SecKey32

data Tweak32

data RecSig65

type CtxFlags = CUInt

type SerFlags = CUInt

type Ret = CInt

type NonceFun a =
  Ptr CUChar ->
  Ptr CUChar ->
  Ptr CUChar ->
  Ptr CUChar ->
  Ptr a ->
  CInt ->
  IO CInt

compressed :: SerFlags
compressed = 0x0102

uncompressed :: SerFlags
uncompressed = 0x0002

isSuccess :: Ret -> Bool
isSuccess 0 = False
isSuccess 1 = True
isSuccess n = error $ "isSuccess expected 0 or 1 but got " ++ show n
