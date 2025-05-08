{-# LANGUAGE FlexibleContexts #-}

-- |
-- Module      : Crypto.Secp256k1.Internal.Util
-- License     : UNLICENSE
-- Maintainer  : Jean-Pierre Rupp <jprupp@protonmail.ch>
-- Stability   : experimental
-- Portability : POSIX
--
-- The API for this module may change at any time. This is an internal module only
-- exposed for hacking and experimentation.
module Crypto.Secp256k1.Internal.Util where

import Crypto.Secp256k1.Internal.ForeignTypes (Seed32)
import Data.Base16.Types (assertBase16, extractBase16)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Base16 (decodeBase16, encodeBase16, isBase16)
import qualified Data.ByteString.Unsafe as BU
import Data.String.Conversions (ConvertibleStrings, cs)
import Foreign (Ptr, castPtr)
import Foreign.C (CSize (..))
import System.Entropy (getEntropy)

decodeHex :: (ConvertibleStrings a ByteString) => a -> Maybe ByteString
decodeHex str =
  if isBase16 $ cs str
    then Just . decodeBase16 $ assertBase16 $ cs str
    else Nothing

showsHex :: ByteString -> ShowS
showsHex = shows . extractBase16 . encodeBase16

unsafeUseByteString :: ByteString -> ((Ptr a, CSize) -> IO b) -> IO b
unsafeUseByteString bs f =
  BU.unsafeUseAsCStringLen bs $ \(b, l) ->
    f (castPtr b, fromIntegral l)

useByteString :: ByteString -> ((Ptr a, CSize) -> IO b) -> IO b
useByteString bs f =
  BS.useAsCStringLen bs $ \(b, l) ->
    f (castPtr b, fromIntegral l)

unsafePackByteString :: (Ptr a, CSize) -> IO ByteString
unsafePackByteString (b, l) =
  BU.unsafePackMallocCStringLen (castPtr b, fromIntegral l)

packByteString :: (Ptr a, CSize) -> IO ByteString
packByteString (b, l) =
  BS.packCStringLen (castPtr b, fromIntegral l)

withRandomSeed :: (Ptr Seed32 -> IO a) -> IO a
withRandomSeed go = do
  bs <- getEntropy 32
  useByteString bs $ go . fst
