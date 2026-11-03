{-# LANGUAGE FlexibleContexts #-}

module Crypto.Secp256k1.Internal.Util where

import Crypto.Secp256k1.Internal.ForeignTypes (Seed32)
import Data.Base16.Types (extractBase16)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Base16 (decodeBase16, encodeBase16, parseBase16)
import qualified Data.ByteString.Unsafe as BU
import Data.String.Conversions (ConvertibleStrings, cs)
import Control.Exception (onException)
import Foreign (Ptr, castPtr, copyBytes, free, mallocBytes)
import Foreign.C (CSize (..))
import System.Entropy (getEntropy)

decodeHex :: (ConvertibleStrings a ByteString) => a -> Maybe ByteString
decodeHex str =
  case parseBase16 $ cs str of
    Right b16 -> Just $ decodeBase16 b16
    Left _ -> Nothing

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

-- | Like 'unsafeUseByteString', for an argument that the C library reads as a
-- fixed number of bytes. A 'ByteString' of any other length would make it
-- read outside the buffer, so it raises an error instead.
useFixedByteString ::
  String -> Int -> ByteString -> ((Ptr a, CSize) -> IO b) -> IO b
useFixedByteString name len bs f
  | BS.length bs == len = unsafeUseByteString bs f
  | otherwise =
      error $
        name
          ++ " must be "
          ++ show len
          ++ " bytes long, got "
          ++ show (BS.length bs)

-- | Allocate a buffer of the given size for the C library to fill. The buffer
-- becomes the result when the action reports success and is freed otherwise.
withOutput :: Int -> (Ptr a -> IO Bool) -> IO (Maybe ByteString)
withOutput len f = do
  ptr <- mallocBytes len
  ok <- f ptr `onException` free ptr
  if ok
    then Just <$> unsafePackByteString (ptr, fromIntegral len)
    else free ptr >> return Nothing

-- | Like 'withOutput', with the buffer holding a copy of a fixed-size input
-- that the C library modifies in place. The input is not modified.
withCopy ::
  String -> Int -> ByteString -> (Ptr a -> IO Bool) -> IO (Maybe ByteString)
withCopy name len bs f =
  useFixedByteString name len bs $ \(src, _) ->
    withOutput len $ \dst -> do
      copyBytes dst (castPtr src) len
      f dst

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
