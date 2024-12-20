{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Crypto.Secp256k1.Internal.Recovery
-- License     : UNLICENSE
-- Maintainer  : Jean-Pierre Rupp <jprupp@protonmail.ch>
-- Stability   : experimental
-- Portability : POSIX
--
-- Crytpographic functions related to recoverable signatures from Bitcoin’s secp256k1 library.
--
-- The API for this module may change at any time. This is an internal module only
-- exposed for hacking and experimentation.
module Crypto.Secp256k1.Internal.Recovery where

import Control.DeepSeq (NFData)
import Control.Monad (unless, (<=<))
import Crypto.Secp256k1.Internal.Base (Msg (..), PubKey (..), SecKey (..), Sig (..))
import Crypto.Secp256k1.Internal.Context (Ctx (..))
import Crypto.Secp256k1.Internal.ForeignTypes
  ( isSuccess,
  )
import Crypto.Secp256k1.Internal.RecoveryOps
  ( ecdsaRecover,
    ecdsaRecoverableSignatureConvert,
    ecdsaRecoverableSignatureParseCompact,
    ecdsaRecoverableSignatureSerializeCompact,
    ecdsaSignRecoverable,
  )
import Crypto.Secp256k1.Internal.Util
  ( decodeHex,
    showsHex,
    unsafePackByteString,
    unsafeUseByteString,
  )
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Maybe (fromMaybe)
import Data.String (IsString (..))
import Data.Word (Word8)
import Foreign
  ( alloca,
    free,
    mallocBytes,
    nullFunPtr,
    nullPtr,
    peek,
  )
import GHC.Generics (Generic)
import System.IO.Unsafe (unsafePerformIO)
import Text.Read
  ( Lexeme (String),
    lexP,
    parens,
    pfail,
    readPrec,
  )

newtype RecSig = RecSig {get :: ByteString}
  deriving (Eq, Generic, NFData)

data CompactRecSig = CompactRecSig
  { rs :: !ByteString,
    v :: {-# UNPACK #-} !Word8
  }
  deriving (Eq, Generic)

instance NFData CompactRecSig

compactRecSig :: ByteString -> Maybe CompactRecSig
compactRecSig bs
  | BS.length bs == 65,
    BS.last bs <= 3 =
      Just (CompactRecSig (BS.take 64 bs) (BS.last bs))
  | otherwise = Nothing

serializeCompactRecSig :: CompactRecSig -> ByteString
serializeCompactRecSig (CompactRecSig bs v) =
  BS.snoc bs v

compactRecSigFromString :: String -> Maybe CompactRecSig
compactRecSigFromString = compactRecSig <=< decodeHex

instance Read CompactRecSig where
  readPrec = parens $ do
    String str <- lexP
    maybe pfail return $ compactRecSigFromString str

instance IsString CompactRecSig where
  fromString = fromMaybe e . compactRecSigFromString
    where
      e = error "Could not decode signature from hex string"

instance Show CompactRecSig where
  showsPrec _ = showsHex . serializeCompactRecSig

-- | Parse a compact ECDSA signature (64 bytes + recovery id).
importCompactRecSig :: Ctx -> CompactRecSig -> Maybe RecSig
importCompactRecSig (Ctx ctx) (CompactRecSig sig_rs sig_v)
  | BS.length sig_rs == 64,
    sig_v <= 3 = unsafePerformIO $
      unsafeUseByteString sig_rs $ \(sig_rs_ptr, _) -> do
        out_rec_sig_ptr <- mallocBytes 65
        ret <-
          ecdsaRecoverableSignatureParseCompact
            ctx
            out_rec_sig_ptr
            sig_rs_ptr
            (fromIntegral sig_v)
        if isSuccess ret
          then do
            out_bs <- unsafePackByteString (out_rec_sig_ptr, 65)
            return (Just (RecSig out_bs))
          else do
            free out_rec_sig_ptr
            return Nothing
  | otherwise = Nothing

-- | Serialize an ECDSA signature in compact format (64 bytes + recovery id).
exportCompactRecSig :: Ctx -> RecSig -> CompactRecSig
exportCompactRecSig (Ctx ctx) (RecSig rec_sig_bs) = unsafePerformIO $
  unsafeUseByteString rec_sig_bs $ \(rec_sig_ptr, _) ->
    alloca $ \out_v_ptr -> do
      out_sig_ptr <- mallocBytes 64
      ret <-
        ecdsaRecoverableSignatureSerializeCompact
          ctx
          out_sig_ptr
          out_v_ptr
          rec_sig_ptr
      unless (isSuccess ret) $ do
        free out_sig_ptr
        error "Could not obtain compact signature"
      out_bs <- unsafePackByteString (out_sig_ptr, 64)
      out_v <- peek out_v_ptr
      return $ CompactRecSig out_bs (fromIntegral out_v)

-- | Convert a recoverable signature into a normal signature.
convertRecSig :: Ctx -> RecSig -> Sig
convertRecSig (Ctx ctx) (RecSig rec_sig_bs) = unsafePerformIO $
  unsafeUseByteString rec_sig_bs $ \(rec_sig_ptr, _) -> do
    out_ptr <- mallocBytes 64
    ret <- ecdsaRecoverableSignatureConvert ctx out_ptr rec_sig_ptr
    unless (isSuccess ret) $
      error "Could not convert a recoverable signature"
    out_bs <- unsafePackByteString (out_ptr, 64)
    return $ Sig out_bs

-- | Create a recoverable ECDSA signature.
signRecMsg :: Ctx -> SecKey -> Msg -> RecSig
signRecMsg (Ctx ctx) (SecKey sec_key) (Msg m) = unsafePerformIO $
  unsafeUseByteString sec_key $ \(sec_key_ptr, _) ->
    unsafeUseByteString m $ \(msg_ptr, _) -> do
      rec_sig_ptr <- mallocBytes 65
      ret <- ecdsaSignRecoverable ctx rec_sig_ptr msg_ptr sec_key_ptr nullFunPtr nullPtr
      unless (isSuccess ret) $ do
        free rec_sig_ptr
        error "could not sign message"
      RecSig <$> unsafePackByteString (rec_sig_ptr, 65)

-- | Recover an ECDSA public key from a signature.
recover :: Ctx -> RecSig -> Msg -> Maybe PubKey
recover (Ctx ctx) (RecSig rec_sig) (Msg m) = unsafePerformIO $
  unsafeUseByteString rec_sig $ \(rec_sig_ptr, _) ->
    unsafeUseByteString m $ \(msg_ptr, _) -> do
      pub_key_ptr <- mallocBytes 64
      ret <- ecdsaRecover ctx pub_key_ptr rec_sig_ptr msg_ptr
      if isSuccess ret
        then do
          pub_key_bs <- unsafePackByteString (pub_key_ptr, 64)
          return (Just (PubKey pub_key_bs))
        else do
          free pub_key_ptr
          return Nothing
