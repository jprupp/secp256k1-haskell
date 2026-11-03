{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE NoFieldSelectors #-}

-- | Internal module. Everything is exported, including the raw 'RecSig'
-- constructor that "Crypto.Secp256k1.Recovery" hides, and there is no API
-- stability guarantee. This module is only built when the @recovery@ flag of
-- the package is on.
--
-- A 'RecSig' built with the raw constructor skips validation. Every function
-- here still checks the length of its bytes before calling the C library and
-- raises an 'Control.Exception.ErrorCall' when the length is wrong, but it
-- does not check the content. A raw 'RecSig' with invalid content makes
-- functions return 'Nothing', a value that does not verify, or throw, never
-- abort or read outside a buffer.
module Crypto.Secp256k1.Internal.Recovery where

import Control.DeepSeq (NFData)
import Control.Monad (guard, (<=<))
import Crypto.Secp256k1.Internal.Base
  ( CompactSig (..),
    Msg (..),
    PubKey (..),
    SecKey (..),
    Sig (..),
    hasNonZeroComponents,
  )
import Crypto.Secp256k1.Internal.Context (Ctx (..), validationContext)
import Crypto.Secp256k1.Internal.ForeignTypes (isSuccess)
import Crypto.Secp256k1.Internal.RecoveryOps
  ( ecdsaRecover,
    ecdsaRecoverableSignatureConvert,
    ecdsaRecoverableSignatureParseCompact,
    ecdsaRecoverableSignatureSerializeCompact,
    ecdsaSignRecoverable,
  )
import Crypto.Secp256k1.Internal.Util
  ( decodeHex,
    packByteString,
    showsHex,
    unsafeUseByteString,
    useFixedByteString,
    withOutput,
  )
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Hashable (Hashable)
import Data.Maybe (fromMaybe)
import Data.String (IsString (..))
import Data.Word (Word8)
import Foreign (alloca, allocaBytes, nullFunPtr, nullPtr, peek, withForeignPtr)
import GHC.Generics (Generic)
import System.IO.Unsafe (unsafePerformIO)
import Text.Read
  ( Lexeme (String),
    lexP,
    parens,
    pfail,
    readPrec,
  )

-- | ECDSA signature with a recovery id, in the internal representation of
-- libsecp256k1 (65 bytes). A valid 'RecSig' has both components in the range
-- 1 to n−1, where n is the order of the curve, and a recovery id of 0 to 3.
--
-- The bytes in @get@ are opaque. They are not a standard encoding, and they
-- are not portable between platforms or library versions. Use
-- 'exportCompactRecSig' to serialize a signature and 'importCompactRecSig' to
-- parse one. 'recSig' only exists to rebuild a signature from the bytes of
-- @get@ on the same platform.
--
-- 'Show', 'Read' and 'IsString' use hex of the 65-byte encoding that
-- 'exportCompactRecSig' gives: r and s as 32-byte big-endian numbers, then
-- the recovery id as one byte.
newtype RecSig = RecSig {get :: ByteString}
  deriving (Eq, Generic, Hashable, NFData)

instance Read RecSig where
  readPrec = parens $ do
    String str <- lexP
    maybe pfail return $ recSigFromEncoding =<< decodeHex str

instance IsString RecSig where
  fromString = fromMaybe e . (recSigFromEncoding <=< decodeHex)
    where
      e = error "Could not decode recoverable signature from hex string"

instance Show RecSig where
  showsPrec _ = showsHex . recSigToEncoding

-- | The 65-byte encoding of a signature: the compact encoding of r and s,
-- then the recovery id as one byte. Used by the 'Show' instance.
recSigToEncoding :: RecSig -> ByteString
recSigToEncoding rs = compact.get `BS.snoc` rec_id
  where
    (compact, rec_id) = exportCompactRecSig validationContext rs

-- | Parse the 65-byte encoding of 'recSigToEncoding' without a
-- caller-provided context. Used by the 'Read' and 'IsString' instances.
recSigFromEncoding :: ByteString -> Maybe RecSig
recSigFromEncoding bs = do
  guard (BS.length bs == 65)
  importCompactRecSig validationContext (CompactSig (BS.take 64 bs)) (BS.last bs)

-- | Import a recoverable signature from the bytes of its internal
-- representation, as found in the @get@ field of a 'RecSig' on the same
-- platform. 'Nothing' unless the bytes are the canonical representation of a
-- signature whose components are both in the range 1 to n−1, with a recovery
-- id of 0 to 3. Signatures from other sources go through
-- 'importCompactRecSig'.
recSig :: ByteString -> Maybe RecSig
recSig bs
  | isCanonicalRecSig bs = Just (RecSig bs)
  | otherwise = Nothing

-- | Serialize the internal bytes to the compact encoding and the id, parse
-- those back and compare, as 'Crypto.Secp256k1.Internal.Base.isCanonicalSig'
-- does. Parsing checks that both components are below the curve order and
-- that the id is 0 to 3. Comparing the bytes rejects non-canonical forms, so
-- that each signature has one representation and 'Eq' is meaningful. Zero
-- components are rejected too, so that 'convertRecSig' always gives a valid
-- 'Sig'.
isCanonicalRecSig :: ByteString -> Bool
isCanonicalRecSig bs =
  BS.length bs == 65
    && unsafePerformIO
      ( withForeignPtr fctx $ \ctx ->
          unsafeUseByteString bs $ \(rec_sig_ptr, _) ->
            allocaBytes 64 $ \compact_ptr ->
              alloca $ \rec_id_ptr -> do
                ret <-
                  ecdsaRecoverableSignatureSerializeCompact
                    ctx
                    compact_ptr
                    rec_id_ptr
                    rec_sig_ptr
                if not (isSuccess ret)
                  then return False
                  else do
                    rec_id <- peek rec_id_ptr
                    compact <- packByteString (compact_ptr, 64)
                    parsed <- withOutput 65 $ \out ->
                      isSuccess
                        <$> ecdsaRecoverableSignatureParseCompact ctx out compact_ptr rec_id
                    return (parsed == Just bs && hasNonZeroComponents compact)
      )
  where
    Ctx fctx = validationContext

-- | Sign a message hash and keep the recovery id. The nonce comes from RFC
-- 6979, so the same key and hash always give the same signature, and r and s
-- are those of 'Crypto.Secp256k1.signMsg', in lower-S form. There is no low-R
-- grinding. Bitcoin Core does not grind when it signs a message with
-- @SignCompact@ either, so the signatures are the same as Bitcoin Core's.
signRecMsg :: Ctx -> SecKey -> Msg -> RecSig
signRecMsg (Ctx fctx) (SecKey sec_key) (Msg m) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "SecKey" 32 sec_key $ \(sec_key_ptr, _) ->
      useFixedByteString "Msg" 32 m $ \(msg_ptr, _) -> do
        -- A null nonce function selects the RFC 6979 default.
        out <- withOutput 65 $ \rec_sig_ptr ->
          isSuccess
            <$> ecdsaSignRecoverable ctx rec_sig_ptr msg_ptr sec_key_ptr nullFunPtr nullPtr
        maybe (error "could not sign message") (return . RecSig) out

-- | The public key that made a signature of a message hash. 'Nothing' when no
-- key comes out: no point has the x coordinate that r and the recovery id
-- give, or the computation reaches the point at infinity.
--
-- A key that comes out verifies the signature for the hash, except for the
-- lower-S rule, which recovery does not apply: the high-S form of a
-- signature, with the parity bit of its recovery id flipped, recovers the
-- same key. Bitcoin Core accepts such message signatures too. Where the rule
-- matters, check 'Crypto.Secp256k1.isLowS' on 'convertRecSig'. The hash is
-- reduced modulo the curve order, as 'Crypto.Secp256k1.verifySig' does.
recover :: Ctx -> RecSig -> Msg -> Maybe PubKey
recover (Ctx fctx) (RecSig rec_sig) (Msg m) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "RecSig" 65 rec_sig $ \(rec_sig_ptr, _) ->
      useFixedByteString "Msg" 32 m $ \(msg_ptr, _) ->
        (fmap . fmap) PubKey . withOutput 64 $ \pub_key_ptr ->
          isSuccess <$> ecdsaRecover ctx pub_key_ptr rec_sig_ptr msg_ptr

-- | The signature without its recovery id. For a signature from
-- 'signRecMsg', this is the signature that 'Crypto.Secp256k1.signMsg' gives.
convertRecSig :: Ctx -> RecSig -> Sig
convertRecSig (Ctx fctx) (RecSig rec_sig) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "RecSig" 65 rec_sig $ \(rec_sig_ptr, _) -> do
      out <- withOutput 64 $ \sig_ptr ->
        isSuccess <$> ecdsaRecoverableSignatureConvert ctx sig_ptr rec_sig_ptr
      maybe (error "could not convert recoverable signature") (return . Sig) out

-- | Parse a signature from the compact encoding and its recovery id.
-- 'Nothing' unless both components are in the range 1 to n−1 and the id is 0
-- to 3. The signature may be in high-S form.
importCompactRecSig :: Ctx -> CompactSig -> Word8 -> Maybe RecSig
importCompactRecSig (Ctx fctx) (CompactSig compact) rec_id = do
  guard (rec_id <= 3)
  -- libsecp256k1 accepts a zero component here and only refuses it in
  -- 'recover'. It is rejected here so that 'convertRecSig' always gives a
  -- valid 'Sig', as 'Crypto.Secp256k1.importCompactSig' does.
  guard (hasNonZeroComponents compact)
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "CompactSig" 64 compact $ \(compact_ptr, _) ->
      (fmap . fmap) RecSig . withOutput 65 $ \out ->
        isSuccess
          <$> ecdsaRecoverableSignatureParseCompact ctx out compact_ptr (fromIntegral rec_id)

-- | Serialize a signature to the compact encoding and its recovery id. The
-- header byte of a Bitcoin signed message is 27 plus the id, plus 4 for a
-- compressed key, which the caller adds.
exportCompactRecSig :: Ctx -> RecSig -> (CompactSig, Word8)
exportCompactRecSig (Ctx fctx) (RecSig rec_sig) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "RecSig" 65 rec_sig $ \(rec_sig_ptr, _) ->
      alloca $ \rec_id_ptr -> do
        out <- withOutput 64 $ \compact_ptr ->
          isSuccess
            <$> ecdsaRecoverableSignatureSerializeCompact ctx compact_ptr rec_id_ptr rec_sig_ptr
        case out of
          Nothing -> error "could not serialize recoverable signature"
          Just compact -> do
            rec_id <- peek rec_id_ptr
            return (CompactSig compact, fromIntegral rec_id)
