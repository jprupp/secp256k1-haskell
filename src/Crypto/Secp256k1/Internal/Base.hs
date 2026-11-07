{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE NoFieldSelectors #-}

-- | Internal module. Everything is exported, including the raw constructors
-- that "Crypto.Secp256k1" hides, and there is no API stability guarantee.
--
-- A value built with a raw constructor skips validation. Every function here
-- still checks the length of its bytes before calling the C library and
-- raises an 'Control.Exception.ErrorCall' when the length is wrong, but it does not check the
-- content. A raw 'PubKey' or 'Sig' with invalid content makes functions
-- return 'Nothing', 'False' or throw, never abort or read outside a buffer.
module Crypto.Secp256k1.Internal.Base where

import Control.DeepSeq (NFData)
import Control.Exception (evaluate, finally)
import Control.Monad (guard, join, replicateM, unless, (<=<))
import Control.Monad.IO.Class (MonadIO, liftIO)
import Crypto.Secp256k1.Internal.BaseOps
  ( ecPubKeyCombine,
    ecPubKeyCreate,
    ecPubKeyParse,
    ecPubKeySerialize,
    ecPubKeyTweakAdd,
    ecPubKeyTweakMul,
    ecSecKeyTweakAdd,
    ecSecKeyTweakMul,
    ecTweakNegate,
    ecdsaSign,
    ecdsaSignatureNormalize,
    ecdsaSignatureParseCompact,
    ecdsaSignatureParseDer,
    ecdsaSignatureSerializeCompact,
    ecdsaSignatureSerializeDer,
    ecdsaVerify,
    keyPairCreate,
    keyPairSec,
    keyPairXOnlyPub,
    keyPairXOnlyTweakAdd,
    schnorrSigSign32,
    schnorrSigVerify,
    xOnlyPubKeyFromPubKey,
    xOnlyPubKeySerialize,
    xOnlyPubKeyTweakAdd,
  )
import Crypto.Secp256k1.Internal.Context (Ctx (..), validationContext)
import Crypto.Secp256k1.Internal.ForeignTypes
  ( KeyPair96,
    LCtx,
    SchnorrSig64,
    XOnlyPubKey64,
    compressed,
    isSuccess,
    uncompressed,
  )
import Crypto.Secp256k1.Internal.Util
  ( decodeHex,
    fillOutput,
    packByteString,
    showsHex,
    unsafeUseByteString,
    useFixedByteString,
    withCopy,
    withOutput,
    wrongLength,
  )
import Data.Bits (shiftR)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Hashable (Hashable (..))
import Data.Maybe (fromJust, fromMaybe, isJust)
import Data.String (IsString (..))
import Data.Word (Word32)
import Foreign
  ( Ptr,
    alloca,
    allocaArray,
    allocaBytes,
    castPtr,
    fillBytes,
    nullFunPtr,
    nullPtr,
    peek,
    poke,
    pokeArray,
    withForeignPtr,
  )
import Foreign.C (CUChar)
import GHC.Generics (Generic)
import System.Entropy (getEntropy)
import System.IO.Unsafe (unsafePerformIO)
import Test.QuickCheck
  ( Arbitrary (..),
    arbitraryBoundedRandom,
    suchThat,
  )
import Text.Read
  ( Lexeme (String),
    lexP,
    parens,
    pfail,
    readPrec,
  )

-- | Public key in the internal representation of libsecp256k1 (64 bytes).
--
-- The bytes in @get@ are opaque. They are not a standard encoding, and they
-- are not portable between platforms or library versions. Use 'exportPubKey'
-- to serialize a key and 'importPubKey' to parse one. 'pubKey' only exists to
-- rebuild a key from the bytes of @get@ on the same platform.
--
-- 'Show', 'Read' and 'IsString' use the compressed SEC1 encoding in hex.
-- 'Read' and 'IsString' also accept the uncompressed and hybrid encodings.
newtype PubKey = PubKey {get :: ByteString}
  deriving (Eq, Generic, Hashable, NFData)

-- | 32-byte message hash to sign or verify.
--
-- This must be the output of a cryptographic hash function chosen by the
-- verifier. Verifying a value that an attacker can choose makes it easy to
-- produce a signature that verifies without knowing the secret key.
--
-- 'Show', 'Read' and 'IsString' use hex.
newtype Msg = Msg {get :: ByteString}
  deriving (Eq, Generic, Hashable, NFData)

-- | ECDSA signature in the internal representation of libsecp256k1 (64
-- bytes). Both components of a valid 'Sig' are in the range 1 to n−1, where n
-- is the order of the curve.
--
-- The bytes in @get@ are opaque and not portable. Use 'exportSig' (DER) or
-- 'exportCompactSig' (64-byte r‖s) to serialize. 'sig' only exists to rebuild
-- a signature from the bytes of @get@ on the same platform.
--
-- 'Show', 'Read' and 'IsString' use the compact encoding in hex: r and s as
-- 32-byte big-endian numbers.
newtype Sig = Sig {get :: ByteString}
  deriving (Eq, Generic, Hashable, NFData)

-- | 32-byte secret key as a big-endian number in the range 1 to n−1, where n
-- is the order of the curve.
--
-- 'Read' and 'IsString' use hex. 'Show' prints @SecKey \<redacted\>@ and never
-- the key, so a record that holds a key and derives 'Show' can go in a log
-- line or an error message without revealing it. Read the bytes from @get@
-- when you mean to write a key out. They live in an ordinary 'ByteString', so
-- the garbage collector copies them and nothing ever clears them from memory.
newtype SecKey = SecKey {get :: ByteString}
  deriving (Eq, Generic, Hashable, NFData)

-- | 32-byte scalar as a big-endian number in the range 0 to n−1, to add to or
-- multiply with a key. 'Show', 'Read' and 'IsString' use hex.
newtype Tweak = Tweak {get :: ByteString}
  deriving (Eq, Generic, Hashable, NFData)

-- | Compact signature encoding: r and s as 32-byte big-endian numbers.
-- 'compactSig' only checks the length. 'importCompactSig' checks the values.
-- 'Show', 'Read' and 'IsString' use hex.
newtype CompactSig = CompactSig {get :: ByteString}
  deriving (Eq, Generic, Hashable, NFData)

-- | BIP-340 Schnorr signature. Unlike 'Sig', the 64 bytes in @get@ are the
-- serialized form that BIP-340 defines, r‖s as 32-byte big-endian numbers,
-- which is the same on every platform. 'schnorrSig' only checks the length.
-- 'verifySchnorr' checks the values. 'Show', 'Read' and 'IsString' use hex.
newtype SchnorrSig = SchnorrSig {get :: ByteString}
  deriving (Eq, Generic, Hashable, NFData)

instance Read PubKey where
  readPrec = parens $ do
    String str <- lexP
    maybe pfail return $ importPubKey validationContext =<< decodeHex str

instance IsString PubKey where
  fromString = fromMaybe e . (importPubKey validationContext <=< decodeHex)
    where
      e = error "Could not decode public key from hex string"

instance Show PubKey where
  showsPrec _ = showsHex . exportPubKey validationContext True

instance Read Msg where
  readPrec = parens $ do
    String str <- lexP
    maybe pfail return $ msg =<< decodeHex str

instance IsString Msg where
  fromString = fromMaybe e . (msg <=< decodeHex)
    where
      e = error "Could not decode message from hex string"

instance Show Msg where
  showsPrec _ = showsHex . (.get)

instance Read Sig where
  readPrec = parens $ do
    String str <- lexP
    maybe pfail return $ sigFromCompactBytes =<< decodeHex str

instance IsString Sig where
  fromString = fromMaybe e . (sigFromCompactBytes <=< decodeHex)
    where
      e = error "Could not decode signature from hex string"

instance Show Sig where
  showsPrec _ = showsHex . (.get) . exportCompactSig validationContext

instance Read SecKey where
  readPrec = parens $ do
    String str <- lexP
    maybe pfail return $ secKey =<< decodeHex str

instance IsString SecKey where
  fromString = fromMaybe e . (secKey <=< decodeHex)
    where
      e = error "Could not decode secret key from hex string"

-- | Prints @SecKey \<redacted\>@. A secret key reaches 'show' by accident more
-- often than on purpose: a record that holds one and derives 'Show', an
-- error message, a debug trace, a REPL. None of those should reveal it.
--
-- The placeholder is constant. Showing the public key instead would tell
-- keys apart, but it needs a context and a point multiplication for every
-- 'show', and a raw key of invalid content from this module has no public
-- key. Call 'derivePubKey' and show that when you need to identify a key.
--
-- 'Read' is not the inverse of 'Show' for this type. It still parses hex, so
-- that keys can be written as literals and read from configuration.
instance Show SecKey where
  showsPrec d _ = showParen (d > 10) $ showString "SecKey <redacted>"

instance Read Tweak where
  readPrec = parens $ do
    String str <- lexP
    maybe pfail return $ tweak =<< decodeHex str

instance IsString Tweak where
  fromString = fromMaybe e . (tweak <=< decodeHex)
    where
      e = error "Could not decode tweak from hex string"

instance Show Tweak where
  showsPrec _ = showsHex . (.get)

instance Read CompactSig where
  readPrec = parens $ do
    String str <- lexP
    maybe pfail return $ compactSig =<< decodeHex str

instance IsString CompactSig where
  fromString = fromMaybe e . (compactSig <=< decodeHex)
    where
      e = error "Could not decode compact signature from hex string"

instance Show CompactSig where
  showsPrec _ = showsHex . (.get)

instance Read SchnorrSig where
  readPrec = parens $ do
    String str <- lexP
    maybe pfail return $ schnorrSig =<< decodeHex str

instance IsString SchnorrSig where
  fromString = fromMaybe e . (schnorrSig <=< decodeHex)
    where
      e = error "Could not decode Schnorr signature from hex string"

instance Show SchnorrSig where
  showsPrec _ = showsHex . (.get)

-- | Parse the 64-byte compact encoding into a 'Sig' without a caller-provided
-- context. Used by the 'Read' and 'IsString' instances.
sigFromCompactBytes :: ByteString -> Maybe Sig
sigFromCompactBytes = importCompactSig validationContext <=< compactSig

-- | Order of the secp256k1 group, n, as a 32-byte big-endian number.
curveOrder :: ByteString
curveOrder =
  BS.pack
    [ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
      0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
      0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
    ]

-- | Thirty-two zero bytes.
zero32 :: ByteString
zero32 = BS.replicate 32 0

-- | True when the bytes are a 32-byte big-endian number lower than the curve
-- order. 'ByteString' comparison is lexicographic, which for two strings of
-- the same length is the numeric order of the big-endian numbers.
belowCurveOrder :: ByteString -> Bool
belowCurveOrder bs = BS.length bs == 32 && bs < curveOrder

-- | Import a signature from the bytes of its internal representation, as
-- found in the @get@ field of a 'Sig' on the same platform. 'Nothing' unless
-- the bytes are the canonical representation of a signature whose components
-- are both in the range 1 to n−1. Signatures from other sources go through
-- 'importSig' or 'importCompactSig'.
sig :: ByteString -> Maybe Sig
sig bs
  | isCanonicalSig bs = Just (Sig bs)
  | otherwise = Nothing

-- | Serialize the internal bytes to the compact encoding, parse that back and
-- compare. Parsing checks that both components are below the curve order.
-- Comparing the bytes rejects non-canonical forms, so that each signature has
-- one representation and 'Eq' is meaningful. Zero components are rejected
-- too, because such a signature can never verify.
isCanonicalSig :: ByteString -> Bool
isCanonicalSig bs =
  BS.length bs == 64
    && unsafePerformIO
      ( withForeignPtr fctx $ \ctx ->
          unsafeUseByteString bs $ \(sig_ptr, _) ->
            allocaBytes 64 $ \compact_ptr -> do
              ret <- ecdsaSignatureSerializeCompact ctx compact_ptr sig_ptr
              if not (isSuccess ret)
                then return False
                else do
                  compact <- packByteString (compact_ptr, 64)
                  parsed <- withOutput 64 $ \out ->
                    isSuccess <$> ecdsaSignatureParseCompact ctx out compact_ptr
                  return (parsed == Just bs && hasNonZeroComponents compact)
      )
  where
    Ctx fctx = validationContext

-- | True when neither r nor s of a compact-encoded signature is zero.
hasNonZeroComponents :: ByteString -> Bool
hasNonZeroComponents compact =
  BS.take 32 compact /= zero32 && BS.drop 32 compact /= zero32

-- | Import a public key from the bytes of its internal representation, as
-- found in the @get@ field of a 'PubKey' on the same platform. 'Nothing'
-- unless the bytes are the canonical representation of a point on the curve.
-- Keys from other sources go through 'importPubKey'.
pubKey :: ByteString -> Maybe PubKey
pubKey bs
  | isCanonicalPubKey bs = Just (PubKey bs)
  | otherwise = Nothing

-- | Serialize the internal bytes as an uncompressed key, parse that back and
-- compare. Parsing checks that the point is on the curve. Comparing the bytes
-- rejects non-canonical forms, so that each point has one representation and
-- 'Eq' is meaningful.
--
-- The serialization must be uncompressed. A compressed serialization drops
-- the y coordinate, so invalid bytes with a valid x would be accepted as a
-- different point.
isCanonicalPubKey :: ByteString -> Bool
isCanonicalPubKey bs =
  BS.length bs == 64
    && unsafePerformIO
      ( withForeignPtr fctx $ \ctx ->
          unsafeUseByteString bs $ \(pub_key_ptr, _) ->
            alloca $ \len_ptr ->
              allocaBytes 65 $ \ser_ptr -> do
                poke len_ptr 65
                ret <-
                  ecPubKeySerialize ctx ser_ptr len_ptr pub_key_ptr uncompressed
                if not (isSuccess ret)
                  then return False
                  else do
                    len <- peek len_ptr
                    parsed <- withOutput 64 $ \out ->
                      isSuccess <$> ecPubKeyParse ctx out ser_ptr len
                    return (parsed == Just bs)
      )
  where
    Ctx fctx = validationContext

-- | Import a 32-byte message hash.
msg :: ByteString -> Maybe Msg
msg bs
  | BS.length bs == 32 = Just (Msg bs)
  | otherwise = Nothing

-- | Import a 32-byte big-endian secret key. 'Nothing' unless the number is in
-- the range 1 to n−1, which is what @secp256k1_ec_seckey_verify@ requires.
secKey :: ByteString -> Maybe SecKey
secKey bs
  | belowCurveOrder bs && bs /= zero32 = Just (SecKey bs)
  | otherwise = Nothing

-- | Import a 32-byte big-endian tweak. 'Nothing' unless the number is in the
-- range 0 to n−1. Zero is allowed because adding it is harmless, but
-- multiplying by it fails.
tweak :: ByteString -> Maybe Tweak
tweak bs
  | belowCurveOrder bs = Just (Tweak bs)
  | otherwise = Nothing

-- | Import a 64-byte compact signature encoding. Only the length is checked.
-- 'importCompactSig' checks the values.
compactSig :: ByteString -> Maybe CompactSig
compactSig bs
  | BS.length bs == 64 = Just (CompactSig bs)
  | otherwise = Nothing

-- | Convert a signature to its lower-S form. A signature that is already in
-- that form is returned unchanged. 'verifySig' only accepts lower-S
-- signatures, so apply this first to signatures that may come from software
-- that does not produce them.
normalizeSig :: Ctx -> Sig -> Sig
normalizeSig (Ctx fctx) (Sig sig_bs) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "Sig" 64 sig_bs $ \(sig_in, _) ->
      -- The return value only says whether s was high. The output is written
      -- in both cases.
      Sig <$> fillOutput 64 (\sig_out -> () <$ ecdsaSignatureNormalize ctx sig_out sig_in)

-- | True when the s component is not greater than n/2. This is the form that
-- 'signMsg' produces and the only form that 'verifySig' accepts.
isLowS :: Ctx -> Sig -> Bool
isLowS (Ctx fctx) (Sig sig_bs) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "Sig" 64 sig_bs $ \(sig_in, _) -> do
      -- With a null output pointer the C function only reports whether s is
      -- high: 1 when it is, 0 when it is not.
      was_high <- ecdsaSignatureNormalize ctx nullPtr sig_in
      return (not (isSuccess was_high))

-- | True when the r component is lower than 2^255, which makes the DER
-- encoding at most 70 bytes. 'signMsgLowR' produces such signatures.
isLowR :: Ctx -> Sig -> Bool
isLowR ctx s = BS.index (exportCompactSig ctx s).get 0 < 0x80

-- | Parse a public key in SEC1 encoding: 33 bytes compressed (prefix 0x02 or
-- 0x03), 65 bytes uncompressed (prefix 0x04) or 65 bytes hybrid (prefix 0x06
-- or 0x07). 'Nothing' when the encoding is wrong or the point is not on the
-- curve.
importPubKey :: Ctx -> ByteString -> Maybe PubKey
importPubKey (Ctx fctx) bs
  | BS.null bs = Nothing
  | otherwise =
      unsafePerformIO $ withForeignPtr fctx $ \ctx ->
        unsafeUseByteString bs $ \(input, len) ->
          (fmap . fmap) PubKey . withOutput 64 $ \pub_key ->
            isSuccess <$> ecPubKeyParse ctx pub_key input len

-- | Serialize a public key in SEC1 encoding. 'True' for the 33-byte
-- compressed form, 'False' for the 65-byte uncompressed form.
exportPubKey :: Ctx -> Bool -> PubKey -> ByteString
exportPubKey (Ctx fctx) compress (PubKey in_bs) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "PubKey" 64 in_bs $ \(in_ptr, _) ->
      alloca $ \len_ptr ->
        allocaBytes len $ \out_ptr -> do
          poke len_ptr $ fromIntegral len
          ret <- ecPubKeySerialize ctx out_ptr len_ptr in_ptr flags
          unless (isSuccess ret) $ error "could not serialize public key"
          final_len <- peek len_ptr
          packByteString (out_ptr, final_len)
  where
    len = if compress then 33 else 65 :: Int
    flags = if compress then compressed else uncompressed

-- | Serialize a signature in the compact encoding.
exportCompactSig :: Ctx -> Sig -> CompactSig
exportCompactSig (Ctx fctx) (Sig sig_bs) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "Sig" 64 sig_bs $ \(sig_ptr, _) -> do
      out <- withOutput 64 $ \out_ptr ->
        isSuccess <$> ecdsaSignatureSerializeCompact ctx out_ptr sig_ptr
      maybe
        (error "could not serialize compact signature")
        (return . CompactSig)
        out

-- | Parse a signature from the compact encoding. 'Nothing' unless both
-- components are in the range 1 to n−1. The signature may be in high-S form.
importCompactSig :: Ctx -> CompactSig -> Maybe Sig
importCompactSig (Ctx fctx) (CompactSig compact) = do
  guard (hasNonZeroComponents compact)
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "CompactSig" 64 compact $ \(compact_ptr, _) ->
      (fmap . fmap) Sig . withOutput 64 $ \out_sig ->
        isSuccess <$> ecdsaSignatureParseCompact ctx out_sig compact_ptr

-- | Parse a signature in strict DER encoding. 'Nothing' when the encoding is
-- not strict DER or when a component is outside the range 1 to n−1. The
-- signature may be in high-S form.
importSig :: Ctx -> ByteString -> Maybe Sig
importSig ctx@(Ctx fctx) bs
  | BS.null bs = Nothing
  | otherwise = do
      parsed <-
        unsafePerformIO $ withForeignPtr fctx $ \ctx_ptr ->
          unsafeUseByteString bs $ \(in_ptr, in_len) ->
            (fmap . fmap) Sig . withOutput 64 $ \out_sig ->
              isSuccess <$> ecdsaSignatureParseDer ctx_ptr out_sig in_ptr in_len
      -- libsecp256k1 parses a component that is not below the curve order as
      -- zero and still reports success. Such a signature can never verify.
      guard (hasNonZeroComponents (exportCompactSig ctx parsed).get)
      return parsed

-- | Serialize a signature in strict DER encoding (8 to 72 bytes).
exportSig :: Ctx -> Sig -> ByteString
exportSig (Ctx fctx) (Sig in_sig) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "Sig" 64 in_sig $ \(in_ptr, _) ->
      alloca $ \out_len ->
        allocaBytes 72 $ \out_ptr -> do
          poke out_len 72
          ret <- ecdsaSignatureSerializeDer ctx out_ptr out_len in_ptr
          unless (isSuccess ret) $ error "could not serialize signature"
          final_len <- peek out_len
          packByteString (out_ptr, final_len)

-- | Verify a signature over a message hash. 'True' means the signature is
-- valid for the key and the hash and is in lower-S form. A valid signature
-- in high-S form gives 'False'. Apply 'normalizeSig' first to accept it.
--
-- The lower-S rule exists because ECDSA signatures are malleable: if (r, s)
-- is valid, so is (r, n − s). Anyone could change a transaction's signature,
-- and therefore its id, without the key. Accepting only one of the two forms
-- removes that freedom, which is why libsecp256k1 and Bitcoin's relay rules
-- insist on it.
verifySig :: Ctx -> PubKey -> Sig -> Msg -> Bool
verifySig (Ctx fctx) (PubKey pub_key) (Sig sig_bs) (Msg m) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "PubKey" 64 pub_key $ \(pub_key_ptr, _) ->
      useFixedByteString "Sig" 64 sig_bs $ \(sig_ptr, _) ->
        useFixedByteString "Msg" 32 m $ \(msg_ptr, _) ->
          isSuccess <$> ecdsaVerify ctx sig_ptr msg_ptr pub_key_ptr

-- | Sign a message hash. The nonce comes from RFC 6979, so the same key and
-- hash always give the same signature. The signature is in lower-S form.
--
-- Deterministic nonces are the reason this is a pure function, and they are a
-- safety feature, not a convenience: an ECDSA nonce that repeats, or that is
-- even slightly predictable, reveals the secret key. Deriving it from the key
-- and the hash, as RFC 6979 does, removes the need for a good random number
-- generator at signing time.
signMsg :: Ctx -> SecKey -> Msg -> Sig
signMsg ctx key m = signMsgWith ctx key m Nothing

-- | Sign a message hash with RFC 6979 and 32 bytes of extra nonce data (RFC
-- 6979 section 3.6), or without extra data for 'Nothing', which is the same as
-- 'signMsg'. The data must be exactly 32 bytes long. This is the primitive
-- behind 'signMsgLowR'.
signMsgWith :: Ctx -> SecKey -> Msg -> Maybe ByteString -> Sig
signMsgWith (Ctx fctx) (SecKey sec_key) (Msg m) nonce_data =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "SecKey" 32 sec_key $ \(sec_key_ptr, _) ->
      useFixedByteString "Msg" 32 m $ \(msg_ptr, _) ->
        withNonceData $ \data_ptr -> do
          -- A null nonce function selects the RFC 6979 default, which still
          -- receives the extra data.
          out <- withOutput 64 $ \sig_ptr ->
            isSuccess
              <$> ecdsaSign ctx sig_ptr msg_ptr sec_key_ptr nullFunPtr data_ptr
          maybe (error "could not sign message") (return . Sig) out
  where
    withNonceData f = case nonce_data of
      Nothing -> f nullPtr
      Just d -> useFixedByteString "nonce data" 32 d $ \(p, _) -> f p

-- | Sign like 'signMsg', then retry with extra nonce data until the r
-- component is lower than 2^255, so that the DER encoding is at most 70
-- bytes. This is what Bitcoin Core does since version 0.17, with the same
-- nonce data (a 32-bit little-endian counter padded to 32 bytes), so the
-- signatures are the same as Bitcoin Core's. On average it takes two
-- attempts. The result is still deterministic.
--
-- Use it where the size of a signature matters, as in Bitcoin transactions,
-- where every byte costs a fee, or where signatures must match Bitcoin Core's
-- byte for byte. Use 'signMsg' where the RFC 6979 test vectors must hold.
signMsgLowR :: Ctx -> SecKey -> Msg -> Sig
signMsgLowR ctx key m = go 0 (signMsg ctx key m)
  where
    go :: Word32 -> Sig -> Sig
    go counter s
      | isLowR ctx s = s
      | otherwise =
          let next = counter + 1
           in go next (signMsgWith ctx key m (Just (counterData next)))
    counterData c =
      BS.pack (map (fromIntegral . (c `shiftR`)) [0, 8, 16, 24])
        <> BS.replicate 28 0

-- | Compute the public key of a secret key.
--
-- It is a pure function and cannot fail, because a 'SecKey' is valid by
-- construction.
derivePubKey :: Ctx -> SecKey -> PubKey
derivePubKey (Ctx fctx) (SecKey sec_key) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "SecKey" 32 sec_key $ \(sec_key_ptr, _) -> do
      out <- withOutput 64 $ \pub_key_ptr ->
        isSuccess <$> ecPubKeyCreate ctx pub_key_ptr sec_key_ptr
      maybe (error "could not compute public key") (return . PubKey) out

-- | Add a tweak to a secret key: @key + tweak mod n@. 'Nothing' when the
-- result would be zero, which happens when the tweak is the negation of the
-- key.
--
-- Tweaks are the building block of key derivation: BIP-32 child keys are a
-- parent key plus a tweak, and Taproot outputs are an internal key plus a
-- tweak. 'tweakAddPubKey' does the same on the public side, which is what lets
-- a watch-only wallet derive addresses without any secret.
tweakAddSecKey :: Ctx -> SecKey -> Tweak -> Maybe SecKey
tweakAddSecKey (Ctx fctx) (SecKey sec_key) (Tweak t) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "Tweak" 32 t $ \(tweak_ptr, _) ->
      (fmap . fmap) SecKey . withCopy "SecKey" 32 sec_key $ \sec_key_ptr ->
        isSuccess <$> ecSecKeyTweakAdd ctx sec_key_ptr tweak_ptr

-- | Multiply a secret key by a tweak: @key * tweak mod n@. 'Nothing' when the
-- tweak is zero.
tweakMulSecKey :: Ctx -> SecKey -> Tweak -> Maybe SecKey
tweakMulSecKey (Ctx fctx) (SecKey sec_key) (Tweak t) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "Tweak" 32 t $ \(tweak_ptr, _) ->
      (fmap . fmap) SecKey . withCopy "SecKey" 32 sec_key $ \sec_key_ptr ->
        isSuccess <$> ecSecKeyTweakMul ctx sec_key_ptr tweak_ptr

-- | Add a tweak to a public key: @key + tweak * G@. 'Nothing' when the result
-- would be the point at infinity, which happens when the tweak is the negation
-- of the secret key.
tweakAddPubKey :: Ctx -> PubKey -> Tweak -> Maybe PubKey
tweakAddPubKey (Ctx fctx) (PubKey pub_key) (Tweak t) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "Tweak" 32 t $ \(tweak_ptr, _) ->
      (fmap . fmap) PubKey . withCopy "PubKey" 64 pub_key $ \pub_key_ptr ->
        isSuccess <$> ecPubKeyTweakAdd ctx pub_key_ptr tweak_ptr

-- | Multiply a public key by a tweak: @tweak * key@. 'Nothing' when the tweak
-- is zero.
tweakMulPubKey :: Ctx -> PubKey -> Tweak -> Maybe PubKey
tweakMulPubKey (Ctx fctx) (PubKey pub_key) (Tweak t) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "Tweak" 32 t $ \(tweak_ptr, _) ->
      (fmap . fmap) PubKey . withCopy "PubKey" 64 pub_key $ \pub_key_ptr ->
        isSuccess <$> ecPubKeyTweakMul ctx pub_key_ptr tweak_ptr

-- | Add public keys together. 'Nothing' for an empty list, when a key is not
-- a valid point, or when the sum is the point at infinity.
combinePubKeys :: Ctx -> [PubKey] -> Maybe PubKey
combinePubKeys _ [] = Nothing
combinePubKeys (Ctx fctx) pubs
  -- @secp256k1_ec_pubkey_combine@ ignores whether each key loads, so an
  -- invalid key would be added as if it were a point.
  | not (all isValidPoint pubs) = Nothing
  | otherwise =
      unsafePerformIO $ withForeignPtr fctx $ \ctx ->
        withPointers pubs $ \ps ->
          allocaArray (length ps) $ \arr -> do
            pokeArray arr ps
            (fmap . fmap) PubKey . withOutput 64 $ \out ->
              isSuccess <$> ecPubKeyCombine ctx out arr (fromIntegral (length ps))
  where
    -- A raw key of the wrong length is a programming error, like everywhere
    -- else. A raw key of the right length that is not a point gives Nothing.
    isValidPoint (PubKey bs)
      | BS.length bs /= 64 = wrongLength "PubKey" 64 bs
      | otherwise = isCanonicalPubKey bs
    withPointers [] f = f []
    withPointers (PubKey pub_key : rest) f =
      useFixedByteString "PubKey" 64 pub_key $ \(p, _) ->
        withPointers rest $ \ps -> f (p : ps)

-- | Negate a tweak modulo the curve order: @n − tweak@, or zero for zero.
-- Adding a tweak and then its negation gives the original key back.
-- 'Nothing' only for a raw 'Tweak' that is not below the curve order.
tweakNegate :: Ctx -> Tweak -> Maybe Tweak
tweakNegate (Ctx fctx) (Tweak t)
  | t == zero32 = Just (Tweak t)
  | otherwise =
      unsafePerformIO $ withForeignPtr fctx $ \ctx ->
        (fmap . fmap) Tweak . withCopy "Tweak" 32 t $ \out ->
          isSuccess <$> ecTweakNegate ctx out

-- * Schnorr signatures (BIP-340)

-- | Import a 64-byte BIP-340 Schnorr signature. Only the length is checked.
-- 'verifySchnorr' rejects a signature whose components are out of range.
schnorrSig :: ByteString -> Maybe SchnorrSig
schnorrSig bs
  | BS.length bs == 64 = Just (SchnorrSig bs)
  | otherwise = Nothing

-- | Run an action with the x-only form of a public key, which keeps the x
-- coordinate and drops the parity of y. 'Nothing' if the key does not load
-- as a point.
withXOnlyPubKey ::
  Ptr LCtx -> ByteString -> (Ptr XOnlyPubKey64 -> IO a) -> IO (Maybe a)
withXOnlyPubKey ctx pub_key f =
  useFixedByteString "PubKey" 64 pub_key $ \(pub_key_ptr, _) ->
    allocaBytes 64 $ \xonly_ptr -> do
      ret <- xOnlyPubKeyFromPubKey ctx xonly_ptr nullPtr pub_key_ptr
      if isSuccess ret then Just <$> f xonly_ptr else return Nothing

-- | Run an action with the key pair of a secret key. 'Nothing' if the secret
-- key is not valid. The key pair holds the secret key, so its buffer is
-- zeroed when the action is done, whether it returns or throws.
withKeyPair ::
  Ptr LCtx -> ByteString -> (Ptr KeyPair96 -> IO a) -> IO (Maybe a)
withKeyPair ctx sec_key f =
  useFixedByteString "SecKey" 32 sec_key $ \(sec_key_ptr, _) ->
    allocaBytes 96 $ \key_pair -> do
      let create = do
            ret <- keyPairCreate ctx key_pair sec_key_ptr
            if isSuccess ret then Just <$> f key_pair else return Nothing
      create `finally` fillBytes key_pair 0 96

-- | Import a 32-byte BIP-340 x-only public key: the x coordinate of a point.
-- The result is the point with that x coordinate and an even y coordinate,
-- as BIP-340 defines. 'Nothing' if no point has that x coordinate.
importXOnlyPubKey :: Ctx -> ByteString -> Maybe PubKey
importXOnlyPubKey ctx bs
  | BS.length bs == 32 = importPubKey ctx (BS.cons 0x02 bs)
  | otherwise = Nothing

-- | Export a public key as a 32-byte BIP-340 x-only public key: its x
-- coordinate. A key and its negation have the same x-only form.
exportXOnlyPubKey :: Ctx -> PubKey -> ByteString
exportXOnlyPubKey (Ctx fctx) (PubKey pub_key) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx -> do
    out <- withXOnlyPubKey ctx pub_key $ \xonly_ptr ->
      fillOutput 32 $ \out_ptr -> do
        ret <- xOnlyPubKeySerialize ctx out_ptr xonly_ptr
        unless (isSuccess ret) $ error "could not serialize x-only public key"
    maybe (error "could not serialize x-only public key") return out

-- | Sign a message hash with BIP-340 and no auxiliary randomness. The
-- signature is deterministic, and the same as with 32 zero bytes of auxiliary
-- randomness. BIP-340 recommends fresh randomness for every signature, which
-- protects the key against side-channel and fault attacks; 'signSchnorrIO'
-- provides it.
--
-- As BIP-340 requires, the signature is verified before it is returned, and
-- an error is raised if that fails.
signSchnorr :: Ctx -> SecKey -> Msg -> SchnorrSig
signSchnorr ctx key m = signSchnorrInternal ctx key m Nothing

-- | Sign a message hash with BIP-340 and the given 32 bytes of auxiliary
-- randomness. 'Nothing' if the randomness is not 32 bytes long. The
-- signature is verified before it is returned, as in 'signSchnorr'.
signSchnorrWithAux :: Ctx -> SecKey -> Msg -> ByteString -> Maybe SchnorrSig
signSchnorrWithAux ctx key m aux
  | BS.length aux == 32 = Just (signSchnorrInternal ctx key m (Just aux))
  | otherwise = Nothing

-- | Sign a message hash with BIP-340 and fresh auxiliary randomness from the
-- system, as BIP-340 recommends. The signature is different each time. It is
-- verified before it is returned, as in 'signSchnorr'.
signSchnorrIO :: (MonadIO m) => Ctx -> SecKey -> Msg -> m SchnorrSig
signSchnorrIO ctx key m = liftIO $ do
  aux <- getEntropy 32
  evaluate (signSchnorrInternal ctx key m (Just aux))

-- | Sign with optional auxiliary randomness, then verify the signature with
-- the key pair that made it. BIP-340 makes that check the last step of
-- signing, so that a signature corrupted by a fault in the signer never
-- leaves it. Bitcoin Core does the same.
signSchnorrInternal :: Ctx -> SecKey -> Msg -> Maybe ByteString -> SchnorrSig
signSchnorrInternal (Ctx fctx) (SecKey sec_key) (Msg m) aux =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "Msg" 32 m $ \(msg_ptr, _) ->
      withAux $ \aux_ptr -> do
        out <- withKeyPair ctx sec_key $ \key_pair ->
          withOutput 64 $ \sig_ptr -> do
            ret <- schnorrSigSign32 ctx sig_ptr msg_ptr key_pair aux_ptr
            if isSuccess ret
              then verifyFreshSignature ctx key_pair sig_ptr (castPtr msg_ptr)
              else return False
        case out of
          Nothing -> error "could not sign message"
          Just Nothing -> error "could not sign message: the signature does not verify"
          Just (Just s) -> return (SchnorrSig s)
  where
    withAux f = case aux of
      Nothing -> f nullPtr
      Just bs -> useFixedByteString "auxiliary randomness" 32 bs $ \(p, _) -> f p

-- | Verify a signature that a key pair just made, with the x-only public key
-- of that key pair. The message is 32 bytes.
verifyFreshSignature ::
  Ptr LCtx -> Ptr KeyPair96 -> Ptr SchnorrSig64 -> Ptr CUChar -> IO Bool
verifyFreshSignature ctx key_pair sig_ptr msg_ptr =
  allocaBytes 64 $ \xonly_ptr -> do
    ret <- keyPairXOnlyPub ctx xonly_ptr nullPtr key_pair
    if isSuccess ret
      then isSuccess <$> schnorrSigVerify ctx sig_ptr msg_ptr 32 xonly_ptr
      else return False

-- | Verify a BIP-340 signature of a message hash. Only the x coordinate of
-- the public key is used, so a key and its negation verify the same
-- signatures. 'True' means that the signature is correct.
verifySchnorr :: Ctx -> PubKey -> SchnorrSig -> Msg -> Bool
verifySchnorr (Ctx fctx) (PubKey pub_key) (SchnorrSig sig_bs) (Msg m) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "SchnorrSig" 64 sig_bs $ \(sig_ptr, _) ->
      useFixedByteString "Msg" 32 m $ \(msg_ptr, msg_len) ->
        fmap (fromMaybe False) . withXOnlyPubKey ctx pub_key $ \xonly_ptr ->
          isSuccess <$> schnorrSigVerify ctx sig_ptr msg_ptr msg_len xonly_ptr

-- | Add a tweak to the x-only form of a public key: @P + t·G@, where @P@ is
-- the point with the key's x coordinate and an even y coordinate. This is
-- how BIP-341 derives a Taproot output key from an internal key. The result
-- is a full point: its x coordinate is the tweaked x-only key, and the parity
-- of its y coordinate goes into the control block of a script path spend.
-- 'Nothing' if the result is the point at infinity, or for a raw 'Tweak' that
-- is not below the curve order.
tweakAddXOnlyPubKey :: Ctx -> PubKey -> Tweak -> Maybe PubKey
tweakAddXOnlyPubKey (Ctx fctx) (PubKey pub_key) (Tweak t) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "Tweak" 32 t $ \(tweak_ptr, _) ->
      fmap join . withXOnlyPubKey ctx pub_key $ \xonly_ptr ->
        (fmap . fmap) PubKey . withOutput 64 $ \out ->
          isSuccess <$> xOnlyPubKeyTweakAdd ctx out xonly_ptr tweak_ptr

-- | Add a tweak to a secret key the way 'tweakAddXOnlyPubKey' adds it to the
-- public key: the secret key is negated first when its public key has an odd
-- y coordinate, then the tweak is added. The result signs for the Taproot
-- output of 'tweakAddXOnlyPubKey' in a key path spend. 'Nothing' if the
-- result is zero, or for a raw 'Tweak' that is not below the curve order.
tweakAddXOnlySecKey :: Ctx -> SecKey -> Tweak -> Maybe SecKey
tweakAddXOnlySecKey (Ctx fctx) (SecKey sec_key) (Tweak t) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "Tweak" 32 t $ \(tweak_ptr, _) ->
      fmap join . withKeyPair ctx sec_key $ \key_pair -> do
        ret <- keyPairXOnlyTweakAdd ctx key_pair tweak_ptr
        if isSuccess ret
          then
            (fmap . fmap) SecKey . withOutput 32 $ \out ->
              isSuccess <$> keyPairSec ctx out key_pair
          else return Nothing

instance Arbitrary Msg where
  arbitrary = fromJust <$> (gen `suchThat` isJust)
    where
      gen = msg . BS.pack <$> replicateM 32 arbitraryBoundedRandom

instance Arbitrary SecKey where
  arbitrary = fromJust <$> (gen `suchThat` isJust)
    where
      gen = secKey . BS.pack <$> replicateM 32 arbitraryBoundedRandom

instance Arbitrary Tweak where
  arbitrary = fromJust <$> (gen `suchThat` isJust)
    where
      gen = tweak . BS.pack <$> replicateM 32 arbitraryBoundedRandom
