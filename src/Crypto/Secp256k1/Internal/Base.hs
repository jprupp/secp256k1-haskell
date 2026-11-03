{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE NoFieldSelectors #-}
module Crypto.Secp256k1.Internal.Base where

import Control.DeepSeq (NFData)
import Control.Monad (replicateM, unless, (<=<))
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
  )
import Crypto.Secp256k1.Internal.Context (Ctx (..), validationContext)
import Crypto.Secp256k1.Internal.ForeignTypes
  ( compressed,
    isSuccess,
    uncompressed,
  )
import Crypto.Secp256k1.Internal.Util
  ( decodeHex,
    packByteString,
    showsHex,
    unsafeUseByteString,
    useFixedByteString,
    withCopy,
    withOutput,
  )
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Hashable (Hashable (..))
import Data.Maybe (fromJust, fromMaybe, isJust)
import Data.String (IsString (..))
import Foreign
  ( alloca,
    allocaArray,
    allocaBytes,
    nullFunPtr,
    nullPtr,
    peek,
    poke,
    pokeArray,
    withForeignPtr,
  )
import GHC.Generics (Generic)
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

newtype PubKey = PubKey {get :: ByteString}
  deriving (Eq, Generic, Hashable, NFData)

newtype Msg = Msg {get :: ByteString}
  deriving (Eq, Generic, Hashable, NFData)

newtype Sig = Sig {get :: ByteString}
  deriving (Eq, Generic, Hashable, NFData)

newtype SecKey = SecKey {get :: ByteString}
  deriving (Eq, Generic, Hashable, NFData)

newtype Tweak = Tweak {get :: ByteString}
  deriving (Eq, Generic, Hashable, NFData)

newtype CompactSig = CompactSig {get :: ByteString}
  deriving (Eq, Generic, Hashable, NFData)

instance Read PubKey where
  readPrec = parens $ do
    String str <- lexP
    maybe pfail return $ pubKey =<< decodeHex str

instance IsString PubKey where
  fromString = fromMaybe e . (pubKey <=< decodeHex)
    where
      e = error "Could not decode public key from hex string"

instance Show PubKey where
  showsPrec _ = showsHex . (.get)

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
    maybe pfail return $ sig =<< decodeHex str

instance IsString Sig where
  fromString = fromMaybe e . (sig <=< decodeHex)
    where
      e = error "Could not decode signature from hex string"

instance Show Sig where
  showsPrec _ = showsHex . (.get)

instance Read SecKey where
  readPrec = parens $ do
    String str <- lexP
    maybe pfail return $ secKey =<< decodeHex str

instance IsString SecKey where
  fromString = fromMaybe e . (secKey <=< decodeHex)
    where
      e = error "Could not decode secret key from hex string"

instance Show SecKey where
  showsPrec _ = showsHex . (.get)

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

-- | Import a signature in its internal 64-byte representation, as found in
-- the 'get' field of a 'Sig'. The representation depends on the platform; use
-- 'importSig' or 'importCompactSig' for signatures from other sources.
-- 'Nothing' unless the bytes are a canonical representation of a signature
-- whose components are both lower than the curve order.
sig :: ByteString -> Maybe Sig
sig bs
  | BS.length bs == 64 && canonical = Just (Sig bs)
  | otherwise = Nothing
  where
    Ctx fctx = validationContext
    canonical =
      unsafePerformIO $ withForeignPtr fctx $ \ctx ->
        unsafeUseByteString bs $ \(sig_ptr, _) ->
          allocaBytes 64 $ \compact_ptr -> do
            ret <- ecdsaSignatureSerializeCompact ctx compact_ptr sig_ptr
            if not (isSuccess ret)
              then return False
              else do
                parsed <- withOutput 64 $ \out ->
                  isSuccess <$> ecdsaSignatureParseCompact ctx out compact_ptr
                return (parsed == Just bs)

-- | Import a public key in its internal 64-byte representation, as found in
-- the 'get' field of a 'PubKey'. The representation depends on the platform;
-- use 'importPubKey' for keys from other sources. 'Nothing' unless the bytes
-- are a canonical representation of a point on the curve.
pubKey :: ByteString -> Maybe PubKey
pubKey bs
  | BS.length bs == 64 && canonical = Just (PubKey bs)
  | otherwise = Nothing
  where
    Ctx fctx = validationContext
    canonical =
      unsafePerformIO $ withForeignPtr fctx $ \ctx ->
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

-- | Import 32-byte 'ByteString' as 'Msg'.
msg :: ByteString -> Maybe Msg
msg bs
  | BS.length bs == 32 = Just (Msg bs)
  | otherwise = Nothing

-- | Import 32-byte big-endian 'ByteString' as 'SecKey'. 'Nothing' unless the
-- number is greater than zero and lower than the curve order, as
-- @secp256k1_ec_seckey_verify@ requires.
secKey :: ByteString -> Maybe SecKey
secKey bs
  | BS.length bs == 32 && bs /= BS.replicate 32 0 && bs < curveOrder =
      Just (SecKey bs)
  | otherwise = Nothing

-- | Order of the secp256k1 group as a 32-byte big-endian 'ByteString'.
curveOrder :: ByteString
curveOrder =
  BS.pack
    [ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
      0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
      0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
    ]

-- | Import 64-byte 'ByteString' as 'CompactSig'.
compactSig :: ByteString -> Maybe CompactSig
compactSig bs
  | BS.length bs == 64 = Just (CompactSig bs)
  | otherwise = Nothing

-- | Convert signature to a normalized lower-S form. 'Nothing' indicates that it
-- was already normal.
normalizeSig :: Ctx -> Sig -> Maybe Sig
normalizeSig (Ctx fctx) (Sig sig_bs) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "Sig" 64 sig_bs $ \(sig_in, _) ->
      (fmap . fmap) Sig . withOutput 64 $ \sig_out ->
        isSuccess <$> ecdsaSignatureNormalize ctx sig_out sig_in

-- | 32-Byte 'ByteString' as 'Tweak'.
tweak :: ByteString -> Maybe Tweak
tweak bs
  | BS.length bs == 32 = Just (Tweak bs)
  | otherwise = Nothing

-- | Import DER-encoded public key.
importPubKey :: Ctx -> ByteString -> Maybe PubKey
importPubKey (Ctx fctx) bs
  | BS.null bs = Nothing
  | otherwise =
      unsafePerformIO $ withForeignPtr fctx $ \ctx ->
        unsafeUseByteString bs $ \(input, len) ->
          (fmap . fmap) PubKey . withOutput 64 $ \pub_key ->
            isSuccess <$> ecPubKeyParse ctx pub_key input len

-- | Encode public key as DER. First argument 'True' for compressed output.
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
    len = if compress then 33 else 65
    flags = if compress then compressed else uncompressed

exportCompactSig :: Ctx -> Sig -> CompactSig
exportCompactSig (Ctx fctx) (Sig sig_bs) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "Sig" 64 sig_bs $ \(sig_ptr, _) -> do
      out <- withOutput 64 $ \out_ptr ->
        isSuccess <$> ecdsaSignatureSerializeCompact ctx out_ptr sig_ptr
      maybe
        (error "Could not obtain compact signature")
        (return . CompactSig)
        out

-- | Import compact signature. 'Nothing' if either component is not lower than
-- the curve order.
importCompactSig :: Ctx -> CompactSig -> Maybe Sig
importCompactSig (Ctx fctx) (CompactSig compact_sig) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "CompactSig" 64 compact_sig $ \(compact_ptr, _) ->
      (fmap . fmap) Sig . withOutput 64 $ \out_sig ->
        isSuccess <$> ecdsaSignatureParseCompact ctx out_sig compact_ptr

-- | Import DER-encoded signature.
importSig :: Ctx -> ByteString -> Maybe Sig
importSig (Ctx fctx) bs
  | BS.null bs = Nothing
  | otherwise =
      unsafePerformIO $ withForeignPtr fctx $ \ctx ->
        unsafeUseByteString bs $ \(in_ptr, in_len) ->
          (fmap . fmap) Sig . withOutput 64 $ \out_sig ->
            isSuccess <$> ecdsaSignatureParseDer ctx out_sig in_ptr in_len

-- | Encode signature as strict DER.
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

-- | Verify message signature. 'True' means that the signature is correct.
verifySig :: Ctx -> PubKey -> Sig -> Msg -> Bool
verifySig (Ctx fctx) (PubKey pub_key) (Sig sig_bs) (Msg m) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "PubKey" 64 pub_key $ \(pub_key_ptr, _) ->
      useFixedByteString "Sig" 64 sig_bs $ \(sig_ptr, _) ->
        useFixedByteString "Msg" 32 m $ \(msg_ptr, _) ->
          isSuccess <$> ecdsaVerify ctx sig_ptr msg_ptr pub_key_ptr

signMsg :: Ctx -> SecKey -> Msg -> Sig
signMsg (Ctx fctx) (SecKey sec_key) (Msg m) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "SecKey" 32 sec_key $ \(sec_key_ptr, _) ->
      useFixedByteString "Msg" 32 m $ \(msg_ptr, _) -> do
        out <- withOutput 64 $ \sig_ptr ->
          isSuccess
            <$> ecdsaSign ctx sig_ptr msg_ptr sec_key_ptr nullFunPtr nullPtr
        maybe (error "could not sign message") (return . Sig) out

derivePubKey :: Ctx -> SecKey -> PubKey
derivePubKey (Ctx fctx) (SecKey sec_key) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "SecKey" 32 sec_key $ \(sec_key_ptr, _) -> do
      out <- withOutput 64 $ \pub_key_ptr ->
        isSuccess <$> ecPubKeyCreate ctx pub_key_ptr sec_key_ptr
      maybe (error "could not compute public key") (return . PubKey) out

-- | Add tweak to secret key.
tweakAddSecKey :: Ctx -> SecKey -> Tweak -> Maybe SecKey
tweakAddSecKey (Ctx fctx) (SecKey sec_key) (Tweak t) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "Tweak" 32 t $ \(tweak_ptr, _) ->
      (fmap . fmap) SecKey . withCopy "SecKey" 32 sec_key $ \sec_key_ptr ->
        isSuccess <$> ecSecKeyTweakAdd ctx sec_key_ptr tweak_ptr

-- | Multiply secret key by tweak.
tweakMulSecKey :: Ctx -> SecKey -> Tweak -> Maybe SecKey
tweakMulSecKey (Ctx fctx) (SecKey sec_key) (Tweak t) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "Tweak" 32 t $ \(tweak_ptr, _) ->
      (fmap . fmap) SecKey . withCopy "SecKey" 32 sec_key $ \sec_key_ptr ->
        isSuccess <$> ecSecKeyTweakMul ctx sec_key_ptr tweak_ptr

-- | Add tweak to public key. Tweak is multiplied first by G to obtain a point.
tweakAddPubKey :: Ctx -> PubKey -> Tweak -> Maybe PubKey
tweakAddPubKey (Ctx fctx) (PubKey pub_key) (Tweak t) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "Tweak" 32 t $ \(tweak_ptr, _) ->
      (fmap . fmap) PubKey . withCopy "PubKey" 64 pub_key $ \pub_key_ptr ->
        isSuccess <$> ecPubKeyTweakAdd ctx pub_key_ptr tweak_ptr

-- | Multiply public key by tweak.
tweakMulPubKey :: Ctx -> PubKey -> Tweak -> Maybe PubKey
tweakMulPubKey (Ctx fctx) (PubKey pub_key) (Tweak t) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    useFixedByteString "Tweak" 32 t $ \(tweak_ptr, _) ->
      (fmap . fmap) PubKey . withCopy "PubKey" 64 pub_key $ \pub_key_ptr ->
        isSuccess <$> ecPubKeyTweakMul ctx pub_key_ptr tweak_ptr

-- | Add multiple public keys together. 'Nothing' for an empty list, when a key
-- is not a valid point, or when the sum is the point at infinity.
combinePubKeys :: Ctx -> [PubKey] -> Maybe PubKey
combinePubKeys _ [] = Nothing
combinePubKeys (Ctx fctx) pubs
  -- @secp256k1_ec_pubkey_combine@ ignores whether each key loads, so an
  -- invalid key would be added as if it were a point.
  | not (all (\(PubKey bs) -> isJust (pubKey bs)) pubs) = Nothing
  | otherwise =
      unsafePerformIO $ withForeignPtr fctx $ \ctx ->
        pointers [] pubs $ \ps ->
          allocaArray (length ps) $ \a -> do
            pokeArray a ps
            (fmap . fmap) PubKey . withOutput 64 $ \out ->
              isSuccess
                <$> ecPubKeyCombine ctx out a (fromIntegral $ length ps)
  where
    pointers ps [] f = f ps
    pointers ps (PubKey pub_key : pub_keys) f =
      useFixedByteString "PubKey" 64 pub_key $ \(p, _) ->
        pointers (p : ps) pub_keys f

-- | Negate a tweak modulo the curve order. 'Nothing' if the tweak is zero or
-- not lower than the curve order.
tweakNegate :: Ctx -> Tweak -> Maybe Tweak
tweakNegate (Ctx fctx) (Tweak t) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    (fmap . fmap) Tweak . withCopy "Tweak" 32 t $ \out ->
      isSuccess <$> ecTweakNegate ctx out

instance Arbitrary Msg where
  arbitrary = gen_msg
    where
      valid_bs = bs_gen `suchThat` isJust
      bs_gen = msg . BS.pack <$> replicateM 32 arbitraryBoundedRandom
      gen_msg = fromJust <$> valid_bs

instance Arbitrary SecKey where
  arbitrary = gen_key
    where
      valid_bs = bs_gen `suchThat` isJust
      bs_gen = secKey . BS.pack <$> replicateM 32 arbitraryBoundedRandom
      gen_key = fromJust <$> valid_bs
