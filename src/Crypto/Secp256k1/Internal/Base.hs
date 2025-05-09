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
import Control.Exception (bracket)
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
import Crypto.Secp256k1.Internal.Context (Ctx (..))
import Crypto.Secp256k1.Internal.ForeignTypes
  ( LCtx,
    compressed,
    isSuccess,
    uncompressed,
  )
import Crypto.Secp256k1.Internal.Util
  ( decodeHex,
    packByteString,
    showsHex,
    unsafePackByteString,
    unsafeUseByteString,
  )
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Hashable (Hashable (..))
import Data.Maybe (fromJust, fromMaybe, isJust)
import Data.String (IsString (..))
import Foreign
  ( Bits (bitSize),
    Ptr,
    alloca,
    allocaArray,
    allocaBytes,
    free,
    mallocBytes,
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
      e = error "Colud not decode secret key from hex string"

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

-- | Import 64-byte 'ByteString' as 'Sig'.
sig :: ByteString -> Maybe Sig
sig bs
  | BS.length bs == 64 = Just (Sig bs)
  | otherwise = Nothing

-- | Import 64-byte 'ByteString' as 'PubKey'.
pubKey :: ByteString -> Maybe PubKey
pubKey bs
  | BS.length bs == 64 = Just (PubKey bs)
  | otherwise = Nothing

-- | Import 32-byte 'ByteString' as 'Msg'.
msg :: ByteString -> Maybe Msg
msg bs
  | BS.length bs == 32 = Just (Msg bs)
  | otherwise = Nothing

-- | Import 32-byte 'ByteString' as 'SecKey'.
secKey :: ByteString -> Maybe SecKey
secKey bs
  | BS.length bs == 32 = Just (SecKey bs)
  | otherwise = Nothing

compactSig :: ByteString -> Maybe CompactSig
compactSig bs
  | BS.length bs == 64 = Just (CompactSig bs)
  | otherwise = Nothing

-- | Convert signature to a normalized lower-S form. 'Nothing' indicates that it
-- was already normal.
normalizeSig :: Ctx -> Sig -> Maybe Sig
normalizeSig (Ctx fctx) (Sig sig) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    unsafeUseByteString sig $ \(sig_in, _) -> do
      sig_out <- mallocBytes 64
      ret <- ecdsaSignatureNormalize ctx sig_out sig_in
      if isSuccess ret
        then do
          bs <- unsafePackByteString (sig_out, 64)
          return (Just (Sig bs))
        else do
          free sig_out
          return Nothing

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
        unsafeUseByteString bs $ \(input, len) -> do
          pub_key <- mallocBytes 64
          ret <- ecPubKeyParse ctx pub_key input len
          if isSuccess ret
            then do
              out <- unsafePackByteString (pub_key, 64)
              return (Just (PubKey out))
            else do
              free pub_key
              return Nothing

-- | Encode public key as DER. First argument 'True' for compressed output.
exportPubKey :: Ctx -> Bool -> PubKey -> ByteString
exportPubKey (Ctx fctx) compress (PubKey in_bs) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    unsafeUseByteString in_bs $ \(in_ptr, _) ->
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
    unsafeUseByteString sig_bs $ \(sig_ptr, _) -> do
      out_ptr <- mallocBytes 64
      ret <- ecdsaSignatureSerializeCompact ctx out_ptr sig_ptr
      unless (isSuccess ret) $ do
        free out_ptr
        error "Could not obtain compact signature"
      out_bs <- unsafePackByteString (out_ptr, 64)
      return $ CompactSig out_bs

importCompactSig :: Ctx -> CompactSig -> Maybe Sig
importCompactSig (Ctx fctx) (CompactSig compact_sig) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    unsafeUseByteString compact_sig $ \(compact_ptr, _) -> do
      out_sig <- mallocBytes 64
      ret <- ecdsaSignatureParseCompact ctx out_sig compact_ptr
      if isSuccess ret
        then do
          out_bs <- unsafePackByteString (out_sig, 64)
          return (Just (Sig out_bs))
        else do
          free out_sig
          return Nothing

-- | Import DER-encoded signature.
importSig :: Ctx -> ByteString -> Maybe Sig
importSig (Ctx fctx) bs
  | BS.null bs = Nothing
  | otherwise =
      unsafePerformIO $ withForeignPtr fctx $ \ctx ->
        unsafeUseByteString bs $ \(in_ptr, in_len) -> do
          out_sig <- mallocBytes 64
          ret <- ecdsaSignatureParseDer ctx out_sig in_ptr in_len
          if isSuccess ret
            then do
              out_bs <- unsafePackByteString (out_sig, 64)
              return (Just (Sig out_bs))
            else do
              free out_sig
              return Nothing

-- | Encode signature as strict DER.
exportSig :: Ctx -> Sig -> ByteString
exportSig (Ctx fctx) (Sig in_sig) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    unsafeUseByteString in_sig $ \(in_ptr, _) ->
      alloca $ \out_len ->
        allocaBytes 72 $ \out_ptr -> do
          poke out_len 72
          ret <- ecdsaSignatureSerializeDer ctx out_ptr out_len in_ptr
          unless (isSuccess ret) $ error "could not serialize signature"
          final_len <- peek out_len
          packByteString (out_ptr, final_len)

-- | Verify message signature. 'True' means that the signature is correct.
verifySig :: Ctx -> PubKey -> Sig -> Msg -> Bool
verifySig (Ctx fctx) (PubKey pub_key) (Sig sig) (Msg m) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    unsafeUseByteString pub_key $ \(pub_key_ptr, _) ->
      unsafeUseByteString sig $ \(sig_ptr, _) ->
        unsafeUseByteString m $ \(msg_ptr, _) ->
          isSuccess <$> ecdsaVerify ctx sig_ptr msg_ptr pub_key_ptr

signMsg :: Ctx -> SecKey -> Msg -> Sig
signMsg (Ctx fctx) (SecKey sec_key) (Msg m) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    unsafeUseByteString sec_key $ \(sec_key_ptr, _) ->
      unsafeUseByteString m $ \(msg_ptr, _) -> do
        sig_ptr <- mallocBytes 64
        ret <- ecdsaSign ctx sig_ptr msg_ptr sec_key_ptr nullFunPtr nullPtr
        unless (isSuccess ret) $ do
          free sig_ptr
          error "could not sign message"
        Sig <$> unsafePackByteString (sig_ptr, 64)

derivePubKey :: Ctx -> SecKey -> PubKey
derivePubKey (Ctx fctx) (SecKey sec_key) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    unsafeUseByteString sec_key $ \(sec_key_ptr, _) -> do
      pub_key_ptr <- mallocBytes 64
      ret <- ecPubKeyCreate ctx pub_key_ptr sec_key_ptr
      unless (isSuccess ret) $ do
        free pub_key_ptr
        error "could not compute public key"
      PubKey <$> unsafePackByteString (pub_key_ptr, 64)

-- | Add tweak to secret key.
tweakAddSecKey :: Ctx -> SecKey -> Tweak -> Maybe SecKey
tweakAddSecKey (Ctx fctx) (SecKey sec_key) (Tweak t) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    unsafeUseByteString new_bs $ \(sec_key_ptr, _) ->
      unsafeUseByteString t $ \(tweak_ptr, _) -> do
        ret <- ecSecKeyTweakAdd ctx sec_key_ptr tweak_ptr
        if isSuccess ret
          then return (Just (SecKey new_bs))
          else return Nothing
  where
    new_bs = BS.copy sec_key

-- | Multiply secret key by tweak.
tweakMulSecKey :: Ctx -> SecKey -> Tweak -> Maybe SecKey
tweakMulSecKey (Ctx fctx) (SecKey sec_key) (Tweak t) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    unsafeUseByteString new_bs $ \(sec_key_ptr, _) ->
      unsafeUseByteString t $ \(tweak_ptr, _) -> do
        ret <- ecSecKeyTweakMul ctx sec_key_ptr tweak_ptr
        if isSuccess ret
          then return (Just (SecKey new_bs))
          else return Nothing
  where
    new_bs = BS.copy sec_key

-- | Add tweak to public key. Tweak is multiplied first by G to obtain a point.
tweakAddPubKey :: Ctx -> PubKey -> Tweak -> Maybe PubKey
tweakAddPubKey (Ctx fctx) (PubKey pub_key) (Tweak t) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    unsafeUseByteString new_bs $ \(pub_key_ptr, _) ->
      unsafeUseByteString t $ \(tweak_ptr, _) -> do
        ret <- ecPubKeyTweakAdd ctx pub_key_ptr tweak_ptr
        if isSuccess ret
          then return (Just (PubKey new_bs))
          else return Nothing
  where
    new_bs = BS.copy pub_key

-- | Multiply public key by tweak. Tweak is multiplied first by G to obtain a
-- point.
tweakMulPubKey :: Ctx -> PubKey -> Tweak -> Maybe PubKey
tweakMulPubKey (Ctx fctx) (PubKey pub_key) (Tweak t) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    unsafeUseByteString new_bs $ \(pub_key_ptr, _) ->
      unsafeUseByteString t $ \(tweak_ptr, _) -> do
        ret <- ecPubKeyTweakMul ctx pub_key_ptr tweak_ptr
        if isSuccess ret
          then return (Just (PubKey new_bs))
          else return Nothing
  where
    new_bs = BS.copy pub_key

-- | Add multiple public keys together.
combinePubKeys :: Ctx -> [PubKey] -> Maybe PubKey
combinePubKeys _ [] = Nothing
combinePubKeys (Ctx fctx) pubs =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    pointers [] pubs $ \ps ->
      allocaArray (length ps) $ \a -> do
        out <- mallocBytes 64
        pokeArray a ps
        ret <- ecPubKeyCombine ctx out a (fromIntegral $ length ps)
        if isSuccess ret
          then do
            bs <- unsafePackByteString (out, 64)
            return (Just (PubKey bs))
          else do
            free out
            return Nothing
  where
    pointers ps [] f = f ps
    pointers ps (PubKey pub_key : pub_keys) f =
      unsafeUseByteString pub_key $ \(p, _) ->
        pointers (p : ps) pub_keys f

tweakNegate :: Ctx -> Tweak -> Maybe Tweak
tweakNegate (Ctx fctx) (Tweak t) =
  unsafePerformIO $ withForeignPtr fctx $ \ctx ->
    unsafeUseByteString new $ \(out, _) -> do
      ret <- ecTweakNegate ctx out
      if isSuccess ret
        then return (Just (Tweak new))
        else return Nothing
  where
    new = BS.copy t

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
