{-# LANGUAGE OverloadedStrings #-}

module Crypto.Secp256k1.InternalSpec (spec) where

import Control.Exception
import Control.Monad
import Control.Monad.Trans
import Crypto.Secp256k1.Internal.BaseOps
import Crypto.Secp256k1.Internal.Context
import Crypto.Secp256k1.Internal.ForeignTypes
import Crypto.Secp256k1.Internal.Util
import Data.Base16.Types (assertBase16)
import Data.ByteString
  ( ByteString,
    copy,
    packCStringLen,
    useAsCStringLen,
  )
import Data.ByteString.Base16 (decodeBase16)
import Foreign
import System.Entropy
import Test.HUnit (Assertion, assertBool, assertEqual, assertFailure)
import Test.Hspec

spec :: Spec
spec = do
  describe "housekeeping" $ do
    it "creates context" createContextTest
    it "randomizes context" randomizeContextTest
    it "clones context" cloneContextTest
  describe "serialization" $ do
    it "parses public key" ecPubkeyParseTest
    it "serializes public key" ecPubKeySerializeTest
    it "parses DER signature" ecdsaSignatureParseDerTest
    it "serializes DER signature" ecdsaSignatureSerializeDerTest
  describe "signatures" $ do
    it "verifies signature" ecdsaVerifyTest
    -- TODO:
    -- , testCase "RFC6979 nonce function"   nonce_function_rfc6979_test
    it "signs message" ecdsaSignTest
  describe "secret keys" $ do
    it "verifies secret key" ecSecKeyVerifyTest
    it "creates public key" ecPubkeyCreateTest
    it "adds secret key" ecSecKeyTweakAddTest
    it "multiplies secret key" ecSecKeyTweakMulTest
  describe "public keys" $ do
    it "adds public key" ecPubKeyTweakAddTest
    it "multiplies public key" ecPubKeyTweakMulTest
    it "combines public keys" ecPubKeyCombineTest

withCtxPtr :: CtxFlags -> (Ptr LCtx -> IO a) -> IO a
withCtxPtr f = bracket (contextCreate f) contextDestroy

withEntropy :: (Ptr Seed32 -> IO a) -> IO a
withEntropy f =
  getEntropy 32 >>= \e ->
    useByteString e $ \(s, _) -> f s

createContextTest :: Assertion
createContextTest = withCtxPtr signVerify $ \ctx -> do
  assertBool "context not null" $ ctx /= nullPtr

randomizeContextTest :: Assertion
randomizeContextTest = withCtxPtr sign $ \ctx -> do
  ret <- withEntropy (contextRandomize ctx)
  assertBool "context randomized" $ isSuccess ret

cloneContextTest :: Assertion
cloneContextTest = do
  (x1, x2) <- liftIO $ do
    x1 <- contextCreate signVerify
    ret <- withEntropy $ contextRandomize x1
    unless (isSuccess ret) $ error "failed to randomize context"
    x2 <- contextClone x1
    return (x1, x2)
  assertBool "original context not null" $ x1 /= nullPtr
  assertBool "cloned context not null" $ x2 /= nullPtr
  assertBool "context ptrs different" $ x1 /= x2

ecPubkeyParseTest :: Assertion
ecPubkeyParseTest = do
  ret <- liftIO $ useAsCStringLen der $ \(i, il) -> do
    x <- contextCreate verify
    allocaBytes 64 $ \pubkey ->
      ecPubKeyParse x pubkey (castPtr i) (fromIntegral il)
  assertBool "parsed public key" (isSuccess ret)
  where
    der =
      decodeBase16 $
        assertBase16
          "03dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd44705"

ecPubKeySerializeTest :: Assertion
ecPubKeySerializeTest = do
  (ret, dec) <- liftIO $
    useByteString der $ \(i, il) ->
      allocaBytes 64 $ \k ->
        alloca $ \ol ->
          allocaBytes 72 $ \o -> do
            poke ol 72
            x <- contextCreate verify
            ret1 <- ecPubKeyParse x k i il
            unless (isSuccess ret1) $ error "failed to parse pubkey"
            ret2 <- ecPubKeySerialize x o ol k compressed
            len <- fromIntegral <$> peek ol
            decoded <- packCStringLen (castPtr o, len)
            return (ret2, decoded)
  assertBool "serialized public key successfully" $ isSuccess ret
  assertEqual "public key matches" der dec
  where
    der =
      decodeBase16 $
        assertBase16
          "03dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd44705"

ecdsaSignatureParseDerTest :: Assertion
ecdsaSignatureParseDerTest = do
  ret <- liftIO $ useAsCStringLen der $ \(d, dl) -> allocaBytes 64 $ \s -> do
    x <- contextCreate verify
    ecdsaSignatureParseDer x s (castPtr d) (fromIntegral dl)
  assertBool "parsed signature successfully" $ isSuccess ret
  where
    der =
      decodeBase16 $
        assertBase16
          "3045022100f502bfa07af43e7ef265618b0d929a7619ee01d6150e37eb6eaaf2c8bd37\
          \fb2202206f0415ab0e9a977afd78b2c26ef39b3952096d319fd4b101c768ad6c132e30\
          \45"

parseDer :: Ptr LCtx -> ByteString -> IO ByteString
parseDer x bs =
  useAsCStringLen bs $ \(d, dl) ->
    allocaBytes 64 $ \s -> do
      ret <- ecdsaSignatureParseDer x s (castPtr d) (fromIntegral dl)
      unless (isSuccess ret) $ error "could not parse DER"
      packByteString (s, 64)

ecdsaSignatureSerializeDerTest :: Assertion
ecdsaSignatureSerializeDerTest = do
  (ret, enc) <- liftIO . bracket (contextCreate verify) contextDestroy $ \x -> do
    sig <- parseDer x der
    (ret, enc) <- alloca $ \ol ->
      allocaBytes 72 $ \o ->
        useByteString sig $ \(s, _) -> do
          poke ol 72
          ret <- ecdsaSignatureSerializeDer x o ol s
          len <- fromIntegral <$> peek ol
          enc <- packCStringLen (castPtr o, len)
          return (ret, enc)
    return (ret, enc)
  assertBool "serialization successful" $ isSuccess ret
  assertEqual "signatures match" der enc
  where
    der =
      decodeBase16 $
        assertBase16
          "3045022100f502bfa07af43e7ef265618b0d929a7619ee01d6150e37eb6eaaf2c8bd37\
          \fb2202206f0415ab0e9a977afd78b2c26ef39b3952096d319fd4b101c768ad6c132e30\
          \45"

ecdsaVerifyTest :: Assertion
ecdsaVerifyTest = withCtxPtr verify $ \ctx -> do
  ret <- liftIO $ do
    sig <- parseDer ctx der
    pk <- useByteString pub $ \(p, pl) ->
      allocaBytes 64 $ \k -> do
        ret <- ecPubKeyParse ctx k p (fromIntegral pl)
        unless (isSuccess ret) $ error "could not parse public key"
        packByteString (k, 64)
    useByteString msg $ \(m, _) ->
      useByteString pk $ \(k, _) ->
        useByteString sig $ \(s, _) ->
          ecdsaVerify ctx s m k
  assertBool "signature valid" $ isSuccess ret
  where
    der =
      decodeBase16 $
        assertBase16
          "3045022100f502bfa07af43e7ef265618b0d929a7619ee01d6150e37eb6eaaf2c8bd37\
          \fb2202206f0415ab0e9a977afd78b2c26ef39b3952096d319fd4b101c768ad6c132e30\
          \45"
    pub =
      decodeBase16 $
        assertBase16
          "04dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd447051221\
          \3d5ed790522c042dee8e85c4c0ec5f96800b72bc5940c8bc1c5e11e4fcbf"
    msg =
      decodeBase16 $
        assertBase16
          "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"

signCtx :: IO (Ptr LCtx)
signCtx =
  contextCreate sign >>= \c ->
    withEntropy (contextRandomize c) >>= \r ->
      unless (isSuccess r) (error "failed to randomize context") >> return c

withSignCtxPtr :: (Ptr LCtx -> IO a) -> IO a
withSignCtxPtr = bracket signCtx contextDestroy

createPubKey :: Ptr LCtx -> Ptr SecKey32 -> Ptr PubKey64 -> IO ()
createPubKey ctx k p = do
  ret <- ecPubKeyCreate ctx p k
  unless (isSuccess ret) $ error "failed to create public key"

ecdsaSignTest :: Assertion
ecdsaSignTest = do
  der <- liftIO $ withSignCtxPtr $ \ctx -> do
    allocaBytes 64 $ \s ->
      useByteString msg $ \(m, _) ->
        useByteString key $ \(k, _) ->
          alloca $ \ol ->
            allocaBytes 72 $ \o -> do
              poke ol 72
              ret1 <- ecdsaSign ctx s m k nullFunPtr nullPtr
              unless (isSuccess ret1) $ error "could not sign message"
              ret2 <- ecdsaSignatureSerializeDer ctx o ol s
              unless (isSuccess ret2) $ error "could not serialize signature"
              len <- peek ol
              packCStringLen (castPtr o, fromIntegral len)
  ret <- liftIO $ do
    pub <- withSignCtxPtr $ \ctx -> allocaBytes 64 $ \p ->
      useByteString key $ \(s, _) -> do
        createPubKey ctx s p
        packByteString (p, 64)
    withCtxPtr verify $ \ctx -> useByteString msg $ \(m, _) ->
      useByteString pub $ \(p, _) -> do
        s' <- parseDer ctx der
        useByteString s' $ \(s, _) -> ecdsaVerify ctx s m p
  assertBool "signature matches" (isSuccess ret)
  where
    msg =
      decodeBase16 $
        assertBase16
          "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"
    key =
      decodeBase16 $
        assertBase16
          "f65255094d7773ed8dd417badc9fc045c1f80fdc5b2d25172b031ce6933e039a"

ecSecKeyVerifyTest :: Assertion
ecSecKeyVerifyTest = withSignCtxPtr $ \ctx -> do
  ret <- liftIO $ useByteString key $ \(k, _) -> do
    ecSecKeyVerify ctx k
  assertBool "valid secret key" $ isSuccess ret
  where
    key =
      decodeBase16 $
        assertBase16
          "f65255094d7773ed8dd417badc9fc045c1f80fdc5b2d25172b031ce6933e039a"

ecPubkeyCreateTest :: Assertion
ecPubkeyCreateTest = withSignCtxPtr $ \ctx -> do
  pk <- liftIO $
    useByteString key $ \(s, _) ->
      allocaBytes 64 $ \k -> do
        createPubKey ctx s k
        allocaBytes 65 $ \o ->
          alloca $ \ol -> do
            poke ol 65
            rets <- ecPubKeySerialize ctx o ol k uncompressed
            unless (isSuccess rets) $ error "failed to serialize public key"
            len <- fromIntegral <$> peek ol
            packCStringLen (castPtr o, len)
  assertEqual "public key matches" pub pk
  where
    key =
      decodeBase16 $
        assertBase16
          "f65255094d7773ed8dd417badc9fc045c1f80fdc5b2d25172b031ce6933e039a"
    pub =
      decodeBase16 $
        assertBase16
          "04dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd447051221\
          \3d5ed790522c042dee8e85c4c0ec5f96800b72bc5940c8bc1c5e11e4fcbf"

ecSecKeyTweakAddTest :: Assertion
ecSecKeyTweakAddTest = do
  (ret, tweaked) <-
    liftIO . withSignCtxPtr $ \ctx ->
      useByteString tweak $ \(w, _) ->
        useByteString key $ \(k, _) -> do
          ret <- ecSecKeyTweakAdd ctx k w
          tweaked <- packByteString (k, 32)
          return (ret, tweaked)
  assertBool "successful secret key tweak" $ isSuccess ret
  assertEqual "tweaked keys match" expected tweaked
  where
    key =
      decodeBase16 $
        assertBase16
          "f65255094d7773ed8dd417badc9fc045c1f80fdc5b2d25172b031ce6933e039a"
    tweak =
      decodeBase16 $
        assertBase16
          "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"
    expected =
      decodeBase16 $
        assertBase16
          "ec1e3ce1cefa18a671d51125e2b249688d934b0e28f5d1665384d9b02f929059"

ecSecKeyTweakMulTest :: Assertion
ecSecKeyTweakMulTest = do
  (ret, tweaked) <- liftIO $ withSignCtxPtr $ \ctx -> do
    useByteString tweak $ \(w, _) -> useByteString key $ \(k, _) -> do
      ret <- ecSecKeyTweakMul ctx k w
      tweaked <- packByteString (k, 32)
      return (ret, tweaked)
  assertBool "successful secret key tweak" $ isSuccess ret
  assertEqual "tweaked keys match" expected tweaked
  where
    key =
      decodeBase16 $
        assertBase16
          "f65255094d7773ed8dd417badc9fc045c1f80fdc5b2d25172b031ce6933e039a"
    tweak =
      decodeBase16 $
        assertBase16
          "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"
    expected =
      decodeBase16 $
        assertBase16
          "a96f5962493acb179f60a86a9785fc7a30e0c39b64c09d24fe064d9aef15e4c0"

serializeKey :: Ptr LCtx -> Ptr PubKey64 -> IO ByteString
serializeKey x p = allocaBytes 72 $ \d -> alloca $ \dl -> do
  poke dl 72
  ret <- ecPubKeySerialize x d dl p uncompressed
  unless (isSuccess ret) $ error "could not serialize public key"
  len <- peek dl
  packCStringLen (castPtr d, fromIntegral len)

parseKey :: Ptr LCtx -> ByteString -> IO ByteString
parseKey x bs =
  allocaBytes 64 $ \p ->
    useByteString bs $ \(d, dl) -> do
      ret <- ecPubKeyParse x p d dl
      unless (isSuccess ret) $ error "could not parse public key"
      packByteString (p, 64)

ecPubKeyTweakAddTest :: Assertion
ecPubKeyTweakAddTest = do
  (ret, tweaked) <- liftIO $ do
    x <- contextCreate verify
    pk <- copy <$> parseKey x pub
    useByteString tweak $ \(w, _) ->
      useByteString pk $ \(p, _) -> do
        ret <- ecPubKeyTweakAdd x p w
        tweaked <- serializeKey x p
        return (ret, tweaked)
  assertBool "successful secret key tweak" $ isSuccess ret
  assertEqual "tweaked keys match" expected tweaked
  where
    pub =
      decodeBase16 $
        assertBase16
          "04dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd447051221\
          \3d5ed790522c042dee8e85c4c0ec5f96800b72bc5940c8bc1c5e11e4fcbf"
    tweak =
      decodeBase16 $
        assertBase16
          "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"
    expected =
      decodeBase16 $
        assertBase16
          "04441c3982b97576646e0df0c96736063df6b42f2ee566d13b9f6424302d1379e518fd\
          \c87a14c5435bff7a5db4552042cb4120c6b86a4bbd3d0643f3c14ad01368"

ecPubKeyTweakMulTest :: Assertion
ecPubKeyTweakMulTest = do
  (ret, tweaked) <- liftIO $ do
    x <- contextCreate verify
    pk <- copy <$> parseKey x pub
    useByteString tweak $ \(w, _) ->
      useByteString pk $ \(p, _) -> do
        ret <- ecPubKeyTweakMul x p w
        tweaked <- serializeKey x p
        return (ret, tweaked)
  assertBool "successful secret key tweak" $ isSuccess ret
  assertEqual "tweaked keys match" expected tweaked
  where
    pub =
      decodeBase16 $
        assertBase16
          "04dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd447051221\
          \3d5ed790522c042dee8e85c4c0ec5f96800b72bc5940c8bc1c5e11e4fcbf"
    tweak =
      decodeBase16 $
        assertBase16
          "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"
    expected =
      decodeBase16 $
        assertBase16
          "04f379dc99cdf5c83e433defa267fbb3377d61d6b779c06a0e4ce29ae3ff5353b12ae4\
          \9c9d07e7368f2ba5a446c203255ce912322991a2d6a9d5d5761c61ed1845"

ecPubKeyCombineTest :: Assertion
ecPubKeyCombineTest = do
  (ret, com) <- liftIO $
    allocaBytes 64 $ \p1 ->
      allocaBytes 64 $ \p2 ->
        allocaBytes 64 $ \p3 ->
          allocaArray 3 $ \a ->
            allocaBytes 64 $ \p -> do
              x <- contextCreate verify
              parse x pub1 p1
              parse x pub2 p2
              parse x pub3 p3
              pokeArray a [p1, p2, p3]
              ret <- ecPubKeyCombine x p a 3
              com <- serializeKey x p
              return (ret, com)
  assertBool "successful key combination" $ isSuccess ret
  assertEqual "combined keys match" expected com
  where
    parse x pub p = useByteString pub $ \(d, dl) -> do
      ret <- ecPubKeyParse x p d dl
      unless (isSuccess ret) $ error "could not parse public key"
    pub1 =
      decodeBase16 $
        assertBase16
          "04dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd447051221\
          \3d5ed790522c042dee8e85c4c0ec5f96800b72bc5940c8bc1c5e11e4fcbf"
    pub2 =
      decodeBase16 $
        assertBase16
          "0487d82042d93447008dfe2af762068a1e53ff394a5bf8f68a045fa642b99ea5d153f5\
          \77dd2dba6c7ae4cfd7b6622409d7edd2d76dd13a8092cd3af97b77bd2c77"
    pub3 =
      decodeBase16 $
        assertBase16
          "049b101edcbe1ee37ff6b2318526a425b629e823d7d8d9154417880595a28000ee3feb\
          \d908754b8ce4e491aa6fe488b41fb5d4bb3788e33c9ff95a7a9229166d59"
    expected =
      decodeBase16 $
        assertBase16
          "043d9a7ec70011efc23c33a7e62d2ea73cca87797e3b659d93bea6aa871aebde56c3bc\
          \6134ca82e324b0ab9c0e601a6d2933afe7fb5d9f3aae900f5c5dc6e362c8"
