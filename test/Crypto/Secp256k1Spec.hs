{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}

module Crypto.Secp256k1Spec (spec) where

import Control.Arrow (first)
import Control.Monad.Par qualified as P
import Crypto.Secp256k1
import Data.Base16.Types (assertBase16, extractBase16)
import Data.ByteString qualified as BS
import Data.ByteString.Base16 (decodeBase16, encodeBase16)
import Data.ByteString.Char8 qualified as B8
import Data.Either (fromRight)
import Data.Maybe (fromJust, fromMaybe, isJust, isNothing)
import Data.String (fromString)
import Data.String.Conversions (cs)
import Test.HUnit (Assertion, assertBool, assertEqual)
import Test.Hspec
import Test.QuickCheck

spec :: Spec
spec = around withContext $ do
  describe "signatures" $ do
    it "signs message" $ \ctx ->
      property $ signMsgTest ctx
    it "signs messages in parallel" $ \ctx ->
      property $ signMsgParTest ctx
    it "detects bad signature" $ \ctx ->
      property $ badSignatureTest ctx
    it "normalizes signatures" $ \ctx ->
      property $ normalizeSigTest ctx
  describe "serialization" $ do
    it "serializes public key" $ \ctx ->
      property $ serializePubKeyTest ctx
    it "serializes public keys in parallel" $ \ctx ->
      property $ parSerializePubKeyTest ctx
    it "serializes DER signature" $ \ctx ->
      property $ serializeSigTest ctx
    it "serializes DER signatures in parallel" $ \ctx ->
      property $ parSerializeSigTest ctx
    it "serializes compact signature" $ \ctx ->
      property $ serializeCompactSigTest ctx
    it "serialize secret key" $ \_ ->
      property serializeSecKeyTest
    it "shows and reads secret key" $ \_ ->
      property (showRead :: SecKey -> Bool)
    it "shows and reads tweak" $ \_ ->
      property showReadTweak
    it "shows and reads message" $ \_ ->
      property (showRead :: Msg -> Bool)
    it "shows and reads public key" $ \ctx ->
      property $ showReadPubKey ctx
    it "reads secret key from string" $ \_ ->
      property isStringSecKey
    it "reads message from string" $ \_ ->
      property isStringMsg
    it "reads tweak from string" $ \_ ->
      property isStringTweak
  describe "tweaks" $ do
    it "add secret key" $ \ctx ->
      property $ tweakAddSecKeyTest ctx
    it "multiply secret key" $ \ctx ->
      property $ tweakMulSecKeyTest ctx
    it "add public key" $ \ctx ->
      property $ tweakAddPubKeyTest ctx
    it "multiply public key" $ \ctx ->
      property $ tweakMulPubKeyTest ctx
    it "combine public keys" $ \ctx ->
      property $ combinePubKeyTest ctx
    it "can't combine 0 public keys" $ \ctx ->
      property $ combinePubKeyEmptyListTest ctx
    it "negates tweak" $ \ctx ->
      property $ negateTweakTest ctx

hexToBytes :: String -> BS.ByteString
hexToBytes = decodeBase16 . assertBase16 . B8.pack

isStringMsg :: Msg -> Bool
isStringMsg m = m == fromString (cs m')
  where
    m' = (extractBase16 . encodeBase16) m.get

isStringSecKey :: SecKey -> Bool
isStringSecKey k = k == fromString (cs hex)
  where
    hex = (extractBase16 . encodeBase16) k.get

isStringTweak :: SecKey -> Bool
isStringTweak k = t == fromString (cs hex)
  where
    t = (fromMaybe e . tweak) k.get
    hex = (extractBase16 . encodeBase16) t.get
    e = error "Could not extract tweak from secret key"

showReadTweak :: SecKey -> Bool
showReadTweak k = showRead t
  where
    t = tweak k.get

showReadPubKey :: Ctx -> SecKey -> Bool
showReadPubKey ctx k =
  (read . show) p == p
  where
    p = derivePubKey ctx k

showRead :: (Show a, Read a, Eq a) => a -> Bool
showRead x = read (show x) == x

signMsgTest :: Ctx -> (Msg, SecKey) -> Bool
signMsgTest ctx (fm, fk) = verifySig ctx fp fg fm
  where
    fp = derivePubKey ctx fk
    fg = signMsg ctx fk fm

signMsgParTest :: Ctx -> [(Msg, SecKey)] -> Bool
signMsgParTest ctx xs = P.runPar $ do
  ys <- mapM (P.spawnP . signMsgTest ctx) xs
  and <$> mapM P.get ys

badSignatureTest :: Ctx -> (Msg, SecKey, SecKey) -> Bool
badSignatureTest ctx (fm, fk, fk') = not $ verifySig ctx fp fg fm
  where
    fp = derivePubKey ctx fk'
    fg = signMsg ctx fk fm

normalizeSigTest :: Ctx -> (Msg, SecKey) -> Bool
normalizeSigTest ctx (fm, fk) = isNothing sig
  where
    fg = signMsg ctx fk fm
    sig = normalizeSig ctx fg

serializePubKeyTest :: Ctx -> (SecKey, Bool) -> Bool
serializePubKeyTest ctx (fk, b) =
  case importPubKey ctx $ exportPubKey ctx b fp of
    Just fp' -> fp == fp'
    Nothing -> False
  where
    fp = derivePubKey ctx fk

parSerializePubKeyTest :: Ctx -> [(SecKey, Bool)] -> Bool
parSerializePubKeyTest ctx ks = P.runPar $ do
  as <- mapM (P.spawnP . serializePubKeyTest ctx) ks
  and <$> mapM P.get as
  where
    ps = map (first (derivePubKey ctx)) ks

serializeSigTest :: Ctx -> (Msg, SecKey) -> Bool
serializeSigTest ctx (fm, fk) =
  case importSig ctx $ exportSig ctx fg of
    Just fg' -> fg == fg'
    Nothing -> False
  where
    fg = signMsg ctx fk fm

parSerializeSigTest :: Ctx -> [(Msg, SecKey)] -> Bool
parSerializeSigTest ctx ms = P.runPar $ do
  as <- mapM (P.spawnP . serializeSigTest ctx) ms
  and <$> mapM P.get as

serializeCompactSigTest :: Ctx -> (Msg, SecKey) -> Bool
serializeCompactSigTest ctx (fm, fk) =
  case importCompactSig ctx $ exportCompactSig ctx fg of
    Just fg' -> fg == fg'
    Nothing -> False
  where
    fg = signMsg ctx fk fm

serializeSecKeyTest :: SecKey -> Bool
serializeSecKeyTest fk =
  case secKey fk.get of
    Just fk' -> fk == fk'
    Nothing -> False

tweakAddSecKeyTest :: Ctx -> Assertion
tweakAddSecKeyTest ctx =
  assertEqual "tweaked keys match" expected tweaked
  where
    tweaked = do
      key <-
        secKey $
          hexToBytes
            "f65255094d7773ed8dd417badc9fc045c1f80fdc5b2d25172b031ce6933e039a"
      twk <-
        tweak $
          hexToBytes
            "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"
      tweakAddSecKey ctx key twk
    expected =
      secKey $
        hexToBytes
          "ec1e3ce1cefa18a671d51125e2b249688d934b0e28f5d1665384d9b02f929059"

tweakMulSecKeyTest :: Ctx -> Assertion
tweakMulSecKeyTest ctx =
  assertEqual "tweaked keys match" expected tweaked
  where
    tweaked = do
      key <-
        secKey $
          hexToBytes
            "f65255094d7773ed8dd417badc9fc045c1f80fdc5b2d25172b031ce6933e039a"
      twk <-
        tweak $
          hexToBytes
            "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"
      tweakMulSecKey ctx key twk
    expected =
      secKey $
        hexToBytes
          "a96f5962493acb179f60a86a9785fc7a30e0c39b64c09d24fe064d9aef15e4c0"

tweakAddPubKeyTest :: Ctx -> Assertion
tweakAddPubKeyTest ctx = do
  assertBool "did not fail to decode" $ isJust tweaked
  assertBool "is not empty" $ not $ maybe False BS.null tweaked
  assertEqual "tweaked keys match" expected tweaked
  where
    tweaked = do
      pub <-
        importPubKey ctx $
          hexToBytes
            "04dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd4470512213d5ed790522c042dee8e85c4c0ec5f96800b72bc5940c8bc1c5e11e4fcbf"
      twk <-
        tweak $
          hexToBytes
            "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"
      key <- tweakAddPubKey ctx pub twk
      return $ exportPubKey ctx True key
    expected = do
      key <-
        importPubKey ctx $
          hexToBytes
            "04441c3982b97576646e0df0c96736063df6b42f2ee566d13b9f6424302d1379e518fdc87a14c5435bff7a5db4552042cb4120c6b86a4bbd3d0643f3c14ad01368"
      return $ exportPubKey ctx True key

tweakMulPubKeyTest :: Ctx -> Assertion
tweakMulPubKeyTest ctx = do
  assertBool "did not fail to decode" $ isJust tweaked
  assertBool "is not empty" $ not $ maybe False BS.null tweaked
  assertEqual "tweaked keys match" expected tweaked
  where
    tweaked = do
      pub <-
        importPubKey ctx $
          hexToBytes
            "04dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd4470512213d5ed790522c042dee8e85c4c0ec5f96800b72bc5940c8bc1c5e11e4fcbf"
      twk <-
        tweak $
          hexToBytes
            "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"
      key <- tweakMulPubKey ctx pub twk
      return $ exportPubKey ctx True key
    expected = do
      key <-
        importPubKey ctx $
          hexToBytes
            "04f379dc99cdf5c83e433defa267fbb3377d61d6b779c06a0e4ce29ae3ff5353b12ae49c9d07e7368f2ba5a446c203255ce912322991a2d6a9d5d5761c61ed1845"
      return $ exportPubKey ctx True key

combinePubKeyTest :: Ctx -> Assertion
combinePubKeyTest ctx = do
  assertBool "did not fail to decode" $ isJust combined
  assertBool "is not empty" $ not $ maybe False BS.null combined
  assertEqual "combined keys match" expected combined
  where
    combined = do
      pub1 <-
        importPubKey ctx $
          hexToBytes
            "04dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd4470512213d5ed790522c042dee8e85c4c0ec5f96800b72bc5940c8bc1c5e11e4fcbf"
      pub2 <-
        importPubKey ctx $
          hexToBytes
            "0487d82042d93447008dfe2af762068a1e53ff394a5bf8f68a045fa642b99ea5d153f577dd2dba6c7ae4cfd7b6622409d7edd2d76dd13a8092cd3af97b77bd2c77"
      pub3 <-
        importPubKey ctx $
          hexToBytes
            "049b101edcbe1ee37ff6b2318526a425b629e823d7d8d9154417880595a28000ee3febd908754b8ce4e491aa6fe488b41fb5d4bb3788e33c9ff95a7a9229166d59"
      key <- combinePubKeys ctx [pub1, pub2, pub3]
      return $ exportPubKey ctx True key
    expected = do
      key <-
        importPubKey ctx $
          hexToBytes
            "043d9a7ec70011efc23c33a7e62d2ea73cca87797e3b659d93bea6aa871aebde56c3bc6134ca82e324b0ab9c0e601a6d2933afe7fb5d9f3aae900f5c5dc6e362c8"
      return $ exportPubKey ctx True key

combinePubKeyEmptyListTest :: Ctx -> Assertion
combinePubKeyEmptyListTest ctx =
  assertEqual "empty pubkey list must return Nothing" expected combined
  where
    expected = Nothing
    combined = do
      key <- combinePubKeys ctx []
      return $ exportPubKey ctx True key

negateTweakTest :: Ctx -> Assertion
negateTweakTest ctx =
  assertEqual "can recover secret key 1 after adding tweak 1" oneKey subtracted
  where
    Just oneKey =
      secKey . decodeBase16 . assertBase16 $
        B8.pack
          "0000000000000000000000000000000000000000000000000000000000000001"
    Just oneTwk =
      tweak . decodeBase16 . assertBase16 $
        B8.pack
          "0000000000000000000000000000000000000000000000000000000000000001"
    Just minusOneTwk = tweakNegate ctx oneTwk
    Just twoKey = tweakAddSecKey ctx oneKey oneTwk
    Just subtracted = tweakAddSecKey ctx twoKey minusOneTwk
