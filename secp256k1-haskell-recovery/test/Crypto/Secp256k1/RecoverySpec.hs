module Crypto.Secp256k1.RecoverySpec (spec) where

import Crypto.Secp256k1 (verifySig)
import Crypto.Secp256k1.Recovery
import Data.Base16.Types (assertBase16, extractBase16)
import qualified Data.ByteString as BS
import Data.ByteString.Base16 (decodeBase16, encodeBase16)
import qualified Data.ByteString.Char8 as B8
import Data.Maybe (fromJust)
import Data.String (fromString)
import Data.String.Conversions (cs)
import Test.HUnit (Assertion, assertEqual)
import Test.Hspec
import Test.QuickCheck

spec :: Spec
spec = around withContext $ do
  describe "recovery" $ do
    it "recovers public keys" $ property . recoverTest
    it "recovers key from signed message" $ property . signRecMsgTest
    it "does not recover bad public keys" $ property . badRecoverTest
    it "detects bad recoverable signature" $ property . badRecSignatureTest
    it "serializes compact recoverable signature" $ property . serializeCompactRecSigTest
    it "shows and reads recoverable signature" $ property . showReadCompactRecSig
    it "reads recoverable signature from string" $ property . isStringCompactRecSig
    it "produces the expected signature" $ property . producesExpectedSignature
    it "recovers the expected pub key" $ property . recoversExpectedPubKey

hexToBytes :: String -> BS.ByteString
hexToBytes = decodeBase16 . assertBase16 . B8.pack

bytesToHex :: B8.ByteString -> String
bytesToHex = cs . extractBase16 . encodeBase16

showRead :: (Show a, Read a, Eq a) => a -> Bool
showRead x = read (show x) == x

exampleSecKey :: SecKey
exampleSecKey =
  fromJust . secKey $
    hexToBytes "0101010101010101010101010101010101010101010101010101010101010101"

examplePubKey' :: Ctx -> PubKey
examplePubKey' ctx =
  derivePubKey ctx exampleSecKey

exampleMsg :: Msg
exampleMsg =
  fromJust . msg $
    hexToBytes "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

exampleRecSig' :: Ctx -> RecSig
exampleRecSig' ctx =
  fromJust . importCompactRecSig ctx . fromJust . compactRecSig $
    hexToBytes
      "02559ab98a8908ba4cf0f914eb8b66651405ab69ab7c461dd140e40baa1b5e1d\
      \2ef6ac88a13e2226f76a9d8d49bb9cf3061dac1364c0dfe7b69cd165a8d08f07\
      \00"

recoverTest :: Ctx -> (Msg, SecKey) -> Bool
recoverTest ctx (fm, fk) = recover ctx fg fm == Just fp
  where
    fp = derivePubKey ctx fk
    fg = signRecMsg ctx fk fm

signRecMsgTest :: Ctx -> (Msg, SecKey) -> Bool
signRecMsgTest ctx (fm, fk) = verifySig ctx fp fg fm
  where
    fp = derivePubKey ctx fk
    fg = convertRecSig ctx $ signRecMsg ctx fk fm

badRecoverTest :: Ctx -> (Msg, SecKey, Msg) -> Property
badRecoverTest ctx (fm, fk, fm') =
  fm' /= fm ==> fp' /= Nothing ==> fp' /= Just fp
  where
    fg = signRecMsg ctx fk fm
    fp = derivePubKey ctx fk
    fp' = recover ctx fg fm'

badRecSignatureTest :: Ctx -> (Msg, SecKey, SecKey) -> Bool
badRecSignatureTest ctx (fm, fk, fk2) = not $ verifySig ctx fp fg fm
  where
    fp = derivePubKey ctx fk2
    fg = convertRecSig ctx $ signRecMsg ctx fk fm

serializeCompactRecSigTest :: Ctx -> (Msg, SecKey) -> Bool
serializeCompactRecSigTest ctx (fm, fk) =
  case importCompactRecSig ctx $ exportCompactRecSig ctx fg of
    Just fg' -> fg == fg'
    Nothing -> False
  where
    fg = signRecMsg ctx fk fm

showReadCompactRecSig :: Ctx -> (SecKey, Msg) -> Bool
showReadCompactRecSig ctx (k, m) = showRead crecSig
  where
    crecSig = exportCompactRecSig ctx $ signRecMsg ctx k m

isStringCompactRecSig :: Ctx -> (SecKey, Msg) -> Bool
isStringCompactRecSig ctx (k, m) = Just g == importCompactRecSig ctx (fromString hex)
  where
    g = signRecMsg ctx k m
    hex = bytesToHex . serializeCompactRecSig $ exportCompactRecSig ctx g

producesExpectedSignature :: Ctx -> Assertion
producesExpectedSignature ctx =
  assertEqual "produced signature matches" (exportCompactRecSig ctx (exampleRecSig' ctx)) $
    exportCompactRecSig ctx (signRecMsg ctx exampleSecKey exampleMsg)

recoversExpectedPubKey :: Ctx -> Assertion
recoversExpectedPubKey ctx =
  assertEqual "recovered pub key matches" (Just (examplePubKey' ctx)) $
    recover ctx (exampleRecSig' ctx) exampleMsg
