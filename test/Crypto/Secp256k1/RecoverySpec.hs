{-# LANGUAGE CPP #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | ECDSA public key recovery. The module under test only exists when the
-- @recovery@ flag of the package is on, so the whole specification is behind
-- the same flag. This module avoids string gaps, because CPP would join
-- their lines.
module Crypto.Secp256k1.RecoverySpec (spec) where

import Test.Hspec

#ifdef RECOVERY

import Control.DeepSeq (deepseq)
import Control.Exception (evaluate)
import Control.Monad (forM_)
import Control.Monad.Par qualified as P
import Crypto.Secp256k1
import Crypto.Secp256k1.Fixtures
import Crypto.Secp256k1.Internal.Base (CompactSig (CompactSig), Msg (Msg), SecKey (SecKey))
import Crypto.Secp256k1.Internal.Recovery (RecSig (RecSig))
import Crypto.Secp256k1.Recovery
import Data.Bits (xor)
import Data.ByteString qualified as BS
import Data.Hashable (hash)
import Data.Maybe (fromJust, isJust)
import Data.String (fromString)
import Data.Word (Word8)
import Test.QuickCheck
import Text.Read (readMaybe)

spec :: Spec
spec = around withContext $ describe "public key recovery" $ do
  signingSpec
  recoverySpec
  formulaSpec
  compactSpec
  valueSpec
  rawValueSpec
  instanceSpec

-- * Fixtures
--
-- As in "Crypto.Secp256k1.Fixtures", every expected value is a literal from
-- an independent source, recomputed with an independent implementation of
-- the curve.

-- Bitcoin Core key_tests.cpp: the SignCompact signature of coreKey over
-- coreMsg is 20 ++ coreR ++ coreS. The header byte 0x20 = 32 = 27 + 1 + 4
-- says recovery id 1 and a compressed key. coreDer is 30440220 ++ coreR ++
-- 0220 ++ coreS.
coreR, coreS :: String
coreR = "5dbbddda71772d95ce91cd2d14b592cfbc1dd0aabd6a394b6c2d377bbe59d31d"
coreS = "14ddda21494a4e221f0824f0b8b924c43fa43c0ad57dccdaa11f81a6bd4582f6"

coreRecId :: Word8
coreRecId = 1

-- The compressed public key of coreKey, and the key that recovery id 0 gives
-- for the same signature.
corePub, coreOtherPub :: String
corePub = "030b4c866585dd868a9d62348a9cd008d6a312937048fff31670e7e920cfc7a744"
coreOtherPub = "02818f8ef9ebd82871789a39ea0385398c267d3d6bb6f537166bd813135870c8ec"

-- Bitcoin Core util_tests.cpp, message_sign: the key of the address
-- 15CRxFdyRpGZLW9w8HnHvVduizdL5jKNbs signs the message "Trust no one".
messageKey :: SecKey
messageKey = "d97f5108f11cda6eeebaaa420fef0726b1f898060b98489fa3098463c0032866"

-- sha256d of the varstrings "Bitcoin Signed Message:\n" and "Trust no one".
messageHash :: Msg
messageHash = "aa8215d723ecd2f14867eeb7e19f192be7bc15a2352a24b991d4f5870cbaf6e8"

-- The expected signature, base64
-- IPojfrX2dfPnH26UegfbGQQLrdK844DlHq5157/P6h57WyuS/Qsl+h/WSVGDF4MUi4rWSswW38oimDYfNNUBUOk=
-- decoded: the header byte 0x20, recovery id 1 and a compressed key, then r
-- and s.
messageR, messageS :: String
messageR = "fa237eb5f675f3e71f6e947a07db19040badd2bce380e51eae75e7bfcfea1e7b"
messageS = "5b2b92fd0b25fa1fd64951831783148b8ad64acc16dfca2298361f34d50150e9"

-- The compressed public key of messageKey.
messagePub :: String
messagePub = "03d2be3dddb497c7c4388cfcb941e14a222cf3e26fe5e2cc260da1821e60d26022"

-- The RFC 6979 vector has recovery id 1. Recovery id 0 gives this other key.
satoshiOtherPub :: String
satoshiOtherPub = "0354d58835e07b996d6378eafa930ae9d2211e767381f1d52aedc67f48c8886f0b"

-- Key 1 signing sha256 "4" (highRDer): r, s and recovery id 0.
highRR, highRS :: String
highRR = "d479c93a086bf5f4ae1fed7eaf2604a4da2007d851c5409961c81dd7f0600194"
highRS = "1cd7a196454152f5b8d19865d49b4fa71e314ebff9c59e2f7b2295bf80331be8"

-- Values for the formula Q = r⁻¹(s·R − e·G).
two, five :: String
two = "0000000000000000000000000000000000000000000000000000000000000002"
-- 5³ + 7 = 132 is not a square modulo p, so no point has x = 5.
five = "0000000000000000000000000000000000000000000000000000000000000005"

-- x = 1 is on the curve: 1 + 7 = 8 is a square modulo p. pointOne is the
-- point with x = 1 and an even y, so its compressed encoding is 02 ++ one and
-- that of its negation is 03 ++ one.
pointOne, pointOneMinusG, twicePointOne :: String
pointOne = "02" ++ one
pointOneMinusG = "02871e0c836ec675e07395aef58d72b646f77e0e33ce1622dfaa0fb8e131f3fe12"
twicePointOne = "03c7ffffffffffffffffffffffffffffffffffffffffffffffffffffff37fffd03"

-- x = n + 2 is on the curve, x = n + 1 is not.
orderPlusTwo :: String
orderPlusTwo = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364143"

-- Half of the point with x = n + 2 and an even y.
halfPointOrderPlusTwo :: String
halfPointOrderPlusTwo = "02ad802f2145df548ce1fc418b851cb32669c5a6bb939e6caf744de90310f8f1ff"

-- p − n and p − n − 1. With the recovery id 2, the first gives x = p, which
-- is outside the field, and the second x = p − 1, which is not on the curve.
fieldMinusOrder, fieldMinusOrderMinusOne :: String
fieldMinusOrder = "000000000000000000000000000000014551231950b75fc4402da1722fc9baee"
fieldMinusOrderMinusOne = "000000000000000000000000000000014551231950b75fc4402da1722fc9baed"

-- The x coordinate of G, and the key −(x⁻¹)·G.
genX, genNegatedOverX :: String
genX = drop 2 genCompressed
genNegatedOverX = "028ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218"

-- * Signing

signingSpec :: SpecWith Ctx
signingSpec = describe "signing" $ do
  it "produces Bitcoin Core's SignCompact signature of sha256d 'Very deterministic message'" $ \ctx ->
    exportCompactRecSig ctx (signRecMsg ctx coreKey coreMsg)
      `shouldBe` (fromString (coreR ++ coreS), coreRecId)
  it "produces Bitcoin Core's signmessage signature of 'Trust no one'" $ \ctx ->
    exportCompactRecSig ctx (signRecMsg ctx messageKey messageHash)
      `shouldBe` (fromString (messageR ++ messageS), 1)
  it "produces the RFC 6979 vector with recovery id 1" $ \ctx ->
    exportCompactRecSig ctx (signRecMsg ctx keyOne satoshiMsg)
      `shouldBe` (fromString (satoshiR ++ satoshiS), 1)
  it "keeps a high r, as Bitcoin Core's message signing does" $ \ctx -> do
    exportCompactRecSig ctx (signRecMsg ctx keyOne highRMsg)
      `shouldBe` (fromString (highRR ++ highRS), 0)
    convertRecSig ctx (signRecMsg ctx keyOne highRMsg) `shouldNotBe` signMsgLowR ctx keyOne highRMsg
  it "signs with the r and s of signMsg" $ \ctx ->
    property $ \(m :: Msg, k :: SecKey) -> convertRecSig ctx (signRecMsg ctx k m) == signMsg ctx k m
  it "is deterministic" $ \ctx ->
    property $ \(m :: Msg, k :: SecKey) -> signRecMsg ctx k m == signRecMsg ctx k m
  it "gives a recovery id of 0 or 1" $ \ctx ->
    -- The ids 2 and 3 need r below p - n, about one signature in 2^128.
    property $ \(m :: Msg, k :: SecKey) ->
      snd (exportCompactRecSig ctx (signRecMsg ctx k m)) `elem` [0, 1]
  it "produces lower-S signatures" $ \ctx ->
    property $ \(m :: Msg, k :: SecKey) -> isLowS ctx (convertRecSig ctx (signRecMsg ctx k m))
  it "signs and recovers in parallel" $ \ctx ->
    property $ \(xs :: [(Msg, SecKey)]) -> P.runPar $ do
      results <- mapM (P.spawnP . signsAndRecovers ctx) xs
      and <$> mapM P.get results
  where
    signsAndRecovers ctx (m, k) =
      recover ctx (signRecMsg ctx k m) m == Just (derivePubKey ctx k)

-- * Recovery

recoverySpec :: SpecWith Ctx
recoverySpec = describe "recovery" $ do
  it "recovers the key of Bitcoin Core's SignCompact vector" $ \ctx ->
    recovered ctx (coreR ++ coreS ++ "01") coreMsg `shouldBe` Just corePub
  it "recovers another key with the other recovery id" $ \ctx ->
    recovered ctx (coreR ++ coreS ++ "00") coreMsg `shouldBe` Just coreOtherPub
  it "recovers the signer of Bitcoin Core's 'Trust no one' message" $ \ctx ->
    recovered ctx (messageR ++ messageS ++ "01") messageHash `shouldBe` Just messagePub
  it "recovers G from the RFC 6979 vector" $ \ctx -> do
    recovered ctx (satoshiR ++ satoshiS ++ "01") satoshiMsg `shouldBe` Just genCompressed
    recovered ctx (satoshiR ++ satoshiS ++ "00") satoshiMsg `shouldBe` Just satoshiOtherPub
  it "recovers the signing key" $ \ctx ->
    property $ \(m :: Msg, k :: SecKey) ->
      recover ctx (signRecMsg ctx k m) m == Just (derivePubKey ctx k)
  it "recovers a different key for another message" $ \ctx ->
    property $ \(m :: Msg, m' :: Msg, k :: SecKey) ->
      m /= m' ==> recover ctx (signRecMsg ctx k m) m' /= Just (derivePubKey ctx k)
  it "recovers the same key from the high-S form with the parity bit flipped" $ \ctx -> do
    -- The RFC 6979 vector with s replaced by n - s and the id 1 turned into 0.
    recovered ctx (satoshiR ++ satoshiHighS ++ "00") satoshiMsg `shouldBe` Just genCompressed
    recovered ctx (satoshiR ++ satoshiHighS ++ "01") satoshiMsg `shouldNotBe` Just genCompressed
  it "does not apply the lower-S rule" $ \ctx ->
    property $ \(m :: Msg, k :: SecKey) ->
      let (compact, i) = exportCompactRecSig ctx (signRecMsg ctx k m)
          (r, s) = BS.splitAt 32 compact.get
          -- n - s, through the negation of a tweak.
          highS = (fromJust (tweakNegate ctx (fromJust (tweak s)))).get
          high = fromJust (importCompactRecSig ctx (fromJust (compactSig (r <> highS))) (i `xor` 1))
       in recover ctx high m == Just (derivePubKey ctx k)
  where
    recovered ctx sigHex m = bytesToHex . exportPubKey ctx True <$> recover ctx (fromString sigHex) m

-- * The formula

formulaSpec :: SpecWith Ctx
formulaSpec = describe "the formula Q = r⁻¹(s·R − e·G)" $ do
  it "gives R itself for r = 1, s = 1 and a zero hash" $ \ctx ->
    recovered ctx (one ++ one ++ "00") zero `shouldBe` Just pointOne
  it "takes the parity of y from the recovery id" $ \ctx ->
    recovered ctx (one ++ one ++ "01") zero `shouldBe` Just ("03" ++ one)
  it "reduces the hash modulo n" $ \ctx ->
    recovered ctx (one ++ one ++ "00") order `shouldBe` Just pointOne
  it "subtracts e·G" $ \ctx ->
    recovered ctx (one ++ one ++ "00") one `shouldBe` Just pointOneMinusG
  it "multiplies by s" $ \ctx -> do
    recovered ctx (one ++ two ++ "00") zero `shouldBe` Just twicePointOne
    recovered ctx (one ++ orderMinusOne ++ "00") zero `shouldBe` Just ("03" ++ one)
  it "divides by r" $ \ctx ->
    recovered ctx (two ++ one ++ "02") zero `shouldBe` Just halfPointOrderPlusTwo
  it "uses r + n as the x coordinate for the ids 2 and 3" $ \ctx -> do
    recovered ctx (two ++ two ++ "02") zero `shouldBe` Just ("02" ++ orderPlusTwo)
    recovered ctx (two ++ two ++ "03") zero `shouldBe` Just ("03" ++ orderPlusTwo)
  it "gives nothing when no point has the x coordinate" $ \ctx -> do
    recovered ctx (five ++ one ++ "00") zero `shouldBe` Nothing
    recovered ctx (one ++ one ++ "02") zero `shouldBe` Nothing
    recovered ctx (fieldMinusOrderMinusOne ++ one ++ "02") zero `shouldBe` Nothing
  it "gives nothing when r + n reaches the field size" $ \ctx ->
    recovered ctx (fieldMinusOrder ++ one ++ "02") zero `shouldBe` Nothing
  it "gives nothing when s·R − e·G is the point at infinity" $ \ctx -> do
    -- R = G, s = 1 and e = 1: G - G.
    recovered ctx (genX ++ one ++ "00") one `shouldBe` Nothing
    -- With e = 2 instead: (G - 2G) / x = -(x⁻¹)·G.
    recovered ctx (genX ++ one ++ "00") two `shouldBe` Just genNegatedOverX
  where
    recovered ctx sigHex msgHex =
      bytesToHex . exportPubKey ctx True <$> recover ctx (fromString sigHex) (fromString msgHex)

-- * Compact encoding

compactSpec :: SpecWith Ctx
compactSpec = describe "compact encoding" $ do
  it "imports and exports back the same signature" $ \ctx ->
    property $ \(m :: Msg, k :: SecKey) ->
      let s = signRecMsg ctx k m
          (compact, i) = exportCompactRecSig ctx s
       in importCompactRecSig ctx compact i == Just s
  it "accepts the recovery ids 0 to 3 and rejects 4 and 255" $ \ctx -> do
    forM_ [0 .. 3] $ \i -> importCompactRecSig ctx (fromString (one ++ one)) i `shouldSatisfy` isJust
    importCompactRecSig ctx (fromString (one ++ one)) 4 `shouldBe` Nothing
    importCompactRecSig ctx (fromString (one ++ one)) 255 `shouldBe` Nothing
  it "accepts components of 1 and n - 1 and rejects 0 and n" $ \ctx -> do
    importCompactRecSig ctx (fromString (one ++ one)) 0 `shouldSatisfy` isJust
    importCompactRecSig ctx (fromString (orderMinusOne ++ orderMinusOne)) 0 `shouldSatisfy` isJust
    importCompactRecSig ctx (fromString (order ++ one)) 0 `shouldBe` Nothing
    importCompactRecSig ctx (fromString (one ++ order)) 0 `shouldBe` Nothing
    importCompactRecSig ctx (fromString (zero ++ one)) 0 `shouldBe` Nothing
    importCompactRecSig ctx (fromString (one ++ zero)) 0 `shouldBe` Nothing
  it "imports a high-S signature" $ \ctx ->
    importCompactRecSig ctx (fromString (satoshiR ++ satoshiHighS)) 0 `shouldSatisfy` isJust
  it "converts to the signature without the id" $ \ctx -> do
    bytesToHex (exportSig ctx (convertRecSig ctx (fromString (coreR ++ coreS ++ "01")))) `shouldBe` coreDer
    convertRecSig ctx (fromString (coreR ++ coreS ++ "00"))
      `shouldBe` convertRecSig ctx (fromString (coreR ++ coreS ++ "01"))
  it "converts to a signature that verifies" $ \ctx ->
    property $ \(m :: Msg, k :: SecKey) ->
      verifySig ctx (derivePubKey ctx k) (convertRecSig ctx (signRecMsg ctx k m)) m

-- * Signature values

valueSpec :: SpecWith Ctx
valueSpec = describe "signature values" $ do
  it "rebuild from their internal bytes" $ \ctx ->
    property $ \(m :: Msg, k :: SecKey) -> let s = signRecMsg ctx k m in recSig s.get == Just s
  it "reject internal bytes that are not a signature" $ \_ -> do
    recSig (BS.replicate 65 0) `shouldBe` Nothing
    recSig (BS.replicate 65 0xff) `shouldBe` Nothing
    recSig (BS.replicate 64 1) `shouldBe` Nothing
    recSig (BS.replicate 66 1) `shouldBe` Nothing
  it "reject an internal recovery id above 3" $ \ctx -> do
    -- libsecp256k1 keeps the id in the last byte of the representation.
    let bytes = (signRecMsg ctx keyOne satoshiMsg).get
    recSig (BS.init bytes `BS.snoc` 4) `shouldBe` Nothing
  it "show r, s and the recovery id in hex" $ \ctx ->
    show (signRecMsg ctx coreKey coreMsg) `shouldBe` quoted (coreR ++ coreS ++ "01")
  it "read that encoding" $ \ctx -> do
    read (quoted (coreR ++ coreS ++ "01")) `shouldBe` signRecMsg ctx coreKey coreMsg
    (fromString (coreR ++ coreS ++ "01") :: RecSig) `shouldBe` signRecMsg ctx coreKey coreMsg
  it "show and read" $ \ctx ->
    property $ \(m :: Msg, k :: SecKey) -> showRead (signRecMsg ctx k m)
  it "do not read an invalid signature" $ \_ -> do
    (readMaybe (quoted (coreR ++ coreS)) :: Maybe RecSig) `shouldBe` Nothing
    (readMaybe (quoted (coreR ++ coreS ++ "04")) :: Maybe RecSig) `shouldBe` Nothing
    (readMaybe (quoted (zero ++ coreS ++ "01")) :: Maybe RecSig) `shouldBe` Nothing
    (readMaybe (quoted (order ++ coreS ++ "01")) :: Maybe RecSig) `shouldBe` Nothing
    (readMaybe (quoted (coreR ++ coreS ++ "0")) :: Maybe RecSig) `shouldBe` Nothing
    evaluate (fromString (coreR ++ coreS) :: RecSig) `shouldThrow` anyErrorCall

-- * Values built with the raw constructors of the Internal modules

rawValueSpec :: SpecWith Ctx
rawValueSpec = describe "raw values from the Internal modules" $ do
  it "a signature of 65 zero bytes recovers nothing, instead of aborting the process" $ \ctx ->
    recover ctx (RecSig (BS.replicate 65 0)) satoshiMsg `shouldBe` Nothing
  it "a zero secret key throws instead of signing" $ \ctx ->
    evaluate (signRecMsg ctx (SecKey (BS.replicate 32 0)) satoshiMsg) `shouldThrow` anyErrorCall
  it "values of the wrong length throw before reaching the library" $ \ctx -> do
    evaluate (signRecMsg ctx (SecKey "a") satoshiMsg) `shouldThrow` anyErrorCall
    evaluate (signRecMsg ctx keyOne (Msg "a")) `shouldThrow` anyErrorCall
    evaluate (recover ctx (RecSig "a") satoshiMsg) `shouldThrow` anyErrorCall
    evaluate (recover ctx (signRecMsg ctx keyOne satoshiMsg) (Msg "a")) `shouldThrow` anyErrorCall
    evaluate (convertRecSig ctx (RecSig "a")) `shouldThrow` anyErrorCall
    evaluate (exportCompactRecSig ctx (RecSig "a")) `shouldThrow` anyErrorCall
    evaluate (importCompactRecSig ctx (CompactSig "a") 0) `shouldThrow` anyErrorCall
    evaluate (length (show (RecSig "a"))) `shouldThrow` anyErrorCall

-- * Derived instances

instanceSpec :: SpecWith Ctx
instanceSpec = describe "derived instances" $ do
  it "equal values hash equally, whichever way they were built" $ \ctx ->
    property $ \(m :: Msg, k :: SecKey) ->
      let s = signRecMsg ctx k m
          (compact, i) = exportCompactRecSig ctx s
       in hash s == hash (fromJust (importCompactRecSig ctx compact i))
            && hash s == hash (fromJust (recSig s.get))
  it "can be fully evaluated" $ \ctx ->
    (signRecMsg ctx keyOne satoshiMsg `deepseq` ()) `shouldBe` ()

#else

spec :: Spec
spec =
  describe "public key recovery" $
    it "needs the recovery flag of the package" $
      pendingWith "the package was built with -f -recovery"

#endif
