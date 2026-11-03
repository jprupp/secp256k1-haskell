{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

module Crypto.Secp256k1Spec (spec) where

import Control.Arrow (first)
import Control.Exception (evaluate)
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
import Text.Read (readMaybe)

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
    it "combines a key with its negation to nothing" $ \ctx ->
      property $ combineOppositeTest ctx
    it "combines two keys like adding their secret keys" $ \ctx ->
      property $ combineTwoTest ctx
  describe "validation" $ do
    it "accepts secret keys 1 and n - 1" $ \_ -> do
      secKey (hexToBytes one) `shouldSatisfy` isJust
      secKey (hexToBytes orderMinusOne) `shouldSatisfy` isJust
    it "rejects secret keys 0, n and above n" $ \_ -> do
      secKey (hexToBytes zero) `shouldBe` Nothing
      secKey (hexToBytes order) `shouldBe` Nothing
      secKey (hexToBytes orderPlusOne) `shouldBe` Nothing
      secKey (BS.replicate 32 0xff) `shouldBe` Nothing
    it "rejects secret keys of the wrong length" $ \_ -> do
      secKey (BS.drop 1 (hexToBytes one)) `shouldBe` Nothing
      secKey (hexToBytes one <> "\x00") `shouldBe` Nothing
    it "does not read an invalid secret key" $ \_ -> do
      (readMaybe (show zero) :: Maybe SecKey) `shouldBe` Nothing
      (readMaybe (show order) :: Maybe SecKey) `shouldBe` Nothing
      evaluate (fromString order :: SecKey) `shouldThrow` anyErrorCall
    it "accepts the internal form of public keys" $ \ctx ->
      property $ \k ->
        let p = derivePubKey ctx k in pubKey p.get == Just p
    it "rejects public keys that are not on the curve" $ \_ -> do
      pubKey (BS.replicate 64 0) `shouldBe` Nothing
      pubKey (BS.replicate 64 0xff) `shouldBe` Nothing
      pubKey (BS.pack [1 .. 64]) `shouldBe` Nothing
      (readMaybe (show (BS.replicate 64 0x00)) :: Maybe PubKey)
        `shouldBe` Nothing
    it "accepts the internal form of signatures" $ \ctx ->
      property $ \(m, k) ->
        let g = signMsg ctx k m in sig g.get == Just g
    it "rejects signatures with components not below the order" $ \_ ->
      sig (BS.replicate 64 0xff) `shouldBe` Nothing
    it "rejects compact signatures with components not below the order" $
      \ctx -> do
        let s = hexToBytes one
        importCompactSig ctx (CompactSig (hexToBytes order <> s))
          `shouldBe` Nothing
        importCompactSig ctx (CompactSig (s <> hexToBytes order))
          `shouldBe` Nothing
        importCompactSig ctx (CompactSig (s <> s)) `shouldSatisfy` isJust
  describe "invalid raw values" $ do
    it "verification fails for a zero public key instead of aborting" $
      \ctx -> property $ \(m, k) ->
        not $ verifySig ctx (PubKey (BS.replicate 64 0)) (signMsg ctx k m) m
    it "serializing a zero public key throws instead of aborting" $ \ctx ->
      evaluate (exportPubKey ctx True (PubKey (BS.replicate 64 0)))
        `shouldThrow` anyErrorCall
    it "tweaking a zero public key fails instead of aborting" $ \ctx ->
      tweakAddPubKey ctx (PubKey (BS.replicate 64 0)) oneTweak
        `shouldBe` Nothing
    it "combining a zero public key fails instead of aborting" $ \ctx ->
      property $ \k ->
        combinePubKeys ctx [derivePubKey ctx k, PubKey (BS.replicate 64 0)]
          `shouldBe` Nothing
    it "rejects values of the wrong length before calling the library" $
      \ctx -> do
        let m = Msg (BS.replicate 32 1)
        evaluate (derivePubKey ctx (SecKey "a")) `shouldThrow` anyErrorCall
        evaluate (signMsg ctx (SecKey "a") m) `shouldThrow` anyErrorCall
        evaluate (signMsg ctx (SecKey (hexToBytes one)) (Msg "a"))
          `shouldThrow` anyErrorCall
        evaluate (importCompactSig ctx (CompactSig "a"))
          `shouldThrow` anyErrorCall
        evaluate (exportSig ctx (Sig "a")) `shouldThrow` anyErrorCall
        evaluate (exportPubKey ctx True (PubKey "a"))
          `shouldThrow` anyErrorCall
        evaluate (tweakAddSecKey ctx (SecKey (hexToBytes one)) (Tweak "a"))
          `shouldThrow` anyErrorCall
        evaluate (tweakNegate ctx (Tweak "a")) `shouldThrow` anyErrorCall
    it "does not modify the inputs of tweaks" $ \ctx ->
      property $ \k ->
        let before = BS.copy k.get
            p = derivePubKey ctx k
            pBefore = BS.copy p.get
         in tweakAddSecKey ctx k oneTweak `seq`
              tweakMulPubKey ctx p oneTweak `seq`
                (k.get == before && p.get == pBefore)
  describe "schnorr signatures" $ do
    it "passes the BIP-340 test vectors" $ \ctx ->
      mapM_ (bip340VectorTest ctx) bip340Vectors
    it "signs and verifies" $ \ctx ->
      property $ \(m, k) ->
        verifySchnorr ctx (derivePubKey ctx k) (signSchnorr ctx k m) m
    it "signs and verifies with fresh randomness" $ \ctx ->
      property $ \(m, k) -> ioProperty $ do
        s <- signSchnorrIO ctx k m
        return $ verifySchnorr ctx (derivePubKey ctx k) s m
    it "signs without randomness as with 32 zero bytes" $ \ctx ->
      property $ \(m, k) ->
        Just (signSchnorr ctx k m)
          === signSchnorrWithAux ctx k m (BS.replicate 32 0)
    it "uses the auxiliary randomness" $ \ctx ->
      property $ \(m, k) ->
        signSchnorrWithAux ctx k m (BS.replicate 32 1)
          =/= signSchnorrWithAux ctx k m (BS.replicate 32 2)
    it "rejects auxiliary randomness of the wrong length" $ \ctx ->
      property $ \(m, k) -> do
        signSchnorrWithAux ctx k m (BS.replicate 31 0) `shouldBe` Nothing
        signSchnorrWithAux ctx k m (BS.replicate 33 0) `shouldBe` Nothing
    it "detects a bad signature" $ \ctx ->
      property $ \(m, k, k') ->
        k /= k' ==>
          not (verifySchnorr ctx (derivePubKey ctx k') (signSchnorr ctx k m) m)
    it "detects a different message" $ \ctx ->
      property $ \(m, m', k) ->
        m /= m' ==>
          not (verifySchnorr ctx (derivePubKey ctx k) (signSchnorr ctx k m) m')
    it "verifies with the negation of the public key" $ \ctx ->
      property $ \(m, k) ->
        verifySchnorr
          ctx
          (negatePubKey ctx (derivePubKey ctx k))
          (signSchnorr ctx k m)
          m
    it "shows and reads signatures" $ \ctx ->
      property $ \(m, k) -> showRead (signSchnorr ctx k m)
    it "reads signatures from strings" $ \ctx ->
      property $ \(m, k) ->
        let s = signSchnorr ctx k m
         in s == fromString (cs (extractBase16 (encodeBase16 s.get)))
    it "accepts only 64-byte signatures" $ \_ -> do
      schnorrSig (BS.replicate 64 0) `shouldSatisfy` isJust
      schnorrSig (BS.replicate 63 0) `shouldBe` Nothing
      schnorrSig (BS.replicate 65 0) `shouldBe` Nothing
  describe "x-only public keys" $ do
    it "exports the X coordinate of a public key" $ \ctx ->
      property $ \k ->
        let p = derivePubKey ctx k
         in exportXOnlyPubKey ctx p === BS.drop 1 (exportPubKey ctx True p)
    it "exports a key and its negation the same way" $ \ctx ->
      property $ \k ->
        let p = derivePubKey ctx k
         in exportXOnlyPubKey ctx p
              === exportXOnlyPubKey ctx (negatePubKey ctx p)
    it "imports the point with an even Y coordinate" $ \ctx ->
      property $ \k ->
        let p = derivePubKey ctx k
            x = exportXOnlyPubKey ctx p
         in fmap (exportPubKey ctx True) (importXOnlyPubKey ctx x)
              === Just (BS.cons 0x02 x)
    it "rejects invalid x-only public keys" $ \ctx -> do
      importXOnlyPubKey ctx (hexToBytes fieldSize) `shouldBe` Nothing
      importXOnlyPubKey ctx (BS.replicate 31 1) `shouldBe` Nothing
      importXOnlyPubKey ctx (BS.replicate 33 1) `shouldBe` Nothing
  describe "taproot tweaks" $ do
    it "tweaks secret and public keys alike" $ \ctx ->
      property $ \(k, t) ->
        let tw = tweakOf t
         in fmap (derivePubKey ctx) (tweakAddXOnlySecKey ctx k tw)
              === tweakAddXOnlyPubKey ctx (derivePubKey ctx k) tw
    it "tweaks a key and its negation alike" $ \ctx ->
      property $ \(k, t) ->
        let tw = tweakOf t
            p = derivePubKey ctx k
         in tweakAddXOnlyPubKey ctx p tw
              === tweakAddXOnlyPubKey ctx (negatePubKey ctx p) tw
    it "signs with a tweaked key" $ \ctx ->
      property $ \(m, k, t) ->
        let tw = tweakOf t
            Just k' = tweakAddXOnlySecKey ctx k tw
            Just p' = tweakAddXOnlyPubKey ctx (derivePubKey ctx k) tw
         in verifySchnorr ctx p' (signSchnorr ctx k' m) m
    it "passes the BIP-341 test vectors" $ \ctx ->
      mapM_ (bip341VectorTest ctx) bip341Vectors
    it "rejects tweaks not below the order" $ \ctx ->
      property $ \k -> do
        let tw = Tweak (hexToBytes order)
        tweakAddXOnlySecKey ctx k tw `shouldBe` Nothing
        tweakAddXOnlyPubKey ctx (derivePubKey ctx k) tw `shouldBe` Nothing
    it "rejects a tweak giving zero" $ \ctx -> do
      -- The public key of 1 has an even Y coordinate, so n - 1 cancels it.
      let k = SecKey (hexToBytes one)
          tw = Tweak (hexToBytes orderMinusOne)
      tweakAddXOnlySecKey ctx k tw `shouldBe` Nothing
      tweakAddXOnlyPubKey ctx (derivePubKey ctx k) tw `shouldBe` Nothing
  describe "invalid raw values in schnorr functions" $ do
    it "verification fails for a zero public key instead of aborting" $
      \ctx -> property $ \(m, k) ->
        not $
          verifySchnorr ctx (PubKey (BS.replicate 64 0)) (signSchnorr ctx k m) m
    it "tweaking a zero public key fails instead of aborting" $ \ctx ->
      tweakAddXOnlyPubKey ctx (PubKey (BS.replicate 64 0)) oneTweak
        `shouldBe` Nothing
    it "exporting a zero public key throws instead of aborting" $ \ctx ->
      evaluate (exportXOnlyPubKey ctx (PubKey (BS.replicate 64 0)))
        `shouldThrow` anyErrorCall
    it "signing with a zero secret key throws instead of aborting" $ \ctx ->
      property $ \m ->
        evaluate (signSchnorr ctx (SecKey (hexToBytes zero)) m)
          `shouldThrow` anyErrorCall
    it "tweaking a zero secret key fails instead of aborting" $ \ctx ->
      tweakAddXOnlySecKey ctx (SecKey (hexToBytes zero)) oneTweak
        `shouldBe` Nothing
    it "rejects values of the wrong length before calling the library" $
      \ctx -> do
        let m = Msg (BS.replicate 32 1)
            k = SecKey (hexToBytes one)
            p = derivePubKey ctx k
        evaluate (signSchnorr ctx (SecKey "a") m) `shouldThrow` anyErrorCall
        evaluate (signSchnorr ctx k (Msg "a")) `shouldThrow` anyErrorCall
        evaluate (verifySchnorr ctx p (SchnorrSig "a") m)
          `shouldThrow` anyErrorCall
        evaluate (verifySchnorr ctx (PubKey "a") (signSchnorr ctx k m) m)
          `shouldThrow` anyErrorCall
        evaluate (exportXOnlyPubKey ctx (PubKey "a")) `shouldThrow` anyErrorCall
        evaluate (tweakAddXOnlyPubKey ctx p (Tweak "a"))
          `shouldThrow` anyErrorCall
        evaluate (tweakAddXOnlySecKey ctx k (Tweak "a"))
          `shouldThrow` anyErrorCall

-- | Random tweak lower than the curve order.
tweakOf :: SecKey -> Tweak
tweakOf k = Tweak k.get

-- | Field size of secp256k1, which is not a valid X coordinate.
fieldSize :: String
fieldSize = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"

negatePubKey :: Ctx -> PubKey -> PubKey
negatePubKey ctx p = fromMaybe (error "negate") $ do
  minusOne <- tweakNegate ctx oneTweak
  tweakMulPubKey ctx p minusOne

-- | BIP-340 test vector, from
-- <https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv>.
-- Vectors 15 to 18 sign messages that are not 32 bytes long, which 'Msg'
-- does not support, and are left out.
data BIP340Vector = BIP340Vector
  { index :: Int,
    secretKey :: Maybe String,
    publicKey :: String,
    auxRand :: Maybe String,
    message :: String,
    signature :: String,
    result :: Bool
  }

bip340VectorTest :: Ctx -> BIP340Vector -> Expectation
bip340VectorTest ctx v = do
  let name = "vector " ++ show v.index ++ ": "
      Just m = msg (hexToBytes v.message)
      Just s = schnorrSig (hexToBytes v.signature)
  case v.secretKey of
    Nothing -> return ()
    Just hex -> do
      let Just k = secKey (hexToBytes hex)
          Just aux = hexToBytes <$> v.auxRand
      assertEqual
        (name ++ "public key")
        (hexToBytes v.publicKey)
        (exportXOnlyPubKey ctx (derivePubKey ctx k))
      assertEqual
        (name ++ "signature")
        (Just s)
        (signSchnorrWithAux ctx k m aux)
  let verified = case importXOnlyPubKey ctx (hexToBytes v.publicKey) of
        Nothing -> False
        Just p -> verifySchnorr ctx p s m
  assertEqual (name ++ "verification") v.result verified

bip340Vectors :: [BIP340Vector]
bip340Vectors =
  [ BIP340Vector
      { index = 0,
        secretKey = Just "0000000000000000000000000000000000000000000000000000000000000003",
        publicKey = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        auxRand = Just "0000000000000000000000000000000000000000000000000000000000000000",
        message = "0000000000000000000000000000000000000000000000000000000000000000",
        signature = "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0",
        result = True
      },
    BIP340Vector
      { index = 1,
        secretKey = Just "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef",
        publicKey = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        auxRand = Just "0000000000000000000000000000000000000000000000000000000000000001",
        message = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        signature = "6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a",
        result = True
      },
    BIP340Vector
      { index = 2,
        secretKey = Just "c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9",
        publicKey = "dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8",
        auxRand = Just "c87aa53824b4d7ae2eb035a2b5bbbccc080e76cdc6d1692c4b0b62d798e6d906",
        message = "7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c",
        signature = "5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7",
        result = True
      },
    BIP340Vector
      { index = 3,
        secretKey = Just "0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710",
        publicKey = "25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517",
        auxRand = Just "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        message = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        signature = "7eb0509757e246f19449885651611cb965ecc1a187dd51b64fda1edc9637d5ec97582b9cb13db3933705b32ba982af5af25fd78881ebb32771fc5922efc66ea3",
        result = True
      },
    BIP340Vector
      { index = 4,
        secretKey = Nothing,
        publicKey = "d69c3509bb99e412e68b0fe8544e72837dfa30746d8be2aa65975f29d22dc7b9",
        auxRand = Nothing,
        message = "4df3c3f68fcc83b27e9d42c90431a72499f17875c81a599b566c9889b9696703",
        signature = "00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c6376afb1548af603b3eb45c9f8207dee1060cb71c04e80f593060b07d28308d7f4",
        result = True
      },
    BIP340Vector
      { index = 5,
        secretKey = Nothing,
        publicKey = "eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34",
        auxRand = Nothing,
        message = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        signature = "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
        result = False
      },
    BIP340Vector
      { index = 6,
        secretKey = Nothing,
        publicKey = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        auxRand = Nothing,
        message = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        signature = "fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975563cc27944640ac607cd107ae10923d9ef7a73c643e166be5ebeafa34b1ac553e2",
        result = False
      },
    BIP340Vector
      { index = 7,
        secretKey = Nothing,
        publicKey = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        auxRand = Nothing,
        message = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        signature = "1fa62e331edbc21c394792d2ab1100a7b432b013df3f6ff4f99fcb33e0e1515f28890b3edb6e7189b630448b515ce4f8622a954cfe545735aaea5134fccdb2bd",
        result = False
      },
    BIP340Vector
      { index = 8,
        secretKey = Nothing,
        publicKey = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        auxRand = Nothing,
        message = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        signature = "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769961764b3aa9b2ffcb6ef947b6887a226e8d7c93e00c5ed0c1834ff0d0c2e6da6",
        result = False
      },
    BIP340Vector
      { index = 9,
        secretKey = Nothing,
        publicKey = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        auxRand = Nothing,
        message = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        signature = "0000000000000000000000000000000000000000000000000000000000000000123dda8328af9c23a94c1feecfd123ba4fb73476f0d594dcb65c6425bd186051",
        result = False
      },
    BIP340Vector
      { index = 10,
        secretKey = Nothing,
        publicKey = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        auxRand = Nothing,
        message = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        signature = "00000000000000000000000000000000000000000000000000000000000000017615fbaf5ae28864013c099742deadb4dba87f11ac6754f93780d5a1837cf197",
        result = False
      },
    BIP340Vector
      { index = 11,
        secretKey = Nothing,
        publicKey = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        auxRand = Nothing,
        message = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        signature = "4a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1d69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
        result = False
      },
    BIP340Vector
      { index = 12,
        secretKey = Nothing,
        publicKey = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        auxRand = Nothing,
        message = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        signature = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
        result = False
      },
    BIP340Vector
      { index = 13,
        secretKey = Nothing,
        publicKey = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        auxRand = Nothing,
        message = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        signature = "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        result = False
      },
    BIP340Vector
      { index = 14,
        secretKey = Nothing,
        publicKey = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30",
        auxRand = Nothing,
        message = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        signature = "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
        result = False
      }
  ]

-- | BIP-341 key path spending test vector, from
-- <https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json>:
-- internal secret key, tweak, tweaked secret key, signature hash, and
-- signature without the hash type byte.
bip341Vectors :: [(String, String, String, String, String)]
bip341Vectors =
  [ ( "6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa",
      "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70",
      "2405b971772ad26915c8dcdf10f238753a9b837e5f8e6a86fd7c0cce5b7296d9",
      "2514a6272f85cfa0f45eb907fcb0d121b808ed37c6ea160a5a9046ed5526d555",
      "ed7c1647cb97379e76892be0cacff57ec4a7102aa24296ca39af7541246d8ff14d38958d4cc1e2e478e4d4a764bbfd835b16d4e314b72937b29833060b87276c"
    ),
    ( "1e4da49f6aaf4e5cd175fe08a32bb5cb4863d963921255f33d3bc31e1343907f",
      "cbd8679ba636c1110ea247542cfbd964131a6be84f873f7f3b62a777528ed001",
      "ea260c3b10e60f6de018455cd0278f2f5b7e454be1999572789e6a9565d26080",
      "325a644af47e8a5a2591cda0ab0723978537318f10e6a63d4eed783b96a71a4d",
      "052aedffc554b41f52b521071793a6b88d6dbca9dba94cf34c83696de0c1ec35ca9c5ed4ab28059bd606a4f3a657eec0bb96661d42921b5f50a95ad33675b54f"
    ),
    ( "d3c7af07da2d54f7a7735d3d0fc4f0a73164db638b2f2f7c43f711f6d4aa7e64",
      "6af9e28dbf9d6aaf027696e2598a5b3d056f5fd2355a7fd5a37a0e5008132d30",
      "97323385e57015b75b0339a549c56a948eb961555973f0951f555ae6039ef00d",
      "bf013ea93474aa67815b1b6cc441d23b64fa310911d991e713cd34c7f5d46669",
      "ff45f742a876139946a149ab4d9185574b98dc919d2eb6754f8abaa59d18b025637a3aa043b91817739554f4ed2026cf8022dbd83e351ce1fabc272841d2510a"
    ),
    ( "f36bb07a11e469ce941d16b63b11b9b9120a84d9d87cff2c84a8d4affb438f4e",
      "b57bfa183d28eeb6ad688ddaabb265b4a41fbf68e5fed2c72c74de70d5a786f4",
      "a8e7aa924f0d58854185a490e6c41f6efb7b675c0f3331b7f14b549400b4d501",
      "4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef",
      "b4010dd48a617db09926f729e79c33ae0b4e94b79f04a1ae93ede6315eb3669de185a17d2b0ac9ee09fd4c64b678a0b61a0a86fa888a273c8511be83bfd6810f"
    ),
    ( "415cfe9c15d9cea27d8104d5517c06e9de48e2f986b695e4f5ffebf230e725d8",
      "6579138e7976dc13b6a92f7bfd5a2fc7684f5ea42419d43368301470f3b74ed9",
      "241c14f2639d0d7139282aa6abde28dd8a067baa9d633e4e7230287ec2d02901",
      "15f25c298eb5cdc7eb1d638dd2d45c97c4c59dcaec6679cfc16ad84f30876b85",
      "a3785919a2ce3c4ce26f298c3d51619bc474ae24014bcdd31328cd8cfbab2eff3395fa0a16fe5f486d12f22a9cedded5ae74feb4bbe5351346508c5405bcfee0"
    ),
    ( "c7b0e81f0a9a0b0499e112279d718cca98e79a12e2f137c72ae5b213aad0d103",
      "9e0517edc8259bb3359255400b23ca9507f2a91cd1e4250ba068b4eafceba4a9",
      "65b6000cd2bfa6b7cf736767a8955760e62b6649058cbc970b7c0871d786346b",
      "cd292de50313804dabe4685e83f923d2969577191a3e1d2882220dca88cbeb10",
      "ea0c6ba90763c2d3a296ad82ba45881abb4f426b3f87af162dd24d5109edc1cdd11915095ba47c3a9963dc1e6c432939872bc49212fe34c632cd3ab9fed429c4"
    ),
    ( "77863416be0d0665e517e1c375fd6f75839544eca553675ef7fdf4949518ebaa",
      "639f0281b7ac49e742cd25b7f188657626da1ad169209078e2761cefd91fd65e",
      "ec18ce6af99f43815db543f47b8af5ff5df3b2cb7315c955aa4a86e8143d2bf5",
      "cccb739eca6c13a8a89e6e5cd317ffe55669bbda23f2fd37b0f18755e008edd2",
      "bbc9584a11074e83bc8c6759ec55401f0ae7b03ef290c3139814f545b58a9f8127258000874f44bc46db7646322107d4d86aec8e73b8719a61fff761d75b5dd9"
    )
  ]

bip341VectorTest :: Ctx -> (String, String, String, String, String) -> Expectation
bip341VectorTest ctx (internal, tw, tweaked, hash, expected) = do
  let Just k = secKey (hexToBytes internal)
      Just t = tweak (hexToBytes tw)
      Just k' = tweakAddXOnlySecKey ctx k t
      Just m = msg (hexToBytes hash)
  k' `shouldBe` SecKey (hexToBytes tweaked)
  fmap (exportXOnlyPubKey ctx) (tweakAddXOnlyPubKey ctx (derivePubKey ctx k) t)
    `shouldBe` Just (exportXOnlyPubKey ctx (derivePubKey ctx k'))
  signSchnorr ctx k' m `shouldBe` SchnorrSig (hexToBytes expected)

zero, one, order, orderMinusOne, orderPlusOne :: String
zero = "0000000000000000000000000000000000000000000000000000000000000000"
one = "0000000000000000000000000000000000000000000000000000000000000001"
order = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
orderMinusOne =
  "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
orderPlusOne =
  "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142"

oneTweak :: Tweak
oneTweak = Tweak (hexToBytes one)

combineOppositeTest :: Ctx -> SecKey -> Bool
combineOppositeTest ctx k =
  isNothing (combinePubKeys ctx [p, minusP])
  where
    p = derivePubKey ctx k
    minusOne = fromMaybe (error "negate") (tweakNegate ctx oneTweak)
    minusP = fromMaybe (error "mul") (tweakMulPubKey ctx p minusOne)

combineTwoTest :: Ctx -> (SecKey, SecKey) -> Property
combineTwoTest ctx (k1, k2) =
  combinePubKeys ctx [derivePubKey ctx k1, derivePubKey ctx k2]
    === (derivePubKey ctx <$> tweakAddSecKey ctx k1 (Tweak k2.get))

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
