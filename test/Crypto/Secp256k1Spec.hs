{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.Secp256k1Spec (spec) where

import Control.DeepSeq (deepseq)
import Control.Exception (evaluate)
import Control.Monad.Par qualified as P
import Crypto.Secp256k1
import Crypto.Secp256k1.Fixtures
import Crypto.Secp256k1.Internal.Base
  ( CompactSig (CompactSig),
    Msg (Msg),
    PubKey (PubKey),
    SchnorrSig (SchnorrSig),
    SecKey (SecKey),
    Sig (Sig),
    Tweak (Tweak),
    signMsgWith,
  )
import Data.Bits (xor)
import Data.ByteString qualified as BS
import Data.Hashable (hash)
import Data.Maybe (fromJust, isJust, isNothing)
import Data.String (fromString)
import Test.Hspec
import Test.QuickCheck
import Text.Read (readMaybe)

spec :: Spec
spec = do
  secretKeySpec
  publicKeySpec
  messageSpec
  signingSpec
  verificationSpec
  derSpec
  compactSpec
  tweakSpec
  combineSpec
  schnorrSpec
  xOnlySpec
  taprootSpec
  rawValueSpec
  instanceSpec

-- BIP-340 vector 0: secret key 3 signing 32 zero bytes with 32 zero bytes of
-- auxiliary randomness.
bip340Key0 :: SecKey
bip340Key0 = "0000000000000000000000000000000000000000000000000000000000000003"

bip340Pub0, bip340Sig0 :: String
bip340Pub0 = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
bip340Sig0 =
  "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca8215\
  \25f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"

-- A BIP-340 test vector from
-- https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv.
-- Vectors 15 to 18 sign messages that are not 32 bytes long, which 'Msg'
-- does not hold, so they are left out.
data BIP340Vector = BIP340Vector
  { index :: Int,
    comment :: String,
    secretKey :: Maybe String,
    publicKey :: String,
    auxRand :: Maybe String,
    message :: String,
    signature :: String,
    result :: Bool
  }

bip340Vectors :: [BIP340Vector]
bip340Vectors =
  [ BIP340Vector
      { index = 0,
        comment = "",
        secretKey = Just "0000000000000000000000000000000000000000000000000000000000000003",
        publicKey = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        auxRand = Just "0000000000000000000000000000000000000000000000000000000000000000",
        message = "0000000000000000000000000000000000000000000000000000000000000000",
        signature = "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0",
        result = True
      },
    BIP340Vector
      { index = 1,
        comment = "",
        secretKey = Just "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef",
        publicKey = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        auxRand = Just "0000000000000000000000000000000000000000000000000000000000000001",
        message = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        signature = "6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a",
        result = True
      },
    BIP340Vector
      { index = 2,
        comment = "",
        secretKey = Just "c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9",
        publicKey = "dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8",
        auxRand = Just "c87aa53824b4d7ae2eb035a2b5bbbccc080e76cdc6d1692c4b0b62d798e6d906",
        message = "7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c",
        signature = "5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7",
        result = True
      },
    BIP340Vector
      { index = 3,
        comment = "test fails if msg is reduced modulo p or n",
        secretKey = Just "0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710",
        publicKey = "25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517",
        auxRand = Just "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        message = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        signature = "7eb0509757e246f19449885651611cb965ecc1a187dd51b64fda1edc9637d5ec97582b9cb13db3933705b32ba982af5af25fd78881ebb32771fc5922efc66ea3",
        result = True
      },
    BIP340Vector
      { index = 4,
        comment = "",
        secretKey = Nothing,
        publicKey = "d69c3509bb99e412e68b0fe8544e72837dfa30746d8be2aa65975f29d22dc7b9",
        auxRand = Nothing,
        message = "4df3c3f68fcc83b27e9d42c90431a72499f17875c81a599b566c9889b9696703",
        signature = "00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c6376afb1548af603b3eb45c9f8207dee1060cb71c04e80f593060b07d28308d7f4",
        result = True
      },
    BIP340Vector
      { index = 5,
        comment = "public key not on the curve",
        secretKey = Nothing,
        publicKey = "eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34",
        auxRand = Nothing,
        message = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        signature = "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
        result = False
      },
    BIP340Vector
      { index = 6,
        comment = "has_even_y(R) is false",
        secretKey = Nothing,
        publicKey = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        auxRand = Nothing,
        message = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        signature = "fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975563cc27944640ac607cd107ae10923d9ef7a73c643e166be5ebeafa34b1ac553e2",
        result = False
      },
    BIP340Vector
      { index = 7,
        comment = "negated message",
        secretKey = Nothing,
        publicKey = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        auxRand = Nothing,
        message = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        signature = "1fa62e331edbc21c394792d2ab1100a7b432b013df3f6ff4f99fcb33e0e1515f28890b3edb6e7189b630448b515ce4f8622a954cfe545735aaea5134fccdb2bd",
        result = False
      },
    BIP340Vector
      { index = 8,
        comment = "negated s value",
        secretKey = Nothing,
        publicKey = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        auxRand = Nothing,
        message = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        signature = "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769961764b3aa9b2ffcb6ef947b6887a226e8d7c93e00c5ed0c1834ff0d0c2e6da6",
        result = False
      },
    BIP340Vector
      { index = 9,
        comment = "sG - eP is infinite",
        secretKey = Nothing,
        publicKey = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        auxRand = Nothing,
        message = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        signature = "0000000000000000000000000000000000000000000000000000000000000000123dda8328af9c23a94c1feecfd123ba4fb73476f0d594dcb65c6425bd186051",
        result = False
      },
    BIP340Vector
      { index = 10,
        comment = "sG - eP is infinite",
        secretKey = Nothing,
        publicKey = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        auxRand = Nothing,
        message = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        signature = "00000000000000000000000000000000000000000000000000000000000000017615fbaf5ae28864013c099742deadb4dba87f11ac6754f93780d5a1837cf197",
        result = False
      },
    BIP340Vector
      { index = 11,
        comment = "sig[0:32] is not an X coordinate on the curve",
        secretKey = Nothing,
        publicKey = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        auxRand = Nothing,
        message = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        signature = "4a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1d69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
        result = False
      },
    BIP340Vector
      { index = 12,
        comment = "sig[0:32] is equal to field size",
        secretKey = Nothing,
        publicKey = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        auxRand = Nothing,
        message = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        signature = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
        result = False
      },
    BIP340Vector
      { index = 13,
        comment = "sig[32:64] is equal to curve order",
        secretKey = Nothing,
        publicKey = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        auxRand = Nothing,
        message = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        signature = "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        result = False
      },
    BIP340Vector
      { index = 14,
        comment = "public key is not a valid X coordinate because it exceeds the field size",
        secretKey = Nothing,
        publicKey = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30",
        auxRand = Nothing,
        message = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        signature = "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
        result = False
      }
  ]

-- A BIP-341 key path spending vector from
-- https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json:
-- the internal secret key, its x-only public key, the tweak, the tweaked
-- secret key, the output key (from the spent scriptPubKey), the signature
-- hash, and the signature without its hash type byte. The signatures were
-- made without auxiliary randomness.
data BIP341Vector = BIP341Vector
  { internalKey :: String,
    internalPub :: String,
    tapTweak :: String,
    tweakedKey :: String,
    outputKey :: String,
    sigHash :: String,
    keyPathSig :: String
  }

bip341Vectors :: [BIP341Vector]
bip341Vectors =
  [ BIP341Vector
      { internalKey = "6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa",
        internalPub = "d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d",
        tapTweak = "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70",
        tweakedKey = "2405b971772ad26915c8dcdf10f238753a9b837e5f8e6a86fd7c0cce5b7296d9",
        outputKey = "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343",
        sigHash = "2514a6272f85cfa0f45eb907fcb0d121b808ed37c6ea160a5a9046ed5526d555",
        keyPathSig = "ed7c1647cb97379e76892be0cacff57ec4a7102aa24296ca39af7541246d8ff14d38958d4cc1e2e478e4d4a764bbfd835b16d4e314b72937b29833060b87276c"
      },
    BIP341Vector
      { internalKey = "1e4da49f6aaf4e5cd175fe08a32bb5cb4863d963921255f33d3bc31e1343907f",
        internalPub = "187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27",
        tapTweak = "cbd8679ba636c1110ea247542cfbd964131a6be84f873f7f3b62a777528ed001",
        tweakedKey = "ea260c3b10e60f6de018455cd0278f2f5b7e454be1999572789e6a9565d26080",
        outputKey = "147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3",
        sigHash = "325a644af47e8a5a2591cda0ab0723978537318f10e6a63d4eed783b96a71a4d",
        keyPathSig = "052aedffc554b41f52b521071793a6b88d6dbca9dba94cf34c83696de0c1ec35ca9c5ed4ab28059bd606a4f3a657eec0bb96661d42921b5f50a95ad33675b54f"
      },
    BIP341Vector
      { internalKey = "d3c7af07da2d54f7a7735d3d0fc4f0a73164db638b2f2f7c43f711f6d4aa7e64",
        internalPub = "93478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820",
        tapTweak = "6af9e28dbf9d6aaf027696e2598a5b3d056f5fd2355a7fd5a37a0e5008132d30",
        tweakedKey = "97323385e57015b75b0339a549c56a948eb961555973f0951f555ae6039ef00d",
        outputKey = "e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e",
        sigHash = "bf013ea93474aa67815b1b6cc441d23b64fa310911d991e713cd34c7f5d46669",
        keyPathSig = "ff45f742a876139946a149ab4d9185574b98dc919d2eb6754f8abaa59d18b025637a3aa043b91817739554f4ed2026cf8022dbd83e351ce1fabc272841d2510a"
      },
    BIP341Vector
      { internalKey = "f36bb07a11e469ce941d16b63b11b9b9120a84d9d87cff2c84a8d4affb438f4e",
        internalPub = "e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f",
        tapTweak = "b57bfa183d28eeb6ad688ddaabb265b4a41fbf68e5fed2c72c74de70d5a786f4",
        tweakedKey = "a8e7aa924f0d58854185a490e6c41f6efb7b675c0f3331b7f14b549400b4d501",
        outputKey = "91b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605",
        sigHash = "4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef",
        keyPathSig = "b4010dd48a617db09926f729e79c33ae0b4e94b79f04a1ae93ede6315eb3669de185a17d2b0ac9ee09fd4c64b678a0b61a0a86fa888a273c8511be83bfd6810f"
      },
    BIP341Vector
      { internalKey = "415cfe9c15d9cea27d8104d5517c06e9de48e2f986b695e4f5ffebf230e725d8",
        internalPub = "55adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d",
        tapTweak = "6579138e7976dc13b6a92f7bfd5a2fc7684f5ea42419d43368301470f3b74ed9",
        tweakedKey = "241c14f2639d0d7139282aa6abde28dd8a067baa9d633e4e7230287ec2d02901",
        outputKey = "75169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831",
        sigHash = "15f25c298eb5cdc7eb1d638dd2d45c97c4c59dcaec6679cfc16ad84f30876b85",
        keyPathSig = "a3785919a2ce3c4ce26f298c3d51619bc474ae24014bcdd31328cd8cfbab2eff3395fa0a16fe5f486d12f22a9cedded5ae74feb4bbe5351346508c5405bcfee0"
      },
    BIP341Vector
      { internalKey = "c7b0e81f0a9a0b0499e112279d718cca98e79a12e2f137c72ae5b213aad0d103",
        internalPub = "ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592",
        tapTweak = "9e0517edc8259bb3359255400b23ca9507f2a91cd1e4250ba068b4eafceba4a9",
        tweakedKey = "65b6000cd2bfa6b7cf736767a8955760e62b6649058cbc970b7c0871d786346b",
        outputKey = "712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5",
        sigHash = "cd292de50313804dabe4685e83f923d2969577191a3e1d2882220dca88cbeb10",
        keyPathSig = "ea0c6ba90763c2d3a296ad82ba45881abb4f426b3f87af162dd24d5109edc1cdd11915095ba47c3a9963dc1e6c432939872bc49212fe34c632cd3ab9fed429c4"
      },
    BIP341Vector
      { internalKey = "77863416be0d0665e517e1c375fd6f75839544eca553675ef7fdf4949518ebaa",
        internalPub = "f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd8",
        tapTweak = "639f0281b7ac49e742cd25b7f188657626da1ad169209078e2761cefd91fd65e",
        tweakedKey = "ec18ce6af99f43815db543f47b8af5ff5df3b2cb7315c955aa4a86e8143d2bf5",
        outputKey = "77e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220",
        sigHash = "cccb739eca6c13a8a89e6e5cd317ffe55669bbda23f2fd37b0f18755e008edd2",
        keyPathSig = "bbc9584a11074e83bc8c6759ec55401f0ae7b03ef290c3139814f545b58a9f8127258000874f44bc46db7646322107d4d86aec8e73b8719a61fff761d75b5dd9"
      }
  ]

-- * Secret keys

secretKeySpec :: Spec
secretKeySpec = describe "secret keys" $ do
  it "accepts 1 and n - 1" $ do
    secKey (hexToBytes one) `shouldSatisfy` isJust
    secKey (hexToBytes orderMinusOne) `shouldSatisfy` isJust
  it "rejects 0, n, n + 1 and 2^256 - 1" $ do
    secKey (hexToBytes zero) `shouldBe` Nothing
    secKey (hexToBytes order) `shouldBe` Nothing
    secKey (hexToBytes orderPlusOne) `shouldBe` Nothing
    secKey (hexToBytes allOnes) `shouldBe` Nothing
  it "rejects 31 and 33 bytes" $ do
    secKey (BS.replicate 31 1) `shouldBe` Nothing
    secKey (BS.replicate 33 1) `shouldBe` Nothing
  it "keeps the bytes it was given" $
    property $
      \(k :: SecKey) -> secKey k.get == Just k
  it "derives the generator from key 1" $ do
    bytesToHex (exportPubKey True (derivePubKey keyOne))
      `shouldBe` genCompressed
    bytesToHex (exportPubKey False (derivePubKey keyOne))
      `shouldBe` genUncompressed
  it "derives the negated generator from key n - 1" $
    -- -G has the same x as G and an odd y, so the prefix is 03.
    bytesToHex (exportPubKey True (derivePubKey (fromString orderMinusOne)))
      `shouldBe` "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
  it "derives the historical public key" $
    bytesToHex (exportPubKey False (derivePubKey histKey)) `shouldBe` histPub
  it "shows a placeholder instead of the key" $
    property $
      \(k :: SecKey) -> show k == "SecKey <redacted>"
  it "parenthesizes the placeholder inside a larger value" $
    show (Just keyOne) `shouldBe` "Just (SecKey <redacted>)"
  it "reads the key from hex" $
    read (quoted one) `shouldBe` keyOne
  it "reads from a string" $
    property $
      \(k :: SecKey) -> fromString (bytesToHex k.get) == k
  it "does not read an invalid key" $ do
    (readMaybe (quoted zero) :: Maybe SecKey) `shouldBe` Nothing
    (readMaybe (quoted order) :: Maybe SecKey) `shouldBe` Nothing
    (readMaybe (quoted (drop 1 one)) :: Maybe SecKey) `shouldBe` Nothing
    (readMaybe (quoted ("zz" ++ drop 2 one)) :: Maybe SecKey) `shouldBe` Nothing
    evaluate (fromString order :: SecKey) `shouldThrow` anyErrorCall

-- * Public keys

publicKeySpec :: Spec
publicKeySpec = describe "public keys" $ do
  it "imports the compressed, uncompressed and hybrid encodings of G" $ do
    let g = derivePubKey keyOne
    importPubKey (hexToBytes genCompressed) `shouldBe` Just g
    importPubKey (hexToBytes genUncompressed) `shouldBe` Just g
    importPubKey (hexToBytes genHybrid) `shouldBe` Just g
  it "rejects malformed encodings" $ do
    importPubKey "" `shouldBe` Nothing
    -- prefix 05 does not exist
    importPubKey (hexToBytes ("05" ++ drop 2 genCompressed)) `shouldBe` Nothing
    -- x only, no prefix
    importPubKey (hexToBytes (drop 2 genCompressed)) `shouldBe` Nothing
    -- x and y without a prefix
    importPubKey (hexToBytes (drop 2 genUncompressed)) `shouldBe` Nothing
    -- uncompressed prefix on a compressed length
    importPubKey (hexToBytes ("04" ++ drop 2 genCompressed)) `shouldBe` Nothing
    -- compressed prefix on an uncompressed length
    importPubKey (hexToBytes ("02" ++ drop 2 genUncompressed)) `shouldBe` Nothing
  it "rejects points that are not on the curve" $ do
    -- x = 5 has no point on secp256k1 (x^3 + 7 is not a square mod p).
    importPubKey (hexToBytes ("02" ++ take 62 zero ++ "05")) `shouldBe` Nothing
    -- (1, 1) is not on the curve: 1 /= 1 + 7.
    importPubKey (hexToBytes ("04" ++ take 62 zero ++ "01" ++ take 62 zero ++ "01"))
      `shouldBe` Nothing
  it "exports and imports back the same key" $
    property $ \(k :: SecKey, compress :: Bool) ->
      let p = derivePubKey k
       in importPubKey (exportPubKey compress p) == Just p
  it "exports and imports in parallel" $
    property $ \(ks :: [(SecKey, Bool)]) -> P.runPar $ do
      results <- mapM (P.spawnP . roundTrip) ks
      and <$> mapM P.get results
  it "rebuilds a key from its internal bytes" $
    property $
      \(k :: SecKey) -> let p = derivePubKey k in pubKey p.get == Just p
  it "rejects internal bytes that are not a point" $ do
    pubKey (BS.replicate 64 0) `shouldBe` Nothing
    pubKey (BS.replicate 64 1) `shouldBe` Nothing
    pubKey (BS.replicate 64 0xff) `shouldBe` Nothing
    pubKey (BS.pack [1 .. 64]) `shouldBe` Nothing
    pubKey (BS.replicate 63 1) `shouldBe` Nothing
  it "shows the compressed encoding" $
    show (derivePubKey keyOne) `shouldBe` quoted genCompressed
  it "reads any encoding" $ do
    let g = derivePubKey keyOne
    read (quoted genCompressed) `shouldBe` g
    read (quoted genUncompressed) `shouldBe` g
    read (quoted genHybrid) `shouldBe` g
    (fromString genUncompressed :: PubKey) `shouldBe` g
  it "shows and reads" $
    property $
      \(k :: SecKey) -> showRead (derivePubKey k)
  it "does not read an invalid key" $ do
    (readMaybe (quoted (zero ++ zero)) :: Maybe PubKey) `shouldBe` Nothing
    (readMaybe (quoted ("02" ++ take 62 zero ++ "05")) :: Maybe PubKey) `shouldBe` Nothing
    (readMaybe (quoted (drop 2 genCompressed)) :: Maybe PubKey) `shouldBe` Nothing
    evaluate (fromString (drop 2 genCompressed) :: PubKey) `shouldThrow` anyErrorCall
  where
    roundTrip (k, compress) =
      let p = derivePubKey k
       in importPubKey (exportPubKey compress p) == Just p

-- * Messages

messageSpec :: Spec
messageSpec = describe "messages" $ do
  it "accepts 32 bytes and rejects other lengths" $ do
    msg (BS.replicate 32 7) `shouldSatisfy` isJust
    msg (BS.replicate 31 7) `shouldBe` Nothing
    msg (BS.replicate 33 7) `shouldBe` Nothing
    msg "" `shouldBe` Nothing
  it "shows and reads" $
    property (showRead :: Msg -> Bool)
  it "reads from a string, upper or lower case" $
    property $ \(m :: Msg) ->
      fromString (bytesToHex m.get) == m
        && fromString (map toUpperHex (bytesToHex m.get)) == m
  it "does not read an invalid message" $ do
    (readMaybe (quoted (drop 1 one)) :: Maybe Msg) `shouldBe` Nothing
    -- A non-ASCII character is not a hex digit even when its low byte is one
    -- (U+FF41, fullwidth 'a').
    (readMaybe (quoted (take 63 allOnes ++ "\xFF41")) :: Maybe Msg) `shouldBe` Nothing
    evaluate (fromString (take 63 allOnes ++ "\xFF41") :: Msg) `shouldThrow` anyErrorCall
  where
    toUpperHex c = if c >= 'a' && c <= 'f' then toEnum (fromEnum c - 32) else c

-- * Signing

signingSpec :: Spec
signingSpec = describe "signing" $ do
  it "produces the RFC 6979 vector for key 1 and sha256 'Satoshi Nakamoto'" $ do
    bytesToHex (exportSig (signMsg keyOne satoshiMsg)) `shouldBe` satoshiDer
    bytesToHex (exportCompactSig (signMsg keyOne satoshiMsg)).get
      `shouldBe` satoshiR ++ satoshiS
  it "produces Bitcoin Core's deterministic signature" $ do
    bytesToHex (exportSig (signMsg coreKey coreMsg)) `shouldBe` coreDer
    bytesToHex (exportSig (signMsgLowR coreKey coreMsg)) `shouldBe` coreDer
  it "is deterministic" $
    property $
      \(m :: Msg, k :: SecKey) -> signMsg k m == signMsg k m
  it "verifies with the matching public key" $
    property $
      \(m :: Msg, k :: SecKey) -> signsAndVerifies (m, k)
  it "verifies in parallel" $
    property $ \(xs :: [(Msg, SecKey)]) -> P.runPar $ do
      results <- mapM (P.spawnP . signsAndVerifies) xs
      and <$> mapM P.get results
  it "produces lower-S signatures" $
    property $
      \(m :: Msg, k :: SecKey) -> isLowS (signMsg k m)
  describe "with low r" $ do
    it "leaves a signature alone when r is already low" $ do
      bytesToHex (exportSig (signMsg keyOne lowRMsg)) `shouldBe` lowRDer
      signMsgLowR keyOne lowRMsg `shouldBe` signMsg keyOne lowRMsg
    it "grinds a high r down the way Bitcoin Core does" $ do
      bytesToHex (exportSig (signMsg keyOne highRMsg)) `shouldBe` highRDer
      bytesToHex (exportSig (signMsgLowR keyOne highRMsg)) `shouldBe` groundDer
    it "always gives low r, lower s, at most 70 DER bytes, and verifies" $
      property $ \(m :: Msg, k :: SecKey) ->
        let s = signMsgLowR k m
         in isLowR s
              && isLowS s
              && BS.length (exportSig s) <= 70
              && verifySig (derivePubKey k) s m
    it "equals plain signing whenever that already has low r" $
      property $ \(m :: Msg, k :: SecKey) ->
        let s = signMsg k m
         in isLowR s ==> signMsgLowR k m == s
  where
    signsAndVerifies (m, k) =
      verifySig (derivePubKey k) (signMsg k m) m

-- * Verification

verificationSpec :: Spec
verificationSpec = describe "verification" $ do
  it "accepts the RFC 6979 vector from its DER encoding" $
    verifySig (fromString genCompressed) (fromJust (importSig (hexToBytes satoshiDer))) satoshiMsg
      `shouldBe` True
  it "accepts the historical vector" $
    verifySig
      (fromString histPub)
      ( fromJust . importSig . hexToBytes $
          "3045022100f502bfa07af43e7ef265618b0d929a7619ee01d6150e37eb6eaaf2c8bd37fb22\
          \02206f0415ab0e9a977afd78b2c26ef39b3952096d319fd4b101c768ad6c132e3045"
      )
      "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"
      `shouldBe` True
  it "rejects a signature from another key" $
    property $ \(m :: Msg, k :: SecKey, k' :: SecKey) ->
      k /= k' ==> not (verifySig (derivePubKey k') (signMsg k m) m)
  it "rejects a signature over another message" $
    property $ \(m :: Msg, m' :: Msg, k :: SecKey) ->
      m /= m' ==> not (verifySig (derivePubKey k) (signMsg k m) m')
  it "rejects a signature with one bit flipped" $
    property $ \(m :: Msg, k :: SecKey) ->
      let compact = (exportCompactSig (signMsg k m)).get
          -- Flipping the lowest bit of a lower-S s keeps it below n.
          flipped = BS.init compact `BS.snoc` (BS.last compact `xor` 1)
       in case importCompactSig (fromJust (compactSig flipped)) of
            Nothing -> False
            Just s -> not (verifySig (derivePubKey k) s m)
  describe "lower-S form" $ do
    it "rejects the high-S form of a valid signature" $ do
      let high = fromString (satoshiR ++ satoshiHighS) :: Sig
      isLowS high `shouldBe` False
      verifySig (fromString genCompressed) high satoshiMsg `shouldBe` False
    it "normalizes the high-S form to the signature that was made" $ do
      let high = fromString (satoshiR ++ satoshiHighS) :: Sig
          low = normalizeSig high
      low `shouldBe` signMsg keyOne satoshiMsg
      isLowS low `shouldBe` True
      verifySig (fromString genCompressed) low satoshiMsg `shouldBe` True
    it "leaves a lower-S signature unchanged" $
      property $ \(m :: Msg, k :: SecKey) ->
        let s = signMsg k m in normalizeSig s == s
    it "is idempotent" $ do
      let high = fromString (satoshiR ++ satoshiHighS) :: Sig
      normalizeSig (normalizeSig high) `shouldBe` normalizeSig high

-- * DER

derSpec :: Spec
derSpec = describe "DER signatures" $ do
  it "exports the RFC 6979 vector and imports it back" $ do
    let s = signMsg keyOne satoshiMsg
    bytesToHex (exportSig s) `shouldBe` satoshiDer
    importSig (hexToBytes satoshiDer) `shouldBe` Just s
  it "exports and imports back the same signature" $
    property $ \(m :: Msg, k :: SecKey) ->
      let s = signMsg k m in importSig (exportSig s) == Just s
  it "exports and imports in parallel" $
    property $ \(xs :: [(Msg, SecKey)]) -> P.runPar $ do
      results <- mapM (P.spawnP . roundTrip) xs
      and <$> mapM P.get results
  it "exports 70 bytes for low r and 71 bytes for high r" $ do
    BS.length (exportSig (signMsg keyOne lowRMsg)) `shouldBe` 70
    BS.length (exportSig (signMsg keyOne highRMsg)) `shouldBe` 71
  it "imports a high-S signature" $ do
    let high = fromString (satoshiR ++ satoshiHighS) :: Sig
    importSig (exportSig high) `shouldBe` Just high
  it "rejects an empty input" $
    importSig "" `shouldBe` Nothing
  it "rejects a component equal to n or zero" $ do
    -- r = n (33 bytes with a zero pad), s = r of the vector.
    importSig (hexToBytes ("3046022100" ++ order ++ "022100" ++ satoshiR)) `shouldBe` Nothing
    -- r = 0, s = r of the vector. 3 + 35 = 38 = 0x26 bytes.
    importSig (hexToBytes ("3026020100022100" ++ satoshiR)) `shouldBe` Nothing
    -- r of the vector, s = 0.
    importSig (hexToBytes ("3026022100" ++ satoshiR ++ "020100")) `shouldBe` Nothing
  it "rejects encodings that are not strict DER" $ do
    -- Long-form length for a value below 128.
    importSig (hexToBytes ("308145" ++ drop 4 satoshiDer)) `shouldBe` Nothing
    -- A byte after the sequence.
    importSig (hexToBytes (satoshiDer ++ "00")) `shouldBe` Nothing
    -- A byte missing at the end.
    importSig (hexToBytes (take (length satoshiDer - 2) satoshiDer)) `shouldBe` Nothing
    -- Wrong sequence tag.
    importSig (hexToBytes ("31" ++ drop 2 satoshiDer)) `shouldBe` Nothing
    -- Negative r: the zero pad is removed although the first byte is 0x93.
    importSig (hexToBytes ("30440220" ++ satoshiR ++ "0220" ++ satoshiS)) `shouldBe` Nothing
    -- Two zero pad bytes on r.
    importSig (hexToBytes ("3046022200" ++ "00" ++ satoshiR ++ "0220" ++ satoshiS)) `shouldBe` Nothing
  where
    roundTrip (m, k) = let s = signMsg k m in importSig (exportSig s) == Just s

-- * Compact signatures

compactSpec :: Spec
compactSpec = describe "compact signatures" $ do
  it "exports the RFC 6979 vector and imports it back" $ do
    let s = signMsg keyOne satoshiMsg
    bytesToHex (exportCompactSig s).get `shouldBe` satoshiR ++ satoshiS
    importCompactSig (fromString (satoshiR ++ satoshiS)) `shouldBe` Just s
  it "exports and imports back the same signature" $
    property $ \(m :: Msg, k :: SecKey) ->
      let s = signMsg k m in importCompactSig (exportCompactSig s) == Just s
  it "accepts components of 1 and n - 1 and rejects 0 and n" $ do
    importCompactSig (fromString (one ++ one)) `shouldSatisfy` isJust
    importCompactSig (fromString (orderMinusOne ++ orderMinusOne)) `shouldSatisfy` isJust
    importCompactSig (fromString (order ++ one)) `shouldBe` Nothing
    importCompactSig (fromString (one ++ order)) `shouldBe` Nothing
    importCompactSig (fromString (zero ++ one)) `shouldBe` Nothing
    importCompactSig (fromString (one ++ zero)) `shouldBe` Nothing
  it "only accepts 64 bytes as a compact signature" $ do
    compactSig (BS.replicate 64 1) `shouldSatisfy` isJust
    compactSig (BS.replicate 63 1) `shouldBe` Nothing
    compactSig (BS.replicate 65 1) `shouldBe` Nothing
  it "shows and reads a compact signature" $ do
    show (fromString (satoshiR ++ satoshiS) :: CompactSig) `shouldBe` quoted (satoshiR ++ satoshiS)
    (readMaybe (quoted (satoshiR ++ satoshiS)) :: Maybe CompactSig)
      `shouldBe` Just (fromString (satoshiR ++ satoshiS))
    (readMaybe (quoted satoshiR) :: Maybe CompactSig) `shouldBe` Nothing
    evaluate (fromString satoshiR :: CompactSig) `shouldThrow` anyErrorCall
  describe "signature values" $ do
    it "rebuild from their internal bytes" $
      property $
        \(m :: Msg, k :: SecKey) -> let s = signMsg k m in sig s.get == Just s
    it "reject internal bytes that are not a signature" $ do
      sig (BS.replicate 64 0) `shouldBe` Nothing
      sig (BS.replicate 64 0xff) `shouldBe` Nothing
      sig (BS.replicate 63 1) `shouldBe` Nothing
    it "show the compact encoding" $
      show (signMsg keyOne satoshiMsg) `shouldBe` quoted (satoshiR ++ satoshiS)
    it "read the compact encoding" $ do
      read (quoted (satoshiR ++ satoshiS)) `shouldBe` signMsg keyOne satoshiMsg
      (fromString (satoshiR ++ satoshiS) :: Sig) `shouldBe` signMsg keyOne satoshiMsg
    it "show and read" $
      property $
        \(m :: Msg, k :: SecKey) -> showRead (signMsg k m)
    it "do not read an invalid signature" $ do
      (readMaybe (quoted (zero ++ one)) :: Maybe Sig) `shouldBe` Nothing
      (readMaybe (quoted (order ++ one)) :: Maybe Sig) `shouldBe` Nothing
      (readMaybe (quoted satoshiDer) :: Maybe Sig) `shouldBe` Nothing
      evaluate (fromString satoshiDer :: Sig) `shouldThrow` anyErrorCall

-- * Tweaks

tweakSpec :: Spec
tweakSpec = describe "tweaks" $ do
  it "accepts 0 and n - 1 and rejects n and 2^256 - 1" $ do
    tweak (hexToBytes zero) `shouldSatisfy` isJust
    tweak (hexToBytes orderMinusOne) `shouldSatisfy` isJust
    tweak (hexToBytes order) `shouldBe` Nothing
    tweak (hexToBytes allOnes) `shouldBe` Nothing
    tweak (BS.replicate 31 0) `shouldBe` Nothing
  it "shows and reads" $
    property (showRead :: Tweak -> Bool)
  it "does not read a tweak of n" $ do
    (readMaybe (quoted order) :: Maybe Tweak) `shouldBe` Nothing
    evaluate (fromString order :: Tweak) `shouldThrow` anyErrorCall
  it "reads from a string" $
    property $
      \(t :: Tweak) -> fromString (bytesToHex t.get) == t
  it "adds to a secret key" $
    -- (key + tweak) mod n
    tweakAddSecKey histKey histTweak
      `shouldBe` Just "ec1e3ce1cefa18a671d51125e2b249688d934b0e28f5d1665384d9b02f929059"
  it "multiplies a secret key" $
    -- (key * tweak) mod n
    tweakMulSecKey histKey histTweak
      `shouldBe` Just "a96f5962493acb179f60a86a9785fc7a30e0c39b64c09d24fe064d9aef15e4c0"
  it "adds to a public key" $
    -- P + tweak * G
    fmap (bytesToHex . exportPubKey False) (tweakAddPubKey (fromString histPub) histTweak)
      `shouldBe` Just
        "04441c3982b97576646e0df0c96736063df6b42f2ee566d13b9f6424302d1379e5\
        \18fdc87a14c5435bff7a5db4552042cb4120c6b86a4bbd3d0643f3c14ad01368"
  it "multiplies a public key" $
    -- tweak * P
    fmap (bytesToHex . exportPubKey False) (tweakMulPubKey (fromString histPub) histTweak)
      `shouldBe` Just
        "04f379dc99cdf5c83e433defa267fbb3377d61d6b779c06a0e4ce29ae3ff5353b1\
        \2ae49c9d07e7368f2ba5a446c203255ce912322991a2d6a9d5d5761c61ed1845"
  it "tweaks the public key like the secret key" $
    property $ \(k :: SecKey, t :: Tweak) ->
      fmap (derivePubKey) (tweakAddSecKey k t) == tweakAddPubKey (derivePubKey k) t
        && fmap (derivePubKey) (tweakMulSecKey k t) == tweakMulPubKey (derivePubKey k) t
  it "adding zero changes nothing" $
    property $ \(k :: SecKey) ->
      tweakAddSecKey k (fromString zero) == Just k
        && tweakAddPubKey (derivePubKey k) (fromString zero) == Just (derivePubKey k)
  it "multiplying by zero fails" $ do
    tweakMulSecKey keyOne (fromString zero) `shouldBe` Nothing
    tweakMulPubKey (derivePubKey keyOne) (fromString zero) `shouldBe` Nothing
  it "adding the negation of the key fails" $ do
    -- 1 + (n - 1) = 0 mod n
    tweakAddSecKey keyOne (fromString orderMinusOne) `shouldBe` Nothing
    tweakAddPubKey (derivePubKey keyOne) (fromString orderMinusOne) `shouldBe` Nothing
  it "negates modulo n" $ do
    tweakNegate (fromString one) `shouldBe` Just (fromString orderMinusOne)
    tweakNegate (fromString zero) `shouldBe` Just (fromString zero)
    -- n - histTweak
    tweakNegate histTweak
      `shouldBe` Just "0a3418277e7d5b471bff0694f9ed76dd3464c4ce323753b0d77e433663ab7341"
  it "negating twice gives the tweak back" $
    property $
      \(t :: Tweak) -> (tweakNegate t >>= tweakNegate) == Just t
  it "adding a tweak and then its negation gives the key back" $
    property $ \(k :: SecKey, t :: Tweak) ->
      let minus = fromJust (tweakNegate t)
       in (tweakAddSecKey k t >>= \k' -> tweakAddSecKey k' minus) == Just k
  it "leaves its inputs unchanged" $
    property $ \(k :: SecKey, t :: Tweak) ->
      let kBytes = BS.copy k.get
          p = derivePubKey k
          pBytes = BS.copy p.get
          tBytes = BS.copy t.get
       in tweakAddSecKey k t `seq`
            tweakMulPubKey p t `seq`
              tweakNegate t `seq`
                (k.get == kBytes && p.get == pBytes && t.get == tBytes)

-- * Combining public keys

combineSpec :: Spec
combineSpec = describe "combining public keys" $ do
  it "adds three historical keys" $
    fmap
      (bytesToHex . exportPubKey False)
      ( combinePubKeys
          [ fromString histPub,
            "0487d82042d93447008dfe2af762068a1e53ff394a5bf8f68a045fa642b99ea5d1\
            \53f577dd2dba6c7ae4cfd7b6622409d7edd2d76dd13a8092cd3af97b77bd2c77",
            "049b101edcbe1ee37ff6b2318526a425b629e823d7d8d9154417880595a28000ee\
            \3febd908754b8ce4e491aa6fe488b41fb5d4bb3788e33c9ff95a7a9229166d59"
          ]
      )
      `shouldBe` Just
        "043d9a7ec70011efc23c33a7e62d2ea73cca87797e3b659d93bea6aa871aebde56\
        \c3bc6134ca82e324b0ab9c0e601a6d2933afe7fb5d9f3aae900f5c5dc6e362c8"
  it "adds G to itself" $
    -- 2 * G
    fmap (bytesToHex . exportPubKey True) (combinePubKeys [fromString genCompressed, fromString genCompressed])
      `shouldBe` Just "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
  it "adds like the secret keys add" $
    property $ \(k1 :: SecKey, k2 :: SecKey) ->
      combinePubKeys [derivePubKey k1, derivePubKey k2]
        == fmap (derivePubKey) (tweakAddSecKey k1 (fromString (bytesToHex k2.get)))
  it "returns a single key unchanged" $
    property $
      \(k :: SecKey) -> combinePubKeys [derivePubKey k] == Just (derivePubKey k)
  it "fails for no keys" $
    combinePubKeys [] `shouldBe` Nothing
  it "fails when the sum is the point at infinity" $
    property $ \(k :: SecKey) ->
      let p = derivePubKey k
          minusP = fromJust (tweakMulPubKey p (fromString orderMinusOne))
       in isNothing (combinePubKeys [p, minusP])

-- * Schnorr signatures

schnorrSpec :: Spec
schnorrSpec = describe "Schnorr signatures" $ do
  describe "BIP-340 vector" $ mapM_ bip340VectorSpec bip340Vectors
  it "signs vector 0 without auxiliary randomness as with 32 zero bytes" $
    signSchnorr bip340Key0 (fromString zero) `shouldBe` fromString bip340Sig0
  it "signs without randomness as with 32 zero bytes" $
    property $ \(m :: Msg, k :: SecKey) ->
      signSchnorrWithAux k m (BS.replicate 32 0) == Just (signSchnorr k m)
  it "verifies with the matching public key" $
    property $ \(m :: Msg, k :: SecKey) ->
      verifySchnorr (derivePubKey k) (signSchnorr k m) m
  it "verifies with the negation of the public key" $
    property $ \(m :: Msg, k :: SecKey) ->
      verifySchnorr (negatePubKey (derivePubKey k)) (signSchnorr k m) m
  it "verifies a signature made with fresh randomness" $
    property $ \(m :: Msg, k :: SecKey) -> ioProperty $ do
      s <- signSchnorrIO k m
      return (verifySchnorr (derivePubKey k) s m)
  it "changes with the auxiliary randomness" $
    property $ \(m :: Msg, k :: SecKey) ->
      signSchnorrWithAux k m (BS.replicate 32 1) /= signSchnorrWithAux k m (BS.replicate 32 2)
  it "rejects auxiliary randomness that is not 32 bytes" $ do
    signSchnorrWithAux keyOne satoshiMsg (BS.replicate 31 0) `shouldBe` Nothing
    signSchnorrWithAux keyOne satoshiMsg (BS.replicate 33 0) `shouldBe` Nothing
  it "rejects a signature from another key" $
    property $ \(m :: Msg, k :: SecKey, k' :: SecKey) ->
      k /= k' ==> not (verifySchnorr (derivePubKey k') (signSchnorr k m) m)
  it "rejects a signature over another message" $
    property $ \(m :: Msg, m' :: Msg, k :: SecKey) ->
      m /= m' ==> not (verifySchnorr (derivePubKey k) (signSchnorr k m) m')
  it "only accepts 64 bytes as a signature" $ do
    schnorrSig (BS.replicate 64 0) `shouldSatisfy` isJust
    schnorrSig (BS.replicate 63 0) `shouldBe` Nothing
    schnorrSig (BS.replicate 65 0) `shouldBe` Nothing
  it "shows the signature in hex" $
    show (fromString bip340Sig0 :: SchnorrSig) `shouldBe` quoted bip340Sig0
  it "shows and reads" $
    property $
      \(m :: Msg, k :: SecKey) -> showRead (signSchnorr k m)
  it "reads from a string" $
    property $ \(m :: Msg, k :: SecKey) ->
      let s = signSchnorr k m in fromString (bytesToHex s.get) == s
  it "does not read a signature of the wrong length" $ do
    (readMaybe (quoted (replicate 126 '0')) :: Maybe SchnorrSig) `shouldBe` Nothing
    evaluate (fromString (replicate 126 '0') :: SchnorrSig) `shouldThrow` anyErrorCall

-- For a vector with a secret key: the key gives the public key, and signing
-- with the given auxiliary randomness gives the signature. For every vector:
-- verification gives the expected result, where a public key that does not
-- import counts as a failed verification.
bip340VectorSpec :: BIP340Vector -> Spec
bip340VectorSpec v = it (show v.index ++ " " ++ v.comment) $ do
  let m = fromString v.message :: Msg
      s = fromString v.signature :: SchnorrSig
  case (v.secretKey, v.auxRand) of
    (Just key, Just aux) -> do
      let k = fromString key :: SecKey
      bytesToHex (exportXOnlyPubKey (derivePubKey k)) `shouldBe` v.publicKey
      signSchnorrWithAux k m (hexToBytes aux) `shouldBe` Just s
    _ -> return ()
  maybe False (\p -> verifySchnorr p s m) (importXOnlyPubKey (hexToBytes v.publicKey))
    `shouldBe` v.result

-- * X-only public keys

xOnlySpec :: Spec
xOnlySpec = describe "x-only public keys" $ do
  it "exports the x coordinate of G" $
    -- the compressed encoding of G without its 02 prefix
    bytesToHex (exportXOnlyPubKey (derivePubKey keyOne)) `shouldBe` drop 2 genCompressed
  it "exports the public key of BIP-340 vector 0" $
    bytesToHex (exportXOnlyPubKey (derivePubKey bip340Key0)) `shouldBe` bip340Pub0
  it "exports the x coordinate of any key" $
    property $ \(k :: SecKey) ->
      let p = derivePubKey k
       in exportXOnlyPubKey p == BS.drop 1 (exportPubKey True p)
  it "exports a key and its negation the same way" $
    property $ \(k :: SecKey) ->
      let p = derivePubKey k
       in exportXOnlyPubKey p == exportXOnlyPubKey (negatePubKey p)
  it "imports G from its x coordinate" $
    fmap (bytesToHex . exportPubKey True) (importXOnlyPubKey (hexToBytes (drop 2 genCompressed)))
      `shouldBe` Just genCompressed
  it "imports the point with an even y coordinate" $
    property $ \(k :: SecKey) ->
      let x = exportXOnlyPubKey (derivePubKey k)
       in fmap (exportPubKey True) (importXOnlyPubKey x) == Just (BS.cons 0x02 x)
  it "rejects an x coordinate that is not on the curve" $ do
    importXOnlyPubKey (hexToBytes fieldSize) `shouldBe` Nothing
    -- BIP-340 vector 5
    importXOnlyPubKey (hexToBytes "eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34")
      `shouldBe` Nothing
  it "rejects 31 and 33 bytes" $ do
    importXOnlyPubKey (BS.replicate 31 1) `shouldBe` Nothing
    importXOnlyPubKey (BS.replicate 33 1) `shouldBe` Nothing

-- * Taproot tweaks

taprootSpec :: Spec
taprootSpec = describe "Taproot tweaks" $ do
  describe "BIP-341 key path input" $ mapM_ (uncurry bip341VectorSpec) (zip [0 :: Int ..] bip341Vectors)
  it "tweaks the public key like the secret key" $
    property $ \(k :: SecKey, t :: Tweak) ->
      fmap (derivePubKey) (tweakAddXOnlySecKey k t) == tweakAddXOnlyPubKey (derivePubKey k) t
  it "tweaks a key and its negation alike" $
    property $ \(k :: SecKey, t :: Tweak) ->
      let p = derivePubKey k
       in tweakAddXOnlyPubKey p t == tweakAddXOnlyPubKey (negatePubKey p) t
  it "signs for the tweaked output key with the tweaked secret key" $
    property $ \(m :: Msg, k :: SecKey, t :: Tweak) ->
      let k' = fromJust (tweakAddXOnlySecKey k t)
          p' = fromJust (tweakAddXOnlyPubKey (derivePubKey k) t)
       in verifySchnorr p' (signSchnorr k' m) m
  it "adding zero gives the point with an even y coordinate" $
    property $ \(k :: SecKey) ->
      let p = derivePubKey k
       in fmap (exportPubKey True) (tweakAddXOnlyPubKey p (fromString zero))
            == Just (BS.cons 0x02 (exportXOnlyPubKey p))
  it "negates a secret key whose public key has an odd y coordinate" $
    -- Key n - 1 has the public key -G, whose y coordinate is odd, so the key
    -- is negated to 1 before the zero tweak is added.
    tweakAddXOnlySecKey (fromString orderMinusOne) (fromString zero) `shouldBe` Just keyOne
  it "fails when the result would be zero" $ do
    -- G has an even y coordinate, so key 1 is not negated: 1 + (n - 1) = 0.
    tweakAddXOnlySecKey keyOne (fromString orderMinusOne) `shouldBe` Nothing
    tweakAddXOnlyPubKey (derivePubKey keyOne) (fromString orderMinusOne) `shouldBe` Nothing
    -- Key n - 1 is negated to 1 first, with the same result.
    tweakAddXOnlySecKey (fromString orderMinusOne) (fromString orderMinusOne) `shouldBe` Nothing
    tweakAddXOnlyPubKey (derivePubKey (fromString orderMinusOne)) (fromString orderMinusOne)
      `shouldBe` Nothing

-- The internal key gives the internal public key. The tweak gives the tweaked
-- secret key and the output key, and they match. The tweaked key signs the
-- signature hash to the signature in the witness, which verifies against the
-- output key.
bip341VectorSpec :: Int -> BIP341Vector -> Spec
bip341VectorSpec i v = it (show i) $ do
  let k = fromString v.internalKey :: SecKey
      t = fromString v.tapTweak :: Tweak
      k' = fromString v.tweakedKey :: SecKey
      m = fromString v.sigHash :: Msg
      s = fromString v.keyPathSig :: SchnorrSig
  bytesToHex (exportXOnlyPubKey (derivePubKey k)) `shouldBe` v.internalPub
  tweakAddXOnlySecKey k t `shouldBe` Just k'
  fmap (bytesToHex . exportXOnlyPubKey) (tweakAddXOnlyPubKey (derivePubKey k) t)
    `shouldBe` Just v.outputKey
  signSchnorr k' m `shouldBe` s
  verifySchnorr (fromJust (importXOnlyPubKey (hexToBytes v.outputKey))) s m `shouldBe` True

-- * Values built with the raw constructors of the Internal module

rawValueSpec :: Spec
rawValueSpec = describe "raw values from the Internal module" $ do
  describe "a public key with a zero x coordinate" $ do
    it "does not verify, instead of aborting the process" $
      property $ \(m :: Msg, k :: SecKey) ->
        not (verifySig zeroKey (signMsg k m) m)
    it "throws on export" $
      evaluate (exportPubKey True zeroKey) `shouldThrow` anyErrorCall
    it "throws on show" $
      evaluate (length (show zeroKey)) `shouldThrow` anyErrorCall
    it "fails to tweak" $ do
      tweakAddPubKey zeroKey (fromString one) `shouldBe` Nothing
      tweakMulPubKey zeroKey (fromString one) `shouldBe` Nothing
    it "fails to combine" $
      combinePubKeys [derivePubKey keyOne, zeroKey] `shouldBe` Nothing
    it "does not verify a Schnorr signature" $
      verifySchnorr zeroKey (signSchnorr keyOne satoshiMsg) satoshiMsg `shouldBe` False
    it "throws on x-only export" $
      evaluate (exportXOnlyPubKey zeroKey) `shouldThrow` anyErrorCall
    it "fails to tweak as an x-only key" $
      tweakAddXOnlyPubKey zeroKey (fromString one) `shouldBe` Nothing
  it "a public key off the curve fails to combine" $
    combinePubKeys [derivePubKey keyOne, PubKey (BS.replicate 64 1)] `shouldBe` Nothing
  it "a zero secret key throws instead of signing" $ do
    evaluate (signMsg (SecKey (BS.replicate 32 0)) satoshiMsg) `shouldThrow` anyErrorCall
    evaluate (derivePubKey (SecKey (BS.replicate 32 0))) `shouldThrow` anyErrorCall
    evaluate (signSchnorr (SecKey (BS.replicate 32 0)) satoshiMsg) `shouldThrow` anyErrorCall
  it "a zero secret key fails to tweak as an x-only key" $
    tweakAddXOnlySecKey (SecKey (BS.replicate 32 0)) (fromString one) `shouldBe` Nothing
  it "a tweak of n fails" $ do
    tweakAddSecKey keyOne (Tweak (hexToBytes order)) `shouldBe` Nothing
    tweakNegate (Tweak (hexToBytes order)) `shouldBe` Nothing
    tweakAddXOnlySecKey keyOne (Tweak (hexToBytes order)) `shouldBe` Nothing
    tweakAddXOnlyPubKey (derivePubKey keyOne) (Tweak (hexToBytes order)) `shouldBe` Nothing
  it "values of the wrong length throw before reaching the library" $ do
    evaluate (derivePubKey (SecKey "a")) `shouldThrow` anyErrorCall
    evaluate (signMsg (SecKey "a") satoshiMsg) `shouldThrow` anyErrorCall
    evaluate (signMsg keyOne (Msg "a")) `shouldThrow` anyErrorCall
    evaluate (verifySig (derivePubKey keyOne) (Sig "a") satoshiMsg) `shouldThrow` anyErrorCall
    evaluate (verifySig (PubKey "a") (signMsg keyOne satoshiMsg) satoshiMsg) `shouldThrow` anyErrorCall
    evaluate (verifySig (derivePubKey keyOne) (signMsg keyOne satoshiMsg) (Msg "a")) `shouldThrow` anyErrorCall
    evaluate (exportSig (Sig "a")) `shouldThrow` anyErrorCall
    evaluate (exportCompactSig (Sig "a")) `shouldThrow` anyErrorCall
    evaluate (importCompactSig (CompactSig "a")) `shouldThrow` anyErrorCall
    evaluate (normalizeSig (Sig "a")) `shouldThrow` anyErrorCall
    evaluate (isLowS (Sig "a")) `shouldThrow` anyErrorCall
    evaluate (exportPubKey True (PubKey "a")) `shouldThrow` anyErrorCall
    evaluate (tweakAddSecKey keyOne (Tweak "a")) `shouldThrow` anyErrorCall
    evaluate (tweakMulSecKey (SecKey "a") (fromString one)) `shouldThrow` anyErrorCall
    evaluate (tweakAddPubKey (PubKey "a") (fromString one)) `shouldThrow` anyErrorCall
    evaluate (tweakMulPubKey (derivePubKey keyOne) (Tweak "a")) `shouldThrow` anyErrorCall
    evaluate (tweakNegate (Tweak "a")) `shouldThrow` anyErrorCall
    evaluate (combinePubKeys [derivePubKey keyOne, PubKey "a"]) `shouldThrow` anyErrorCall
    evaluate (tweakAddSecKey (SecKey "a") (fromString one)) `shouldThrow` anyErrorCall
    evaluate (tweakMulSecKey keyOne (Tweak "a")) `shouldThrow` anyErrorCall
    evaluate (tweakAddPubKey (derivePubKey keyOne) (Tweak "a")) `shouldThrow` anyErrorCall
    evaluate (tweakMulPubKey (PubKey "a") (fromString one)) `shouldThrow` anyErrorCall
    evaluate (signMsgWith keyOne satoshiMsg (Just "a")) `shouldThrow` anyErrorCall
    evaluate (signSchnorr (SecKey "a") satoshiMsg) `shouldThrow` anyErrorCall
    evaluate (signSchnorr keyOne (Msg "a")) `shouldThrow` anyErrorCall
    evaluate (verifySchnorr (derivePubKey keyOne) (SchnorrSig "a") satoshiMsg) `shouldThrow` anyErrorCall
    evaluate (verifySchnorr (PubKey "a") (signSchnorr keyOne satoshiMsg) satoshiMsg) `shouldThrow` anyErrorCall
    evaluate (verifySchnorr (derivePubKey keyOne) (signSchnorr keyOne satoshiMsg) (Msg "a")) `shouldThrow` anyErrorCall
    evaluate (exportXOnlyPubKey (PubKey "a")) `shouldThrow` anyErrorCall
    evaluate (tweakAddXOnlyPubKey (PubKey "a") (fromString one)) `shouldThrow` anyErrorCall
    evaluate (tweakAddXOnlyPubKey (derivePubKey keyOne) (Tweak "a")) `shouldThrow` anyErrorCall
    evaluate (tweakAddXOnlySecKey (SecKey "a") (fromString one)) `shouldThrow` anyErrorCall
    evaluate (tweakAddXOnlySecKey keyOne (Tweak "a")) `shouldThrow` anyErrorCall
  where
    zeroKey = PubKey (BS.replicate 64 0)

-- * Derived instances

instanceSpec :: Spec
instanceSpec = describe "derived instances" $ do
  it "equal values hash equally, whichever way they were built" $
    property $ \(m :: Msg, k :: SecKey) ->
      let p = derivePubKey k
          s = signMsg k m
          sc = signSchnorr k m
       in hash p == hash (fromJust (importPubKey (exportPubKey False p)))
            && hash s == hash (fromJust (importSig (exportSig s)))
            && hash k == hash (fromJust (secKey k.get))
            && hash sc == hash (fromJust (schnorrSig sc.get))
  it "can be fully evaluated" $ do
    let p = derivePubKey keyOne
        s = signMsg keyOne satoshiMsg
    ((p, s, keyOne, satoshiMsg, histTweak, exportCompactSig s, signSchnorr keyOne satoshiMsg) `deepseq` ())
      `shouldBe` ()
