{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Fixtures and helpers shared by the specifications.
module Crypto.Secp256k1.Fixtures where

import Crypto.Secp256k1
import Data.Base16.Types (assertBase16, extractBase16)
import Data.ByteString qualified as BS
import Data.ByteString.Base16 (decodeBase16, encodeBase16')
import Data.ByteString.Char8 qualified as B8
import Data.Maybe (fromJust)
import Data.String (fromString)

-- * Fixtures
--
-- Every expected value is a literal from an independent source: the secp256k1
-- generator, the RFC 6979 vector for key 1 and sha256 "Satoshi Nakamoto",
-- Bitcoin Core's key_tests.cpp, or this package's historical vectors, all
-- recomputed with an independent implementation of the curve.

zero, one, order, orderMinusOne, orderPlusOne, allOnes :: String
zero = "0000000000000000000000000000000000000000000000000000000000000000"
one = "0000000000000000000000000000000000000000000000000000000000000001"
order = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
orderMinusOne = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
orderPlusOne = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142"
allOnes = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

-- Secret key 1. Its public key is the generator G.
keyOne :: SecKey
keyOne = fromString one

-- The generator G in its three SEC1 encodings. y is even, so the compressed
-- prefix is 02 and the hybrid prefix is 06.
genCompressed, genUncompressed, genHybrid :: String
genCompressed =
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
genUncompressed =
  "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
  \483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
genHybrid =
  "0679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
  \483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"

-- RFC 6979 vector: key 1 signing sha256 "Satoshi Nakamoto".
satoshiMsg :: Msg
satoshiMsg = "a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e"

satoshiR, satoshiS, satoshiHighS :: String
satoshiR = "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8"
satoshiS = "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"
-- n - s
satoshiHighS = "dbbd3162d46e9f9bef7feb87c16dc13b4f6568a87f4e83f728e2443ba586675c"

satoshiDer :: String
satoshiDer = "3045022100" ++ satoshiR ++ "0220" ++ satoshiS

-- Bitcoin Core key_tests.cpp: the secret key of WIF
-- 5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj signing
-- sha256d "Very deterministic message".
coreKey :: SecKey
coreKey = "12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747"

coreMsg :: Msg
coreMsg = "5255683da567900bfd3e786ed8836a4e7763c221bf1ac20ece2a5171b9199e8a"

coreDer :: String
coreDer =
  "304402205dbbddda71772d95ce91cd2d14b592cfbc1dd0aabd6a394b6c2d377bbe59d31d\
  \022014ddda21494a4e221f0824f0b8b924c43fa43c0ad57dccdaa11f81a6bd4582f6"

-- Key 1 signing sha256 "4". Plain RFC 6979 gives a high r (first byte d4),
-- so Bitcoin Core's grinding retries once with counter 1 as extra nonce data.
highRMsg :: Msg
highRMsg = "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"

highRDer, groundDer :: String
highRDer =
  "3045022100d479c93a086bf5f4ae1fed7eaf2604a4da2007d851c5409961c81dd7f0600194\
  \02201cd7a196454152f5b8d19865d49b4fa71e314ebff9c59e2f7b2295bf80331be8"
groundDer =
  "3044022020b11f7066dd4486e811ea4f1fee43b1538fcd5bedb64b52d01e56b13422430c\
  \022056cb81320c8439cee666af08788c08e60fda80216a25f52b38714191c8cd1b99"

-- Key 1 signing sha256 "1". Plain RFC 6979 already gives a low r.
lowRMsg :: Msg
lowRMsg = "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"

lowRDer :: String
lowRDer =
  "304402202d24f8d536fccf696a4edfa858e5d6fc89a11d25f72ef4f89de1577d53643c0a\
  \02200d25586b118d5d7f8b79a7805c885fa8588dfa9e6cc777edc11a7e33de844285"

-- Historical vectors of this package.
histKey :: SecKey
histKey = "f65255094d7773ed8dd417badc9fc045c1f80fdc5b2d25172b031ce6933e039a"

histTweak :: Tweak
histTweak = "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"

histPub :: String
histPub =
  "04dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd44705\
  \12213d5ed790522c042dee8e85c4c0ec5f96800b72bc5940c8bc1c5e11e4fcbf"

-- The field size p of secp256k1. It is not a valid x coordinate.
fieldSize :: String
fieldSize = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"

-- * Helpers

hexToBytes :: String -> BS.ByteString
hexToBytes = decodeBase16 . assertBase16 . B8.pack

bytesToHex :: BS.ByteString -> String
bytesToHex = B8.unpack . extractBase16 . encodeBase16'

showRead :: (Show a, Read a, Eq a) => a -> Bool
showRead x = read (show x) == x

-- The hex literal, quoted the way 'show' quotes a string.
quoted :: String -> String
quoted s = "\"" ++ s ++ "\""

-- The negation of a public key: multiplication by n - 1.
negatePubKey :: Ctx -> PubKey -> PubKey
negatePubKey ctx p = fromJust (tweakMulPubKey ctx p (fromString orderMinusOne))
