-- | Types and constants shared by the foreign imports.
--
-- Each empty data type stands for a C structure of libsecp256k1 and is only
-- ever used behind a 'Ptr', so that the foreign imports cannot mix up, say, a
-- pointer to a public key and a pointer to a signature. The number in the name
-- is the size of the structure in bytes, which the Haskell side must allocate.
-- This module is internal and has no API stability guarantee.
module Crypto.Secp256k1.Internal.ForeignTypes where

import Foreign (Ptr)
import Foreign.C (CInt (..), CUChar, CUInt (..))

-- | Context (@secp256k1_context@).
data LCtx

-- | Public key (@secp256k1_pubkey@), 64 bytes.
data PubKey64

-- | Message hash, 32 bytes.
data Msg32

-- | ECDSA signature (@secp256k1_ecdsa_signature@), 64 bytes.
data Sig64

-- | Randomization seed for a context, 32 bytes.
data Seed32

-- | Compact ECDSA signature, r and s, 64 bytes.
data Compact64

-- | Secret key, 32 bytes.
data SecKey32

-- | Tweak, 32 bytes.
data Tweak32

-- | Recoverable ECDSA signature (@secp256k1_ecdsa_recoverable_signature@), 65 bytes.
data RecSig65

-- | X-only public key (@secp256k1_xonly_pubkey@), 64 bytes.
data XOnlyPubKey64

-- | Key pair (@secp256k1_keypair@), 96 bytes.
data KeyPair96

-- | BIP-340 signature, 64 bytes.
data SchnorrSig64

-- | Auxiliary randomness for BIP-340 signing, 32 bytes.
data AuxRand32

-- | Flags passed to @secp256k1_context_create@.
type CtxFlags = CUInt

-- | Flags passed to @secp256k1_ec_pubkey_serialize@.
type SerFlags = CUInt

-- | Return value of a C function: 1 for success, 0 for failure.
type Ret = CInt

-- | Nonce generation function, as @secp256k1_nonce_function@. The bindings pass
-- 'Foreign.nullFunPtr' for the default RFC 6979 function, or a pointer to
-- Bitcoin Core's grinding data through the last argument.
type NonceFun a =
  Ptr CUChar ->
  Ptr CUChar ->
  Ptr CUChar ->
  Ptr CUChar ->
  Ptr a ->
  CInt ->
  IO CInt

-- | @SECP256K1_EC_COMPRESSED@: serialize a public key in 33 bytes.
compressed :: SerFlags
compressed = 0x0102

-- | @SECP256K1_EC_UNCOMPRESSED@: serialize a public key in 65 bytes.
uncompressed :: SerFlags
uncompressed = 0x0002

-- | Interpret a return value. Anything but 0 or 1 means the C library and these
-- bindings disagree about a function's contract, so it raises an error rather
-- than guess.
isSuccess :: Ret -> Bool
isSuccess 0 = False
isSuccess 1 = True
isSuccess n = error $ "isSuccess expected 0 or 1 but got " ++ show n
