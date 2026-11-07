-- | Foreign imports of the core, @extrakeys@ and @schnorrsig@ modules of libsecp256k1.
--
-- Each function is a direct binding to the C function of the same name in
-- @secp256k1.h@, @secp256k1_extrakeys.h@ or @secp256k1_schnorrsig.h@. The
-- bindings are @safe@ calls: signing and verifying take tens of microseconds,
-- and a @safe@ call lets other Haskell threads run meanwhile. Never call these
-- directly with unchecked inputs; "Crypto.Secp256k1.Internal.Base" validates
-- lengths and contents first. This module is internal and has no API
-- stability guarantee.
module Crypto.Secp256k1.Internal.BaseOps where

import Crypto.Secp256k1.Internal.ForeignTypes
  ( AuxRand32,
    Compact64,
    KeyPair96,
    LCtx,
    Msg32,
    NonceFun,
    PubKey64,
    Ret,
    SchnorrSig64,
    SecKey32,
    SerFlags,
    Sig64,
    Tweak32,
    XOnlyPubKey64,
  )
import Foreign (FunPtr, Ptr)
import Foreign.C
  ( CInt (..),
    CSize (..),
    CUChar,
    CUInt (..),
  )

-- | Binding to @secp256k1_ec_pubkey_parse@.
foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_parse"
  ecPubKeyParse ::
    Ptr LCtx ->
    Ptr PubKey64 ->
    -- | encoded public key array
    Ptr CUChar ->
    -- | size of encoded public key array
    CSize ->
    IO Ret

-- | Binding to @secp256k1_ec_pubkey_serialize@.
foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_serialize"
  ecPubKeySerialize ::
    Ptr LCtx ->
    -- | array for encoded public key, must be large enough
    Ptr CUChar ->
    -- | size of encoded public key, will be updated
    Ptr CSize ->
    Ptr PubKey64 ->
    SerFlags ->
    IO Ret

-- | Binding to @secp256k1_ecdsa_signature_parse_compact@.
foreign import ccall safe "secp256k1.h secp256k1_ecdsa_signature_parse_compact"
  ecdsaSignatureParseCompact ::
    Ptr LCtx ->
    Ptr Sig64 ->
    Ptr Compact64 ->
    IO Ret

-- | Binding to @secp256k1_ecdsa_signature_parse_der@.
foreign import ccall safe "secp256k1.h secp256k1_ecdsa_signature_parse_der"
  ecdsaSignatureParseDer ::
    Ptr LCtx ->
    Ptr Sig64 ->
    -- | encoded DER signature
    Ptr CUChar ->
    -- | size of encoded signature
    CSize ->
    IO Ret

-- | Binding to @secp256k1_ecdsa_signature_serialize_der@.
foreign import ccall safe "secp256k1.h secp256k1_ecdsa_signature_serialize_der"
  ecdsaSignatureSerializeDer ::
    Ptr LCtx ->
    -- | array for encoded signature, must be large enough
    Ptr CUChar ->
    -- | size of encoded signature, will be updated
    Ptr CSize ->
    Ptr Sig64 ->
    IO Ret

-- | Binding to @secp256k1_ecdsa_signature_serialize_compact@.
foreign import ccall safe "secp256k1.h secp256k1_ecdsa_signature_serialize_compact"
  ecdsaSignatureSerializeCompact ::
    Ptr LCtx ->
    Ptr Compact64 ->
    Ptr Sig64 ->
    IO Ret

-- | Binding to @secp256k1_ecdsa_verify@.
foreign import ccall safe "secp256k1.h secp256k1_ecdsa_verify"
  ecdsaVerify ::
    Ptr LCtx ->
    Ptr Sig64 ->
    Ptr Msg32 ->
    Ptr PubKey64 ->
    IO Ret

-- | Binding to @secp256k1_ecdsa_signature_normalize@.
foreign import ccall safe "secp256k1.h secp256k1_ecdsa_signature_normalize"
  ecdsaSignatureNormalize ::
    Ptr LCtx ->
    -- | output
    Ptr Sig64 ->
    -- | input
    Ptr Sig64 ->
    IO Ret

-- | Binding to @secp256k1_ecdsa_sign@.
foreign import ccall safe "secp256k1.h secp256k1_ecdsa_sign"
  ecdsaSign ::
    Ptr LCtx ->
    Ptr Sig64 ->
    Ptr Msg32 ->
    Ptr SecKey32 ->
    FunPtr (NonceFun a) ->
    -- | nonce data
    Ptr a ->
    IO Ret

-- | Binding to @secp256k1_ec_seckey_verify@.
foreign import ccall safe "secp256k1.h secp256k1_ec_seckey_verify"
  ecSecKeyVerify ::
    Ptr LCtx ->
    Ptr SecKey32 ->
    IO Ret

-- | Binding to @secp256k1_ec_pubkey_create@.
foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_create"
  ecPubKeyCreate ::
    Ptr LCtx ->
    Ptr PubKey64 ->
    Ptr SecKey32 ->
    IO Ret

-- | Binding to @secp256k1_ec_seckey_tweak_add@.
foreign import ccall safe "secp256k1.h secp256k1_ec_seckey_tweak_add"
  ecSecKeyTweakAdd ::
    Ptr LCtx ->
    Ptr SecKey32 ->
    Ptr Tweak32 ->
    IO Ret

-- | Binding to @secp256k1_ec_seckey_negate@.
foreign import ccall safe "secp256k1.h secp256k1_ec_seckey_negate"
  ecTweakNegate ::
    Ptr LCtx ->
    Ptr Tweak32 ->
    IO Ret

-- | Binding to @secp256k1_ec_pubkey_tweak_add@.
foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_tweak_add"
  ecPubKeyTweakAdd ::
    Ptr LCtx ->
    Ptr PubKey64 ->
    Ptr Tweak32 ->
    IO Ret

-- | Binding to @secp256k1_ec_seckey_tweak_mul@.
foreign import ccall safe "secp256k1.h secp256k1_ec_seckey_tweak_mul"
  ecSecKeyTweakMul ::
    Ptr LCtx ->
    Ptr SecKey32 ->
    Ptr Tweak32 ->
    IO Ret

-- | Binding to @secp256k1_ec_pubkey_tweak_mul@.
foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_tweak_mul"
  ecPubKeyTweakMul ::
    Ptr LCtx ->
    Ptr PubKey64 ->
    Ptr Tweak32 ->
    IO Ret

-- | Binding to @secp256k1_ec_pubkey_combine@.
foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_combine"
  ecPubKeyCombine ::
    Ptr LCtx ->
    -- | pointer to public key storage
    Ptr PubKey64 ->
    -- | pointer to array of public keys
    Ptr (Ptr PubKey64) ->
    -- | number of public keys
    CSize ->
    IO Ret

-- The following functions belong to the @extrakeys@ and @schnorrsig@ modules
-- of libsecp256k1, enabled by default since version 0.2.0.

-- | Binding to @secp256k1_xonly_pubkey_from_pubkey@.
foreign import ccall safe "secp256k1_extrakeys.h secp256k1_xonly_pubkey_from_pubkey"
  xOnlyPubKeyFromPubKey ::
    Ptr LCtx ->
    Ptr XOnlyPubKey64 ->
    -- | parity of the public key, 1 if odd; may be NULL
    Ptr CInt ->
    Ptr PubKey64 ->
    IO Ret

-- | Binding to @secp256k1_xonly_pubkey_serialize@.
foreign import ccall safe "secp256k1_extrakeys.h secp256k1_xonly_pubkey_serialize"
  xOnlyPubKeySerialize ::
    Ptr LCtx ->
    -- | 32-byte output
    Ptr CUChar ->
    Ptr XOnlyPubKey64 ->
    IO Ret

-- | Binding to @secp256k1_xonly_pubkey_tweak_add@.
foreign import ccall safe "secp256k1_extrakeys.h secp256k1_xonly_pubkey_tweak_add"
  xOnlyPubKeyTweakAdd ::
    Ptr LCtx ->
    -- | tweaked public key
    Ptr PubKey64 ->
    Ptr XOnlyPubKey64 ->
    Ptr Tweak32 ->
    IO Ret

-- | Binding to @secp256k1_keypair_create@.
foreign import ccall safe "secp256k1_extrakeys.h secp256k1_keypair_create"
  keyPairCreate ::
    Ptr LCtx ->
    Ptr KeyPair96 ->
    Ptr SecKey32 ->
    IO Ret

-- | Binding to @secp256k1_keypair_sec@.
foreign import ccall safe "secp256k1_extrakeys.h secp256k1_keypair_sec"
  keyPairSec ::
    Ptr LCtx ->
    Ptr SecKey32 ->
    Ptr KeyPair96 ->
    IO Ret

-- | Binding to @secp256k1_keypair_xonly_pub@.
foreign import ccall safe "secp256k1_extrakeys.h secp256k1_keypair_xonly_pub"
  keyPairXOnlyPub ::
    Ptr LCtx ->
    Ptr XOnlyPubKey64 ->
    -- | parity of the public key, 1 if odd; may be NULL
    Ptr CInt ->
    Ptr KeyPair96 ->
    IO Ret

-- | Binding to @secp256k1_keypair_xonly_tweak_add@.
foreign import ccall safe "secp256k1_extrakeys.h secp256k1_keypair_xonly_tweak_add"
  keyPairXOnlyTweakAdd ::
    Ptr LCtx ->
    Ptr KeyPair96 ->
    Ptr Tweak32 ->
    IO Ret

-- | Binding to @secp256k1_schnorrsig_sign32@.
foreign import ccall safe "secp256k1_schnorrsig.h secp256k1_schnorrsig_sign32"
  schnorrSigSign32 ::
    Ptr LCtx ->
    Ptr SchnorrSig64 ->
    Ptr Msg32 ->
    Ptr KeyPair96 ->
    -- | auxiliary randomness; may be NULL
    Ptr AuxRand32 ->
    IO Ret

-- | Binding to @secp256k1_schnorrsig_verify@.
foreign import ccall safe "secp256k1_schnorrsig.h secp256k1_schnorrsig_verify"
  schnorrSigVerify ::
    Ptr LCtx ->
    Ptr SchnorrSig64 ->
    -- | message
    Ptr CUChar ->
    -- | message length
    CSize ->
    Ptr XOnlyPubKey64 ->
    IO Ret
