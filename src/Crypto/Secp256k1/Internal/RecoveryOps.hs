-- | Foreign imports of the @recovery@ module of libsecp256k1, which the
-- library only has when it was built with @--enable-module-recovery@. See
-- "Crypto.Secp256k1.Recovery". This module is only built when the @recovery@
-- flag of the package is on.
module Crypto.Secp256k1.Internal.RecoveryOps where

import Crypto.Secp256k1.Internal.ForeignTypes
  ( Compact64,
    LCtx,
    Msg32,
    NonceFun,
    PubKey64,
    RecSig65,
    Ret,
    SecKey32,
    Sig64,
  )
import Foreign (FunPtr, Ptr)
import Foreign.C (CInt (..))

-- | Binding to @secp256k1_ecdsa_recoverable_signature_parse_compact@.
foreign import ccall safe "secp256k1_recovery.h secp256k1_ecdsa_recoverable_signature_parse_compact"
  ecdsaRecoverableSignatureParseCompact ::
    Ptr LCtx ->
    Ptr RecSig65 ->
    Ptr Compact64 ->
    -- | recovery id, 0 to 3
    CInt ->
    IO Ret

-- | Binding to @secp256k1_ecdsa_recoverable_signature_serialize_compact@.
foreign import ccall safe "secp256k1_recovery.h secp256k1_ecdsa_recoverable_signature_serialize_compact"
  ecdsaRecoverableSignatureSerializeCompact ::
    Ptr LCtx ->
    Ptr Compact64 ->
    -- | recovery id, written by the function
    Ptr CInt ->
    Ptr RecSig65 ->
    IO Ret

-- | Binding to @secp256k1_ecdsa_recoverable_signature_convert@.
foreign import ccall safe "secp256k1_recovery.h secp256k1_ecdsa_recoverable_signature_convert"
  ecdsaRecoverableSignatureConvert ::
    Ptr LCtx ->
    -- | output
    Ptr Sig64 ->
    -- | input
    Ptr RecSig65 ->
    IO Ret

-- | Binding to @secp256k1_ecdsa_sign_recoverable@.
foreign import ccall safe "secp256k1_recovery.h secp256k1_ecdsa_sign_recoverable"
  ecdsaSignRecoverable ::
    Ptr LCtx ->
    Ptr RecSig65 ->
    Ptr Msg32 ->
    Ptr SecKey32 ->
    FunPtr (NonceFun a) ->
    -- | nonce data
    Ptr a ->
    IO Ret

-- | Binding to @secp256k1_ecdsa_recover@.
foreign import ccall safe "secp256k1_recovery.h secp256k1_ecdsa_recover"
  ecdsaRecover ::
    Ptr LCtx ->
    Ptr PubKey64 ->
    Ptr RecSig65 ->
    Ptr Msg32 ->
    IO Ret
