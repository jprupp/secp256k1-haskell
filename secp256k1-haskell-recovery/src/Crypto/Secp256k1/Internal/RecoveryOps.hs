-- |
-- Module      : Crypto.Secp256k1.Internal.RecoveryOps
-- License     : UNLICENSE
-- Maintainer  : Jean-Pierre Rupp <jprupp@protonmail.ch>
-- Stability   : experimental
-- Portability : POSIX
--
-- The API for this module may change at any time. This is an internal module only
-- exposed for hacking and experimentation.
module Crypto.Secp256k1.Internal.RecoveryOps where

import Crypto.Secp256k1.Internal.ForeignTypes (Compact64, LCtx, Msg32, NonceFun, PubKey64, Ret, SecKey32, Sig64)
import Foreign (FunPtr, Ptr)
import Foreign.C (CInt (..))

data RecSig65

foreign import ccall safe "secp256k1_recovery.h secp256k1_ecdsa_recoverable_signature_parse_compact"
  ecdsaRecoverableSignatureParseCompact ::
    Ptr LCtx ->
    Ptr RecSig65 ->
    Ptr Compact64 ->
    CInt ->
    IO Ret

foreign import ccall safe "secp256k1_recovery.h secp256k1_ecdsa_recoverable_signature_convert"
  ecdsaRecoverableSignatureConvert ::
    Ptr LCtx ->
    Ptr Sig64 ->
    Ptr RecSig65 ->
    IO Ret

foreign import ccall safe "secp256k1_recovery.h secp256k1_ecdsa_recoverable_signature_serialize_compact"
  ecdsaRecoverableSignatureSerializeCompact ::
    Ptr LCtx ->
    Ptr Compact64 ->
    Ptr CInt ->
    Ptr RecSig65 ->
    IO Ret

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

foreign import ccall safe "secp256k1_recovery.h secp256k1_ecdsa_recover"
  ecdsaRecover ::
    Ptr LCtx ->
    Ptr PubKey64 ->
    Ptr RecSig65 ->
    Ptr Msg32 ->
    IO Ret
