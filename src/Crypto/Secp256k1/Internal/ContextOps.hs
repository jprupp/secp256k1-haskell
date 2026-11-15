-- | Foreign imports for creating and managing libsecp256k1 contexts, and the
-- flags they take.
--
-- The package needs these only once, to make its global context in
-- "Crypto.Secp256k1.Internal.Context". The tests also use them, to exercise
-- the raw bindings of "Crypto.Secp256k1.Internal.BaseOps" on contexts of
-- their own.
--
-- This module is hidden: the package does not expose it, nor any other
-- module that makes, takes or names a context. The owner's decision is that
-- the one global context is the only context there is, so the library offers
-- no way to create another. The price is that code outside the package can
-- no longer call the raw bindings; it uses the validated functions of
-- "Crypto.Secp256k1" instead.
--
-- 'contextRandomize' and the two callback setters modify a context, so they
-- need exclusive access to it. They must never be given the global context
-- after its creation.
module Crypto.Secp256k1.Internal.ContextOps where

import Crypto.Secp256k1.Internal.ForeignTypes (Ret, Seed32)
import Foreign (FunPtr, Ptr)
import Foreign.C (CInt (..), CString, CUInt (..))

-- | Context (@secp256k1_context@). Only ever used behind a 'Ptr'. It is
-- declared here and not with the other foreign types so that no exposed
-- module can name a context.
data LCtx

-- | Flags passed to @secp256k1_context_create@.
type CtxFlags = CUInt

-- | @SECP256K1_CONTEXT_NONE@. Enough for every operation since libsecp256k1
-- 0.2.0, and for parsing and serialization in older versions.
none :: CtxFlags
none = 0x0001

-- | @SECP256K1_CONTEXT_VERIFY@. Deprecated upstream since 0.2.0, where it
-- means the same as 'none'. Older libraries need it to verify.
verify :: CtxFlags
verify = 0x0101

-- | @SECP256K1_CONTEXT_SIGN@. Deprecated upstream since 0.2.0, where it means
-- the same as 'none'. Older libraries need it to sign.
sign :: CtxFlags
sign = 0x0201

-- | Both 'sign' and 'verify', which the global context of the package is
-- created with. The package requires libsecp256k1 0.2.0 or later for its
-- Schnorr bindings, and from that version on these flags mean the same as
-- 'none'. Passing them is harmless.
signVerify :: CtxFlags
signVerify = 0x0301

-- | Binding to @secp256k1_context_create@.
foreign import ccall safe "secp256k1.h secp256k1_context_create"
  contextCreate ::
    CtxFlags ->
    IO (Ptr LCtx)

-- | Binding to @secp256k1_context_clone@.
foreign import ccall safe "secp256k1.h secp256k1_context_clone"
  contextClone ::
    Ptr LCtx ->
    IO (Ptr LCtx)

-- | Binding to @secp256k1_context_destroy@.
foreign import ccall safe "secp256k1.h secp256k1_context_destroy"
  contextDestroy :: Ptr LCtx -> IO ()

-- | Pointer to @secp256k1_context_destroy@, for use as a finalizer or callback.
foreign import ccall safe "secp256k1.h &secp256k1_context_destroy"
  contextDestroyFunPtr :: FunPtr (Ptr LCtx -> IO ())

-- | Pointer to @secp256k1_haskell_illegal_callback@ (see
-- @cbits/illegal_callback.c@), a callback that does nothing. Set as the
-- illegal-argument callback of a context, it makes a C function that is given
-- an invalid argument return 0 instead of aborting the process.
foreign import ccall safe "&secp256k1_haskell_illegal_callback"
  illegalCallbackFunPtr :: FunPtr (CString -> Ptr a -> IO ())

-- | Binding to @secp256k1_context_set_illegal_callback@.
foreign import ccall safe "secp256k1.h secp256k1_context_set_illegal_callback"
  setIllegalCallback ::
    Ptr LCtx ->
    -- | message, data
    FunPtr (CString -> Ptr a -> IO ()) ->
    -- | data
    Ptr a ->
    IO ()

-- | Binding to @secp256k1_context_set_error_callback@.
foreign import ccall safe "secp256k1.h secp256k1_context_set_error_callback"
  setErrorCallback ::
    Ptr LCtx ->
    -- | message, data
    FunPtr (CString -> Ptr a -> IO ()) ->
    -- | data
    Ptr a ->
    IO ()

-- | Binding to @secp256k1_context_randomize@.
foreign import ccall safe "secp256k1.h secp256k1_context_randomize"
  contextRandomize ::
    Ptr LCtx ->
    Ptr Seed32 ->
    IO Ret
