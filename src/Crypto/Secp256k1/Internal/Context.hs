{-# LANGUAGE NoFieldSelectors #-}

-- | Internal module. Everything is exported and there is no API stability
-- guarantee. In particular 'contextDestroy' is here for add-on packages and
-- tests that manage raw context pointers. Never call it on the pointer inside
-- a 'Ctx', because the garbage collector will destroy that one again.
module Crypto.Secp256k1.Internal.Context where

import Control.Exception (mask_)
import Control.Monad (unless)
import Crypto.Secp256k1.Internal.ForeignTypes
  ( CtxFlags,
    LCtx,
    Ret,
    Seed32,
    isSuccess,
  )
import Crypto.Secp256k1.Internal.Util (withRandomSeed)
import Foreign (FunPtr, Ptr, nullPtr)
import Foreign.C (CInt (..), CString, CUInt (..))
import Foreign.ForeignPtr
  ( ForeignPtr,
    newForeignPtr,
    withForeignPtr,
  )
import System.IO.Unsafe (unsafePerformIO)

-- | A libsecp256k1 context. It is destroyed by the garbage collector.
--
-- A context can be shared between threads. Every function in
-- "Crypto.Secp256k1" only reads it, except 'randomizeContext', which needs
-- exclusive access. See there.
data Ctx = Ctx (ForeignPtr LCtx)

-- | Re-seed the blinding values that protect secret key operations against
-- side-channel leakage. 'createContext' already does this once, which is what
-- libsecp256k1 recommends, so most programs never need to call it.
--
-- This function modifies the context. Calling it while another thread uses
-- the same context, for example by evaluating 'Crypto.Secp256k1.signMsg', is a
-- data race in the C library. Either call it before the context is shared, or
-- protect every use of the context with a read-write lock.
randomizeContext :: Ctx -> IO ()
randomizeContext (Ctx fctx) = withForeignPtr fctx $ \ctx -> do
  ret <- withRandomSeed $ contextRandomize ctx
  unless (isSuccess ret) $ error "Could not randomize context"

-- | Create a context and randomize it.
createContext :: IO Ctx
createContext = do
  ctx <- mask_ $ contextCreate signVerify >>= wrapContext
  randomizeContext ctx
  return ctx

-- | Copy a context, including its randomization.
cloneContext :: Ctx -> IO Ctx
cloneContext (Ctx fctx) =
  withForeignPtr fctx $ \ctx -> mask_ $ contextClone ctx >>= wrapContext

-- | Create a context and pass it to the action. The context is not destroyed
-- when the action returns. It stays valid for as long as it is referenced,
-- and the garbage collector destroys it afterwards.
withContext :: (Ctx -> IO a) -> IO a
withContext = (createContext >>=)

-- | Wrap a raw context pointer. The illegal-argument callback is replaced
-- with one that does nothing (see @cbits/illegal_callback.c@), so an invalid
-- argument makes the C function return 0 instead of aborting the process.
--
-- Two rules follow for every binding that uses a 'Ctx'. The return value of
-- the C function must always be checked, because after a failed check its
-- outputs are undefined. And a C function that ignores the result of an
-- internal check must get validated inputs, as
-- 'Crypto.Secp256k1.combinePubKeys' does for @secp256k1_ec_pubkey_combine@.
wrapContext :: Ptr LCtx -> IO Ctx
wrapContext pctx = do
  setIllegalCallback pctx illegalCallbackFunPtr nullPtr
  Ctx <$> newForeignPtr contextDestroyFunPtr pctx

-- | Context used to validate values that are built without a context, such
-- as public keys and signatures read from their internal representation or
-- from a string. It is only used for parsing and serialization, which do not
-- involve secret keys and so do not need randomization. It is never modified
-- after creation, so sharing it between threads is safe.
validationContext :: Ctx
validationContext =
  unsafePerformIO . mask_ $ contextCreate none >>= wrapContext
{-# NOINLINE validationContext #-}

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

-- | Both 'sign' and 'verify', passed by 'createContext'. The package requires
-- libsecp256k1 0.2.0 or later for its Schnorr bindings, and from that version
-- on these flags mean the same as 'none'. Passing them is harmless.
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

-- | Pointer to @secp256k1_haskell_illegal_callback@, for use as a finalizer or callback.
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
