{-# LANGUAGE NoFieldSelectors #-}

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

data Ctx = Ctx (ForeignPtr LCtx)

randomizeContext :: Ctx -> IO ()
randomizeContext (Ctx fctx) = withForeignPtr fctx $ \ctx -> do
  ret <- withRandomSeed $ contextRandomize ctx
  unless (isSuccess ret) $ error "Could not randomize context"

-- | Wrap a newly created context. The illegal argument callback is replaced
-- so that an invalid argument makes the library function fail instead of
-- aborting the program.
wrapContext :: Ptr LCtx -> IO Ctx
wrapContext pctx = do
  setIllegalCallback pctx illegalCallbackFunPtr nullPtr
  Ctx <$> newForeignPtr contextDestroyFunPtr pctx

createContext :: IO Ctx
createContext = do
  ctx <- mask_ $ contextCreate signVerify >>= wrapContext
  randomizeContext ctx
  return ctx

cloneContext :: Ctx -> IO Ctx
cloneContext (Ctx fctx) =
  withForeignPtr fctx $ \ctx -> mask_ $ contextClone ctx >>= wrapContext

withContext :: (Ctx -> IO a) -> IO a
withContext = (createContext >>=)

-- | Context used internally to validate values that are built without a
-- context, such as public keys and signatures read from their internal
-- representation. It is only used for parsing and serialization, which do not
-- need randomization.
validationContext :: Ctx
validationContext =
  unsafePerformIO . mask_ $ contextCreate none >>= wrapContext
{-# NOINLINE validationContext #-}

none :: CtxFlags
none = 0x0001

verify :: CtxFlags
verify = 0x0101

sign :: CtxFlags
sign = 0x0201

signVerify :: CtxFlags
signVerify = 0x0301

foreign import ccall safe "secp256k1.h secp256k1_context_create"
  contextCreate ::
    CtxFlags ->
    IO (Ptr LCtx)

foreign import ccall safe "secp256k1.h secp256k1_context_clone"
  contextClone ::
    Ptr LCtx ->
    IO (Ptr LCtx)

foreign import ccall safe "secp256k1.h secp256k1_context_destroy"
  contextDestroy :: Ptr LCtx -> IO ()

foreign import ccall safe "secp256k1.h &secp256k1_context_destroy"
  contextDestroyFunPtr :: FunPtr (Ptr LCtx -> IO ())

foreign import ccall unsafe "&secp256k1_haskell_illegal_callback"
  illegalCallbackFunPtr :: FunPtr (CString -> Ptr a -> IO ())

foreign import ccall safe "secp256k1.h secp256k1_context_set_illegal_callback"
  setIllegalCallback ::
    Ptr LCtx ->
    -- | message, data
    FunPtr (CString -> Ptr a -> IO ()) ->
    -- | data
    Ptr a ->
    IO ()

foreign import ccall safe "secp256k1.h secp256k1_context_set_error_callback"
  setErrorCallback ::
    Ptr LCtx ->
    -- | message, data
    FunPtr (CString -> Ptr a -> IO ()) ->
    -- | data
    Ptr a ->
    IO ()

foreign import ccall safe "secp256k1.h secp256k1_context_randomize"
  contextRandomize ::
    Ptr LCtx ->
    Ptr Seed32 ->
    IO Ret
