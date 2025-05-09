{-# LANGUAGE NoFieldSelectors #-}
module Crypto.Secp256k1.Internal.Context where

import Control.Exception (bracket, mask_)
import Control.Monad (unless)
import Crypto.Secp256k1.Internal.ForeignTypes
  ( CtxFlags,
    LCtx,
    Ret,
    Seed32,
    isSuccess,
  )
import Crypto.Secp256k1.Internal.Util (withRandomSeed)
import Foreign (FunPtr, Ptr)
import Foreign.C (CInt (..), CString, CUInt (..))
import Foreign.ForeignPtr
  ( FinalizerPtr,
    ForeignPtr,
    finalizeForeignPtr,
    newForeignPtr,
    withForeignPtr,
  )
import GHC.Conc (writeTVar)
import System.IO.Unsafe (unsafePerformIO)

newtype Ctx = Ctx {get :: ForeignPtr LCtx}

randomizeContext :: Ctx -> IO ()
randomizeContext (Ctx fctx) = withForeignPtr fctx $ \ctx -> do
  ret <- withRandomSeed $ contextRandomize ctx
  unless (isSuccess ret) $ error "Could not randomize context"

createContext :: IO Ctx
createContext = do
  ctx <- mask_ $ do
    pctx <- contextCreate signVerify
    Ctx <$> newForeignPtr contextDestroyFunPtr pctx
  randomizeContext ctx
  return ctx

cloneContext :: Ctx -> IO Ctx
cloneContext (Ctx fctx) =
  withForeignPtr fctx $ \ctx -> mask_ $ do
    ctx' <- contextClone ctx
    Ctx <$> newForeignPtr contextDestroyFunPtr ctx'

destroyContext :: Ctx -> IO ()
destroyContext (Ctx fctx)= finalizeForeignPtr fctx

withContext :: (Ctx -> IO a) -> IO a
withContext = (createContext >>=)

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
