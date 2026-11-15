-- | The one libsecp256k1 context of the process.
--
-- == Purpose
--
-- Every function of libsecp256k1 takes a context: an object that holds the
-- callbacks for errors and the random blinding values that protect secret key
-- operations against side-channel leakage. Earlier versions of this package
-- made the caller create one and pass it to every function. That argument
-- carried no information, since any context gives the same results, yet it
-- ran through every signature of every program built on the package. Now the
-- package keeps a single context here and uses it for everything.
--
-- == Design
--
-- * __Created on first use.__ 'globalContext' is a top-level value, so the
--   runtime evaluates it once, the first time a function needs it, and every
--   later use gets the same pointer. 'unsafePerformIO' takes a lock on the
--   value while it runs (@unsafeDupablePerformIO@ does not), so two threads
--   that arrive together cannot both create a context. The @NOINLINE@ pragma
--   keeps the compiler from copying the definition to its uses, which would
--   make a context per use.
--
-- * __Randomized once, then read-only.__ The context is seeded with 32 bytes
--   from the operating system before anything else can see it, which is what
--   libsecp256k1 recommends. After that nothing writes to it, and the C
--   library allows any number of threads to read one context at once. This is
--   why there is no way to randomize it again: that writes to the context
--   while other threads may be reading it, which is a data race, and guarding
--   against it would put a lock around every operation.
--
-- * __Never aborts.__ The illegal-argument callback is replaced with one that
--   does nothing (see @cbits/illegal_callback.c@), so an invalid argument
--   makes a C function return 0 instead of aborting the process. Two rules
--   follow for every binding that uses the context. The return value of the C
--   function must always be checked, because after a failed check its outputs
--   are undefined. And a C function that ignores the result of an internal
--   check must get validated inputs, as 'Crypto.Secp256k1.combinePubKeys'
--   does for @secp256k1_ec_pubkey_combine@.
--
-- * __Never destroyed.__ The context lives as long as the process, like any
--   other global, so it has no finalizer. The operating system reclaims it at
--   exit.
--
-- * __Hidden.__ This module is not exposed by the package. If the pointer
--   could be reached from outside, any code could randomize or destroy the
--   context, or change its callbacks, under every other user of it. The
--   modules with the raw bindings, which take a context pointer, and the one
--   that creates contexts are hidden as well, so no code outside the package
--   can make, hold or name a context at all.
--
-- == What is given up
--
-- A program can no longer have several contexts, for example one per thread
-- or one per secret, and it can no longer refresh the blinding during a long
-- run. Neither changes any result. The blinding is defence in depth on top
-- of code that is already constant-time, and seeding it once per process is
-- what the C library asks for.
module Crypto.Secp256k1.Internal.Context (globalContext) where

import Control.Exception (mask_, onException)
import Control.Monad (unless, when)
import Crypto.Secp256k1.Internal.ContextOps
  ( LCtx,
    contextCreate,
    contextDestroy,
    contextRandomize,
    illegalCallbackFunPtr,
    setIllegalCallback,
    signVerify,
  )
import Crypto.Secp256k1.Internal.ForeignTypes (isSuccess)
import Crypto.Secp256k1.Internal.Util (withRandomSeed)
import Foreign (Ptr, nullPtr)
import System.IO.Unsafe (unsafePerformIO)

-- | The context that every binding of the package uses. It is created,
-- given the illegal-argument callback that does nothing, and randomized the
-- first time it is needed, and it is only read from then on, so any number of
-- threads may use it at once. See the module header for why it is built this
-- way.
--
-- Bindings must only pass it to C functions that take a @const@ context.
-- Never pass it to @secp256k1_context_randomize@,
-- @secp256k1_context_destroy@ or a function that sets a callback.
--
-- If the context cannot be created or randomized, for example because the
-- operating system gives no entropy, the error is raised by the function that
-- needed the context, and again by every later one.
globalContext :: Ptr LCtx
globalContext = unsafePerformIO . mask_ $ do
  ctx <- contextCreate signVerify
  when (ctx == nullPtr) $ error "Could not create secp256k1 context"
  setIllegalCallback ctx illegalCallbackFunPtr nullPtr
  ret <- withRandomSeed (contextRandomize ctx) `onException` contextDestroy ctx
  unless (isSuccess ret) $ do
    contextDestroy ctx
    error "Could not randomize secp256k1 context"
  return ctx
{-# NOINLINE globalContext #-}
