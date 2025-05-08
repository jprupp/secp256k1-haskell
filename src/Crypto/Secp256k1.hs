{-# LANGUAGE DuplicateRecordFields #-}
-- |
-- Module      : Crypto.Secp256k1
-- License     : UNLICENSE
-- Maintainer  : Jean-Pierre Rupp <jprupp@protonmail.ch>
-- Stability   : experimental
-- Portability : POSIX
--
-- Crytpographic functions from Bitcoin’s secp256k1 library.
module Crypto.Secp256k1
  ( -- * Context
    Ctx (..),
    withContext,
    randomizeContext,
    createContext,
    cloneContext,
    destroyContext,

    -- * Messages
    Msg (..),
    msg,

    -- * Secret Keys
    SecKey (..),
    secKey,
    derivePubKey,

    -- * Public Keys
    PubKey (..),
    pubKey,
    importPubKey,
    exportPubKey,

    -- * Signatures
    Sig (..),
    sig,
    signMsg,
    verifySig,
    normalizeSig,

    -- ** DER
    importSig,
    exportSig,

    -- ** Compact
    CompactSig (..),
    compactSig,
    exportCompactSig,
    importCompactSig,

    -- * Addition & Multiplication
    Tweak (..),
    tweak,
    tweakAddSecKey,
    tweakMulSecKey,
    tweakAddPubKey,
    tweakMulPubKey,
    combinePubKeys,
    tweakNegate,
  )
where

import Crypto.Secp256k1.Internal.Base
import Crypto.Secp256k1.Internal.Context
