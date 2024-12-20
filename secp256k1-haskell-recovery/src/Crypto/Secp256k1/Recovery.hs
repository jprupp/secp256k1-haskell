-- |
-- Module      : Crypto.Secp256k1.Recovery
-- License     : UNLICENSE
-- Maintainer  : Jean-Pierre Rupp <jprupp@protonmail.ch>
-- Stability   : experimental
-- Portability : POSIX
--
-- Crytpographic functions related to recoverable signatures from Bitcoin’s secp256k1 library.
module Crypto.Secp256k1.Recovery
  ( -- * Context
    Ctx (..),
    withContext,
    randomizeContext,
    createContext,
    cloneContext,
    destroyContext,

    -- * Recovery
    RecSig (..),
    CompactRecSig (..),
    compactRecSig,
    serializeCompactRecSig,
    importCompactRecSig,
    exportCompactRecSig,
    convertRecSig,
    signRecMsg,
    recover,

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
  )
where

import Crypto.Secp256k1.Internal.Base
import Crypto.Secp256k1.Internal.Context
import Crypto.Secp256k1.Internal.Recovery
