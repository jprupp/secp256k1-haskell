{-# LANGUAGE DuplicateRecordFields #-}
module Crypto.Secp256k1
  ( -- * Context
    Ctx (..),
    withContext,
    createContext,
    randomizeContext,
    cloneContext,

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

    -- * Schnorr Signatures (BIP-340)
    SchnorrSig (..),
    schnorrSig,
    signSchnorr,
    signSchnorrWithAux,
    signSchnorrIO,
    verifySchnorr,

    -- ** X-Only Public Keys
    importXOnlyPubKey,
    exportXOnlyPubKey,

    -- ** Taproot Tweaks (BIP-341)
    tweakAddXOnlyPubKey,
    tweakAddXOnlySecKey,
  )
where

import Crypto.Secp256k1.Internal.Base
import Crypto.Secp256k1.Internal.Context
