{-# LANGUAGE DuplicateRecordFields #-}

-- | ECDSA and BIP-340 Schnorr signatures on the secp256k1 curve, through
-- <https://github.com/bitcoin-core/secp256k1 libsecp256k1>.
--
-- == Purpose
--
-- secp256k1 is the elliptic curve of Bitcoin, and libsecp256k1 is the C
-- library Bitcoin Core uses for it: constant-time where secrets are involved,
-- hardened against side channels, exhaustively tested and reviewed. Getting
-- elliptic curve cryptography right is hard enough that a Haskell program
-- should not reimplement it. This package gives Haskell the same library, with
-- types that make the common mistakes hard to make.
--
-- == Design
--
-- * __Valid by construction.__ Every value goes through a smart constructor or
--   an import function that checks it. Code that holds a 'PubKey' or a 'Sig'
--   never has to wonder whether it is a point on the curve or a well-formed
--   signature, and invalid input is refused at the boundary where it arrives.
--
-- * __Never abort.__ The C library calls @abort()@ on an illegal argument by
--   default, which kills the whole Haskell process and cannot be caught. Every
--   context this package creates replaces that callback, so a bad argument
--   becomes 'Nothing', 'False' or an exception instead.
--
-- * __Pure where the mathematics is pure.__ Signing, verifying and tweaking are
--   deterministic functions of their inputs, so they are pure functions here.
--   Only the operations that need fresh randomness, such as 'signSchnorrIO'
--   and 'randomizeContext', run in 'IO'.
--
-- * __Standard encodings at the edges.__ Values print and parse in the encodings
--   other software understands (SEC1, DER, compact, BIP-340), never in the
--   library's internal memory layout, which differs between platforms.
--
-- * __Bitcoin Core compatibility is explicit.__ Where Bitcoin Core does
--   something beyond the standards, such as low-R grinding or accepting high-S
--   signatures from old blocks, this package offers it as a separate function
--   and documents the difference, rather than silently picking one behaviour.
--
-- == Values
--
-- Every value is built through a smart constructor or an import function
-- that validates it, so a value of one of these types is always well formed:
--
-- * 'SecKey': a 32-byte big-endian number in the range 1 to n−1, where n is
--   the order of the curve ('secKey').
-- * 'PubKey': a point on the curve ('importPubKey' for the SEC1 encoding).
-- * 'Sig': a signature whose components are both in the range 1 to n−1
--   ('importSig' for DER, 'importCompactSig' for the compact encoding).
-- * 'Msg': a 32-byte hash ('msg').
-- * 'Tweak': a 32-byte big-endian number in the range 0 to n−1 ('tweak').
-- * 'SchnorrSig': a 64-byte BIP-340 signature ('schnorrSig' checks the
--   length, 'verifySchnorr' the values).
--
-- The @get@ field of each type gives its bytes. For 'SecKey', 'Msg', 'Tweak',
-- 'CompactSig' and 'SchnorrSig' these are the standard big-endian bytes. For 'PubKey' and
-- 'Sig' they are the internal representation of libsecp256k1, which is
-- opaque and not portable. Use 'exportPubKey', 'exportSig' and
-- 'exportCompactSig' to serialize those.
--
-- 'Show', 'Read' and 'Data.String.IsString' use hex of a standard encoding: compressed
-- SEC1 for 'PubKey', compact for 'Sig', and the plain bytes for the others.
-- 'Show' prints secret keys. See 'SecKey' for what that means for logging.
--
-- The raw constructors are not exported from this module. They are in
-- "Crypto.Secp256k1.Internal.Base", which has no API stability guarantee.
--
-- == Schnorr signatures
--
-- BIP-340 public keys are x-only: the 32-byte x coordinate of a point whose
-- y coordinate is even. This module keeps them as 'PubKey' and converts with
-- 'importXOnlyPubKey' and 'exportXOnlyPubKey'. 'verifySchnorr' uses only the
-- x coordinate, so a key and its negation verify the same signatures.
-- 'tweakAddXOnlyPubKey' and 'tweakAddXOnlySecKey' apply a BIP-341 Taproot
-- tweak. Computing the tweak itself, a tagged hash of the internal key and
-- the script tree, is left to the caller.
--
-- 'signSchnorr' is deterministic. BIP-340 recommends fresh auxiliary
-- randomness for every signature, which 'signSchnorrIO' provides. Every
-- Schnorr signing function verifies the signature before returning it, as
-- BIP-340 requires.
--
-- == Contexts
--
-- Every operation takes a 'Ctx'. Create one with 'createContext' and share it
-- between threads. Only 'randomizeContext' modifies a context and needs
-- exclusive access.
--
-- == Differences from Bitcoin Core
--
-- 'signMsg' is plain RFC 6979 and matches the published test vectors.
-- Bitcoin Core also grinds the nonce until r is below 2^255, which keeps DER
-- signatures at 70 bytes. 'signMsgLowR' does the same and gives the same
-- signatures as Bitcoin Core.
--
-- 'verifySig' only accepts lower-S signatures, as libsecp256k1 does. Bitcoin
-- Core normalizes a signature before verifying it, because high-S signatures
-- exist in old blocks. Use 'normalizeSig' before 'verifySig' for that.
--
-- Bitcoin Core verifies every ECDSA signature it makes, as a precaution
-- against a corrupted signature. 'signMsg' does not. The Schnorr signing
-- functions do, because BIP-340 requires it.
--
-- Bitcoin Core's Schnorr signing applies the Taproot tweak itself when it is
-- given a Merkle root. Here 'tweakAddXOnlySecKey' does that step separately.
--
-- == Public key recovery
--
-- ECDSA public key recovery, which Bitcoin signed messages use, is in the
-- module @Crypto.Secp256k1.Recovery@. It is built when the @recovery@ flag of
-- the package is on, which is the default.
module Crypto.Secp256k1
  ( -- * Context
    Ctx,
    withContext,
    createContext,
    randomizeContext,
    cloneContext,

    -- * Messages
    Msg (get),
    msg,

    -- * Secret Keys
    SecKey (get),
    secKey,
    derivePubKey,

    -- * Public Keys
    PubKey (get),
    pubKey,
    importPubKey,
    exportPubKey,

    -- * Signatures
    Sig (get),
    sig,
    signMsg,
    signMsgLowR,
    verifySig,
    normalizeSig,
    isLowS,
    isLowR,

    -- ** DER
    importSig,
    exportSig,

    -- ** Compact
    CompactSig (get),
    compactSig,
    exportCompactSig,
    importCompactSig,

    -- * Addition & Multiplication
    Tweak (get),
    tweak,
    tweakAddSecKey,
    tweakMulSecKey,
    tweakAddPubKey,
    tweakMulPubKey,
    combinePubKeys,
    tweakNegate,

    -- * Schnorr Signatures (BIP-340)
    SchnorrSig (get),
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
