-- | ECDSA public key recovery, through the @recovery@ module of
-- <https://github.com/bitcoin-core/secp256k1 libsecp256k1>.
--
-- Up to four public keys verify a given ECDSA signature (r, s) of a hash. A
-- recovery id of 0 to 3 says which one: R is the point whose x coordinate is
-- r, or r + n for the ids 2 and 3, and whose y coordinate is even for the
-- ids 0 and 2 and odd for 1 and 3. The key is then Q = r⁻¹(s·R − e·G), where
-- e is the hash as a number. 'signRecMsg' signs and keeps the id, and
-- 'recover' computes the key from a signature, its id and the hash.
--
-- Bitcoin signed messages use this: a signature is 65 bytes, a header byte
-- followed by r and s, and the verifier recovers the key and compares its
-- address with the one given. The header byte is 27 plus the id, plus 4 for
-- a compressed key, and BIP 137 adds 8 or 12 more for a SegWit address.
-- 'exportCompactRecSig' and 'importCompactRecSig' convert between a 'RecSig'
-- and the r‖s bytes with the id; the header byte itself is left to the
-- caller.
--
-- == Relation to the ECDSA functions
--
-- 'signRecMsg' uses the same RFC 6979 nonce as 'Crypto.Secp256k1.signMsg',
-- so 'convertRecSig' of its result is the signature that
-- 'Crypto.Secp256k1.signMsg' gives, in lower-S form. There is no low-R
-- grinding, and Bitcoin Core does not grind either when it signs a message,
-- so message signatures are byte for byte the same as Bitcoin Core's.
--
-- 'recover' does not apply the lower-S rule of 'Crypto.Secp256k1.verifySig'.
-- The high-S form of a signature, with the parity bit of its id flipped,
-- recovers the same key, and Bitcoin Core accepts such message signatures
-- too. Where the rule matters, check 'Crypto.Secp256k1.isLowS' on
-- 'convertRecSig'.
--
-- The ids 2 and 3 only come out of 'signRecMsg' when r is below p − n, which
-- happens for about one signature in 2^128. 'importCompactRecSig' accepts
-- them and 'recover' handles them.
--
-- == The recovery module of libsecp256k1
--
-- libsecp256k1 only has this module when it was built with
-- @--enable-module-recovery@, or @SECP256K1_ENABLE_MODULE_RECOVERY=ON@ with
-- CMake. That is off by default upstream, but on in the libraries that
-- Debian, Ubuntu, Fedora, Arch, Alpine, openSUSE, Homebrew and Nixpkgs ship.
-- This package binds it when its @recovery@ flag is on, which is the
-- default. With a library built without the module, the first program to
-- link fails with an undefined reference to @secp256k1_ecdsa_recover@. Build
-- the package with @-f -recovery@ then, and this module is not available.
--
-- == Values
--
-- 'RecSig' is built through 'signRecMsg', 'importCompactRecSig' or 'recSig',
-- which validate it, so a 'RecSig' always has both components in the range 1
-- to n−1 and an id of 0 to 3. Its @get@ field gives the internal
-- representation of libsecp256k1, which is opaque and not portable. 'Show',
-- 'Read' and 'Data.String.IsString' use hex of r and s as 32-byte big-endian
-- numbers followed by the id as one byte. The raw constructor is in
-- "Crypto.Secp256k1.Internal.Recovery", which has no API stability
-- guarantee.
module Crypto.Secp256k1.Recovery
  ( -- * Recoverable signatures
    RecSig (get),
    recSig,
    signRecMsg,
    recover,
    convertRecSig,

    -- ** Compact
    importCompactRecSig,
    exportCompactRecSig,
  )
where

import Crypto.Secp256k1.Internal.Recovery
