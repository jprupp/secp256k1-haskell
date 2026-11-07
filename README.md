# secp256k1-haskell

[![Hackage](https://img.shields.io/hackage/v/secp256k1-haskell.svg)](https://hackage.haskell.org/package/secp256k1-haskell)
[![CI](https://github.com/jprupp/secp256k1-haskell/actions/workflows/ci.yml/badge.svg)](https://github.com/jprupp/secp256k1-haskell/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jprupp/secp256k1-haskell/blob/master/LICENSE)

Haskell bindings to [libsecp256k1](https://github.com/bitcoin-core/secp256k1),
the library that Bitcoin Core uses for elliptic curve cryptography on the
secp256k1 curve. It covers ECDSA signatures, BIP-340 Schnorr signatures,
BIP-341 Taproot tweaks, key tweaking for BIP-32 derivation, and ECDSA public
key recovery for Bitcoin signed messages.

- [API documentation](https://hackage.haskell.org/package/secp256k1-haskell)
- [Changelog](https://github.com/jprupp/secp256k1-haskell/blob/master/CHANGELOG.md)
- [Report a bug](https://github.com/jprupp/secp256k1-haskell/issues)

## Contents

- [Why secp256k1-haskell](#why-secp256k1-haskell)
- [Design principles](#design-principles)
- [Features](#features)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Tutorial: sign, verify and serialize](#tutorial-sign-verify-and-serialize)
- [Concepts](#concepts)
- [Usage guide](#usage-guide)
- [Differences from Bitcoin Core](#differences-from-bitcoin-core)
- [Module overview](#module-overview)
- [Security notes](#security-notes)
- [Development](#development)
- [Related projects](#related-projects)
- [License](#license)

## Why secp256k1-haskell

Elliptic curve cryptography is easy to write and very hard to get right. A
signing routine whose running time depends on the secret key leaks it through
timing. A nonce that repeats once reveals the key outright. An edge case in
point arithmetic accepts a forged signature. These are not theoretical: each has
cost real users real money.

libsecp256k1 is the answer the Bitcoin community converged on. It is
constant-time wherever secrets are involved, blinds secret key operations
against side channels, is tested exhaustively, and has been reviewed for over a
decade. It is what Bitcoin Core runs.

This package lets a Haskell program use that library instead of reimplementing
it, and wraps it in types that make the usual mistakes hard to make. It is the
cryptographic foundation of [haskoin-core](https://github.com/jprupp/haskoin-core)
and, through it, of the rest of the Haskoin libraries.

## Design principles

- **Valid by construction.** Every key, signature, hash and tweak goes through
  a smart constructor or an import function that checks it. A `PubKey` is
  always a point on the curve; a `Sig` always has both components in range.
  Invalid input is refused where it enters the program, not deep inside a
  computation.
- **Never abort the process.** By default libsecp256k1 calls `abort()` on an
  illegal argument, which kills the whole Haskell program and cannot be caught.
  Every context this package creates installs a callback that makes the C
  function fail instead, so a bad argument becomes `Nothing`, `False` or an
  exception.
- **Pure where the mathematics is pure.** Signing with deterministic nonces,
  verifying, deriving and tweaking keys are pure functions. Only operations
  that need fresh randomness run in `IO`.
- **Standard encodings at the edges.** `Show`, `Read` and `IsString` use SEC1,
  compact or plain hex, never libsecp256k1's internal memory layout, which
  differs between platforms and library versions.
- **Explicit about Bitcoin Core.** Where Bitcoin Core goes beyond the
  standards, such as grinding signatures to a low R value or accepting high-S
  signatures from old blocks, this package offers the behaviour as a separate,
  documented function instead of silently picking one.
- **Thin.** Hashing, address encoding, BIP-32 paths and transaction formats
  belong in higher-level libraries such as haskoin-core.

## Features

| Area                 | What you get                                                                                   |
| -------------------- | ---------------------------------------------------------------------------------------------- |
| ECDSA                | Deterministic RFC 6979 signing, Bitcoin Core's low-R grinding, verification, lower-S normalization |
| Encodings            | SEC1 public keys (33 or 65 bytes), DER and compact signatures, hex `Show`/`Read`/`IsString`    |
| Schnorr (BIP-340)    | Signing (deterministic, with given or fresh auxiliary randomness), verification, x-only keys    |
| Taproot (BIP-341)    | Tweaking an x-only public key and its secret key                                               |
| Key arithmetic       | Add or multiply secret and public keys by a tweak, negate, combine public keys                 |
| Recovery             | Recoverable ECDSA signatures and public key recovery, as Bitcoin signed messages use           |
| Safety               | Validated values, no aborts, length checks before every C call, contexts shared across threads |
| Testing              | QuickCheck `Arbitrary` instances for secret keys, hashes and tweaks                            |

### What is not included

- No hashing. Pass a 32-byte hash you computed with a hash library, such as
  `cryptohash-sha256` or haskoin-core.
- No ECDH, MuSig2 or adaptor signatures, although libsecp256k1 or its
  forks offer some of them.
- No secure erasure of secret keys from memory. See [Security notes](#security-notes).

## Installation

### System library

The package needs [libsecp256k1](https://github.com/bitcoin-core/secp256k1)
**0.2.0 or later** and `pkg-config` to find it. Public key recovery also needs
the library's recovery module, which the packages below include.

```sh
# Debian and Ubuntu (24.04 ships 0.2.0)
sudo apt-get install libsecp256k1-dev pkg-config

# Fedora
sudo dnf install libsecp256k1-devel pkgconf

# macOS with Homebrew
brew install secp256k1 pkg-config

# Nix
nix-shell -p secp256k1 pkg-config
```

Check what you have:

```sh
pkg-config --modversion libsecp256k1   # must print 0.2.0 or later
```

Older distributions, such as Debian 11, ship an earlier version. Build the
library from source then:

```sh
git clone https://github.com/bitcoin-core/secp256k1.git
cd secp256k1
./autogen.sh
./configure --enable-module-recovery
make && sudo make install
```

If your library was built without the recovery module, build this package with
the `recovery` flag off: `stack build --flag secp256k1-haskell:-recovery`, or
`cabal build -f -recovery`. Everything except `Crypto.Secp256k1.Recovery` still
works.

### Step by step with Stack

1. Install [Stack](https://docs.haskellstack.org/) and the library above.
2. Create a project:

   ```sh
   stack new sig-demo simple
   cd sig-demo
   ```

3. Add `secp256k1-haskell` and `bytestring` to `build-depends` in
   `sig-demo.cabal`.
4. If your resolver does not include the package, add it to `stack.yaml`:

   ```yaml
   extra-deps:
     - secp256k1-haskell-2.1.0
     - base16-2.0
   ```

5. Put the [quick start](#quick-start) program in `src/Main.hs` and run it with
   `stack run`. It prints `True` three times.

### With Cabal

```cabal
build-depends:
    base
  , bytestring
  , secp256k1-haskell
```

Run `cabal update` first, then `cabal build`.

## Quick start

```haskell
{-# LANGUAGE OverloadedStrings #-}

import Crypto.Secp256k1

main :: IO ()
main = do
  ctx <- createContext

  -- Hex literals go through IsString, which validates them.
  let key = "c7e5a2b4f4c5d7e8a9b0c1d2e3f405162738495a6b7c8d9e0f1a2b3c4d5e6f70" :: SecKey
      hash = "4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a" :: Msg
      pub = derivePubKey ctx key

  -- ECDSA
  let s = signMsg ctx key hash
  print (verifySig ctx pub s hash)

  -- BIP-340 Schnorr, with fresh auxiliary randomness
  schnorr <- signSchnorrIO ctx key hash
  print (verifySchnorr ctx pub schnorr hash)

  -- Round trip through the standard encodings
  let Just pub' = importPubKey ctx (exportPubKey ctx True pub)
  print (pub == pub')
```

## Tutorial: sign, verify and serialize

This walks through what a wallet or a protocol implementation typically does,
and why each step looks the way it does.

### 1. Create one context and share it

```haskell
ctx <- createContext
```

A context holds precomputed tables and random blinding values. Creating one is
relatively expensive, and one context can be used by every thread for the life
of the program. `createContext` randomizes it once, which is what libsecp256k1
recommends.

### 2. Get keys from bytes

```haskell
case secKey keyBytes of
  Nothing -> fail "not a valid secret key"
  Just key -> ...
```

`secKey` refuses 0 and numbers not below the curve order, so a `SecKey` is
always usable. In practice, keys come from a wallet: from a BIP-39 mnemonic and
BIP-32 derivation in haskoin-core, or from 32 bytes of the operating system's
secure randomness (`getEntropy 32` from the `entropy` package).

### 3. Hash, then sign

The library signs 32-byte hashes, not messages. Which hash to use is part of
the protocol: Bitcoin transactions use double SHA-256 of a specific
serialization, BIP-340 uses tagged hashes. Build the `Msg` from your hash:

```haskell
let Just m = msg hashBytes
    s = signMsgLowR ctx key m -- or signMsg for plain RFC 6979
```

Signing is deterministic: the same key and hash give the same signature, so
there is no random number generator to get wrong.

### 4. Serialize for the wire

Never send the `get` bytes of a `PubKey` or `Sig`: they are libsecp256k1's
internal layout. Use the standard encodings:

```haskell
let pubBytes = exportPubKey ctx True pub -- 33-byte compressed SEC1
    derBytes = exportSig ctx s -- DER, as in Bitcoin transactions
    compactBytes = exportCompactSig ctx s -- 64 bytes r || s
```

### 5. Parse and verify what you receive

```haskell
verified = fromMaybe False $ do
  pub <- importPubKey ctx pubBytes
  s <- importSig ctx derBytes
  m <- msg hashBytes
  return (verifySig ctx pub (normalizeSig ctx s) m)
```

Every import returns `Maybe`, so malformed input is handled in one place.
`normalizeSig` is there because `verifySig` only accepts lower-S signatures;
apply it when the signature may come from software that does not produce them,
such as old Bitcoin transactions. Leave it out when your protocol requires
lower-S, as Bitcoin's relay rules do.

### 6. Move to Schnorr where the protocol allows

```haskell
sig <- signSchnorrIO ctx key m
let ok = verifySchnorr ctx pub sig m
    xonly = exportXOnlyPubKey ctx pub -- 32 bytes, as BIP-340 publishes keys
```

Schnorr signatures are always 64 bytes, are not malleable, and are what Taproot
uses. `signSchnorrIO` mixes fresh randomness into the nonce, as BIP-340
recommends, to protect against fault attacks.

## Concepts

### Values

| Type         | What it holds                                            | Built with                              |
| ------------ | -------------------------------------------------------- | --------------------------------------- |
| `SecKey`     | 32-byte number from 1 to n − 1                           | `secKey`, `IsString`                    |
| `PubKey`     | A point on the curve                                     | `importPubKey`, `derivePubKey`          |
| `Msg`        | 32-byte hash                                             | `msg`                                   |
| `Sig`        | ECDSA signature with both components from 1 to n − 1    | `signMsg`, `importSig`, `importCompactSig` |
| `CompactSig` | 64 bytes, r ‖ s                                          | `exportCompactSig`, `compactSig`        |
| `SchnorrSig` | 64-byte BIP-340 signature                                | `signSchnorr`, `schnorrSig`             |
| `Tweak`      | 32-byte number from 0 to n − 1                           | `tweak`                                 |
| `RecSig`     | ECDSA signature with its recovery id                     | `signRecMsg`, `importCompactRecSig`     |

Here n is the order of the curve. The raw constructors are hidden, so these
are the only ways to build values. Each type has a `get` field with its bytes.
`Show` prints hex, except for `SecKey`, which it redacts. See
[Security notes](#security-notes).

### Contexts

Every operation takes a `Ctx`. It is created once, shared freely between
threads, and destroyed by the garbage collector. The only operation that
modifies a context is `randomizeContext`, which needs exclusive access; most
programs never call it.

### Errors

Parsing and constructing return `Maybe`. Arithmetic that can produce an
invalid result, such as a tweak that cancels a key, returns `Maybe`. Pure
operations on valid values, such as signing, cannot fail and return their
result directly. Programming errors, such as a value of the wrong length built
with an internal constructor, raise an exception.

## Usage guide

### Lower-S and low-R

```haskell
isLowS ctx s -- the form verifySig accepts
isLowR ctx s -- r below 2^255, so DER is at most 70 bytes
normalizeSig ctx s -- the lower-S form of any signature
```

### Key tweaking

```haskell
let Just t = tweak tweakBytes
    Just childKey = tweakAddSecKey ctx parentKey t
    Just childPub = tweakAddPubKey ctx parentPub t
-- derivePubKey ctx childKey == childPub
```

This is the operation behind BIP-32 derivation; the tweak itself comes from an
HMAC of the chain code, computed by haskoin-core. `tweakMulSecKey`,
`tweakMulPubKey`, `tweakNegate` and `combinePubKeys` cover the other group
operations.

### Taproot

```haskell
let Just t = tweak taprootTweakBytes -- tagged hash of key and script tree
    Just outputKey = tweakAddXOnlyPubKey ctx internalKey t
    Just outputSecKey = tweakAddXOnlySecKey ctx internalSecKey t
```

Computing the tweak, a BIP-341 tagged hash, is left to the caller.

### Bitcoin signed messages

```haskell
import Crypto.Secp256k1.Recovery

let r = signRecMsg ctx key m
    (compact, recId) = exportCompactRecSig ctx r
-- the 65-byte message signature is a header byte (27 + recId, + 4 if the key
-- is compressed) followed by the 64 compact bytes
recover ctx r m -- Just the signer's PubKey
```

### Testing with QuickCheck

`SecKey`, `Msg` and `Tweak` have `Arbitrary` instances, so properties can
range over them directly. With a context `ctx` created once for the test suite:

```haskell
prop_roundTrip :: SecKey -> Msg -> Bool
prop_roundTrip key m =
  verifySig ctx (derivePubKey ctx key) (signMsg ctx key m) m
```

## Differences from Bitcoin Core

| Topic                      | This package                                     | Bitcoin Core                          |
| -------------------------- | ------------------------------------------------ | ------------------------------------- |
| ECDSA nonce                | `signMsg`: plain RFC 6979                        | Grinds for low R                      |
| Low-R signatures           | `signMsgLowR`: same grinding, same signatures    | Default since 0.17                    |
| High-S signatures          | `verifySig` refuses them; use `normalizeSig`     | Normalizes before verifying           |
| Verify after ECDSA signing | No                                               | Yes, as a precaution                  |
| Taproot tweak when signing | Separate step: `tweakAddXOnlySecKey`             | Built into Schnorr signing            |
| Message signatures         | `signRecMsg`, no grinding                        | Same, so signatures are identical     |

## Module overview

| Module                                  | Contents                                                  |
| --------------------------------------- | --------------------------------------------------------- |
| `Crypto.Secp256k1`                      | The public API: contexts, keys, ECDSA, Schnorr, tweaks    |
| `Crypto.Secp256k1.Recovery`             | Recoverable signatures and public key recovery            |
| `Crypto.Secp256k1.Internal.*`           | Raw constructors and foreign imports; no stability promise |

## Security notes

- **Secret keys stay in memory.** A `SecKey` is an ordinary `ByteString`. The
  garbage collector may copy it, and nothing clears it when it is no longer
  used. If your threat model includes an attacker reading process memory,
  keep keys in a hardware device instead.
- **`Show` redacts secret keys.** `show` on a `SecKey` gives `SecKey <redacted>`,
  so a record that holds a key and derives `Show` can go in a log line or an
  error message. Only `Show` is redacted. `get` gives the bytes, and `Read`
  and `IsString` parse hex, so a key you write out yourself is yours to
  protect.
- **Verification only proves what was signed.** It is your protocol's job to
  hash the right data; signing a hash an attacker chose is as good as signing
  whatever they want.
- **Use fresh randomness for Schnorr when you can.** `signSchnorrIO` protects
  against fault attacks that deterministic signing does not.
- **Keep libsecp256k1 up to date.** Security fixes land in the C library;
  this package only binds it.

## Development

```sh
git clone https://github.com/jprupp/secp256k1-haskell.git
cd secp256k1-haskell

stack build                        # build against the system library
stack --nix build                  # or take GHC and libsecp256k1 from nixpkgs
stack test                         # run the tests
stack haddock --no-haddock-deps    # build the API documentation
```

`package.yaml` is the source of the package description. Change it rather than
`secp256k1-haskell.cabal`, which [hpack](https://github.com/sol/hpack)
generates.

The tests are in `test/` and use [hspec](https://hspec.github.io/) and
QuickCheck, with published test vectors from RFC 6979, Bitcoin Core and
BIP-340. CI runs them with the system library and
with `stack --nix`.

### Contributing

Pull requests are welcome.

- Add tests for the behaviour you change, with published test vectors where
  they exist.
- Keep the documentation in step with the code, as `CLAUDE.md` describes.
- Describe the change in `CHANGELOG.md`, which follows
  [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Related projects

- [haskoin-core](https://github.com/jprupp/haskoin-core) builds Bitcoin keys,
  addresses, transactions and PSBTs on this package.
- [libsecp256k1](https://github.com/bitcoin-core/secp256k1) is the C library
  underneath.

## License

secp256k1-haskell is released under the
[MIT License](https://github.com/jprupp/secp256k1-haskell/blob/master/LICENSE).
