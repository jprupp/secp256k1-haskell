# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [1.4.5] - 2025-05-09

### Removed

- Removed unnecessary file boilerplate.

## [1.4.4] - 2025-05-09

### Changed

- Simplify author name.

## [1.4.3] - 2025-05-08

### Changed

- New home in github.com/jprupp rather than github.com/haskoin.

## [1.4.2] - 2024-12-10

### Changed

- Relax all upper-bound version restrictions in `package.yaml`.

## [1.4.1] - 2024-12-10

### Changed

- Relax version restriction on QuickCheck.

## [1.4.0] - 2024-08-28

### Removed

- Removed BIP-340 support. Fedora’s version of secp256k1 libraries do not have required symbols.

## [1.3.0] - 2024-08-28

### Added

- Added BIP-340 support.

## [1.2.0] - 2023-03-14

### Changed

- Make compatible with latest upstream LTS Haskell.

## [1.1.0] - 2023-11-01

### Changed

- Use ForeignPtr to allow the garbage collector manage the context object (Ctx).

## [1.0.1] - 2023-09-20

### Changed

- Reworked the structure of the Internal modules to allow having add-on packages for optional libsecp256k1 features.

## [1.0.0] - 2023-07-28

### Changed

- Context data structure must be created and passed explicitly.
- Field selectors are now short and duplicates are allowed.
- Use DuplicateRecordFields and OverloadedRecordDot language extensions.

## [0.6.1] - 2022-04-18

### Changed

- Bump version and LTS Haskell.
- Update dependencies.

## [0.6.0] - 2021-08-27

### Changed

- Remove all use of CPP.
- Depend on base16 instead of the old base16-bytestring package.
- Target ghc-9.0.1 compiler.

### Fixed

- Do not crash on bytestrings that are backed by null C pointers.

## [0.5.0] - 2020-10-16

### Changed

- Include version boundaries and other changes submitted by Emily Pillmore.

## [0.4.0] - 2020-07-23

### Changed

- Remove fragile ForeignPtr implementation in favor of just storing ByteStrings.
- Reuse memory instead of copying when possible.

## [0.3.1] - 2020-07-03

### Fixed

- Use unsafe calls in FFI.

## [0.3.0] - 2020-06-13

### Fixed

- Compiles with all flags now.

### Added

- Script to compile with all flags.

### Removed

- Remove ECDH support.
- Remove Schnorr support.
- Remove Recovery support.

## [0.2.5] - 2020-06-13

### Changed

- Reuse context aggressively.
- Generate context in a single thread.

### Fixed

- Memory deallocation bug.

## [0.2.4] - 2020-06-12

### Changed

- Update Cabal and package version.

## [0.2.3] - 2020-06-07

### Changed

- Return meaningful error upon encountering weird ret status from upstream code.

### Added

- Test parallel signature creation and verification.

## [0.2.2] - 2020-04-14

### Removed

- Hide tweak negation behind a flag for compatibilidy with Debian 9.

### Fixed

- Correct code that was not compiling with some flags enabled.

## [0.2.1] - 2020-04-10

### Changed

- Do not depend on hardcoded DER signatures in tests.

## [0.2.0] - 2020-04-10

### Added

- Support for ECDH APIs.
- Support for Schnorr APIs.

### Removed

- Enabling key recovery APIs need a flag.

## [0.1.8] - 2020-01-15

### Added

- Add missing `NFData` instances for some types.

## [0.1.7] - 2020-01-15

### Added

- Add `NFData` instances for all types.

## [0.1.6] - 2019-12-26

### Added

- Use `pkgconfig` for C library dependency.

## [0.1.5] - 2019-09-19

### Added

- Flag for ECDH bindings.

## [0.1.4] - 2018-10-25

### Changed

- Constrain imports to avoid clashes with a QuickCheck function.

## [0.1.3] - 2018-10-13

### Added

- Hashable instances for various types.

## [0.1.2] - 2018-09-10

### Changed

- Separate dependencies between library and tests.
- Remove `hspec` default to prevent problems with Nix.

### Removed

- Dependency to `cryptohash` not needed.

## [0.1.1] - 2018-09-10

### Changed

- Update changelog to reflect name and version change.
- Update to LTS Haskell 12.9.

## [0.1.0] - 2018-09-10

### Changed

- Name of package change from `secp256k1` to `secp256k1-haskell` to avoid Nix conflicts.
