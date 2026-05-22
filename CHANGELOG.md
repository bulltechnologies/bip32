# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2026-05-22

### Added

- Fork ownership under [Bull Technologies](https://github.com/bulltechnologies/bip32) with updated `homepage`, `repository`, and `issue_tracker` in `pubspec.yaml`.
- Layered package layout: `lib/src/core`, `crypto`, `hd`, `wif` with explicit barrel exports in `package:bip32/bip32.dart`.
- **Security**: `BIP32.dispose()`, `zeroize()`, `copyPrivateKey()`; HMAC/CKD scratch buffers zeroed after use; cached pubkeys cleared on dispose.
- **Validation**: chain-code length; depth ≤ 255; compressed-only pubkey import; version/payload consistency; master node metadata rules.
- **BIP32 spec**: official test vectors 3, 4, and 5; CKD identity tests `N(CKDpriv(m,i))` vs `CKDpub(N(m),i)`; full vector 5 invalid-key matrix.
- **API**: `Networks` presets, `Bip32Version`, `WalletLayout`, path helpers (`parseDerivationPath`, `toHardenedIndex`, …), `ExtendedKey` typedef, `isMaster`, `fingerprintInt`, `maxBip32Depth`, `isValidDerivationTweak`.
- **Errors**: `Bip32Exception` hierarchy for new surfaces (legacy factories keep `ArgumentError` messages).

### Changed

- Dart SDK constraint: `>=3.0.0 <4.0.0`.
- Dependencies: `pointycastle` 4.x, current `test` / `lints`.
- Derivation tweak check uses `isValidDerivationTweak` (documented alignment with common implementations).
- `fromPublicKey` factory rejects uncompressed keys explicitly (import path); curve validation unchanged.
- Expanded dartdoc across public modules; README rewritten with security and compliance sections.

### Deprecated

- `Bip32Type` → `Bip32Version`
- `HIGHEST_BIT`, `UINT31_MAX`, `UINT32_MAX` → `hardenedIndexFlag`, `uint31Max`, `uint32Max`
- `hmacSHA512` → `hmacSha512`
- `fromBuffer` / `toBuffer` in `ecurve.dart` → `bufferToBigInt` / `bigIntTo32Bytes`
- `lib/src/utils/*` → top-level `crypto` / `wif` exports

### Fixed

- Extended keys could be derived past depth 255 while serializing depth as `uint8` (silent truncation).
- `derive(index + 1)` could throw `Expected UInt32` instead of a clear failure at `index == uint32Max`.
- `sign()` on neutered nodes now throws `Missing private key` instead of a null error.
- Public key material cached in memory was not cleared on `dispose()`.
- `WalletLayout.deriveExternal` / `deriveInternal` ignored `addressIndex` (3.0.0 beta fix).

### Security

- Treat this release as the baseline for production HD derivation: review the README **Security model** before embedding in wallet software.
- No substitute for secure enclave, hardware wallets, or platform key stores — this library operates in user-space Dart VM memory.

## [2.0.0]

### Added

- Null-safety migration.

## [1.0.0] - [1.0.10]

Historical releases by [anicdh](https://github.com/anicdh) and contributors on [dart-bitcoin/bip32-dart](https://github.com/dart-bitcoin/bip32-dart). See upstream tags for per-version notes.

[3.0.0]: https://github.com/bulltechnologies/bip32/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/bulltechnologies/bip32/releases/tag/v2.0.0
