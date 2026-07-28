# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.0] - 2026-07-24

### Added

- Direct integration with [native_crypto](https://github.com/bulltechnologies/native_crypto) (SHA-256, HMAC-SHA512, RIPEMD-160) and [native_sig](https://github.com/bulltechnologies/native_sig) (secp256k1 ECDSA, tweak-add).
- Internal Bitcoin Base58Check codec (replaces `bs58check`; wire format unchanged).
- v3 compatibility golden tests (`test/v3_compat_golden.json`) and native integration tests.
- Flutter `example/` harness and `tool/run_host_tests.sh` for desktop integration testing with real native libraries.

### Changed

- **Flutter required** (`>=3.44.0`) with Dart `>=3.12.0 <4.0.0`.
- All cryptographic operations delegate to native backends; no PointyCastle or pure-Dart fallback.
- `sign` / `verify` use `native_sig` (RFC 6979, low-S signing; legacy high-S verification preserved at the `BIP32` boundary).
- Serialization and WIF paths zeroize private-key buffers after encode/decode.
- CKD scratch buffers (HMAC output, derivation input, temporary scalars) are wiped after use.

### Removed

- Dependencies: `pointycastle`, `bs58check` (and runtime `hex`).
- PointyCastle-specific exports from `ecurve.dart`: `ECPoint`, `ECCurve_secp256k1`, `secp256k1`, `curveGenerator`, `decodePoint`, `encodePoint`.

### Security

- Native crypto must run on a **dedicated background isolate** (`native_crypto` enforces this in debug).
- Call `NativeSig.ensureInitialized()` once before spawning your crypto isolate.
- `native_sig` `publicKeyTweakAdd` now zeroizes the native tweak buffer (required for BIP32 `IL`).

### Documentation

- README updated for Flutter/native platform contract.
- See **[MIGRATION.md](MIGRATION.md)** § Migrating from 3.0.0 to 4.0.0.

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

### Documentation

- Added **[MIGRATION.md](MIGRATION.md)** — full 2.0.0 → 3.0.0 guide for wallets, stored keys, API deltas, and testing.

## [2.0.0]

### Added

- Null-safety migration.

## [1.0.0] - [1.0.10]

Historical releases by [anicdh](https://github.com/anicdh) and contributors on [dart-bitcoin/bip32-dart](https://github.com/dart-bitcoin/bip32-dart). See upstream tags for per-version notes.

[4.0.0]: https://github.com/bulltechnologies/bip32/compare/v3.0.0...v4.0.0
[3.0.0]: https://github.com/bulltechnologies/bip32/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/bulltechnologies/bip32/releases/tag/v2.0.0
