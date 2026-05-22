# Migrating from bip32 2.0.0 to 3.0.0

This guide is for teams that built wallets, signing flows, or key-storage pipelines on **bip32 2.0.0** (including the upstream [dart-bitcoin/bip32-dart](https://github.com/dart-bitcoin/bip32-dart) lineage) and are moving to **bip32 3.0.0** maintained by [Bull Technologies](https://github.com/bulltechnologies/bip32).

Read this document end-to-end before upgrading production systems that hold user funds.

---

## Table of contents

1. [Executive summary](#1-executive-summary)
2. [Hard requirements (blockers)](#2-hard-requirements-blockers)
3. [Wallets created under v2 — what stays the same](#3-wallets-created-under-v2--what-stays-the-same)
4. [Wallets created under v2 — what can break](#4-wallets-created-under-v2--what-can-break)
5. [Stored wallet artifacts — handling guide](#5-stored-wallet-artifacts--handling-guide)
6. [API compatibility reference](#6-api-compatibility-reference)
7. [Behavioral and semantic changes](#7-behavioral-and-semantic-changes)
8. [Error messages and exception handling](#8-error-messages-and-exception-handling)
9. [Security model changes](#9-security-model-changes)
10. [Dependency and import changes](#10-dependency-and-import-changes)
11. [Recommended migration procedure](#11-recommended-migration-procedure)
12. [Testing checklist (golden wallets)](#12-testing-checklist-golden-wallets)
13. [Rollback plan](#13-rollback-plan)
14. [FAQ](#14-faq)

---

## 1. Executive summary

| Question | Answer |
|----------|--------|
| Will existing **addresses and private keys** change for valid BIP32 data? | **No.** Same seed, same `xprv`/`xpub`, same path, same `NetworkType` → same scalars and same Base58 outputs. |
| Is the public **`BIP32` API** still there? | **Yes.** `BIP32`, `NetworkType`, factories, `derive`, `derivePath`, `neutered`, `toBase58`, `fromBase58`, `fromSeed`, `sign`, `verify`, `toWIF` are preserved. |
| Is it a drop-in upgrade with zero code changes? | **No.** You need **Dart 3+**, you should re-test imports and derivation, and you must adopt security practices (`dispose`, copies) for production. |
| Will **invalid or non-standard** extended keys behave the same? | **No.** v3 rejects more bad inputs at import time (by design). |
| Do I need to **re-derive or migrate user databases**? | **No** for correctly generated BIP32 trees. **Re-validate** imports; fix or quarantine corrupt rows. |

**Semantic version note:** 3.0.0 is a major bump because of SDK bounds, stricter validation, and new security surfaces — not because standard derivation math changed.

---

## 2. Hard requirements (blockers)

### 2.1 Dart SDK

| | v2.0.0 | v3.0.0 |
|---|--------|--------|
| Constraint | `>=2.12.0 <3.0.0` | `>=3.0.0 <4.0.0` |

**Action:** Upgrade your app, packages, and CI to **Dart 3** before bumping `bip32`. Flutter projects need a Flutter version that ships Dart 3.

```yaml
# pubspec.yaml (your app)
environment:
  sdk: ">=3.0.0 <4.0.0"

dependencies:
  bip32: ^3.0.0
```

### 2.2 Transitive crypto stack

v3 pulls **pointycastle 4.x** (v2 used 3.x). You do not call pointycastle directly in typical wallet code, but:

- Resolve conflicts if you pin an older pointycastle elsewhere.
- Re-run **all** crypto integration tests (signing, if used, and any custom ECC).

### 2.3 Package origin (fork)

| | v2.0.0 | v3.0.0 |
|---|--------|--------|
| Homepage | `dart-bitcoin/bip32-dart` | `bulltechnologies/bip32` |

**Action:** Update internal docs, SBOM, and support links. The **package name on pub.dev remains `bip32`** — only verify you depend on the artifact you intend (version + publisher).

---

## 3. Wallets created under v2 — what stays the same

The following are **bit-for-bit stable** between v2 and v3 when inputs are valid BIP32:

### 3.1 Master key from seed

- HMAC-SHA512 key: `"Bitcoin seed"`
- Seed length: 128–512 bits (16–64 bytes)
- Master scalar `IL`, chain code `IR`, invalid master rejection

```dart
// Produces identical xprv/xpub as v2 for the same seed + network
final master = BIP32.fromSeed(seed, Networks.bitcoin);
```

### 3.2 Child derivation (CKD)

- `derive(index)` — hardened when `index >= 0x80000000`
- `deriveHardened(i)` — `derive(i + 0x80000000)`
- `derivePath("m/44'/0'/0'/0/0")` — same path grammar
- Private parent → private child (`CKDpriv`)
- Public parent → public child (`CKDpub`) for non-hardened indices
- Identity: `neutered().derive(i)` equals `derive(i).neutered()` for non-hardened `i`

### 3.3 Serialization

- 78-byte extended key layout (version, depth, fingerprint, index, chain code, key data)
- Base58Check encoding → `xpub` / `xprv` (per `NetworkType`)
- Compressed public keys in serialized extended **public** keys

### 3.4 Metadata

- `identifier` = Hash160(compressed pubkey)
- `fingerprint` = first 4 bytes of identifier
- `depth`, `index`, `parentFingerprint` on derived nodes

### 3.5 Networks

Custom `NetworkType` you used in v2 still works:

```dart
final litecoin = NetworkType(
  wif: 0xb0,
  bip32: Bip32Version(public: 0x019da462, private: 0x019d9cfe), // was Bip32Type
);
```

`Bip32Type` remains as a **deprecated typedef** for `Bip32Version`.

### 3.6 WIF

`toWIF()` still emits compressed WIF for the node's private scalar (same bytes as v2 for the same key + network).

---

## 4. Wallets created under v2 — what can break

### 4.1 Summary table

| Scenario | v2 typical behavior | v3 behavior | Impact on live wallets |
|----------|-------------------|-------------|------------------------|
| Valid `xprv`/`xpub` from v2 | Import + derive OK | Same | **None** |
| Corrupt / non-BIP32 extended key in DB | May import or fail inconsistently | Import **rejected** with `ArgumentError` | **Import fails** until data fixed |
| Uncompressed pubkey via `fromPublicKey` | Allowed if `isPoint` passed | **Rejected** (`Expected compressed public key`) | Only if you built nodes manually — not from Base58 |
| Tree depth > 255 | Derived; depth **truncated** on serialize | **Cannot derive** past 255 | **Only** pathological / buggy trees |
| `node.chainCode = other` mutation | Allowed (`chainCode` mutable) | **`chainCode` is `final`** | Compile error if you mutated it |
| `sign()` on xpub-only node | Possible null/error | `ArgumentError('Missing private key')` | Clearer failure |
| Catching specific `ArgumentError.message` | Stable for your handled cases | Some messages **stricter/clearer** | Brittle catch blocks may break |
| Dart 2 app | Works on 2.0.0 | **Does not compile** on 3.0.0 | Must migrate to Dart 3 |
| Deep import `lib/src/utils/...` | Worked | Deprecated re-exports | Warnings; prefer `package:bip32/bip32.dart` |

### 4.2 Derivation math did NOT change (clarification)

If a v2 wallet produced a valid address at path `m/44'/0'/0'/0/0`, v3 produces the **same** address for the same seed or extended key.  

If you see a mismatch after upgrade, the cause is almost always:

1. Different seed or passphrase (BIP39 layer, not bip32)
2. Different `NetworkType` version bytes (mainnet vs testnet, altcoin params)
3. Different path string (typo, hardened marker, account index)
4. v2 code had a bug upstream of bip32 (custom path builder)
5. Corrupt key material that v2 never actually used in production

---

## 5. Stored wallet artifacts — handling guide

How to treat each type of data persisted while on v2.

### 5.1 BIP39 mnemonic + external passphrase (not bip32)

**bip32 does not implement BIP39.** If users restored from a mnemonic, your app derived a **seed** then called `BIP32.fromSeed`.

| Action | Required? |
|--------|-----------|
| Re-encode mnemonic | No |
| Re-derive seed | No (unless your BIP39 layer changed) |
| Re-test `fromSeed` → master `xprv` | **Yes** (integration test) |

### 5.2 Raw seed bytes (stored encrypted)

| Action | Required? |
|--------|-----------|
| Migrate seed blobs | No |
| On load: `BIP32.fromSeed(seed, network)` | Same API |
| After load: call `dispose()` when session ends | **Recommended** (v3) |

```dart
final master = BIP32.fromSeed(decryptedSeed, Networks.bitcoin);
try {
  // derive / sign
} finally {
  master.dispose();
  zeroize(decryptedSeed); // if you hold seed in a Uint8List you own
}
```

### 5.3 Extended keys (`xprv` / `xpub` strings in DB)

This is the most common v2 storage pattern.

**Procedure:**

1. **Do not** mass-convert strings — they are already standard Base58Check.
2. On upgrade, run a **read-only validation pass** (or lazy validation on load):

```dart
BIP32 node;
try {
  node = BIP32.fromBase58(storedString, yourNetwork);
} on ArgumentError catch (e) {
  // Quarantine wallet: log id, error message, do not derive/spend
  rethrow; // or route to support flow
}
```

3. For each active wallet, assert golden outputs:

```dart
expect(node.fingerprint, previouslyStoredFingerprint); // if you stored it
expect(node.neutered().toBase58(), previouslyStoredXpub);
// Derive first receive path you used in prod and compare address
```

**Valid v2 keys → v3 imports identically.**  

**Invalid keys v2 might have accepted** → v3 throws; treat as **data corruption**, not migration:

| Error (examples) | Meaning |
|------------------|---------|
| `Invalid public key` | xpub payload not compressed SEC1 |
| `Invalid private key` | xprv payload malformed |
| `Invalid parent fingerprint` | Master node with non-zero parent fingerprint |
| `Invalid index` | Master with non-zero child index |
| `Private key not in range [1, n]` | Zero or overflow scalar |
| `Point is not on the curve` | Invalid pubkey coordinates |
| `Invalid network version` | Wrong version bytes for your `NetworkType` |
| `Invalid checksum` | Typo or truncated Base58 |

**Do not** “fix” these by loosening validation — export backup, regenerate from seed if possible, or manual recovery.

### 5.4 Derived private keys / addresses only (no xprv stored)

If you only stored **leaf private keys** or **addresses** (not the HD tree):

| Stored | bip32 role | Migration |
|--------|------------|-----------|
| P2PKH/P2WPKH address | Output of pubkey hash | **No change** — addresses are not recomputed by bip32 |
| WIF at leaf | `toWIF()` equivalent | **No change** if same scalar |
| No xprv, no seed | Cannot re-derive siblings | bip32 upgrade **irrelevant** for recovery — you already abandoned HD |

You still should upgrade the library for **new** derivations.

### 5.5 Cached derivation paths / address indexes

| Stored | Migration |
|--------|-----------|
| Path strings like `m/44'/0'/0'/0/5` | **Reuse as-is** with `derivePath` |
| Per-account `index` counters | **Reuse as-is** — v3 does not change index semantics |
| Serialized `depth` / `index` / `parentFingerprint` | Should match re-imported node metadata |

### 5.6 Neutered (watch-only) wallets

`xpub` imported with v2 → same `xpub` with v3.

**Caveats:**

- Cannot `deriveHardened` from xpub (same as v2).
- Non-hardened derivation still leaks privacy implications if combined with leaked child private keys (BIP32 security — unchanged).

### 5.7 Hot vs cold / watch-only / multisig

| Architecture | bip32 v3 impact |
|--------------|-----------------|
| Hot wallet holds `xprv` | Re-test import + signing; add `dispose()` on logout |
| Cold stores `xprv` QR | No format change |
| Watch-only `xpub` | No change |
| Multisig coordinator uses xpubs | No change to xpub math |
| Cosigner imports another party xpub | Validate on v3 import |

### 5.8 Altchains (Litecoin, custom `NetworkType`)

v2 tests included Litecoin version bytes. v3 preserves custom `NetworkType`.

**Action:** Re-run one golden vector per network you ship (mainnet + testnet + each altcoin).

```dart
static final litecoin = NetworkType(
  wif: 0xb0,
  bip32: Bip32Version(public: 0x019da462, private: 0x019d9cfe),
);
```

---

## 6. API compatibility reference

### 6.1 Unchanged (keep using as-is)

| Symbol | Notes |
|--------|-------|
| `class BIP32` | Same name; implementation refactored |
| `BIP32.fromSeed` | Same signature |
| `BIP32.fromBase58` | Stricter validation |
| `BIP32.fromPrivateKey` / `fromPublicKey` | Stricter on pubkey format |
| `derive` / `deriveHardened` / `derivePath` | Same |
| `neutered` / `isNeutered` | Same |
| `toBase58` / `toWIF` | Same |
| `sign` / `verify` | Same; better error on neutered sign |
| `privateKey` / `publicKey` / `chainCode` | `chainCode` now **final** |
| `depth` / `index` / `parentFingerprint` | Still assignable on instance |
| `identifier` / `fingerprint` | Same |
| `class NetworkType` | `bip32` field; `bip32Type` deprecated getter |
| `class WIF` + `wif.encode` / `decode` | Same |

### 6.2 Deprecated (still works, migrate when convenient)

| v2 | v3 replacement |
|----|----------------|
| `Bip32Type` | `Bip32Version` |
| `HIGHEST_BIT` | `hardenedIndexFlag` |
| `UINT31_MAX` | `uint31Max` |
| `UINT32_MAX` | `uint32Max` |
| `hmacSHA512` | `hmacSha512` |
| `fromBuffer` / `toBuffer` | `bufferToBigInt` / `bigIntTo32Bytes` |
| `import 'package:bip32/src/utils/ecurve.dart'` | `import 'package:bip32/bip32.dart'` |

### 6.3 New in v3 (optional adoption)

| Symbol | Purpose |
|--------|---------|
| `ExtendedKey` | Typedef alias for `BIP32` |
| `Networks.bitcoin` / `bitcoinTestnet` / `litecoin` | Presets |
| `dispose()` | Zeroize secrets on node |
| `copyPrivateKey()` | Defensive copy of scalar |
| `zeroize(Uint8List)` | Wipe any buffer |
| `isMaster` | `depth == 0` |
| `fingerprintInt` | Fingerprint as `uint32` |
| `parseDerivationPath` / `formatDerivationPath` | Path utilities |
| `isHardenedIndex` / `toHardenedIndex` / `fromHardenedIndex` | Index helpers |
| `WalletLayout` | BIP32 default account/external/internal paths |
| `maxBip32Depth` | `255` |
| `isValidDerivationTweak` | Documented IL check |
| `Bip32Exception` hierarchy | New code paths (mostly `ArgumentError` on factories) |

---

## 7. Behavioral and semantic changes

### 7.1 Maximum tree depth (255)

**BIP32** serializes `depth` as **one byte**. v2 allowed deriving beyond 255 while silently truncating depth on export — **dangerous**.

v3 enforces:

```dart
if (depth >= maxBip32Depth) // 255
  throw ArgumentError('Maximum derivation depth exceeded');
```

**Wallet impact:** Normal BIP44/BIP84 paths have depth ≤ 6. **No production impact** unless you had a custom infinite-derive bug.

**If you previously exported nodes with depth > 255:** Those exports were **already invalid** on the wire. Re-derive from an ancestor within depth limit.

### 7.2 Invalid CKD retry at `index == uint32Max`

When `IL` is invalid, BIP32 tries `index + 1`. v2 could throw `Expected UInt32` when wrapping. v3 throws:

`ArgumentError('Failed to derive a valid child key')`

**Wallet impact:** None in practice (probability ~ 2⁻¹²⁷ per step).

### 7.3 `IL = 0` tweak skipping

Both v2 and v3 skip invalid tweaks using a stricter-than-minimal spec check (exclude `IL == 0` and `IL >= n`). Industry-common; **not a v2/v3 diff**.

### 7.4 `chainCode` is immutable

```dart
// v2 — compiled
node.chainCode = anotherChainCode;

// v3 — compile-time error
// node.chainCode = ...;
```

**Migration:** Clone into a new `BIP32.fromPrivateKey` / `fromPublicKey` if you need a different chain code (rare).

### 7.5 `fromPublicKey` — compressed only

BIP32 serialized extended public keys **always** use 33-byte compressed keys. v3 enforces that at the factory:

```dart
BIP32.fromPublicKey(uncompressed65ByteKey, chainCode); // throws in v3
```

**v2** could accept 65-byte uncompressed keys if `isPoint` passed.

**Wallet impact:**

- Keys loaded via **`fromBase58`** — **no change** (always compressed in payload).
- Keys built via **`fromPublicKey`** with non-standard encoding — **fix caller** to compress first.

### 7.6 Master import validation

v3 rejects master (`depth == 0`) with:

- `parentFingerprint != 0` → `Invalid parent fingerprint`
- `index != 0` → `Invalid index`

If v2 accepted such strings, they were **invalid master nodes**. Quarantine those DB rows.

### 7.7 Version byte vs payload type

v3 rejects:

- `xpub` version with `0x00 || private_scalar` payload → `Invalid public key`
- `xprv` version with `0x02/0x03 || ...` pubkey payload → `Invalid private key`

Some v2 error messages differ (e.g. curve error vs explicit invalid public key). **Update brittle tests** that assert exact strings.

### 7.8 `sign` / `verify`

| Call | v2 | v3 |
|------|----|----|
| `sign` on xpub | Undefined / null throw | `Missing private key` |
| `verify` | Same | Same |

Not a key derivation change — error-handling only.

### 7.9 Internal buffer handling (no API change)

v3 zeroizes:

- HMAC output after `fromSeed`
- CKD scratch (`data`, `mac`) after each `derive` attempt

Does not change outputs; reduces sensitive data lifetime in RAM.

---

## 8. Error messages and exception handling

### 8.1 Still `ArgumentError` on core factories

`BIP32.fromBase58`, `fromSeed`, `derive`, `derivePath` continue to throw **`ArgumentError`** with string messages for backward compatibility.

**Do not** write production logic as:

```dart
// Fragile — avoid
if (e.message == 'Point is not on the curve') { ... }
```

Prefer:

```dart
try {
  BIP32.fromBase58(x);
} on ArgumentError {
  return WalletLoadResult.invalid;
}
```

### 8.2 `Bip32DerivationException`

`fromHardenedIndex` on a non-hardened index throws **`Bip32DerivationException`** (new). Unlikely to affect v2 code paths unless you already used new path helpers.

### 8.3 `StateError` after `dispose()`

```dart
node.dispose();
node.derive(0); // StateError: BIP32 node has been disposed
```

New — adopt a lifecycle: one node per session, dispose on close.

### 8.4 Complete factory / derive error catalog (v3)

| Message | When |
|---------|------|
| `Invalid buffer length` | Base58 decoded length ≠ 78 |
| `Invalid network version` | Version bytes ≠ network.bip32.{public,private} |
| `Invalid parent fingerprint` | depth 0 but fingerprint ≠ 0 |
| `Invalid index` | depth 0 but child index ≠ 0 |
| `Invalid chain code length` | chain code ≠ 32 bytes |
| `Invalid private key` | xprv key data[0] ≠ 0x00 |
| `Invalid public key` | xpub bad prefix or private payload |
| `Point is not on the curve` | Pubkey fails curve decode |
| `Private key not in range [1, n]` | Scalar 0 or ≥ n |
| `Expected compressed public key` | `fromPublicKey` wrong length/prefix |
| `Invalid master key` | Seed produces invalid IL |
| `Seed should be at least 128 bits` | seed < 16 bytes |
| `Seed should be at most 512 bits` | seed > 64 bytes |
| `Expected UInt32` | derive index out of range |
| `Expected UInt31` | deriveHardened index out of range |
| `Expected BIP32 Path` | malformed path string |
| `Expected master, got child` | path `m/...` on non-master node |
| `Missing private key for hardened child key` | hardened derive from xpub |
| `Maximum derivation depth exceeded` | depth ≥ 255 |
| `Failed to derive a valid child key` | CKD retry exhausted |
| `Missing private key` | `toWIF` / `sign` on neutered node |
| `Invalid checksum` | Base58Check failure (from bs58check) |

---

## 9. Security model changes

### 9.1 What v3 adds

| Feature | Recommendation |
|---------|----------------|
| `dispose()` | Call when session ends or isolate completes |
| `copyPrivateKey()` | Use before passing scalar to another layer |
| `zeroize(buffer)` | Wipe seed copies you allocated |
| Stricter import | Treat as **gate** for untrusted xpub/xprv strings |
| Depth limit | Prevents silent invalid exports |

### 9.2 What v3 does NOT solve

- Dart GC may copy memory; `zeroize` is **best-effort**
- No secure enclave / TEE integration
- No protection against rooted devices or memory dumps
- `sign` is not a full Bitcoin transaction signing pipeline

### 9.3 v2-managed wallets in production

| Practice | v2 | v3 recommendation |
|----------|----|--------------------|
| Hold `xprv` in RAM indefinitely | Common | Minimize lifetime; `dispose()` on logout |
| Store only encrypted xprv | Good | Keep; validate decrypt → `fromBase58` on v3 |
| Log derivation paths | OK | Never log keys, chain codes, or seeds |
| Share xpub to frontend | OK | Still OK; educate on non-hardened leak model |

**You do not need to rotate keys** solely because of the v3 upgrade if keys were valid BIP32.

---

## 10. Dependency and import changes

### 10.1 pubspec

```yaml
dependencies:
  bip32: ^3.0.0
  # hex / bs58check still transitive unless you use them directly
```

### 10.2 Imports

```dart
// Preferred
import 'package:bip32/bip32.dart';

// Avoid in new code (deprecated re-exports)
import 'package:bip32/src/utils/ecurve.dart';
```

### 10.3 Monorepo / git dependency

If v2 used:

```yaml
bip32:
  git:
    url: https://github.com/dart-bitcoin/bip32-dart
```

Switch to:

```yaml
bip32:
  git:
    url: https://github.com/bulltechnologies/bip32
    ref: v3.0.0 # or tag you trust
```

Run golden tests after changing remotes.

---

## 11. Recommended migration procedure

### Phase A — Inventory (1–2 days)

1. List all call sites: `fromSeed`, `fromBase58`, `derivePath`, `sign`, `toWIF`.
2. List persisted artifacts: seed, `xprv`, `xpub`, paths, network params.
3. Identify custom `NetworkType` definitions.
4. Note any `lib/src/` deep imports or deprecated constants.

### Phase B — Toolchain (blocking)

1. Upgrade to **Dart 3** / compatible Flutter.
2. `dart pub upgrade`
3. `dart analyze` / `flutter analyze`
4. Fix compile errors (`chainCode` assignment, SDK bounds).

### Phase C — Automated tests

1. `dart test` in bip32 (189 tests in upstream 3.0.0).
2. Your golden tests:

```dart
// Pseudocode — per network, per template wallet
final master = BIP32.fromSeed(TEST_SEED, network);
expect(master.toBase58(), KNOWN_V2_XPRV);
expect(master.derivePath("m/44'/0'/0'/0/0").neutered().toBase58(), KNOWN_V2_XPUB_LEAF);
```

3. Import test: load **sample of production** encrypted xprv rows (staging DB) through v3 `fromBase58`.

### Phase D — Staging rollout

1. Deploy app with bip32 3 behind feature flag if possible.
2. Monitor import/derivation error rates.
3. Compare address generation metrics (should be identical).

### Phase E — Security hardening (post-upgrade)

1. Introduce `dispose()` in session teardown.
2. Replace `privateKey` retention with `copyPrivateKey()` where copies are needed.
3. `zeroize` seed buffers after `fromSeed`.

### Phase F — Cleanup (optional)

1. Replace `Bip32Type` → `Bip32Version`.
2. Use `Networks.*` presets.
3. Use `WalletLayout` if you encoded `m/iH/0/k` manually.

---

## 12. Testing checklist (golden wallets)

Use this table and tick each row for **each network** you support.

| # | Test | Expected v2 vs v3 |
|---|------|-------------------|
| 1 | `fromSeed` → master `xprv` Base58 | Identical |
| 2 | `fromSeed` → master `xpub` Base58 | Identical |
| 3 | `fromBase58(stored_xprv)` → same `xprv` string | Identical |
| 4 | `fromBase58(stored_xpub)` → same `xpub` string | Identical |
| 5 | BIP44 account `m/44'/coin'/acc'` | Identical |
| 6 | First receive `.../0/0` | Identical address |
| 7 | Change chain `.../1/0` | Identical |
| 8 | Hardened account derive from xpub fails | Same error class |
| 9 | `neutered().derive(0)` vs `derive(0).neutered()` | Identical xpub |
| 10 | `toWIF()` at known leaf | Identical |
| 11 | `sign` + `verify` roundtrip (if used) | Identical signature |
| 12 | Invalid checksum xprv rejected | Rejected (both) |
| 13 | Litecoin/custom network vector | Identical |
| 14 | Leading-zero private key vector (BIP32 tv 3/4) | Identical |

Official vectors live in `test/fixtures.json` and `test/bip32_official_vectors_test.dart` — run them as a reference.

---

## 13. Rollback plan

If production issues appear:

1. Pin dependency back to `bip32: 2.0.0` (Dart 2.12+ environment).
2. Root-cause whether mismatch is network, path, seed, or corrupt import.
3. Do **not** rollback only because import errors increased — often indicates **bad data** v3 correctly rejects.

Keep a CSV of failing `fromBase58` strings (ids only, not keys in logs) for support.

---

## 14. FAQ

### Do users need to re-generate recovery phrases?

**No.** Mnemonics map to seeds outside bip32; `fromSeed` is unchanged.

### Do we need a blockchain rescan?

**No.** Addresses unchanged for same derivation paths.

### Will pub.dev package name change?

**No.** Still `bip32`; verify publisher/version when upgrading.

### We only used `xpub` for deposit detection — any risk?

**No** derivation change. Import validation is stricter; valid xpubs unchanged.

### We mutated `chainCode` in memory for experiments

v3 will not compile. Refactor to create new nodes via factories.

### Can we run v2 and v3 side-by-side in one app?

Possible in theory (different package names via git dependency alias) but **not recommended** — pick one version and test.

### Is 3.0.0 audited?

No public third-party audit is claimed. Treat as standard open-source risk; run your own review for high-value deployments.

### HD wallet created with bitcoinjs / rust — import into Dart v3?

**Yes**, if extended keys are standard BIP32 and network versions match. This library aims for cross-implementation compatibility on valid keys.

---

## Quick reference: v2 wallet → v3 action

| Your v2 setup | Action on v3 |
|---------------|--------------|
| Standard BIP44 + `fromSeed` / `xprv` | Upgrade SDK; run golden tests; ship |
| Encrypted `xprv` in DB | Decrypt → `fromBase58`; quarantine failures |
| Watch-only `xpub` | Re-import test; no rotation |
| Custom altcoin `NetworkType` | Keep definition; rerun altcoin golden |
| Leaf keys only | Library upgrade optional for history; HD not used |
| Malformed keys in DB | Fix data; do not weaken v3 validation |
| Dart 2 | **Must** move to Dart 3 first |

---

## Document history

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-05-22 | Initial migration guide for bip32 3.0.0 |

For release notes see [CHANGELOG.md](CHANGELOG.md). For API examples see [README.md](README.md).
