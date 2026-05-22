# bip32

[![pub package](https://img.shields.io/pub/v/bip32.svg)](https://pub.dev/packages/bip32)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Dart/Flutter implementation of [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) hierarchical deterministic (HD) wallets.

Maintained by **[Bull Technologies](https://github.com/bulltechnologies/bip32)**. Forked from [dart-bitcoin/bip32-dart](https://github.com/dart-bitcoin/bip32-dart).

---

## Why this library

| Concern | Approach |
|--------|----------|
| **Spec fidelity** | CKDpriv/CKDpub, serialization, master seed, official test vectors 1–5 |
| **Safety** | `dispose()` / `zeroize()`, defensive copies, strict import validation |
| **Clarity** | Layered modules (`core`, `crypto`, `hd`, `wif`), documented public API |
| **Compatibility** | `BIP32` / `NetworkType` API preserved from 2.x; additive 3.x types |

---

## Install

```yaml
dependencies:
  bip32: ^3.0.0
```

Requires Dart **3.0+**.

---

## Quick start

```dart
import 'dart:typed_data';

import 'package:bip32/bip32.dart';
import 'package:hex/hex.dart';

void main() {
  // From BIP32 test vector 1 seed
  final seed = Uint8List.fromList([
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  ]);
  final master = BIP32.fromSeed(seed, Networks.bitcoin);

  // Derive BIP44-style path (caller chooses path; library does not enforce BIP44)
  final account = master.derivePath("m/44'/0'/0'");
  final receive = account.derive(0).derive(0);

  print(receive.neutered().toBase58()); // xpub…
  print(HEX.encode(receive.copyPrivateKey()!));

  master.dispose(); // zeroize secrets when done
}
```

---

## API overview

### Extended keys — `BIP32` / `ExtendedKey`

| Method | BIP32 meaning |
|--------|----------------|
| `fromSeed(seed, [network])` | Master key: HMAC-SHA512(`"Bitcoin seed"`, seed) |
| `fromBase58(string, [network])` | Deserialize 78-byte extended key + checksum |
| `fromPrivateKey` / `fromPublicKey` | Build node from raw 32-byte scalar or compressed pubkey |
| `derive(index)` | One CKD step; hardened if `index ≥ 0x80000000` |
| `deriveHardened(i)` | `derive(i + 0x80000000)` |
| `derivePath("m/44'/0'/0'/0/0")` | Repeated CKD |
| `neutered()` | `N((k,c))` — public-only node, same chain code |
| `toBase58()` / `fromBase58` | Base58Check `xprv` / `xpub` |
| `toWIF()` | Bitcoin WIF (compressed) for leaf private scalar |
| `sign` / `verify` | ECDSA on node key (low-S) |
| `dispose()` | Zeroize private scalar, chain code, cached pubkey |

Metadata: `depth`, `index`, `parentFingerprint`, `fingerprint`, `identifier`, `chainCode`, `isMaster`, `isNeutered()`.

### Networks — `Networks`, `NetworkType`, `Bip32Version`

```dart
Networks.bitcoin        // xpub/xprv, WIF 0x80
Networks.bitcoinTestnet // tpub/tprv, WIF 0xef
Networks.litecoin       // legacy bytes used in upstream tests
```

Custom network:

```dart
final network = NetworkType(
  wif: 0xef,
  bip32: Bip32Version(public: 0x043587cf, private: 0x04358394),
);
```

### Paths — `parseDerivationPath`, `formatDerivationPath`, `toHardenedIndex`, …

### Default wallet layout (BIP32 § wallet structure, advisory)

```dart
WalletLayout.externalPath(0, 5); // m/0'/0/5
WalletLayout.deriveExternal(master, 0, 5);
```

Accounts use hardened indices: `m/iH/0/k` (receive), `m/iH/1/k` (change).

### Low-level crypto (advanced)

`hash160`, `hmacSha512`, `isPrivate`, `isPoint`, `pointFromScalar`, `privateAdd`, `pointAddScalar` — exposed for auditing and custom pipelines.

---

## Security model

### Extended public keys are not “just public”

If an attacker learns:

- parent **xpub**, and  
- any **non-hardened** private child,

they can recover the parent **xprv** and the whole subtree. Use **hardened** derivation for account levels (`44'/0'/…`).

### Secret handling

1. Prefer `copyPrivateKey()` over storing `privateKey` references.  
2. Call `dispose()` on nodes that held secrets.  
3. `zeroize(Uint8List)` for seeds or buffers you allocated.  
4. Dart cannot guarantee RAM is cleared OS-wide; minimize lifetime and avoid `print`/logs of keys.

### Import hardening

Extended keys from untrusted sources are validated for:

- version bytes vs payload type (pub/prv)  
- master depth/fingerprint/index consistency  
- private scalar in `[1, n-1]`  
- **compressed** pubkeys only (`0x02` / `0x03`) on import  
- curve membership for public points  
- depth ≤ **255** (serializable limit)

### Derivation limits

- Child index: `0 … 2³²-1` (hardened flag in bit 31)  
- Tree depth: max **255** (BIP32 1-byte depth field)  
- Invalid CKD outputs skip to `index + 1` per spec (bounded at `uint32Max`)

---

## BIP32 compliance checklist

- [x] Master generation from 128–512 bit seed  
- [x] CKDpriv / CKDpub with hardened and normal indices  
- [x] Neutered keys `N(x)`  
- [x] 78-byte serialization + Base58Check  
- [x] Hash160 identifier / fingerprint  
- [x] Official test vectors 1–2 (fixtures), 3–4 (leading zeros), 5 (invalid keys)  
- [x] Invalid intermediate IL / infinity handling (retry next index)  
- [x] Default wallet layout helpers (advisory paths)

Not in scope: BIP39 mnemonic, BIP44 coin type tables, script types, or blockchain RPC.

---

## Migrating from 2.x

- `BIP32`, `NetworkType`, `Bip32Type` unchanged.  
- `HIGHEST_BIT` → prefer `hardenedIndexFlag` (old name deprecated).  
- `hmacSHA512` → `hmacSha512` (alias deprecated).  
- New: `dispose`, `Networks`, `WalletLayout`, `maxBip32Depth`, stricter imports.  
- SDK: **Dart 3+** required.

---

## Development

```bash
dart pub get
dart test
dart analyze lib
```

---

## License

- **Code**: [MIT](LICENSE) — Copyright anicdh; Bull Technologies (fork).  
- **BIP32 spec**: [BSD-2-Clause](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).

## Credits

- [anicdh](https://github.com/anicdh) — original library  
- [dart-bitcoin/bip32-dart](https://github.com/dart-bitcoin/bip32-dart) — null-safety lineage  
- [bitcoinjs/bip32](https://github.com/bitcoinjs/bip32) — behavioral reference  
- [Bull Technologies](https://github.com/bulltechnologies) — 3.x maintenance and hardening
