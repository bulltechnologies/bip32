import 'dart:convert';
import 'dart:typed_data';

import 'package:bs58check/bs58check.dart' as bs58check;

import '../core/constants.dart';
import '../core/networks.dart';
import '../core/secure_buffer.dart';
import '../core/validation.dart';
import '../crypto/ecurve.dart' as ecc;
import '../crypto/hash.dart';
import '../wif/wif.dart' as wif;
import 'path.dart';

/// Hierarchical deterministic extended key ([BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)).
///
/// Each node holds a secp256k1 key pair (or public-only when [isNeutered]) plus a
/// 32-byte chain code used as the HMAC-SHA512 key for child derivation (CKD).
///
/// ## Derivation (CKD)
/// - [derive] / [deriveHardened] — single step `CKDpriv` or `CKDpub`
/// - [derivePath] — repeated CKD along a path such as `m/44'/0'/0'/0/0`
/// - Hardened indices set bit 31 (`i ≥ 0x80000000`); require a private parent
///
/// ## Serialization
/// 78-byte payload + Base58Check → `xprv` / `xpub` (or network-specific versions).
/// Imports validate version bytes, depth, parent fingerprint, compressed pubkeys only.
///
/// ## Security
/// - Call [dispose] to zeroize private scalars, chain codes, and cached pubkeys
/// - Prefer [copyPrivateKey] over holding [privateKey] references
/// - Extended *public* keys leak privacy if a non-hardened private child is exposed
///   (see BIP32 security section)
class BIP32 {
  BIP32._({
    SecureBuffer? privateKey,
    Uint8List? publicKey,
    required Uint8List chainCode,
    required this.network,
  })  : _privateKey = privateKey,
        _publicKey = publicKey,
        chainCode = Uint8List.fromList(chainCode),
        depth = 0,
        index = 0,
        parentFingerprint = 0;

  SecureBuffer? _privateKey;
  Uint8List? _publicKey;
  bool _disposed = false;

  /// 32-byte chain code (HMAC-SHA512 key for CKD). Cleared by [dispose].
  final Uint8List chainCode;

  /// Tree depth from master (`0` = master).
  int depth;

  /// Child index at this level (`ser32(i)` in serialization; hardened bit in MSB).
  int index;

  /// Network version bytes for extended keys and [toWIF].
  final NetworkType network;

  /// First 32 bits of parent's Hash160(pubkey); `0` at master.
  int parentFingerprint;

  /// Whether this node is the tree root (depth 0).
  bool get isMaster => depth == 0;

  /// Compressed SEC1 public key (33 bytes, `0x02` / `0x03` prefix).
  Uint8List get publicKey {
    _ensureNotDisposed();
    _publicKey ??= ecc.pointFromScalar(_privateKey!.bytes, true)!;
    return _publicKey!;
  }

  /// Private scalar (32 bytes), or `null` when neutered.
  ///
  /// Returns the live buffer for backward compatibility. Prefer [copyPrivateKey]
  /// and [dispose] when handling secrets.
  Uint8List? get privateKey {
    _ensureNotDisposed();
    return _privateKey?.bytes;
  }

  /// Hash160(compressed pubkey) — BIP32 key identifier (same payload as P2PKH).
  Uint8List get identifier => hash160(publicKey);

  /// First four bytes of [identifier] (BIP32 fingerprint).
  Uint8List get fingerprint => identifier.sublist(0, 4);

  /// [fingerprint] interpreted as big-endian uint32.
  int get fingerprintInt =>
      fingerprint.buffer.asByteData().getUint32(0, Endian.big);

  /// `true` when only a public key is present (`N(x)` / neutered).
  bool isNeutered() {
    _ensureNotDisposed();
    return _privateKey == null;
  }

  /// `N((k,c))` — same chain code and tree metadata, without private material.
  BIP32 neutered() {
    _ensureNotDisposed();
    final result = BIP32.fromPublicKey(publicKey, chainCode, network);
    result.depth = depth;
    result.index = index;
    result.parentFingerprint = parentFingerprint;
    return result;
  }

  /// Base58Check-encoded extended key (`xpub` / `xprv` for [Networks.bitcoin]).
  String toBase58() {
    _ensureNotDisposed();
    validateDepth(depth);
    return bs58check.encode(_serialize());
  }

  /// WIF for this node's private scalar (compressed).
  String toWIF() {
    _ensureNotDisposed();
    _requirePrivate('Missing private key');
    return wif.encode(
      wif.WIF(
        version: network.wif,
        privateKey: Uint8List.fromList(_privateKey!.bytes),
        compressed: true,
      ),
    );
  }

  /// Single CKD step: [index] in `0 … 2³²−1` (hardened if `≥ 0x80000000`).
  ///
  /// Implements `CKDpriv` when private material is present, else `CKDpub` for
  /// non-hardened indices only. On invalid child (IL ≥ n or point at infinity /
  /// zero scalar), BIP32 specifies trying the next index; this matches that behavior
  /// until [uint32Max] is exhausted.
  BIP32 derive(int index) {
    _ensureNotDisposed();
    if (index > uint32Max || index < 0) {
      throw ArgumentError('Expected UInt32');
    }
    if (depth >= maxBip32Depth) {
      throw ArgumentError('Maximum derivation depth exceeded');
    }
    return _deriveWithRetry(index);
  }

  /// Hardened child `iH` where [index] is the normal value `i` in `0 … 2³¹−1`.
  BIP32 deriveHardened(int index) {
    if (index > uint31Max || index < 0) {
      throw ArgumentError('Expected UInt31');
    }
    return derive(toHardenedIndex(index));
  }

  /// Derives along [path] (`m/44'/0'/0'/0/0` or relative `44'/0'/0'/0/0`).
  ///
  /// Paths starting with `m/` require a master node ([isMaster]).
  BIP32 derivePath(String path) {
    _ensureNotDisposed();
    final indices = parseDerivationPath(path);
    final requiresMaster = path.startsWith('m/') || path == 'm';
    if (requiresMaster && !isMaster) {
      throw ArgumentError('Expected master, got child');
    }
    var node = this;
    for (final childIndex in indices) {
      node = node.derive(childIndex);
    }
    return node;
  }

  /// ECDSA sign (RFC 6979 via pointycastle, low-S normalized).
  Uint8List sign(Uint8List hash) {
    _ensureNotDisposed();
    _requirePrivate('Missing private key');
    return ecc.sign(hash, _privateKey!.bytes);
  }

  /// Verifies [signature] over [hash] against this node's public key.
  bool verify(Uint8List hash, Uint8List signature) {
    _ensureNotDisposed();
    return ecc.verify(hash, publicKey, signature);
  }

  /// Defensive copy of the private scalar, or `null` if neutered.
  Uint8List? copyPrivateKey() {
    _ensureNotDisposed();
    return _privateKey?.clone();
  }

  /// Zeroizes secrets and disables further use.
  void dispose() {
    if (_disposed) return;
    _privateKey?.dispose();
    _privateKey = null;
    zeroize(chainCode);
    if (_publicKey != null) {
      zeroize(_publicKey!);
      _publicKey = null;
    }
    _disposed = true;
  }

  /// Decodes a Base58Check extended key.
  factory BIP32.fromBase58(String string, [NetworkType? network]) {
    final buffer = bs58check.decode(string);
    if (buffer.length != extendedKeyByteLength) {
      throw ArgumentError('Invalid buffer length');
    }
    return _deserialize(buffer, network ?? Networks.bitcoin);
  }

  /// Extended public node from compressed [publicKey] and [chainCode].
  factory BIP32.fromPublicKey(
    Uint8List publicKey,
    Uint8List chainCode, [
    NetworkType? network,
  ]) {
    validateChainCode(chainCode);
    if (publicKey.length != 33 ||
        (publicKey[0] != 0x02 && publicKey[0] != 0x03)) {
      throw ArgumentError('Expected compressed public key');
    }
    if (!ecc.isPoint(publicKey)) {
      throw ArgumentError('Point is not on the curve');
    }
    return BIP32._(
      publicKey: Uint8List.fromList(publicKey),
      chainCode: chainCode,
      network: network ?? Networks.bitcoin,
    );
  }

  /// Extended private node from 32-byte scalar [privateKey] and [chainCode].
  factory BIP32.fromPrivateKey(
    Uint8List privateKey,
    Uint8List chainCode, [
    NetworkType? network,
  ]) {
    validateChainCode(chainCode);
    if (privateKey.length != 32) {
      throw ArgumentError(
        'Expected property privateKey of type Buffer(Length: 32)',
      );
    }
    if (!ecc.isPrivate(privateKey)) {
      throw ArgumentError('Private key not in range [1, n]');
    }
    return BIP32._(
      privateKey: SecureBuffer(privateKey),
      chainCode: chainCode,
      network: network ?? Networks.bitcoin,
    );
  }

  /// Master node: `I = HMAC-SHA512("Bitcoin seed", seed)`, `k = IL`, `c = IR`.
  factory BIP32.fromSeed(Uint8List seed, [NetworkType? network]) {
    if (seed.length < seedMinBytes) {
      throw ArgumentError('Seed should be at least 128 bits');
    }
    if (seed.length > seedMaxBytes) {
      throw ArgumentError('Seed should be at most 512 bits');
    }
    final nw = network ?? Networks.bitcoin;
    final i = hmacSha512(
      Uint8List.fromList(utf8.encode(bitcoinSeedHmacKey)),
      seed,
    );
    try {
      final il = i.sublist(0, 32);
      final ir = i.sublist(32);
      if (!ecc.isPrivate(il)) {
        throw ArgumentError('Invalid master key');
      }
      return BIP32.fromPrivateKey(il, ir, nw);
    } finally {
      zeroize(i);
    }
  }

  BIP32 _deriveWithRetry(int index) {
    final hardened = isHardenedIndex(index);
    if (hardened && isNeutered()) {
      throw ArgumentError('Missing private key for hardened child key');
    }

    final data = Uint8List(37);
    Uint8List? mac;
    try {
      if (hardened) {
        data[0] = 0x00;
        data.setRange(1, 33, _privateKey!.bytes);
        data.buffer.asByteData().setUint32(33, index);
      } else {
        data.setRange(0, 33, publicKey);
        data.buffer.asByteData().setUint32(33, index);
      }

      mac = hmacSha512(chainCode, data);
      final il = mac.sublist(0, 32);
      final ir = mac.sublist(32);

      // BIP32: invalid if parse256(IL) ≥ n or resulting key is zero / infinity.
      if (!ecc.isValidDerivationTweak(il)) {
        if (index >= uint32Max) {
          throw ArgumentError('Failed to derive a valid child key');
        }
        return _deriveWithRetry(index + 1);
      }

      late BIP32 child;
      if (!isNeutered()) {
        final ki = ecc.privateAdd(_privateKey!.bytes, il);
        if (ki == null) {
          if (index >= uint32Max) {
            throw ArgumentError('Failed to derive a valid child key');
          }
          return _deriveWithRetry(index + 1);
        }
        child = BIP32.fromPrivateKey(ki, ir, network);
      } else {
        final ki = ecc.pointAddScalar(publicKey, il, true);
        if (ki == null) {
          if (index >= uint32Max) {
            throw ArgumentError('Failed to derive a valid child key');
          }
          return _deriveWithRetry(index + 1);
        }
        child = BIP32.fromPublicKey(ki, ir, network);
      }
      child.depth = depth + 1;
      child.index = index;
      child.parentFingerprint = fingerprintInt;
      return child;
    } finally {
      zeroize(data);
      if (mac != null) zeroize(mac);
    }
  }

  Uint8List _serialize() {
    final version =
        isNeutered() ? network.bip32.public : network.bip32.private;
    final buffer = Uint8List(extendedKeyByteLength);
    final bytes = buffer.buffer.asByteData();
    bytes.setUint32(0, version);
    bytes.setUint8(4, depth);
    bytes.setUint32(5, parentFingerprint);
    bytes.setUint32(9, index);
    buffer.setRange(13, 45, chainCode);
    if (!isNeutered()) {
      bytes.setUint8(45, 0);
      buffer.setRange(46, 78, _privateKey!.bytes);
    } else {
      buffer.setRange(45, 78, publicKey);
    }
    return buffer;
  }

  static BIP32 _deserialize(Uint8List buffer, NetworkType network) {
    final bytes = buffer.buffer.asByteData();
    final version = bytes.getUint32(0);
    final isPrivateVersion = version == network.bip32.private;
    final isPublicVersion = version == network.bip32.public;
    if (!isPrivateVersion && !isPublicVersion) {
      throw ArgumentError('Invalid network version');
    }

    final depth = buffer[4];
    validateDepth(depth);

    final parentFingerprint = bytes.getUint32(5);
    if (depth == 0 && parentFingerprint != 0) {
      throw ArgumentError('Invalid parent fingerprint');
    }

    final childIndex = bytes.getUint32(9);
    if (depth == 0 && childIndex != 0) {
      throw ArgumentError('Invalid index');
    }

    final chainCode = buffer.sublist(13, 45);
    validateChainCode(chainCode);
    final keyData = buffer.sublist(45, 78);

    late BIP32 hd;
    if (isPrivateVersion) {
      if (keyData[0] != 0x00) {
        throw ArgumentError('Invalid private key');
      }
      hd = BIP32.fromPrivateKey(keyData.sublist(1, 33), chainCode, network);
    } else {
      if (keyData[0] == 0x00 ||
          (keyData[0] != 0x02 && keyData[0] != 0x03)) {
        throw ArgumentError('Invalid public key');
      }
      hd = BIP32.fromPublicKey(keyData, chainCode, network);
    }

    hd.depth = depth;
    hd.index = childIndex;
    hd.parentFingerprint = parentFingerprint;
    return hd;
  }

  void _requirePrivate(String message) {
    if (_privateKey == null) {
      throw ArgumentError(message);
    }
  }

  void _ensureNotDisposed() {
    if (_disposed) {
      throw StateError('BIP32 node has been disposed');
    }
  }
}

/// Preferred alias for [BIP32] in new code.
typedef ExtendedKey = BIP32;
