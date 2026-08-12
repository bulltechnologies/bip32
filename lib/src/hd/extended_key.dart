import 'dart:convert';
import 'dart:typed_data';

import '../encoding/base58check.dart' as base58check;

import '../core/bytes.dart';
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
    this.depth = 0,
    this.index = 0,
    this.parentFingerprint = 0,
  }) : _privateKey = privateKey,
       _publicKey = publicKey,
       chainCode = Uint8List.fromList(chainCode);

  /// Internal constructor for CKD output that already passed validation.
  ///
  /// Takes ownership of [chainCode] and key material without re-validating or
  /// cloning freshly produced child buffers.
  BIP32._trusted({
    SecureBuffer? privateKey,
    Uint8List? publicKey,
    required Uint8List chainCode,
    required this.network,
    required this.depth,
    required this.index,
    required this.parentFingerprint,
  }) : _privateKey = privateKey,
       _publicKey = publicKey,
       chainCode = chainCode;

  SecureBuffer? _privateKey;
  Uint8List? _publicKey;
  Uint8List? _cachedIdentifier;
  Uint8List? _cachedFingerprint;
  bool _disposed = false;

  /// 32-byte chain code (HMAC-SHA512 key for CKD). Cleared by [dispose].
  ///
  /// Returns the live buffer for backward compatibility. Prefer [copyChainCode].
  final Uint8List chainCode;

  /// Tree depth from master (`0` = master).
  final int depth;

  /// Child index at this level (`ser32(i)` in serialization; hardened bit in MSB).
  final int index;

  /// Network version bytes for extended keys and [toWIF].
  final NetworkType network;

  /// First 32 bits of parent's Hash160(pubkey); `0` at master.
  final int parentFingerprint;

  /// Whether this node is the tree root (depth 0).
  bool get isMaster => depth == 0;

  /// Compressed SEC1 public key (33 bytes, `0x02` / `0x03` prefix).
  ///
  /// Returns the live buffer for backward compatibility. Prefer [copyPublicKey].
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
  Uint8List get identifier {
    _ensureNotDisposed();
    return _cachedIdentifier ??= hash160(publicKey);
  }

  /// First four bytes of [identifier] (BIP32 fingerprint).
  Uint8List get fingerprint {
    _ensureNotDisposed();
    return _cachedFingerprint ??= identifier.sublist(0, 4);
  }

  /// [fingerprint] interpreted as big-endian uint32.
  int get fingerprintInt =>
      fingerprint.buffer.asByteData().getUint32(0, Endian.big);

  /// Whether [dispose] has been called.
  bool get isDisposed => _disposed;

  /// Whether this node holds a private scalar.
  bool get hasPrivateKey {
    _ensureNotDisposed();
    return _privateKey != null;
  }

  /// `true` when only a public key is present (`N(x)` / neutered).
  bool isNeutered() {
    _ensureNotDisposed();
    return _privateKey == null;
  }

  /// `N((k,c))` — same chain code and tree metadata, without private material.
  BIP32 neutered() {
    _ensureNotDisposed();
    return BIP32._(
      publicKey: Uint8List.fromList(publicKey),
      chainCode: chainCode,
      network: network,
      depth: depth,
      index: index,
      parentFingerprint: parentFingerprint,
    );
  }

  /// Base58Check-encoded extended key (`xpub` / `xprv` for [Networks.bitcoin]).
  String toBase58() {
    _ensureNotDisposed();
    validateDepth(depth);
    final payload = toSerializedBytes();
    try {
      return base58check.encode(payload);
    } finally {
      zeroize(payload);
    }
  }

  /// 78-byte BIP32 serialization payload (no Base58Check checksum).
  Uint8List toSerializedBytes() {
    _ensureNotDisposed();
    validateDepth(depth);
    return _serialize();
  }

  /// 82-byte payload with Base58Check checksum (not yet Base58-encoded).
  Uint8List toSerializedFrame() {
    final payload = toSerializedBytes();
    try {
      return base58check.appendChecksum(payload);
    } finally {
      zeroize(payload);
    }
  }

  /// WIF for this node's private scalar.
  String toWIF({bool compressed = true}) {
    _ensureNotDisposed();
    _requirePrivate('Missing private key');
    return wif.encode(
      wif.WIF(
        version: network.wif,
        privateKey: Uint8List.fromList(_privateKey!.bytes),
        compressed: compressed,
      ),
    );
  }

  /// Same tree metadata and key material on [network] version bytes.
  BIP32 copyWithNetwork(NetworkType network) {
    _ensureNotDisposed();
    return BIP32._(
      privateKey: _privateKey != null ? SecureBuffer(_privateKey!.bytes) : null,
      publicKey: _publicKey != null ? Uint8List.fromList(_publicKey!) : null,
      chainCode: chainCode,
      network: network,
      depth: depth,
      index: index,
      parentFingerprint: parentFingerprint,
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
    validateChildIndex(index);
    if (depth >= maxBip32Depth) {
      throw ArgumentError('Maximum derivation depth exceeded');
    }
    return _deriveWithRetry(index);
  }

  /// Hardened child `iH` where [index] is the normal value `i` in `0 … 2³¹−1`.
  BIP32 deriveHardened(int index) {
    validateHardenedChildIndex(index);
    return derive(toHardenedIndex(index));
  }

  /// Derives along pre-parsed [path] without re-parsing segments.
  BIP32 deriveCompiledPath(DerivationPath path) {
    _ensureNotDisposed();
    if (path.isAbsolute && !isMaster) {
      throw ArgumentError('Expected master, got child');
    }
    return deriveIndices(path.indices);
  }

  /// Derives along [indices] with optional per-step callback.
  ///
  /// When [disposeIntermediates] is true, intermediate nodes are [dispose]d
  /// after [onStep] returns; the final node is returned to the caller.
  BIP32 deriveIndices(
    List<int> indices, {
    void Function(BIP32 node, int step)? onStep,
    bool disposeIntermediates = false,
  }) {
    _ensureNotDisposed();
    _preflightDepth(indices.length);
    var node = this;
    for (var step = 0; step < indices.length; step++) {
      final child = node.derive(indices[step]);
      onStep?.call(child, step);
      if (disposeIntermediates && step < indices.length - 1) {
        if (!identical(node, this)) {
          node.dispose();
        }
      }
      node = child;
    }
    return node;
  }

  /// Derives along [path] (`m/44'/0'/0'/0/0` or relative `44'/0'/0'/0/0`).
  ///
  /// Paths starting with `m/` require a master node ([isMaster]).
  BIP32 derivePath(String path) =>
      deriveCompiledPath(parseDerivationPath(path));

  /// Single CKDpub step returning only compressed public-key bytes.
  ///
  /// Useful for watch-only address scans without allocating child [BIP32] nodes.
  Uint8List derivePublicKey(int index) {
    _ensureNotDisposed();
    validateChildIndex(index);
    if (depth >= maxBip32Depth) {
      throw ArgumentError('Maximum derivation depth exceeded');
    }
    return _derivePublicKeyWithRetry(index);
  }

  /// Derives sibling public keys under this node without child-node allocation.
  List<Uint8List> derivePublicKeys(List<int> indices) =>
      indices.map(derivePublicKey).toList(growable: false);

  /// Derives along [indices] and returns only the final compressed public key.
  Uint8List derivePublicKeyPath(List<int> indices) {
    _ensureNotDisposed();
    _preflightDepth(indices.length);
    var pub = Uint8List.fromList(publicKey);
    var cc = Uint8List.fromList(chainCode);
    try {
      for (final index in indices) {
        validateChildIndex(index);
        var childIndex = index;
        _CkdPubResult step;
        while (true) {
          final candidate = _ckdStep(
            pub,
            cc,
            childIndex,
            privateKey: _privateKey,
          );
          if (candidate != null) {
            step = candidate;
            break;
          }
          childIndex = _nextChildIndexOrThrow(childIndex);
        }
        zeroize(pub);
        zeroize(cc);
        pub = step.publicKey;
        cc = step.chainCode;
      }
      return Uint8List.fromList(pub);
    } finally {
      zeroize(pub);
      zeroize(cc);
    }
  }

  /// ECDSA sign (RFC 6979 via native backend, low-S normalized).
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

  /// Defensive copy of the compressed public key.
  Uint8List copyPublicKey() {
    _ensureNotDisposed();
    return Uint8List.fromList(publicKey);
  }

  /// Defensive copy of the chain code.
  Uint8List copyChainCode() {
    _ensureNotDisposed();
    return Uint8List.fromList(chainCode);
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
    _cachedIdentifier = null;
    _cachedFingerprint = null;
    _disposed = true;
  }

  /// Decodes a Base58Check extended key.
  factory BIP32.fromBase58(String string, [NetworkType? network]) =>
      BIP32.fromSerializedBytes(base58check.decode(string), network);

  /// Decodes a 78-byte serialized extended key payload.
  factory BIP32.fromSerializedBytes(List<int> bytes, [NetworkType? network]) {
    final buffer = asUint8List(bytes);
    if (buffer.length != extendedKeyByteLength) {
      throw ArgumentError('Invalid buffer length');
    }
    final copy = Uint8List.fromList(buffer);
    try {
      return _deserialize(copy, network ?? Networks.bitcoin);
    } finally {
      zeroize(copy);
    }
  }

  /// Decodes an 82-byte Base58Check checksum frame (not Base58-encoded).
  factory BIP32.fromSerializedFrame(List<int> frame, [NetworkType? network]) {
    final frameBytes = asUint8List(frame);
    if (frameBytes.length != extendedKeyFrameByteLength) {
      throw ArgumentError('Invalid buffer length');
    }
    final payload = base58check.verifyAndStripChecksum(frameBytes);
    try {
      return BIP32.fromSerializedBytes(payload, network);
    } finally {
      zeroize(payload);
    }
  }

  /// Extended public node from compressed [publicKey] and [chainCode].
  factory BIP32.fromPublicKey(
    List<int> publicKey,
    List<int> chainCode, [
    NetworkType? network,
  ]) {
    final publicKeyBytes = asUint8List(publicKey);
    final chainCodeBytes = asUint8List(chainCode);
    validateChainCode(chainCodeBytes);
    if (publicKeyBytes.length != 33 ||
        (publicKeyBytes[0] != 0x02 && publicKeyBytes[0] != 0x03)) {
      throw ArgumentError('Expected compressed public key');
    }
    if (!ecc.isPoint(publicKeyBytes)) {
      throw ArgumentError('Point is not on the curve');
    }
    return BIP32._(
      publicKey: Uint8List.fromList(publicKeyBytes),
      chainCode: chainCodeBytes,
      network: network ?? Networks.bitcoin,
    );
  }

  /// Extended private node from 32-byte scalar [privateKey] and [chainCode].
  factory BIP32.fromPrivateKey(
    List<int> privateKey,
    List<int> chainCode, [
    NetworkType? network,
  ]) {
    final privateKeyBytes = asUint8List(privateKey);
    final chainCodeBytes = asUint8List(chainCode);
    validateChainCode(chainCodeBytes);
    if (privateKeyBytes.length != 32) {
      throw ArgumentError(
        'Expected property privateKey of type Buffer(Length: 32)',
      );
    }
    if (!ecc.isPrivate(privateKeyBytes)) {
      throw ArgumentError('Private key not in range [1, n]');
    }
    return BIP32._(
      privateKey: SecureBuffer(privateKeyBytes),
      chainCode: chainCodeBytes,
      network: network ?? Networks.bitcoin,
    );
  }

  /// Master node: `I = HMAC-SHA512("Bitcoin seed", seed)`, `k = IL`, `c = IR`.
  factory BIP32.fromSeed(List<int> seed, [NetworkType? network]) {
    final seedBytes = asUint8List(seed);
    if (seedBytes.length < seedMinBytes) {
      throw ArgumentError('Seed should be at least 128 bits');
    }
    if (seedBytes.length > seedMaxBytes) {
      throw ArgumentError('Seed should be at most 512 bits');
    }
    final nw = network ?? Networks.bitcoin;
    final i = hmacSha512(
      Uint8List.fromList(utf8.encode(bitcoinSeedHmacKey)),
      seedBytes,
    );
    try {
      final il = Uint8List.sublistView(i, 0, 32);
      final ir = Uint8List.sublistView(i, 32);
      if (!ecc.isPrivate(il)) {
        throw ArgumentError('Invalid master key');
      }
      return BIP32.fromPrivateKey(il, ir, nw);
    } finally {
      zeroize(i);
    }
  }

  BIP32 _deriveWithRetry(int index) {
    var childIndex = index;
    final parentFingerprint = fingerprintInt;

    while (true) {
      final hardened = isHardenedIndex(childIndex);
      if (hardened && isNeutered()) {
        throw ArgumentError('Missing private key for hardened child key');
      }

      final data = Uint8List(37);
      Uint8List? mac;
      try {
        if (hardened) {
          data[0] = 0x00;
          data.setRange(1, 33, _privateKey!.bytes);
          data.buffer.asByteData().setUint32(33, childIndex);
        } else {
          data.setRange(0, 33, publicKey);
          data.buffer.asByteData().setUint32(33, childIndex);
        }

        mac = hmacSha512(chainCode, data);
        final il = Uint8List.sublistView(mac, 0, 32);

        // BIP32: invalid if parse256(IL) ≥ n or resulting key is zero / infinity.
        if (!ecc.isValidDerivationTweak(il)) {
          childIndex = _nextChildIndexOrThrow(childIndex);
          continue;
        }

        late BIP32 child;
        if (!isNeutered()) {
          final ki = ecc.privateAdd(_privateKey!.bytes, il);
          if (ki == null) {
            childIndex = _nextChildIndexOrThrow(childIndex);
            continue;
          }
          child = BIP32._trusted(
            privateKey: SecureBuffer.adopt(ki),
            chainCode: _chainCodeFromMac(mac),
            network: network,
            depth: depth + 1,
            index: childIndex,
            parentFingerprint: parentFingerprint,
          );
        } else {
          final ki = ecc.pointAddScalar(publicKey, il, true);
          if (ki == null) {
            childIndex = _nextChildIndexOrThrow(childIndex);
            continue;
          }
          try {
            child = BIP32._trusted(
              publicKey: ki,
              chainCode: _chainCodeFromMac(mac),
              network: network,
              depth: depth + 1,
              index: childIndex,
              parentFingerprint: parentFingerprint,
            );
          } catch (error) {
            zeroize(ki);
            rethrow;
          }
        }
        return child;
      } finally {
        zeroize(data);
        if (mac != null) zeroize(mac);
      }
    }
  }

  static int _nextChildIndexOrThrow(int childIndex) {
    if (childIndex >= uint32Max) {
      throw ArgumentError('Failed to derive a valid child key');
    }
    return childIndex + 1;
  }

  void _preflightDepth(int steps) {
    if (steps < 0) {
      throw ArgumentError('Invalid derivation steps');
    }
    if (depth + steps > maxBip32Depth) {
      throw ArgumentError('Maximum derivation depth exceeded');
    }
  }

  static Uint8List _chainCodeFromMac(Uint8List mac) {
    final chainCode = Uint8List(32);
    chainCode.setRange(0, 32, mac, 32);
    return chainCode;
  }

  Uint8List _derivePublicKeyWithRetry(int index) {
    var childIndex = index;
    while (true) {
      final hardened = isHardenedIndex(childIndex);
      if (hardened && isNeutered()) {
        throw ArgumentError('Missing private key for hardened child key');
      }

      final step = _ckdStep(
        publicKey,
        chainCode,
        childIndex,
        privateKey: _privateKey,
      );
      if (step == null) {
        childIndex = _nextChildIndexOrThrow(childIndex);
        continue;
      }
      try {
        return Uint8List.fromList(step.publicKey);
      } finally {
        zeroize(step.publicKey);
        zeroize(step.chainCode);
      }
    }
  }

  _CkdPubResult? _ckdStep(
    Uint8List parentPublicKey,
    Uint8List parentChainCode,
    int childIndex, {
    SecureBuffer? privateKey,
  }) {
    final hardened = isHardenedIndex(childIndex);
    if (hardened && privateKey == null) {
      return null;
    }

    final data = Uint8List(37);
    Uint8List? mac;
    try {
      if (hardened) {
        data[0] = 0x00;
        data.setRange(1, 33, privateKey!.bytes);
        data.buffer.asByteData().setUint32(33, childIndex);
      } else {
        data.setRange(0, 33, parentPublicKey);
        data.buffer.asByteData().setUint32(33, childIndex);
      }

      mac = hmacSha512(parentChainCode, data);
      final il = Uint8List.sublistView(mac, 0, 32);
      if (!ecc.isValidDerivationTweak(il)) {
        return null;
      }

      if (hardened) {
        final ki = ecc.privateAdd(privateKey!.bytes, il);
        if (ki == null) {
          return null;
        }
        try {
          final childPublicKey = ecc.pointFromScalar(ki, true);
          if (childPublicKey == null) {
            return null;
          }
          return _CkdPubResult(
            publicKey: childPublicKey,
            chainCode: _chainCodeFromMac(mac),
          );
        } finally {
          zeroize(ki);
        }
      }

      final childPublicKey = ecc.pointAddScalar(parentPublicKey, il, true);
      if (childPublicKey == null) {
        return null;
      }
      return _CkdPubResult(
        publicKey: childPublicKey,
        chainCode: _chainCodeFromMac(mac),
      );
    } finally {
      zeroize(data);
      if (mac != null) zeroize(mac);
    }
  }

  Uint8List _serialize() {
    final version = isNeutered() ? network.bip32.public : network.bip32.private;
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
      if (keyData[0] == 0x00 || (keyData[0] != 0x02 && keyData[0] != 0x03)) {
        throw ArgumentError('Invalid public key');
      }
      hd = BIP32.fromPublicKey(keyData, chainCode, network);
    }

    return BIP32._(
      privateKey: hd._privateKey,
      publicKey: hd._publicKey,
      chainCode: hd.chainCode,
      network: network,
      depth: depth,
      index: childIndex,
      parentFingerprint: parentFingerprint,
    );
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

class _CkdPubResult {
  _CkdPubResult({required this.publicKey, required this.chainCode});

  final Uint8List publicKey;
  final Uint8List chainCode;
}
