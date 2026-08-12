/// secp256k1 primitives for BIP32: point/scalar validation, CKD math, ECDSA.
///
/// Curve: SECG secp256k1 (same as Bitcoin). Group order *n* bounds all private
/// scalars and BIP32 tweaks `IL`.
///
/// v4 uses [native_sig] for curve operations. PointyCastle-specific types
/// (`ECPoint`, `decodePoint`, `encodePoint`, …) are no longer exported.
library;

import 'dart:typed_data';

import 'package:native_sig/native_sig.dart';

import '../core/secure_buffer.dart';

final Uint8List _zero32 = Uint8List(32);
final Uint8List _ecGroupOrder = Uint8List.fromList([
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
  0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
  0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
]);
final Uint8List _ecFieldPrime = Uint8List.fromList([
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
]);
final Uint8List _halfCurveOrderBytes = Uint8List.fromList([
  0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
  0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
]);

BigInt? _curveOrder;
BigInt? _halfCurveOrder;

/// secp256k1 group order *n*.
///
/// This compatibility value is only used by the public BigInt conversion
/// helpers and signature canonicalization. Private scalar validation and CKD
/// never convert secret bytes to [BigInt].
BigInt get curveOrder => _curveOrder ??= BigInt.parse(
  'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
  radix: 16,
);

/// Half of [curveOrder] (BIP62 low-S bound).
BigInt get halfCurveOrder => _halfCurveOrder ??= curveOrder >> 1;

const String throwBadPrivate = 'Expected Private';
const String throwBadPoint = 'Expected Point';
const String throwBadTweak = 'Expected Tweak';
const String throwBadHash = 'Expected Hash';
const String throwBadSignature = 'Expected Signature';

/// Whether [x] is a valid private scalar: 32 bytes, 0 < x < n.
bool isPrivate(Uint8List x) {
  if (!isScalar(x)) return false;
  return _compare(x, _zero32) > 0 && _compare(x, _ecGroupOrder) < 0;
}

/// Whether [p] is a valid secp256k1 public key (compressed or uncompressed SEC1).
bool isPoint(Uint8List p) {
  if (p.length < 33) return false;
  final prefix = p[0];
  final xCoord = p.sublist(1, 33);

  if (_compare(xCoord, _zero32) == 0) return false;
  if (_compare(xCoord, _ecFieldPrime) == 1) return false;
  try {
    if (!Secp256k1.isValidPublicKey(p)) return false;
  } on NativeSigException {
    return false;
  }
  if ((prefix == 0x02 || prefix == 0x03) && p.length == 33) return true;
  final yCoord = p.sublist(33);
  if (_compare(yCoord, _zero32) == 0) return false;
  if (_compare(yCoord, _ecFieldPrime) == 1) return false;
  if (prefix == 0x04 && p.length == 65) return true;
  return false;
}

bool isScalar(Uint8List x) => x.length == 32;

/// Whether [x] is a 32-byte scalar strictly less than curve order n.
bool isOrderScalar(Uint8List x) {
  if (!isScalar(x)) return false;
  return _compare(x, _ecGroupOrder) < 0;
}

/// Whether [tweak] is usable as BIP32 `IL` (parse256(IL) < n).
///
/// Child derivation skips to the next index when this is false. Note: `IL = 0`
/// is valid per the spec but is treated as invalid here (negligible probability),
/// consistent with common implementations.
bool isValidDerivationTweak(Uint8List tweak) {
  if (!isScalar(tweak)) return false;
  return _compare(tweak, _ecGroupOrder) < 0 && _compare(tweak, _zero32) > 0;
}

bool isSignature(Uint8List value) {
  if (value.length != 64) return false;
  final r = value.sublist(0, 32);
  final s = value.sublist(32, 64);
  return _compare(r, _ecGroupOrder) < 0 && _compare(s, _ecGroupOrder) < 0;
}

bool _isPointCompressed(Uint8List p) => p[0] != 0x04;

bool assumeCompression(bool? value, Uint8List? pubkey) {
  if (value == null && pubkey != null) return _isPointCompressed(pubkey);
  if (value == null) return true;
  return value;
}

/// serP(k): compressed SEC1 encoding of scalar [d].
Uint8List? pointFromScalar(Uint8List d, bool compressed) {
  if (!isPrivate(d)) throw ArgumentError(throwBadPrivate);
  return Secp256k1.publicKeyFromSecret(d, compressed: compressed);
}

/// Child public key: point(parse256(IL)) + Kpar (BIP32 CKDpub).
Uint8List? pointAddScalar(Uint8List p, Uint8List tweak, bool compressed) {
  if (!isPoint(p)) throw ArgumentError(throwBadPoint);
  if (!isOrderScalar(tweak)) throw ArgumentError(throwBadTweak);
  final useCompressed = assumeCompression(compressed, p);
  try {
    return Secp256k1.publicKeyTweakAdd(
      publicKey: p,
      tweak: tweak,
      compressed: useCompressed,
    );
  } on TweakInfinityException {
    return null;
  } on InvalidTweakException {
    throw ArgumentError(throwBadTweak);
  } on InvalidPublicKeyException {
    throw ArgumentError(throwBadPoint);
  }
}

/// Child private key: parse256(IL) + kpar (mod n).
Uint8List? privateAdd(Uint8List d, Uint8List tweak) {
  if (!isPrivate(d)) throw ArgumentError(throwBadPrivate);
  if (!isOrderScalar(tweak)) throw ArgumentError(throwBadTweak);
  try {
    final child = Secp256k1.privateKeyTweakAdd(secretKey: d, tweak: tweak);
    if (!isPrivate(child)) {
      zeroize(child);
      return null;
    }
    return child;
  } on TweakInfinityException {
    return null;
  } on InvalidTweakException {
    throw ArgumentError(throwBadTweak);
  } on InvalidSecretKeyException {
    throw ArgumentError(throwBadPrivate);
  }
}

/// ECDSA sign with low-S normalization (BIP62-style).
Uint8List sign(Uint8List hash, Uint8List privateKey) {
  if (!isScalar(hash)) throw ArgumentError(throwBadHash);
  if (!isPrivate(privateKey)) throw ArgumentError(throwBadPrivate);
  try {
    return Secp256k1.ecdsaSign(messageHash: hash, secretKey: privateKey);
  } on InvalidSecretKeyException {
    throw ArgumentError(throwBadPrivate);
  }
}

bool verify(Uint8List hash, Uint8List publicKey, Uint8List signature) {
  if (!isScalar(hash)) throw ArgumentError(throwBadHash);
  if (!isPoint(publicKey)) throw ArgumentError(throwBadPoint);
  if (!isSignature(signature)) throw ArgumentError(throwBadSignature);

  final verifySig = _canonicalizeSignatureForVerify(signature);
  try {
    return Secp256k1.ecdsaVerify(
      signature: verifySig,
      messageHash: hash,
      publicKey: publicKey,
    );
  } on InvalidPublicKeyException {
    throw ArgumentError(throwBadPoint);
  } on InvalidSignatureException {
    throw ArgumentError(throwBadSignature);
  } finally {
    if (!identical(verifySig, signature)) {
      zeroize(verifySig);
    }
  }
}

/// Maps legacy high-S signatures to low-S for verification (BIP32 compat).
Uint8List _canonicalizeSignatureForVerify(Uint8List signature) {
  final s = signature.sublist(32, 64);
  if (_compare(s, _halfCurveOrderBytes) <= 0) {
    return signature;
  }
  final canonical = Uint8List.fromList(signature);
  final lowS = curveOrder - bufferToBigInt(s);
  canonical.setRange(32, 64, bigIntTo32Bytes(lowS));
  return canonical;
}

BigInt bufferToBigInt(List<int> bytes) {
  var result = BigInt.zero;
  for (var i = 0; i < bytes.length; i++) {
    result += BigInt.from(bytes[bytes.length - i - 1]) << (8 * i);
  }
  return result;
}

Uint8List bigIntTo32Bytes(BigInt number) {
  final encoded = _encodeBigInt(number);
  if (encoded.length == 32) return encoded;
  if (encoded.length > 32) {
    return encoded.sublist(encoded.length - 32);
  }
  final padded = Uint8List(32);
  padded.setRange(32 - encoded.length, 32, encoded);
  return padded;
}

Uint8List _encodeBigInt(BigInt number) {
  if (number == BigInt.zero) return Uint8List(1);

  var needsPaddingByte = 0;
  var rawSize = (number.bitLength + 7) >> 3;
  final highByte = (number >> ((rawSize - 1) * 8)) & BigInt.from(0xff);
  if (highByte >= BigInt.from(128)) {
    needsPaddingByte = 1;
  }
  if (rawSize < 32) needsPaddingByte = 1;

  final size = rawSize < 32 ? rawSize + needsPaddingByte : rawSize;
  final result = Uint8List(size);
  var value = number;
  for (var i = 0; i < size; i++) {
    result[size - i - 1] = (value & BigInt.from(0xff)).toInt();
    value >>= 8;
  }
  return result;
}

int _compare(Uint8List a, Uint8List b) {
  if (a.length != b.length) {
    return a.length < b.length ? -1 : 1;
  }

  // Compare fixed-width big-endian byte strings without materializing either
  // operand as a managed BigInt. The arithmetic keeps the result stable after
  // the first differing byte, so private scalar validation does not create
  // uncontrolled numeric copies.
  var greater = 0;
  var less = 0;
  for (var i = 0; i < a.length; i++) {
    final undecided = (greater | less) ^ 1;
    greater |= undecided & (((b[i] - a[i]) >> 8) & 1);
    less |= undecided & (((a[i] - b[i]) >> 8) & 1);
  }
  return greater - less;
}

/// @deprecated Use [bufferToBigInt].
@Deprecated('Use bufferToBigInt instead')
BigInt fromBuffer(Uint8List d) => bufferToBigInt(d);

/// @deprecated Use [bigIntTo32Bytes].
@Deprecated('Use bigIntTo32Bytes instead')
Uint8List toBuffer(BigInt d) => bigIntTo32Bytes(d);
