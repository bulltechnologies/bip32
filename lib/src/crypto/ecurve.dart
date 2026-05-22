/// secp256k1 primitives for BIP32: point/scalar validation, CKD math, ECDSA.
///
/// Curve: SECG secp256k1 (same as Bitcoin). Group order *n* bounds all private
/// scalars and BIP32 tweaks `IL`.
library;

import 'dart:typed_data';

import 'package:hex/hex.dart';
import 'package:pointycastle/api.dart'
    show PrivateKeyParameter, PublicKeyParameter;
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/ecc/api.dart'
    show ECPrivateKey, ECPublicKey, ECSignature, ECPoint;
import 'package:pointycastle/ecc/curves/secp256k1.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';

final Uint8List _zero32 = Uint8List(32);
final Uint8List _ecGroupOrder = Uint8List.fromList(
  HEX.decode(
    'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
  ),
);
final Uint8List _ecFieldPrime = Uint8List.fromList(
  HEX.decode(
    'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
  ),
);

final ECCurve_secp256k1 secp256k1 = ECCurve_secp256k1();
final BigInt curveOrder = secp256k1.n;
final ECPoint curveGenerator = secp256k1.G;
final BigInt halfCurveOrder = curveOrder >> 1;

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
    decodePoint(p);
  } catch (_) {
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
  final scalar = bufferToBigInt(d);
  final point = curveGenerator * scalar;
  if (point == null || point.isInfinity) return null;
  return encodePoint(point, compressed);
}

/// Child public key: point(parse256(IL)) + Kpar (BIP32 CKDpub).
Uint8List? pointAddScalar(Uint8List p, Uint8List tweak, bool compressed) {
  if (!isPoint(p)) throw ArgumentError(throwBadPoint);
  if (!isOrderScalar(tweak)) throw ArgumentError(throwBadTweak);
  final useCompressed = assumeCompression(compressed, p);
  final parent = decodePoint(p);
  if (_compare(tweak, _zero32) == 0) {
    return encodePoint(parent, useCompressed);
  }
  final tweakScalar = bufferToBigInt(tweak);
  final tweakPoint = curveGenerator * tweakScalar;
  if (tweakPoint == null) return null;
  final sum = parent! + tweakPoint;
  if (sum == null || sum.isInfinity) return null;
  return encodePoint(sum, useCompressed);
}

/// Child private key: parse256(IL) + kpar (mod n).
Uint8List? privateAdd(Uint8List d, Uint8List tweak) {
  if (!isPrivate(d)) throw ArgumentError(throwBadPrivate);
  if (!isOrderScalar(tweak)) throw ArgumentError(throwBadTweak);
  final dd = bufferToBigInt(d);
  final tt = bufferToBigInt(tweak);
  var dt = bigIntTo32Bytes((dd + tt) % curveOrder);
  if (!isPrivate(dt)) return null;
  return dt;
}

/// ECDSA sign with low-S normalization (BIP62-style).
Uint8List sign(Uint8List hash, Uint8List privateKey) {
  if (!isScalar(hash)) throw ArgumentError(throwBadHash);
  if (!isPrivate(privateKey)) throw ArgumentError(throwBadPrivate);
  final sig = _deterministicGenerateK(hash, privateKey);
  final buffer = Uint8List(64);
  buffer.setRange(0, 32, _encodeBigIntTo32(sig.r));
  final s = sig.s.compareTo(halfCurveOrder) > 0 ? curveOrder - sig.s : sig.s;
  buffer.setRange(32, 64, _encodeBigIntTo32(s));
  return buffer;
}

bool verify(Uint8List hash, Uint8List publicKey, Uint8List signature) {
  if (!isScalar(hash)) throw ArgumentError(throwBadHash);
  if (!isPoint(publicKey)) throw ArgumentError(throwBadPoint);
  if (!isSignature(signature)) throw ArgumentError(throwBadSignature);

  final q = decodePoint(publicKey);
  final r = bufferToBigInt(signature.sublist(0, 32));
  final s = bufferToBigInt(signature.sublist(32, 64));
  final signer = ECDSASigner(null, HMac(SHA256Digest(), 64));
  signer.init(false, PublicKeyParameter(ECPublicKey(q, secp256k1)));
  return signer.verifySignature(hash, ECSignature(r, s));
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

Uint8List _encodeBigIntTo32(BigInt number) => bigIntTo32Bytes(number);

ECPoint? decodePoint(Uint8List encoded) =>
    secp256k1.curve.decodePoint(encoded);

Uint8List encodePoint(ECPoint? point, bool compressed) =>
    point!.getEncoded(compressed);

ECSignature _deterministicGenerateK(Uint8List hash, Uint8List privateKey) {
  final signer = ECDSASigner(null, HMac(SHA256Digest(), 64));
  signer.init(
    true,
    PrivateKeyParameter(
      ECPrivateKey(bufferToBigInt(privateKey), secp256k1),
    ),
  );
  return signer.generateSignature(hash) as ECSignature;
}

int _compare(Uint8List a, Uint8List b) {
  final aa = bufferToBigInt(a);
  final bb = bufferToBigInt(b);
  if (aa == bb) return 0;
  return aa > bb ? 1 : -1;
}

/// @deprecated Use [bufferToBigInt].
@Deprecated('Use bufferToBigInt instead')
BigInt fromBuffer(Uint8List d) => bufferToBigInt(d);

/// @deprecated Use [bigIntTo32Bytes].
@Deprecated('Use bigIntTo32Bytes instead')
Uint8List toBuffer(BigInt d) => bigIntTo32Bytes(d);
