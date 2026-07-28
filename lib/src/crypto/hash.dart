import 'dart:typed_data';

import 'package:native_crypto/native_crypto.dart';

import '../core/secure_buffer.dart';
import 'digest.dart';

final _ripemd160 = Ripemd160();
final _hmacSha512 = HmacSha512();

/// Hash160 (SHA256 then RIPEMD160) — BIP32 key identifier and Bitcoin address payload.
Uint8List hash160(Uint8List buffer) {
  final sha = sha256.hash(buffer);
  try {
    return _ripemd160.hash(sha);
  } finally {
    zeroize(sha);
  }
}

/// HMAC-SHA512 per RFC 4231.
///
/// Used for:
/// - Master key: `I = HMAC-SHA512("Bitcoin seed", S)`
/// - Child keys: `I = HMAC-SHA512(cpar, data)` then split into `IL` | `IR`
Uint8List hmacSha512(Uint8List key, Uint8List data) =>
    _hmacSha512.compute(key: key, data: data);

/// @deprecated Use [hmacSha512].
@Deprecated('Use hmacSha512 instead')
Uint8List hmacSHA512(Uint8List key, Uint8List data) => hmacSha512(key, data);
