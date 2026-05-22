import 'dart:typed_data';

import 'package:pointycastle/api.dart' show KeyParameter;
import 'package:pointycastle/digests/ripemd160.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/macs/hmac.dart';

/// Hash160 (SHA256 then RIPEMD160) — BIP32 key identifier and Bitcoin address payload.
Uint8List hash160(Uint8List buffer) {
  final sha = SHA256Digest().process(buffer);
  return RIPEMD160Digest().process(sha);
}

/// HMAC-SHA512 per RFC 4231.
///
/// Used for:
/// - Master key: `I = HMAC-SHA512("Bitcoin seed", S)`
/// - Child keys: `I = HMAC-SHA512(cpar, data)` then split into `IL` | `IR`
Uint8List hmacSha512(Uint8List key, Uint8List data) {
  final mac = HMac(SHA512Digest(), 128)..init(KeyParameter(key));
  return mac.process(data);
}

/// @deprecated Use [hmacSha512].
@Deprecated('Use hmacSha512 instead')
Uint8List hmacSHA512(Uint8List key, Uint8List data) => hmacSha512(key, data);
