import 'dart:typed_data';

import '../core/secure_buffer.dart';
import '../encoding/base58check.dart' as base58check;

/// Wallet Import Format (WIF) payload — not part of BIP32, but commonly used
/// alongside derived private scalars.
class WIF {
  WIF({
    required this.version,
    required this.privateKey,
    required this.compressed,
  });

  final int version;
  final Uint8List privateKey;
  final bool compressed;
}

/// Decodes raw WIF bytes (33 or 34 bytes).
WIF decodeRaw(Uint8List buffer, [int? version]) {
  if (version != null && buffer[0] != version) {
    throw ArgumentError('Invalid network version');
  }
  if (buffer.length == 33) {
    return WIF(
      version: buffer[0],
      privateKey: Uint8List.fromList(buffer.sublist(1, 33)),
      compressed: false,
    );
  }
  if (buffer.length != 34) {
    throw ArgumentError('Invalid WIF length');
  }
  if (buffer[33] != 0x01) {
    throw ArgumentError('Invalid compression flag');
  }
  return WIF(
    version: buffer[0],
    privateKey: Uint8List.fromList(buffer.sublist(1, 33)),
    compressed: true,
  );
}

Uint8List encodeRaw(int version, Uint8List privateKey, bool compressed) {
  if (privateKey.length != 32) {
    throw ArgumentError('Invalid privateKey length');
  }
  final result = Uint8List(compressed ? 34 : 33);
  result.buffer.asByteData().setUint8(0, version);
  result.setRange(1, 33, privateKey);
  if (compressed) {
    result[33] = 0x01;
  }
  return result;
}

WIF decode(String string, [int? version]) {
  final decoded = base58check.decode(string);
  try {
    return decodeRaw(decoded, version);
  } finally {
    zeroize(decoded);
  }
}

String encode(WIF wif) {
  final raw = encodeRaw(wif.version, wif.privateKey, wif.compressed);
  try {
    return base58check.encode(raw);
  } finally {
    zeroize(raw);
  }
}
