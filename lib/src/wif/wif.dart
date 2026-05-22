import 'dart:typed_data';

import 'package:bs58check/bs58check.dart' as bs58check;

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
      privateKey: buffer.sublist(1, 33),
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
    privateKey: buffer.sublist(1, 33),
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

WIF decode(String string, [int? version]) =>
    decodeRaw(bs58check.decode(string), version);

String encode(WIF wif) =>
    bs58check.encode(encodeRaw(wif.version, wif.privateKey, wif.compressed));
