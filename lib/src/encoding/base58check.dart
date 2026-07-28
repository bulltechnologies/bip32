import 'dart:typed_data';

import '../core/secure_buffer.dart';
import '../crypto/digest.dart';

const _alphabet =
    '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

final Map<String, int> _alphabetMap = {
  for (var i = 0; i < _alphabet.length; i++) _alphabet[i]: i,
};

Uint8List _sha256x2(Uint8List buffer) {
  final first = sha256.hash(buffer);
  try {
    return sha256.hash(first);
  } finally {
    zeroize(first);
  }
}

String encode(Uint8List payload) {
  final hash = _sha256x2(payload);
  try {
    final combined = Uint8List(payload.length + 4);
    combined.setRange(0, payload.length, payload);
    combined.setRange(payload.length, payload.length + 4, hash.sublist(0, 4));
    return _base58Encode(combined);
  } finally {
    zeroize(hash);
  }
}

Uint8List decode(String string) {
  final buffer = _base58Decode(string);
  try {
    return _decodeRaw(buffer);
  } finally {
    zeroize(buffer);
  }
}

Uint8List _decodeRaw(Uint8List buffer) {
  if (buffer.length < 4) {
    throw ArgumentError('Invalid checksum');
  }
  final payload = buffer.sublist(0, buffer.length - 4);
  final checksum = buffer.sublist(buffer.length - 4);
  final expected = _sha256x2(Uint8List.fromList(payload));
  try {
    if (checksum[0] != expected[0] ||
        checksum[1] != expected[1] ||
        checksum[2] != expected[2] ||
        checksum[3] != expected[3]) {
      throw ArgumentError('Invalid checksum');
    }
    return Uint8List.fromList(payload);
  } finally {
    zeroize(expected);
  }
}

String _base58Encode(Uint8List source) {
  if (source.isEmpty) {
    return '';
  }
  final digits = <int>[0];
  for (final byte in source) {
    var carry = byte;
    for (var j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry ~/= 58;
    }
    while (carry > 0) {
      digits.add(carry % 58);
      carry ~/= 58;
    }
  }
  final buffer = StringBuffer();
  for (var k = 0; k < source.length - 1 && source[k] == 0; k++) {
    buffer.write(_alphabet[0]);
  }
  for (var q = digits.length - 1; q >= 0; q--) {
    buffer.write(_alphabet[digits[q]]);
  }
  return buffer.toString();
}

Uint8List _base58Decode(String string) {
  if (string.isEmpty) {
    throw ArgumentError('Non-base58 character');
  }
  final bytes = <int>[0];
  for (var i = 0; i < string.length; i++) {
    final value = _alphabetMap[string[i]];
    if (value == null) {
      throw ArgumentError('Non-base58 character');
    }
    var carry = value;
    for (var j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.add(carry & 0xff);
      carry >>= 8;
    }
  }
  for (var k = 0; k < string.length - 1 && string[k] == _alphabet[0]; k++) {
    bytes.add(0);
  }
  return Uint8List.fromList(bytes.reversed.toList());
}
