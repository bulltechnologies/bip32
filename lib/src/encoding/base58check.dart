import 'dart:typed_data';

import '../core/constants.dart';
import '../core/secure_buffer.dart';
import '../crypto/digest.dart';

const _alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

const int _alphabetLength = 58;

final List<int> _alphabetIndices = () {
  final indices = List<int>.filled(128, -1);
  for (var i = 0; i < _alphabet.length; i++) {
    indices[_alphabet.codeUnitAt(i)] = i;
  }
  return indices;
}();

Uint8List _sha256x2(Uint8List buffer) {
  final first = sha256.hash(buffer);
  try {
    return sha256.hash(first);
  } finally {
    zeroize(first);
  }
}

/// Appends the Base58Check checksum to [payload] without encoding.
Uint8List appendChecksum(Uint8List payload) {
  final hash = _sha256x2(payload);
  try {
    final frame = Uint8List(payload.length + extendedKeyChecksumLength);
    frame.setRange(0, payload.length, payload);
    frame.setRange(payload.length, frame.length, hash, 0);
    return frame;
  } finally {
    zeroize(hash);
  }
}

/// Verifies the checksum on [frame] and returns the payload bytes.
Uint8List verifyAndStripChecksum(Uint8List frame) {
  if (frame.length < extendedKeyChecksumLength) {
    throw ArgumentError('Invalid checksum');
  }
  final payloadLength = frame.length - extendedKeyChecksumLength;
  final payloadView = Uint8List.sublistView(frame, 0, payloadLength);
  final expected = _sha256x2(payloadView);
  try {
    final checksumOffset = payloadLength;
    if (frame[checksumOffset] != expected[0] ||
        frame[checksumOffset + 1] != expected[1] ||
        frame[checksumOffset + 2] != expected[2] ||
        frame[checksumOffset + 3] != expected[3]) {
      throw ArgumentError('Invalid checksum');
    }
    return Uint8List.fromList(payloadView);
  } finally {
    zeroize(expected);
  }
}

String encode(Uint8List payload) {
  final frame = appendChecksum(payload);
  try {
    return _base58Encode(frame);
  } finally {
    zeroize(frame);
  }
}

Uint8List decode(String string) {
  final buffer = _base58Decode(string);
  try {
    return verifyAndStripChecksum(buffer);
  } finally {
    zeroize(buffer);
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
      digits[j] = carry % _alphabetLength;
      carry ~/= _alphabetLength;
    }
    while (carry > 0) {
      digits.add(carry % _alphabetLength);
      carry ~/= _alphabetLength;
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

  var leadingZeros = 0;
  while (leadingZeros < string.length && string[leadingZeros] == _alphabet[0]) {
    leadingZeros++;
  }

  final bytes = <int>[0];
  for (var i = leadingZeros; i < string.length; i++) {
    final codeUnit = string.codeUnitAt(i);
    if (codeUnit >= _alphabetIndices.length) {
      throw ArgumentError('Non-base58 character');
    }
    final value = _alphabetIndices[codeUnit];
    if (value < 0) {
      throw ArgumentError('Non-base58 character');
    }

    var carry = value;
    for (var j = 0; j < bytes.length; j++) {
      carry += bytes[j] * _alphabetLength;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.add(carry & 0xff);
      carry >>= 8;
    }
  }

  final totalLength = bytes.length + leadingZeros;
  final result = Uint8List(totalLength);
  for (var i = 0; i < bytes.length; i++) {
    result[totalLength - 1 - i] = bytes[i];
  }
  return result;
}
