import 'dart:typed_data';

/// Maximum [BIP32] tree depth encodable in serialization (1-byte depth field).
const int maxBip32Depth = 255;

/// Expected chain code length in bytes (BIP32 extended key).
const int chainCodeLength = 32;

/// Ensures [chainCode] is exactly 32 bytes (BIP32 serialization field).
void validateChainCode(Uint8List chainCode) {
  if (chainCode.length != chainCodeLength) {
    throw ArgumentError('Invalid chain code length');
  }
}

/// Ensures [depth] fits the BIP32 1-byte depth field (0–255).
void validateDepth(int depth) {
  if (depth < 0 || depth > maxBip32Depth) {
    throw ArgumentError('Invalid depth');
  }
}
