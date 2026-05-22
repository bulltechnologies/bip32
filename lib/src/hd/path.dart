import '../core/constants.dart';
import '../core/errors.dart';

/// Path grammar: optional `m/` prefix, segments `index` or `index'`, `/` separated.
final RegExp _bip32PathRegex = RegExp(r"^(m\/)?(\d+'?\/)*\d+'?$");

/// `true` when [index] encodes a hardened child (`i ≥ 2³¹`).
bool isHardenedIndex(int index) => index >= hardenedIndexFlag;

/// Maps normal index `i` to hardened `iH = i + 2³¹` (BIP32 notation).
int toHardenedIndex(int index) {
  if (index < 0 || index > uint31Max) {
    throw ArgumentError('Expected UInt31');
  }
  return index + hardenedIndexFlag;
}

/// Returns `i` from hardened index `iH`.
int fromHardenedIndex(int hardenedIndex) {
  if (!isHardenedIndex(hardenedIndex)) {
    throw Bip32DerivationException('Index is not hardened');
  }
  return hardenedIndex - hardenedIndexFlag;
}

/// Whether [path] matches BIP32 path syntax (does not prove indices are in range).
bool isValidDerivationPath(String path) => _bip32PathRegex.hasMatch(path);

/// Parses [path] into uint32 child indices (hardened indices include `0x80000000`).
///
/// Throws [ArgumentError] with message `Expected BIP32 Path` when malformed.
List<int> parseDerivationPath(String path) {
  if (!isValidDerivationPath(path)) {
    throw ArgumentError('Expected BIP32 Path');
  }
  var segments = path.split('/');
  if (segments.first == 'm') {
    segments = segments.sublist(1);
  }
  return segments.map((segment) {
    final hardened = segment.endsWith("'");
    final raw = hardened ? segment.substring(0, segment.length - 1) : segment;
    final index = int.parse(raw);
    if (hardened) {
      return toHardenedIndex(index);
    }
    if (index < 0 || index > uint32Max) {
      throw ArgumentError('Expected UInt32');
    }
    return index;
  }).toList();
}

/// Formats [indices] as a BIP32 path string.
String formatDerivationPath(
  List<int> indices, {
  bool includeMasterPrefix = true,
}) {
  final parts = indices.map((index) {
    if (isHardenedIndex(index)) {
      return "${fromHardenedIndex(index)}'";
    }
    return index.toString();
  });
  final body = parts.join('/');
  return includeMasterPrefix ? 'm/$body' : body;
}
