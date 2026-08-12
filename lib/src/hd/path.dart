import '../core/constants.dart';
import '../core/errors.dart';

/// Path grammar: optional `m` / `m/` prefix, segments `index` or `index'`, `/` separated.
final RegExp _bip32PathRegex = RegExp(r"^(m(\/\d+'?)*/?)?$|^(\d+'?\/)*\d+'?$");

/// Parsed BIP32 derivation path.
///
/// Root absolute paths (`m`, `m/`) use an empty [indices] list with [isAbsolute]
/// set to `true`. Relative empty paths use an empty [indices] list with
/// [isAbsolute] set to `false`.
class DerivationPath {
  const DerivationPath({required this.indices, required this.isAbsolute});

  /// Child indices to derive (empty for root / no-op paths).
  final List<int> indices;

  /// Whether the path was prefixed with `m` or `m/`.
  final bool isAbsolute;
}

/// `true` when [index] encodes a hardened child (`i ≥ 2³¹`).
bool isHardenedIndex(int index) => index >= hardenedIndexFlag;

/// Maps normal index `i` to hardened `iH = i + 2³¹` (BIP32 notation).
int toHardenedIndex(int index) {
  validateHardenedChildIndex(index);
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

/// Ensures [index] is a valid BIP32 child index (`0 … 2³²−1`).
void validateChildIndex(int index) {
  if (index > uint32Max || index < 0) {
    throw ArgumentError('Expected UInt32');
  }
}

/// Ensures [index] is a valid normal hardened index before applying `+ 2³¹`.
void validateHardenedChildIndex(int index) {
  if (index > uint31Max || index < 0) {
    throw ArgumentError('Expected UInt31');
  }
}

/// Parses [path] when valid, otherwise returns `null`.
DerivationPath? tryParseDerivationPath(String path) {
  if (!isValidDerivationPath(path)) return null;
  try {
    return parseDerivationPath(path);
  } on ArgumentError {
    return null;
  }
}

/// Compiles [path] once for repeated derivation without re-parsing.
DerivationPath compileDerivationPath(String path) => parseDerivationPath(path);

/// Parses [path] into child indices and an absolute/relative flag.
///
/// Throws [ArgumentError] with message `Expected BIP32 Path` when malformed.
DerivationPath parseDerivationPath(String path) {
  if (!isValidDerivationPath(path)) {
    throw ArgumentError('Expected BIP32 Path');
  }

  final isAbsolute = path == 'm' || path.startsWith('m/');
  if (path.isEmpty || path == 'm' || path == 'm/') {
    return DerivationPath(indices: const [], isAbsolute: isAbsolute);
  }

  var segments = path.split('/');
  if (segments.first == 'm') {
    segments = segments.sublist(1);
  }
  segments = segments.where((segment) => segment.isNotEmpty).toList();

  final indices = segments.map((segment) {
    final hardened = segment.endsWith("'");
    final raw = hardened ? segment.substring(0, segment.length - 1) : segment;
    final index = int.parse(raw);
    if (hardened) {
      return toHardenedIndex(index);
    }
    validateChildIndex(index);
    return index;
  }).toList();

  return DerivationPath(indices: indices, isAbsolute: isAbsolute);
}

/// Formats [indices] as a BIP32 path string.
String formatDerivationPath(
  List<int> indices, {
  bool includeMasterPrefix = true,
}) {
  if (indices.isEmpty) {
    return includeMasterPrefix ? 'm' : '';
  }

  final parts = indices.map((index) {
    if (isHardenedIndex(index)) {
      return "${fromHardenedIndex(index)}'";
    }
    return index.toString();
  });
  final body = parts.join('/');
  return includeMasterPrefix ? 'm/$body' : body;
}
