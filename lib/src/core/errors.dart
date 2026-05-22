/// Typed errors for BIP32 (new code paths; legacy APIs still use [ArgumentError]).
library;

/// Base type for BIP32 failures.
class Bip32Exception implements Exception {
  Bip32Exception(this.message);

  final String message;

  @override
  String toString() => 'Bip32Exception: $message';
}

/// Base58Check decode or extended-key structure invalid.
class Bip32SerializationException extends Bip32Exception {
  Bip32SerializationException(super.message);
}

/// Path or child index invalid.
class Bip32DerivationException extends Bip32Exception {
  Bip32DerivationException(super.message);
}

/// Seed, scalar, or curve point invalid.
class Bip32KeyException extends Bip32Exception {
  Bip32KeyException(super.message);
}
