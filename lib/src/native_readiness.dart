import 'package:native_sig/native_sig.dart';

/// Package-level native backend initialization for BIP32 operations.
///
/// Call [ensureInitialized] once during app startup before spawning crypto
/// isolates or performing derivation/signing. BIP32 delegates curve work to
/// [native_sig] and hashing to [native_crypto].
abstract final class Bip32Native {
  /// Initializes native_sig (idempotent).
  static void ensureInitialized() => NativeSig.ensureInitialized();
}
