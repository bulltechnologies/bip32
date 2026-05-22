import 'extended_key.dart';
import '../core/constants.dart';

/// BIP32 **default wallet layout** path builders (advisory, not enforced).
///
/// BIP32 recommends (but does not require) splitting each hardened account `iH`
/// into:
/// - **External** chain `m/iH/0/k` — addresses shown to payers
/// - **Internal** chain `m/iH/1/k` — change and internal outputs
///
/// BIP44 and later standards embed similar ideas under their own path conventions;
/// this type only encodes the raw BIP32 layout from the spec.
abstract final class WalletLayout {
  /// Path to hardened account `i`: `m/iH` or `iH` when [fromMaster] is false.
  static String accountPath(int account, {bool fromMaster = true}) {
    _checkAccount(account);
    final segment = "${account}'";
    return fromMaster ? 'm/$segment' : segment;
  }

  /// Path to external chain address index [k] under account [account].
  static String externalPath(int account, int addressIndex,
      {bool fromMaster = true}) {
    return '${accountPath(account, fromMaster: fromMaster)}/0/$addressIndex';
  }

  /// Path to internal (change) chain index [k] under account [account].
  static String internalPath(int account, int addressIndex,
      {bool fromMaster = true}) {
    return '${accountPath(account, fromMaster: fromMaster)}/1/$addressIndex';
  }

  /// Derives the external-chain child at [addressIndex] for [account].
  static BIP32 deriveExternal(BIP32 master, int account, int addressIndex) =>
      master.derivePath(externalPath(account, addressIndex));

  /// Derives the internal-chain child at [addressIndex] for [account].
  static BIP32 deriveInternal(BIP32 master, int account, int addressIndex) =>
      master.derivePath(internalPath(account, addressIndex));

  /// Derives hardened account [account] from [master].
  static BIP32 deriveAccount(BIP32 master, int account) =>
      master.derivePath(accountPath(account));

  static void _checkAccount(int account) {
    if (account < 0 || account > uint31Max) {
      throw ArgumentError('Expected UInt31');
    }
  }
}
