import 'extended_key.dart';
import 'path.dart';

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
    validateHardenedChildIndex(account);
    final segment = "$account'";
    return fromMaster ? 'm/$segment' : segment;
  }

  /// Path to external chain address index [k] under account [account].
  static String externalPath(
    int account,
    int addressIndex, {
    bool fromMaster = true,
  }) {
    return '${accountPath(account, fromMaster: fromMaster)}/0/$addressIndex';
  }

  /// Path to internal (change) chain index [k] under account [account].
  static String internalPath(
    int account,
    int addressIndex, {
    bool fromMaster = true,
  }) {
    return '${accountPath(account, fromMaster: fromMaster)}/1/$addressIndex';
  }

  /// Derives hardened account [account] from [master].
  static BIP32 deriveAccount(BIP32 master, int account) {
    validateHardenedChildIndex(account);
    return master.deriveHardened(account);
  }

  /// Same as [deriveAccount]; retained for callers that cache account nodes.
  static BIP32 accountNode(BIP32 master, int account) =>
      deriveAccount(master, account);

  /// External chain node `…/0` under [account].
  static BIP32 externalChain(BIP32 account) => account.derive(0);

  /// Internal (change) chain node `…/1` under [account].
  static BIP32 internalChain(BIP32 account) => account.derive(1);

  /// Derives the external-chain child at [addressIndex] for [account].
  static BIP32 deriveExternal(BIP32 master, int account, int addressIndex) {
    validateHardenedChildIndex(account);
    validateChildIndex(addressIndex);
    return deriveAccount(master, account).derive(0).derive(addressIndex);
  }

  /// Derives the internal-chain child at [addressIndex] for [account].
  static BIP32 deriveInternal(BIP32 master, int account, int addressIndex) {
    validateHardenedChildIndex(account);
    validateChildIndex(addressIndex);
    return deriveAccount(master, account).derive(1).derive(addressIndex);
  }

  /// Derives [addressIndex] on the external chain from cached [account].
  static BIP32 deriveExternalFromAccount(BIP32 account, int addressIndex) {
    validateChildIndex(addressIndex);
    return externalChain(account).derive(addressIndex);
  }

  /// Derives [addressIndex] on the internal chain from cached [account].
  static BIP32 deriveInternalFromAccount(BIP32 account, int addressIndex) {
    validateChildIndex(addressIndex);
    return internalChain(account).derive(addressIndex);
  }
}
