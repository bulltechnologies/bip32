/// Network-specific version bytes for extended keys and WIF.
library;

/// Four-byte big-endian version prefix for serialized extended keys.
class Bip32Version {
  const Bip32Version({required this.public, required this.private});

  /// Extended public key version (e.g. mainnet `0x0488b21e` → `xpub…`).
  final int public;

  /// Extended private key version (e.g. mainnet `0x0488ade4` → `xprv…`).
  final int private;
}

/// @deprecated Use [Bip32Version].
@Deprecated('Use Bip32Version instead')
typedef Bip32Type = Bip32Version;

/// Parameters for Base58Check extended keys and WIF on a given chain.
class NetworkType {
  NetworkType({required this.wif, required this.bip32});

  /// WIF version byte.
  final int wif;

  /// Extended key version bytes.
  final Bip32Version bip32;

  /// @deprecated Use [bip32].
  @Deprecated('Use bip32 instead')
  Bip32Version get bip32Type => bip32;
}

/// Common [NetworkType] presets.
abstract final class Networks {
  /// Bitcoin mainnet: `xpub` / `xprv`, WIF `0x80`.
  static final NetworkType bitcoin = NetworkType(
    wif: 0x80,
    bip32: const Bip32Version(public: 0x0488b21e, private: 0x0488ade4),
  );

  /// Bitcoin testnet / regtest: `tpub` / `tprv`, WIF `0xef`.
  static final NetworkType bitcoinTestnet = NetworkType(
    wif: 0xef,
    bip32: const Bip32Version(public: 0x043587cf, private: 0x04358394),
  );

  /// Litecoin mainnet (legacy version bytes used in upstream fixtures).
  static final NetworkType litecoin = NetworkType(
    wif: 0xb0,
    bip32: const Bip32Version(public: 0x019da462, private: 0x019d9cfe),
  );
}
