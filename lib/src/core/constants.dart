/// BIP32 protocol constants.
///
/// Reference: [BIP32 specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).
library;

/// Hardened child index flag: CKD uses private parent data when `i ≥ 2³¹`.
const int hardenedIndexFlag = 0x80000000;

/// Largest normal (non-hardened) child index: `2³¹ − 1`.
const int uint31Max = 2147483647;

/// Largest child index: `2³² − 1`.
const int uint32Max = 4294967295;

/// Byte length of a serialized extended key (before Base58Check).
const int extendedKeyByteLength = 78;

/// HMAC-SHA512 key for master extended key generation (`I = HMAC-SHA512(Key, S)`).
const String bitcoinSeedHmacKey = 'Bitcoin seed';

/// Minimum seed length (128 bits). BIP32 allows 128–512 bit seeds.
const int seedMinBytes = 16;

/// Maximum seed length (512 bits).
const int seedMaxBytes = 64;

/// @deprecated Use [hardenedIndexFlag].
@Deprecated('Use hardenedIndexFlag instead')
const int HIGHEST_BIT = hardenedIndexFlag;

/// @deprecated Use [uint31Max].
@Deprecated('Use uint31Max instead')
const int UINT31_MAX = uint31Max;

/// @deprecated Use [uint32Max].
@Deprecated('Use uint32Max instead')
const int UINT32_MAX = uint32Max;
