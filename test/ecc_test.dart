import 'dart:typed_data';

import 'package:bip32/bip32.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hex/hex.dart';
import 'package:bip32/src/crypto/ecurve.dart' as ecc;

import 'support/native_test_init.dart';

final _defichainTestnet = NetworkType(
  bip32: Bip32Type(private: 0x04358394, public: 0x043587cf),
  wif: 0xef,
);

void main() {
  registerNativeTestHooks();

  group('defichain derivation', () {
    test('seed to m/0\'/0\'/0\' private key', () {
      final hdSeed = BIP32.fromSeed(
        _hex(
          '6607599b768ce88470b3b20919f9c63bff663e2f1ec3e3072d22fd9da3847784'
          'c361d5accc3b411019f5c81dd3e4ccf9fd1fddb232bfc9bfe23864e2e6ee793f',
        ),
        _defichainTestnet,
      );
      final xMasterPriv = BIP32.fromSeed(hdSeed.privateKey!, _defichainTestnet);
      final leaf = xMasterPriv.derivePath("m/0'/0'/0'");
      expect(
        HEX.encode(leaf.privateKey!),
        '55b18e96ce3964ef2c81ad69249eca6d42682c11fbe525df6671fcbf0c2be902',
      );
    });
  });

  group('ecdsa', () {
    const priv =
        '55b18e96ce3964ef2c81ad69249eca6d42682c11fbe525df6671fcbf0c2be902';
    final msg = _hex(
      'b11d3d5e4ae12b89d5e3872ccc7d1f96d29b0ab888b67dccf1be5164b811cdbe',
    );

    test('sign and verify round-trip', () {
      final signature = ecc.sign(msg, _hex(priv));
      expect(signature.length, 64);
      final pub = ecc.pointFromScalar(_hex(priv), true)!;
      expect(ecc.verify(msg, pub, signature), isTrue);
      expect(ecc.verify(msg, pub, Uint8List(64)), isFalse);
    });
  });
}

Uint8List _hex(String h) => Uint8List.fromList(HEX.decode(h));
