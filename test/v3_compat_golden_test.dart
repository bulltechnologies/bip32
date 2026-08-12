import 'dart:typed_data';

import 'package:bip32/bip32.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hex/hex.dart';

import 'support/native_test_init.dart';
import 'support/test_assets.dart';

/// Immutable outputs pinned from bip32 3.0.0 (pointycastle + bs58check).
///
/// Any drift blocks the v4 release.
Future<void> main() async {
  TestWidgetsFlutterBinding.ensureInitialized();
  registerNativeTestHooks();

  final goldens = decodeTestAssetJson(
    await loadTestAssetJson('v3_compat_golden.json'),
  );

  group('v3 compatibility goldens', () {
    test('master seed vector 1', () {
      _assertNode(
        BIP32.fromSeed(_hex(goldens['seed_vector_1']['seed'] as String)),
        goldens['seed_vector_1'] as Map<String, dynamic>,
      );
    });

    test('deterministic ECDSA signature', () {
      final case_ = goldens['ecdsa'] as Map<String, dynamic>;
      final seed = _hex(case_['seed'] as String);
      final hash = _hex(case_['hash'] as String);
      final node = BIP32.fromSeed(seed);
      expect(HEX.encode(node.sign(hash)), case_['signature']);
      expect(node.verify(hash, _hex(case_['signature'] as String)), isTrue);
    });

    test('high-S signature still verifies (legacy compat)', () {
      final case_ = goldens['high_s_verify'] as Map<String, dynamic>;
      final seed = _hex(case_['seed'] as String);
      final hash = _hex(case_['hash'] as String);
      final highS = _hex(case_['high_s_signature'] as String);
      final node = BIP32.fromSeed(seed);
      expect(node.verify(hash, highS), isTrue);
      expect(HEX.encode(node.sign(hash)), case_['low_s_signature']);
    });

    test('leading-zero private key path', () {
      final case_ = goldens['leading_zero'] as Map<String, dynamic>;
      final node = BIP32.fromBase58(case_['xprv'] as String);
      expect(HEX.encode(node.privateKey!), case_['private_key']);
      final child = node.derivePath(case_['path'] as String);
      expect(HEX.encode(child.privateKey!), case_['child_private_key']);
    });

    for (final entry in (goldens['official_paths'] as List<dynamic>)) {
      final map = entry as Map<String, dynamic>;
      test('official ${map['label']}', () {
        final node = BIP32
            .fromSeed(_hex(map['seed'] as String))
            .derivePath(map['path'] as String);
        _assertNode(node, map);
      });
    }
  });
}

void _assertNode(BIP32 node, Map<String, dynamic> expected) {
  if (expected.containsKey('chain_code')) {
    expect(HEX.encode(node.chainCode), expected['chain_code']);
  }
  if (expected.containsKey('public_key')) {
    expect(HEX.encode(node.publicKey), expected['public_key']);
  }
  if (expected.containsKey('private_key')) {
    expect(HEX.encode(node.privateKey!), expected['private_key']);
    expect(node.toWIF(), expected['wif']);
  }
  if (expected.containsKey('xprv')) {
    expect(node.toBase58(), expected['xprv']);
  }
  if (expected.containsKey('xpub')) {
    expect(node.neutered().toBase58(), expected['xpub']);
  }
  if (expected.containsKey('identifier')) {
    expect(HEX.encode(node.identifier), expected['identifier']);
  }
  if (expected.containsKey('fingerprint')) {
    expect(HEX.encode(node.fingerprint), expected['fingerprint']);
  }
}

Uint8List _hex(String h) => Uint8List.fromList(HEX.decode(h));
