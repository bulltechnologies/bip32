import 'dart:typed_data';

import 'package:bip32/bip32.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/native_test_init.dart';

void main() {
  registerNativeTestHooks();

  test('fromPrivateKey rejects wrong chain code length', () {
    expect(
      () => BIP32.fromPrivateKey(Uint8List(32), Uint8List(16)),
      throwsA(
        predicate(
          (e) =>
              e is ArgumentError && e.message == 'Invalid chain code length',
        ),
      ),
    );
  });

  test('fromPublicKey rejects uncompressed keys on import', () {
    final uncompressed = Uint8List(65);
    uncompressed[0] = 0x04;
    expect(
      () => BIP32.fromPublicKey(uncompressed, Uint8List(32)),
      throwsA(
        predicate(
          (e) =>
              e is ArgumentError &&
              e.message == 'Expected compressed public key',
        ),
      ),
    );
  });

  test('parseDerivationPath rejects out-of-range segment', () {
    expect(
      () => parseDerivationPath('m/${uint32Max + 1}'),
      throwsA(
        predicate(
          (e) => e is ArgumentError && e.message == 'Expected UInt32',
        ),
      ),
    );
  });

  test('WIF round-trip preserves private key after decode buffer wipe', () {
    final node = BIP32.fromSeed(Uint8List.fromList(List<int>.generate(16, (i) => i)));
    final wifString = node.toWIF();
    final decoded = decode(wifString);
    expect(decoded.privateKey, node.privateKey);
    expect(decoded.privateKey.every((b) => b != 0), isTrue);
    expect(decoded.compressed, isTrue);
  });
}
