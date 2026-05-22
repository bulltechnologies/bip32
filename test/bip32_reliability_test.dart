import 'dart:typed_data';

import 'package:bip32/bip32.dart';
import 'package:hex/hex.dart';
import 'package:test/test.dart';

void main() {
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
}
