import 'dart:typed_data';

import 'package:bip32/bip32.dart';
import 'package:test/test.dart';

void main() {
  test('Networks.bitcoin matches legacy defaults', () {
    final node = BIP32.fromSeed(
      Uint8List.fromList(List<int>.generate(16, (i) => i)),
      Networks.bitcoin,
    );
    expect(node.toBase58().startsWith('xprv'), isTrue);
  });

  test('WalletLayout paths', () {
    expect(WalletLayout.accountPath(0), "m/0'");
    expect(WalletLayout.externalPath(0, 5), "m/0'/0/5");
    expect(WalletLayout.internalPath(1, 2), "m/1'/1/2");
  });

  test('path helpers', () {
    expect(isHardenedIndex(0x80000000), isTrue);
    expect(toHardenedIndex(0), 0x80000000);
    expect(fromHardenedIndex(0x80000001), 1);
    expect(parseDerivationPath("m/0'/1"), [0x80000000, 1]);
  });
}
