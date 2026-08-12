import 'dart:typed_data';

import 'package:bip32/bip32.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/native_test_init.dart';

void main() {
  registerNativeTestHooks();
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

  test('WalletLayout direct derivation matches path derivation', () {
    final master = BIP32.fromSeed(
      Uint8List.fromList(List<int>.generate(16, (i) => i)),
    );
    final account = WalletLayout.deriveAccount(master, 0);
    expect(account.toBase58(), master.derivePath("m/0'").toBase58());

    final external = WalletLayout.deriveExternal(master, 0, 5);
    expect(external.toBase58(), master.derivePath("m/0'/0/5").toBase58());

    final cachedAccount = WalletLayout.accountNode(master, 0);
    final externalFromAccount = WalletLayout.deriveExternalFromAccount(
      cachedAccount,
      5,
    );
    expect(externalFromAccount.toBase58(), external.toBase58());
  });

  test('compiled path and depth preflight', () {
    final master = BIP32.fromSeed(
      Uint8List.fromList(List<int>.generate(16, (i) => i)),
    );
    final compiled = compileDerivationPath("m/0'/1");
    expect(
      master.deriveCompiledPath(compiled).toBase58(),
      master.derivePath("m/0'/1").toBase58(),
    );
    expect(
      () => master.deriveIndices(List.filled(maxBip32Depth + 1, 0)),
      throwsA(
        predicate(
          (e) =>
              e is ArgumentError &&
              e.message == 'Maximum derivation depth exceeded',
        ),
      ),
    );
  });

  test('derivePublicKey APIs match full node derivation', () {
    final master = BIP32.fromSeed(
      Uint8List.fromList(List<int>.generate(16, (i) => i)),
    );
    final account = master.deriveHardened(0).neutered();
    final child = account.derive(5);
    expect(account.derivePublicKey(5), child.publicKey);
    expect(account.derivePublicKeys([4, 5, 6]).length, 3);
    expect(
      account.derivePublicKeyPath(const [0, 5]),
      master.derivePath("m/0'/0/5").publicKey,
    );
  });

  test('tryParseDerivationPath', () {
    expect(tryParseDerivationPath("m/0'/1")?.indices, [0x80000000, 1]);
    expect(tryParseDerivationPath('not-a-path'), isNull);
    expect(tryParseDerivationPath('m/${uint32Max + 1}'), isNull);
  });

  test('path helpers', () {
    expect(isHardenedIndex(0x80000000), isTrue);
    expect(toHardenedIndex(0), 0x80000000);
    expect(fromHardenedIndex(0x80000001), 1);
    expect(parseDerivationPath("m/0'/1").indices, [0x80000000, 1]);
    expect(parseDerivationPath("m/0'/1").isAbsolute, isTrue);
  });

  test('derivation path round-trip', () {
    for (final path in ['m', 'm/', "m/0'/1"]) {
      final parsed = parseDerivationPath(path);
      expect(
        formatDerivationPath(
          parsed.indices,
          includeMasterPrefix: parsed.isAbsolute,
        ),
        path == 'm/' ? 'm' : path,
      );
    }

    final relative = parseDerivationPath("0'/1");
    expect(relative.indices, [0x80000000, 1]);
    expect(relative.isAbsolute, isFalse);
    expect(
      formatDerivationPath(relative.indices, includeMasterPrefix: false),
      "0'/1",
    );

    final relativeLong = parseDerivationPath("44'/0'/0'/0/0");
    expect(
      formatDerivationPath(
        relativeLong.indices,
        includeMasterPrefix: relativeLong.isAbsolute,
      ),
      "44'/0'/0'/0/0",
    );

    final root = parseDerivationPath('m');
    expect(root.indices, isEmpty);
    expect(root.isAbsolute, isTrue);
    expect(formatDerivationPath(root.indices), 'm');

    final master = BIP32.fromSeed(
      Uint8List.fromList(List<int>.generate(16, (i) => i)),
    );
    expect(master.derivePath('m').toBase58(), master.toBase58());
    expect(master.derivePath('m/').toBase58(), master.toBase58());
  });
}
