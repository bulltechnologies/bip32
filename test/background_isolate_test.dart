import 'dart:isolate';
import 'dart:typed_data';

import 'package:bip32/bip32.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:native_sig/native_sig.dart';

void main() {
  test('full BIP32 workflow in background isolate', () async {
    final result = await Isolate.run(_deriveInIsolate);
    expect(result, 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8');
  });
}

String _deriveInIsolate() {
  NativeSig.ensureInitialized();
  final seed = Uint8List.fromList([
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  ]);
  final master = BIP32.fromSeed(seed);
  final xpub = master.neutered().toBase58();
  final child = master.derivePath("m/0'/1/2'");
  final hash = Uint8List.fromList(List<int>.filled(32, 2));
  final sig = child.sign(hash);
  if (sig.length != 64 || !child.verify(hash, sig)) {
    throw StateError('background isolate BIP32 workflow failed');
  }
  master.dispose();
  child.dispose();
  return xpub;
}
