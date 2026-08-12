@Tags(['benchmark'])
library;

import 'dart:typed_data';

import 'package:bip32/bip32.dart';
import 'package:bip32/bip32_advanced.dart';
import 'package:flutter_test/flutter_test.dart';

import '../support/native_test_init.dart';

void main() {
  registerNativeTestHooks();

  const iterations = 100;
  final seed = Uint8List.fromList(List<int>.generate(16, (i) => i));
  final master = BIP32.fromSeed(seed);
  final xpub = master.neutered();
  final compiledPath = compileDerivationPath("m/44'/0'/0'/0/0");
  final hash = Uint8List.fromList(List<int>.filled(32, 2));

  void bench(String name, void Function() run) {
    test(name, () {
      final stopwatch = Stopwatch()..start();
      for (var i = 0; i < iterations; i++) {
        run();
      }
      stopwatch.stop();
      final microsPerOp = stopwatch.elapsedMicroseconds / iterations;
      // Benchmark output is intentionally printed for CI/profile log capture.
      // ignore: avoid_print
      print(
        '$name: ${microsPerOp.toStringAsFixed(1)} µs/op ($iterations iter)',
      );
      expect(stopwatch.elapsedMicroseconds, greaterThan(0));
    });
  }

  group('bip32 benchmarks', () {
    bench('parseDerivationPath', () {
      parseDerivationPath("m/44'/0'/0'/0/0");
    });

    bench('deriveCompiledPath (cached indices)', () {
      master.deriveCompiledPath(compiledPath);
    });

    bench('derivePath (string parse each call)', () {
      master.derivePath("m/44'/0'/0'/0/0");
    });

    bench('CKDpriv single step', () {
      final child = master.derive(0);
      child.dispose();
    });

    bench('CKDpub single step', () {
      xpub.derivePublicKey(0);
    });

    bench('fingerprint (cached)', () {
      final fingerprint = master.fingerprintInt;
      expect(fingerprint, greaterThanOrEqualTo(0));
    });

    bench('toSerializedBytes', () {
      final bytes = master.toSerializedBytes();
      zeroize(bytes);
    });

    bench('toBase58', () {
      expect(master.toBase58(), isNotEmpty);
    });

    bench('WIF encode', () {
      expect(master.toWIF(), isNotEmpty);
    });

    bench('ECDSA sign', () {
      expect(master.sign(hash), hasLength(64));
    });
  });
}
