import 'dart:typed_data';

import 'package:bip32/bip32.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/native_test_init.dart';

void main() {
  registerNativeTestHooks();

  BIP32 master() {
    final node = BIP32.fromSeed(List<int>.generate(16, (index) => index));
    addTearDown(node.dispose);
    return node;
  }

  group('intermediate ownership', () {
    for (final length in [0, 1, 2, 3]) {
      test('disposes only intermediates on a $length-step path', () {
        final root = master();
        final nodes = <BIP32>[];
        final secrets = <Uint8List>[];
        final chainCodes = <Uint8List>[];
        final leaf = root.deriveIndices(
          List<int>.generate(length, (index) => index),
          disposeIntermediates: true,
          onStep: (node, _) {
            expect(node.isDisposed, isFalse);
            nodes.add(node);
            secrets.add(node.privateKey!);
            chainCodes.add(node.chainCode);
          },
        );
        addTearDown(leaf.dispose);

        expect(root.isDisposed, isFalse);
        expect(leaf.isDisposed, isFalse);
        expect(leaf.hasPrivateKey, isTrue);
        for (var index = 0; index < nodes.length - 1; index++) {
          expect(nodes[index].isDisposed, isTrue);
          expect(secrets[index], everyElement(0));
          expect(chainCodes[index], everyElement(0));
        }
        if (length == 0) expect(leaf, same(root));
      });
    }

    for (final failingStep in [0, 1, 2]) {
      test('cleans up when callback $failingStep fails', () {
        final root = master();
        final nodes = <BIP32>[];
        final secrets = <Uint8List>[];
        final failure = StateError('callback failed');
        expect(
          () => root.deriveIndices(
            const [0, 1, 2],
            disposeIntermediates: true,
            onStep: (node, step) {
              nodes.add(node);
              secrets.add(node.privateKey!);
              if (step == failingStep) throw failure;
            },
          ),
          throwsA(same(failure)),
        );
        expect(root.isDisposed, isFalse);
        expect(
          nodes,
          everyElement(predicate<BIP32>((node) => node.isDisposed)),
        );
        for (final secret in secrets) {
          expect(secret, everyElement(0));
        }
      });
    }

    test('cleans up after a later derivation fails', () {
      final root = master();
      late BIP32 first;
      late Uint8List secret;
      expect(
        () => root.deriveIndices(
          const [0, -1],
          disposeIntermediates: true,
          onStep: (node, _) {
            first = node;
            secret = node.privateKey!;
          },
        ),
        throwsArgumentError,
      );
      expect(first.isDisposed, isTrue);
      expect(secret, everyElement(0));
      expect(root.isDisposed, isFalse);
    });

    test(
      'default ownership preserves captured nodes on success and failure',
      () {
        final root = master();
        final nodes = <BIP32>[];
        void capture(BIP32 node, int _) {
          nodes.add(node);
          addTearDown(node.dispose);
        }

        root.deriveIndices(const [0, 1, 2], onStep: capture);
        expect(
          () => root.deriveIndices(const [0, -1], onStep: capture),
          throwsArgumentError,
        );
        final failure = StateError('callback failed');
        expect(
          () => root.deriveIndices(
            const [0],
            onStep: (node, step) {
              capture(node, step);
              throw failure;
            },
          ),
          throwsA(same(failure)),
        );
        expect(nodes.length, 5);
        for (final node in nodes) {
          expect(node.hasPrivateKey, isTrue);
          expect(node.isDisposed, isFalse);
        }
      },
    );

    test('watch-only derivation disposes owned public intermediates', () {
      final root = master().neutered();
      addTearDown(root.dispose);
      final nodes = <BIP32>[];
      final publicKeys = <Uint8List>[];
      final leaf = root.deriveIndices(
        const [0, 1],
        disposeIntermediates: true,
        onStep: (node, _) {
          nodes.add(node);
          publicKeys.add(node.publicKey);
        },
      );
      addTearDown(leaf.dispose);
      expect(root.isDisposed, isFalse);
      expect(nodes.first.isDisposed, isTrue);
      expect(publicKeys.first, everyElement(0));
      expect(leaf.isDisposed, isFalse);
      expect(leaf.isNeutered(), isTrue);
      expect(publicKeys.last, leaf.publicKey);
    });
  });

  group('bounded fixed-format imports', () {
    test('oversized inputs fail before checksum/native work', () {
      // Invalid final alphabet characters must not be reached by the decoder.
      expect(
        () => BIP32.fromBase58('${'z' * 112}0'),
        throwsA(
          isA<ArgumentError>().having(
            (error) => error.message,
            'message',
            'Invalid buffer length',
          ),
        ),
      );
      expect(
        () => decode('${'z' * 52}0'),
        throwsA(
          isA<ArgumentError>().having(
            (error) => error.message,
            'message',
            'Invalid WIF length',
          ),
        ),
      );
    });

    for (final version in [0, 1, 0xffffffff]) {
      test(
        'extended-key versions $version retain leading-zero compatibility',
        () {
          final root = master();
          final network = NetworkType(
            wif: 0,
            bip32: Bip32Version(private: version, public: version ^ 1),
          );
          final custom = root.copyWithNetwork(network);
          addTearDown(custom.dispose);
          final public = custom.neutered();
          addTearDown(public.dispose);
          for (final node in [custom, public]) {
            final encoded = node.toBase58();
            expect(encoded.length, lessThanOrEqualTo(112));
            final restored = BIP32.fromBase58(encoded, network);
            addTearDown(restored.dispose);
            expect(restored.toSerializedBytes(), node.toSerializedBytes());
          }
          if (version == 0) expect(custom.toBase58(), startsWith('1'));
          if (version == 0xffffffff) expect(custom.toBase58().length, 112);
        },
      );
    }

    for (final version in [0, 1, 255]) {
      for (final compressed in [false, true]) {
        test('WIF version $version compressed=$compressed round trips', () {
          final key = Uint8List(32)..[31] = 1;
          final encoded = encode(
            WIF(version: version, privateKey: key, compressed: compressed),
          );
          final restored = decode(encoded, version);
          expect(restored.privateKey, key);
          expect(restored.compressed, compressed);
          expect(restored.version, version);
          if (version == 0) expect(encoded, startsWith('1'));
        });
      }
    }

    test('raw import owns its bytes independently of caller buffers', () {
      final root = master();
      final payload = root.toSerializedBytes();
      final expected = Uint8List.fromList(payload);
      final restored = BIP32.fromSerializedBytes(payload);
      addTearDown(restored.dispose);
      expect(payload, expected);
      payload.fillRange(0, payload.length, 0);
      expect(restored.toSerializedBytes(), expected);
      expect(decode(root.toWIF()).privateKey, root.privateKey);
    });
  });

  test(
    'try parser rejects numeric overflow in normal and hardened components',
    () {
      final large = '9' * 100;
      expect(tryParseDerivationPath('m/$large'), isNull);
      expect(tryParseDerivationPath("m/$large'"), isNull);
      expect(tryParseDerivationPath('m/$uint32Max')!.indices, [uint32Max]);
    },
  );
}
