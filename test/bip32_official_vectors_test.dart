import 'dart:typed_data';

import 'package:bip32/bip32.dart';
import 'package:hex/hex.dart';
import 'package:test/test.dart';

/// Official [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) vectors.
void main() {
  group('BIP32 test vector 3 (leading zero private keys)', () {
    const seed =
        '4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be';

    test('m', () {
      final node = BIP32.fromSeed(_hex(seed));
      expect(
        node.neutered().toBase58(),
        'xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13',
      );
      expect(
        node.toBase58(),
        'xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6',
      );
    });

    test('m/0H', () {
      final node = BIP32.fromSeed(_hex(seed)).derivePath("m/0'");
      expect(
        node.neutered().toBase58(),
        'xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y',
      );
      expect(
        node.toBase58(),
        'xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L',
      );
    });
  });

  group('BIP32 test vector 4 (leading zero private keys)', () {
    const seed =
        '3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678';

    test('m', () {
      final node = BIP32.fromSeed(_hex(seed));
      expect(
        node.neutered().toBase58(),
        'xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa',
      );
      expect(
        node.toBase58(),
        'xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv',
      );
    });

    test('m/0H', () {
      final node = BIP32.fromSeed(_hex(seed)).derivePath("m/0'");
      expect(
        node.neutered().toBase58(),
        'xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m',
      );
      expect(
        node.toBase58(),
        'xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G',
      );
    });

    test('m/0H/1H', () {
      final node = BIP32.fromSeed(_hex(seed)).derivePath("m/0'/1'");
      expect(
        node.neutered().toBase58(),
        'xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt',
      );
      expect(
        node.toBase58(),
        'xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1',
      );
    });
  });

  group('BIP32 test vector 5 (invalid extended keys)', () {
    final cases = <Map<String, String>>[
      {
        'label': 'xpub version with private payload',
        'key':
            'xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm',
        'error': 'Invalid public key',
      },
      {
        'label': 'xprv version with public payload',
        'key':
            'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH',
        'error': 'Invalid private key',
      },
      {
        'label': 'invalid pubkey prefix 04',
        'key':
            'xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn',
        'error': 'Invalid public key',
      },
      {
        'label': 'invalid prvkey prefix 04',
        'key':
            'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ',
        'error': 'Invalid private key',
      },
      {
        'label': 'invalid pubkey prefix 01',
        'key':
            'xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4',
        'error': 'Invalid public key',
      },
      {
        'label': 'invalid prvkey prefix 01',
        'key':
            'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J',
        'error': 'Invalid private key',
      },
      {
        'label': 'zero depth with non-zero parent fingerprint (xprv)',
        'key':
            'xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv',
        'error': 'Invalid parent fingerprint',
      },
      {
        'label': 'zero depth with non-zero parent fingerprint (xpub)',
        'key':
            'xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ',
        'error': 'Invalid parent fingerprint',
      },
      {
        'label': 'zero depth with non-zero index (xprv)',
        'key':
            'xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN',
        'error': 'Invalid index',
      },
      {
        'label': 'zero depth with non-zero index (xpub)',
        'key':
            'xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8',
        'error': 'Invalid index',
      },
      {
        'label': 'unknown extended key version',
        'key':
            'DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4',
        'error': 'Invalid network version',
      },
      {
        'label': 'private key 0',
        'key':
            'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx',
        'error': 'Private key not in range [1, n]',
      },
      {
        'label': 'private key n',
        'key':
            'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G',
        'error': 'Private key not in range [1, n]',
      },
      {
        'label': 'invalid curve point',
        'key':
            'xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY',
        'error': 'Point is not on the curve',
      },
      {
        'label': 'invalid checksum',
        'key':
            'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL',
        'error': 'Invalid checksum',
      },
    ];

    for (final c in cases) {
      test(c['label']!, () {
        expect(
          () => BIP32.fromBase58(c['key']!),
          throwsA(
            predicate(
              (e) => e is ArgumentError && e.message == c['error'],
            ),
          ),
        );
      });
    }
  });

  group('BIP32 structural guarantees', () {
    test('CKDpub(N(m),i) equals N(CKDpriv(m,i)) for non-hardened i', () {
      final master = BIP32.fromSeed(
        _hex('000102030405060708090a0b0c0d0e0f'),
      );
      for (final i in [0, 1, 5, 0x7fffffff]) {
        final fromPrivate = master.derive(i).neutered().toBase58();
        final fromPublic = master.neutered().derive(i).toBase58();
        expect(fromPublic, fromPrivate, reason: 'index $i');
      }
    });

    test('round-trip Base58 preserves key', () {
      final node = BIP32.fromSeed(
        _hex('000102030405060708090a0b0c0d0e0f'),
      ).derivePath("m/0'/1/2'");
      final encoded = node.toBase58();
      final decoded = BIP32.fromBase58(encoded);
      expect(decoded.toBase58(), encoded);
      expect(decoded.depth, node.depth);
      expect(decoded.index, node.index);
    });

    test('derivation depth cannot exceed 255', () {
      var node = BIP32.fromSeed(
        _hex('000102030405060708090a0b0c0d0e0f'),
      );
      for (var d = 0; d < maxBip32Depth; d++) {
        node = node.derive(0);
      }
      expect(
        () => node.derive(0),
        throwsA(
          predicate(
            (e) =>
                e is ArgumentError &&
                e.message == 'Maximum derivation depth exceeded',
          ),
        ),
      );
    });
  });

  group('security', () {
    test('dispose zeroizes private key, chain code, and cached pubkey', () {
      final node = BIP32.fromSeed(_hex('000102030405060708090a0b0c0d0e0f'));
      final priv = node.privateKey!;
      final chain = node.chainCode;
      final pub = node.publicKey;
      node.dispose();
      expect(priv.every((b) => b == 0), isTrue);
      expect(chain.every((b) => b == 0), isTrue);
      expect(pub.every((b) => b == 0), isTrue);
      expect(() => node.privateKey, throwsStateError);
      expect(() => node.derive(0), throwsStateError);
    });

    test('sign on neutered node throws', () {
      final pub = BIP32.fromBase58(
        'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',
      );
      expect(
        () => pub.sign(Uint8List(32)),
        throwsA(
          predicate(
            (e) =>
                e is ArgumentError && e.message == 'Missing private key',
          ),
        ),
      );
    });
  });
}

Uint8List _hex(String h) => Uint8List.fromList(HEX.decode(h));
