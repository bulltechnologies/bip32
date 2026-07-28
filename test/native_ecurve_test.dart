import 'dart:typed_data';

import 'package:bip32/bip32.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hex/hex.dart';
import 'package:native_sig/native_sig.dart';

import 'support/native_test_init.dart';

final Uint8List _gCompressed = _hex(
  '0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798',
);
final Uint8List _one = _hex(
  '0000000000000000000000000000000000000000000000000000000000000001',
);
final Uint8List _twoGCompressed = _hex(
  '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
);
final Uint8List _gUncompressed = _hex(
  '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
  '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
);

void main() {
  registerNativeTestHooks();

  group('native ecurve integration', () {
    test('publicKeyFromSecret matches pointFromScalar', () {
      expect(pointFromScalar(_one, true), equals(_gCompressed));
    });

    test('public tweak-add matches BIP32 CKD step', () {
      expect(pointAddScalar(_gCompressed, _one, true), equals(_twoGCompressed));
    });

    test('private tweak-add is consistent with public tweak-add', () {
      final privChild = privateAdd(_one, _one)!;
      final pubChild = pointFromScalar(privChild, true)!;
      expect(pubChild, equals(_twoGCompressed));
      zeroize(privChild);
    });

    test('zero tweak preserves the parent point and requested encoding', () {
      final zero = Uint8List(32);
      expect(pointAddScalar(_gCompressed, zero, true), equals(_gCompressed));
      expect(pointAddScalar(_gCompressed, zero, false), equals(_gUncompressed));
      expect(pointAddScalar(_gUncompressed, zero, true), equals(_gCompressed));
      expect(
        pointAddScalar(_gUncompressed, zero, false),
        equals(_gUncompressed),
      );
      expect(privateAdd(_one, zero), equals(_one));
    });

    test('infinity tweak returns null', () {
      final orderMinusOne = _hex(
        'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140',
      );
      expect(pointAddScalar(_gCompressed, orderMinusOne, true), isNull);
      expect(privateAdd(_one, orderMinusOne), isNull);
    });

    test('invalid inputs keep legacy ArgumentError messages', () {
      expect(
        () => pointFromScalar(Uint8List(32), true),
        throwsA(
          predicate((e) => e is ArgumentError && e.message == throwBadPrivate),
        ),
      );
      expect(
        () => pointAddScalar(Uint8List(33), _one, true),
        throwsA(
          predicate((e) => e is ArgumentError && e.message == throwBadPoint),
        ),
      );
      expect(
        () => privateAdd(_one, Uint8List(33)),
        throwsA(
          predicate((e) => e is ArgumentError && e.message == throwBadTweak),
        ),
      );
    });

    test('malformed SEC1 point is rejected by isPoint', () {
      final offCurve = _hex(
        '02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      );
      expect(isPoint(offCurve), isFalse);
    });

    test('invalid signatures are rejected without silent fallback', () {
      final badLength = Uint8List(63);
      expect(
        () => Secp256k1.ecdsaVerify(
          signature: badLength,
          messageHash: Uint8List(32),
          publicKey: _gCompressed,
        ),
        throwsA(isA<InvalidInputException>()),
      );
      expect(
        Secp256k1.ecdsaVerify(
          signature: Uint8List(64),
          messageHash: Uint8List(32),
          publicKey: _gCompressed,
        ),
        isFalse,
      );
    });
  });
}

Uint8List _hex(String h) => Uint8List.fromList(HEX.decode(h));
