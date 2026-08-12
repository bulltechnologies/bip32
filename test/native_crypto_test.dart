import 'dart:typed_data';

import 'package:bip32/bip32_advanced.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hex/hex.dart';
import 'package:native_crypto/native_crypto.dart';

import 'support/native_test_init.dart';

void main() {
  registerNativeTestHooks();

  group('native_crypto KATs', () {
    test('SHA-256 empty', () {
      expect(
        HEX.encode(Sha256().hash(Uint8List(0))),
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      );
    });

    test('RIPEMD-160 empty', () {
      expect(
        HEX.encode(Ripemd160().hash(Uint8List(0))),
        '9c1185a5c5e9fc54612808977ee8f548b2258d31',
      );
    });

    test('HMAC-SHA512 native KAT (RFC 4231 case 1 inputs)', () {
      final key = Uint8List(20)..fillRange(0, 20, 0x0b);
      final data = Uint8List.fromList('Hi There'.codeUnits);
      expect(
        HEX.encode(HmacSha512().compute(key: key, data: data)),
        '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cd'
        'edaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
      );
    });

    test('HMAC-SHA512 native KAT (RFC 4231 case 2 inputs)', () {
      final key = Uint8List.fromList('Jefe'.codeUnits);
      final data = Uint8List.fromList('what do ya want for nothing?'.codeUnits);
      expect(
        HEX.encode(HmacSha512().compute(key: key, data: data)),
        '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554'
        '9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
      );
    });

    test('HMAC-SHA512 constant-time verification', () {
      final key = Uint8List.fromList('bip32'.codeUnits);
      final data = Uint8List.fromList('native crypto'.codeUnits);
      final mac = HmacSha512().compute(key: key, data: data);
      final altered = Uint8List.fromList(mac);
      altered[0] ^= 1;
      final hmac = HmacSha512();

      expect(hmac.verify(key: key, data: data, expected: mac), isTrue);
      expect(hmac.verify(key: key, data: data, expected: altered), isFalse);
    });

    test('caller-owned digest and HMAC outputs', () {
      final data = Uint8List.fromList('hello'.codeUnits);
      final digest = Uint8List(Sha256.digestLength);
      Sha256().hashInto(data, digest);
      expect(
        HEX.encode(digest),
        '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
      );

      final key = Uint8List.fromList('key'.codeUnits);
      final mac = Uint8List(HmacSha512.tagLength);
      HmacSha512().computeInto(key: key, data: data, out: mac);
      expect(
        HEX.encode(mac),
        'ff06ab36757777815c008d32c8e14a705b4e7bf310351a06a23b612dc4c7433e'
        '7757d20525a5593b71020ea2ee162d2311b247e9855862b270122419652c0c92',
      );
    });

    test('hash160 matches native stack', () {
      final data = Uint8List.fromList('hello'.codeUnits);
      expect(
        HEX.encode(hash160(data)),
        'b6a9c8c230722b7c748331a8b450f05566dc7d0f',
      );
    });
  });
}
