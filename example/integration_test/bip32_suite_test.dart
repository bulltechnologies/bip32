import 'package:integration_test/integration_test.dart';
import 'package:native_sig/native_sig.dart';

import '../../test/background_isolate_test.dart' as background_isolate_test;
import '../../test/bip32_api_test.dart' as bip32_api_test;
import '../../test/bip32_official_vectors_test.dart'
    as bip32_official_vectors_test;
import '../../test/bip32_reliability_test.dart' as bip32_reliability_test;
import '../../test/bip32_test.dart' as bip32_test;
import '../../test/ecc_test.dart' as ecc_test;
import '../../test/native_crypto_test.dart' as native_crypto_test;
import '../../test/native_ecurve_test.dart' as native_ecurve_test;
import '../../test/v3_compat_golden_test.dart' as v3_compat_golden_test;

Future<void> main() async {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  NativeSig.ensureInitialized();

  final suites = <Future<void> Function()>[
    () async => background_isolate_test.main(),
    () async => bip32_api_test.main(),
    () async => bip32_official_vectors_test.main(),
    () async => bip32_reliability_test.main(),
    bip32_test.main,
    () async => ecc_test.main(),
    () async => native_crypto_test.main(),
    () async => native_ecurve_test.main(),
    v3_compat_golden_test.main,
  ];

  for (final run in suites) {
    await run();
  }
}
