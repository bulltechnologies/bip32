import 'package:flutter_test/flutter_test.dart';
import 'package:native_sig/native_sig.dart';

bool _nativeReady = false;

/// Ensures [NativeSig] is initialized once per test process.
void ensureNativeSigForTests() {
  if (_nativeReady) {
    return;
  }
  NativeSig.ensureInitialized();
  _nativeReady = true;
}

/// Registers [ensureNativeSigForTests] for every test file that imports this.
void registerNativeTestHooks() {
  setUpAll(ensureNativeSigForTests);
}
