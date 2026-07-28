import 'package:flutter/material.dart';
import 'package:native_sig/native_sig.dart';

/// Minimal host app so Flutter links native_crypto and native_sig for tests.
void main() {
  WidgetsFlutterBinding.ensureInitialized();
  NativeSig.ensureInitialized();
  runApp(const MaterialApp(home: SizedBox.shrink()));
}
