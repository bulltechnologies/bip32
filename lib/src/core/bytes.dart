import 'dart:typed_data';

/// Adapts [bytes] to [Uint8List] without copying when already typed.
Uint8List asUint8List(List<int> bytes) =>
    bytes is Uint8List ? bytes : Uint8List.fromList(bytes);
