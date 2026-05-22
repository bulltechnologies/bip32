import 'dart:typed_data';

/// Overwrites [buffer] with zeros (best-effort secret cleanup).
///
/// Dart may retain copies in memory outside your control; always minimize lifetime
/// of secrets and avoid logging or serializing private material.
void zeroize(Uint8List buffer) {
  for (var i = 0; i < buffer.length; i++) {
    buffer[i] = 0;
  }
}

/// Holds sensitive bytes that can be wiped with [dispose].
class SecureBuffer {
  /// Copies [data] so callers cannot mutate this buffer via their reference.
  SecureBuffer(Uint8List data) : bytes = Uint8List.fromList(data);

  Uint8List bytes;

  bool _disposed = false;

  bool get isDisposed => _disposed;

  /// Returns a defensive copy.
  Uint8List clone() => Uint8List.fromList(bytes);

  /// Zeros [bytes] and marks this holder disposed.
  void dispose() {
    if (_disposed) return;
    zeroize(bytes);
    _disposed = true;
  }
}
