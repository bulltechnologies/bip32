import 'package:native_crypto/native_crypto.dart';

Sha256? _sha256;

/// Shared native SHA-256 instance for hash and Base58Check checksums.
Sha256 get sha256 => _sha256 ??= Sha256();
