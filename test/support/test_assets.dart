import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart' show rootBundle;
import 'package:path/path.dart' as p;

/// Resolves JSON test fixtures for package `test/` runs and example integration
/// tests (bundled under `assets/`).
Future<String> loadTestAssetJson(String name) async {
  for (final path in _fileCandidates(name)) {
    final file = File(path);
    if (file.existsSync()) {
      return file.readAsStringSync();
    }
  }
  return rootBundle.loadString('assets/$name');
}

Map<String, dynamic> decodeTestAssetJson(String json) =>
    jsonDecode(json) as Map<String, dynamic>;

List<String> _fileCandidates(String name) {
  final roots = <String>{
    Directory.current.path,
    File(Platform.script.toFilePath()).parent.path,
    File(Platform.script.toFilePath()).parent.parent.path,
    File(Platform.script.toFilePath()).parent.parent.parent.path,
  };
  final out = <String>[];
  for (final base in roots) {
    for (final rel in ['test/$name', '../test/$name', '../../test/$name']) {
      out.add(p.normalize(p.join(base, rel)));
    }
  }
  return out;
}
