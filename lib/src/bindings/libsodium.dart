import 'dart:ffi';
import 'dart:io';

import 'package:flutter_sodium/flutter_sodium.dart';

final libsodium = _load();

DynamicLibrary _load() {
  if (Platform.isAndroid) {
    return DynamicLibrary.open('libsodium.so');
  }
  if (Platform.isIOS) {
    return DynamicLibrary.process();
  }
  if (Platform.isMacOS) {
    String? path;
    // assuming user installed libsodium as per the installation instructions
    // see also https://libsodium.gitbook.io/doc/installation
    final paths = [
      '/usr/local/lib/libsodium.dylib',
      '/opt/homebrew/lib/libsodium.dylib'
    ];
    for (final p in paths) {
      if (File(p).existsSync()) {
        path = p;
        break;
      }
    }
    if (path == null) {
      throw SodiumException('cannot find associated path');
    }
    return DynamicLibrary.open(path);
  }
  if (Platform.isLinux) {
    // assuming user installed libsodium as per the installation instructions
    // see also https://libsodium.gitbook.io/doc/installation
    return DynamicLibrary.open('libsodium.so.23');
  }
  if (Platform.isWindows) {
    // assuming user installed libsodium as per the installation instructions
    // see also https://py-ipv8.readthedocs.io/en/latest/preliminaries/install_libsodium/
    return DynamicLibrary.open('C:\\Windows\\System32\\libsodium.dll');
  }
  throw SodiumException('platform not supported');
}

// Extension helper for functions returning size_t
// this is a workaround for size_t not being properly supported in ffi. IntPtr
// almost works, but is sign extended.
extension Bindings on DynamicLibrary {
  int Function() lookupSizet(String symbolName) => sizeOf<IntPtr>() == 4
      ? lookup<NativeFunction<Uint32 Function()>>(symbolName).asFunction()
      : lookup<NativeFunction<Uint64 Function()>>(symbolName).asFunction();
}
