# flutter_sodium

Flutter plugin exposing libsodium to the app.

## Refreshing Android archives

Run the helper below to rebuild the checked-in Android `libsodium` shared
libraries from the pinned upstream release. The wrapper delegates the actual
compile step to libsodium's upstream Android `dist-build` scripts and then
copies the resulting `.so` files into this repository:

```sh
./scripts/build-libsodium-android.sh
```

This generates:

- `android/src/main/jniLibs/armeabi-v7a/libsodium.so`
- `android/src/main/jniLibs/arm64-v8a/libsodium.so`
- `android/src/main/jniLibs/x86/libsodium.so`
- `android/src/main/jniLibs/x86_64/libsodium.so`
- `android/prebuilt/libsodium-build-info.json`

## Refreshing iOS archives

Run the helper below to rebuild the checked-in iOS `libsodium` archives from the
pinned upstream release. The wrapper loads libsodium's upstream Apple
`dist-build` helpers, builds the iOS slices we ship, and then writes the final
archives into this repository:

```sh
./scripts/build-libsodium-ios.sh
```

This generates:

- `ios/prebuilt/libsodium-device.a`
- `ios/prebuilt/libsodium-simulator.a`
- `ios/prebuilt/libsodium-build-info.json`
