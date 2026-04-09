# flutter_sodium

Flutter plugin exposing libsodium to the app.

## Refreshing iOS archives

Run the helper below to rebuild the checked-in iOS `libsodium` archives from the
pinned upstream release:

```sh
./scripts/build-libsodium-ios.sh
```

This generates:

- `ios/prebuilt/libsodium-device.a`
- `ios/prebuilt/libsodium-simulator.a`
- `ios/prebuilt/libsodium-build-info.json`
