# Bonded Android Client

This directory contains the Flutter Android client shell app.

## Development Commands

```bash
cd android
flutter pub get
flutter test
flutter analyze
```

## Rust FFI Bridge

Rust FFI code lives in the workspace crate `crates/bonded-ffi`.

Release Android builds now run the Rust JNI build automatically via Gradle task wiring.
Use a single command from this `android/` directory:

```bash
flutter build appbundle
```

This invokes `scripts/build-android-native.sh` before `bundleRelease` / `assembleRelease`.

Planned Android bridge build flow:

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo install cargo-ndk

# from repository root
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o android/android/app/src/main/jniLibs build -p bonded-ffi --release
```

Manual Rust build remains useful when you want to prebuild JNI libraries without running a Flutter release build.

The Flutter app will load this native library in Phase 4.3 via Dart FFI / platform bridge wiring.
