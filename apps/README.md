# Spartan benchmark app

### iOS
- Add r1cs and witness files to `RustBenchmarkApp/Resources`
```
cd RustBenchmarkApp/RustBenchmarkApp/rust_lib
cargo build --target aarch64-apple-ios --release
```
- Make sure `rust_lib/target/aarch64-apple-ios/release/librust_lib.a` is linked
- Configure code signing
- Run the app in Xcode

### Android

- Add artifacts to in `apps/android/app/src/main/assets`
- Change paths in `apps/android/app/src/main/java/com/example/rustbenchmarkapp/MainActivity.kt`
```
cd android/rust_lib
cargo ndk -t arm64-v8a -o ../app/src/main/jniLibs build --release --no-default-features --features android
cd ..
./gradlew installDebug
```
