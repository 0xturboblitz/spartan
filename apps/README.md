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

