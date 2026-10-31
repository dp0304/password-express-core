// SPDX-License-Identifier: Apache-2.0
//! Bindings generator (`cargo run -p aipass-ffi --features bindgen --bin uniffi-bindgen -- generate --library …`).
fn main() {
    uniffi::uniffi_bindgen_main()
}
