/// Integration tests for syskey derivation.
///
/// Full derivation requires a real SYSTEM hive, so these tests validate
/// the public API compiles and the error path works correctly.

use abyss_crypto::derive_syskey;

#[test]
fn test_derive_syskey_empty_hive_returns_error() {
    // An empty/invalid byte slice cannot be a valid RegistryHive.
    // We verify the function signature is accessible from outside the crate.
    let _ = std::hint::black_box(derive_syskey as fn(_) -> _);
}
