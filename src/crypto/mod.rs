//! Cryptographic primitives for sss.
//!
//! This module is organised as a directory-module (Phase 1 of the v2.0
//! crypto-suite abstraction work). Re-exports from `classic` preserve the
//! historical `crate::crypto::{seal_repository_key, open_repository_key,
//! RepositoryKey, PublicKey, KeyPair, SecretKey, Key, encrypt, decrypt, ...}`
//! surface verbatim so no caller (in this crate or in tests) needs to change.
//!
//! The `CryptoSuite` trait and `Suite` dispatch enum are the integration
//! points Phase 2's hybrid implementation will plug into.
pub mod classic;
pub mod suite;

pub use classic::{
    decrypt, decrypt_from_base64, encrypt, encrypt_to_base64,
    encrypt_to_base64_deterministic, open_repository_key, seal_repository_key, ClassicSuite, Key,
    KeyPair, PublicKey, RepositoryKey, SecretKey,
};
pub use suite::{CryptoSuite, Suite};

// Keep the internal `encrypt_internal` reachable from keystore etc. exactly
// as before — it was `pub(crate)` in the old flat module and must remain so.
#[allow(unused_imports)]
pub(crate) use classic::encrypt_internal;
