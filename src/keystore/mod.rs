//! Keystore module — v2.2 layout.
//!
//! Module directory split from a single `src/keystore.rs` file in Phase 18-00
//! to make room for the signature submodule (`sig.rs` lands in 18-01).
//! Public surface is unchanged: all consumers continue to import from
//! `crate::keystore::*` and resolve identically.

mod store;
pub use self::store::*;
