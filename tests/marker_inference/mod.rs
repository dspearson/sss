// Why: integration tests use .unwrap()/.expect()/panic! freely; test code is exempt
// from the panic-surface lint policy per CONTEXT.md Area 1 carve-out.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

// Integration tests for marker inference

mod integration;
mod edge_cases;
mod properties;
mod spec_compliance;
mod expander_unit;
