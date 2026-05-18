# Clippy Policy

This project enforces a strict clippy contract declared in
`Cargo.toml` under `[lints.clippy]`. That block is the single source of
truth for what fires and at what level; this document is the rationale
layer auditors read. CI gates the block per matrix cell with
`cargo clippy --workspace --all-targets ${{ matrix.cargo_features }} -- -D warnings`
and never overrides per-invocation.

## Enabled Lint Groups

- `pedantic = { level = "warn", priority = -1 }` — baseline strictness floor.
  `warn` (not `deny`) lets contributors land WIP locally; CI converts to
  errors via `-D warnings` so master stays green. `priority = -1` keeps the
  group from drowning out cherry-picked deny lints below.
- Pedantic-noise suppressions (four, only four):
  - `module_name_repetitions = "allow"` — Rust nomenclature naturally produces
    `module::ModuleThing` shapes; renaming for the lint is churn.
  - `missing_errors_doc = "allow"` — public API uses `anyhow::Error`; per-fn
    `# Errors` rustdoc duplicates the error chain without adding signal.
  - `missing_panics_doc = "allow"` — already covered structurally by
    `panic = "deny"`; doc duplication is redundant.
  - `unnecessary_wraps = "allow"` — internal trait-API symmetry across
    Linux/macOS variants intentionally returns `Result` for caller uniformity.

Adding a fifth suppression requires a PR-reviewed policy change (see § Evolution
Workflow). The instinct "this lint is noisy" must be answered with per-site
`#[allow] // Why: …` rationale, not a workspace blanket.

## Cherry-Picked Strictness Lints

Each cherry-pick escalates pedantic or restriction-group beyond the floor.
Rationale lives here; enforcement lives in `Cargo.toml`.

**Panic-Surface Gate:** `unwrap_used = "deny"`, `expect_used = "deny"`,
`panic = "deny"`. Locks the v2.1 Phase 8 HARDEN-01..05 audit (4 caller-facing
panics converted to `?`, 22 zeroisation sites, 26 FFI sites walked, 59-test
`tests/public_api_panic_surface.rs` regression suite). Without the deny,
a future PR can reintroduce `.unwrap()` in a load-bearing path. Test code is
exempt at crate-root via `#![cfg_attr(test, allow(clippy::unwrap_used,
clippy::expect_used, clippy::panic))]` in `src/lib.rs` and `src/main.rs`.

**Unsafe-Block Discipline:** `undocumented_unsafe_blocks = "deny"`,
`missing_safety_doc = "deny"`. Forces `// SAFETY:` immediately above every
`unsafe { }` block and `# Safety` rustdoc on every `pub unsafe fn`; closes the
v2.1 Phase 8 HARDEN-03 documented gap at `src/crypto/classic.rs:91`. The one
auditor-visible exception is `src/fuse/fs.rs`, which carries 72 libc-syscall
blocks behind a single file-top `#![allow(clippy::undocumented_unsafe_blocks)]`
and a module rustdoc paragraph stating the universal SAFETY invariant
(`Option B` — fuse-gated, not in the v2.3 CI matrix). Structural enforcement
complements this: `src/bin/sss-askpass-tty.rs` and
`src/bin/sss-askpass-gui.rs` carry `#![forbid(unsafe_code)]`, making any new
`unsafe { }` block in those files a compile error. `sss-agent` is deliberately
excluded because it re-exports `sss::*` modules that use libc/sodium FFI.

**Zeroisation Hygiene:** `mem_forget = "deny"`. `std::mem::forget` defeats
`ZeroizeOnDrop`; deny prevents accidental zeroisation-bypass. None present in
the current codebase.

**Cast Surface Anchors:** `cast_possible_truncation = { level = "warn",
priority = -1 }`, `cast_sign_loss = { level = "warn", priority = -1 }`.
Already in pedantic at warn; surfaced as explicit anchors so the auditor
reading `[lints.clippy]` sees the cast-surface gate by name. `priority = -1`
is required to avoid warn-on-warn duplication. Phase 23 MEMSAFE-05 will use
these as a clean starting list.

## `// Why:` Comment Requirement

Every `#[allow(...)]` MUST carry a `// Why:` comment immediately above the
attribute. Trailing comments do not satisfy the convention. Block comments
(`/* Why: … */`) above the attribute are acceptable. Indented allows
(method-scoped or impl-scoped) require the `// Why:` line above with
matching indentation. Example:

```rust
// Why: KdfParams is kept by value for API clarity; callers
// have no further use for the params after construction.
#[allow(clippy::needless_pass_by_value)]
fn derive_key(params: KdfParams) -> Key { /* … */ }
```

`#[expect(...)]` (stable since Rust 1.81) is a future option that re-triggers
the lint when the underlying code changes, but Phase 21 standardises on
`#[allow] + // Why:` for consistency with the v2.1 Plan 11-04 convention.

Regression gates enforce both invariants per matrix cell:
- `scripts/check-allow-why.sh` (Plan 21-04) checks that every `#[allow]` has a
  `// Why:` line directly above (indented-tolerant grep).
- `scripts/check-safety-comments.sh` (Plan 21-03) checks that every production
  `unsafe { }` block has `// SAFETY:` within 3 lines above.

## Evolution Workflow

Changing this policy is a PR-reviewed event:

1. Open a PR modifying `Cargo.toml` `[lints.clippy]`.
2. Update this doc in the same PR with rationale.
3. Require a reviewer sign-off explicitly noting "policy change reviewed".
4. Avoid tightening mid-milestone — churn drowns out signal.

Loosening (deny → warn, or warn → allow) requires explicit rationale because
it reduces signal. Tightening that adds lints is welcome any time.

When a new clippy version surfaces unexpected warnings: fix them, or add
`#[allow(clippy::SPECIFIC_LINT)] // Why: …` at the site. Never widen the
workspace suppression list without going through the workflow above.
