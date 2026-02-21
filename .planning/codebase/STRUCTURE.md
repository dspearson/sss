# Codebase Structure

**Analysis Date:** 2026-02-21

## Directory Layout

```
sss/
├── src/                    # Rust source code
│   ├── bin/                # Binary entry points (sss-agent, sss-askpass-*)
│   ├── commands/           # CLI command handlers (20+ modules)
│   ├── marker_inference/   # Smart marker preservation (8 modules)
│   ├── fuse/               # FUSE filesystem internals (4 modules)
│   ├── processor/          # Content transformation (2 modules)
│   ├── main.rs             # CLI app definition and routing
│   ├── lib.rs              # Module exports and public API
│   ├── crypto.rs           # Encryption/decryption (XChaCha20-Poly1305)
│   ├── keystore.rs         # Key storage and KDF
│   ├── keyring_manager.rs  # System keyring integration
│   ├── project.rs          # ProjectConfig structure
│   ├── config.rs           # Configuration loading
│   ├── scanner.rs          # File pattern scanning
│   ├── secrets.rs          # Secrets interpolation
│   ├── merge.rs            # Merge conflict handling
│   ├── rotation.rs         # Key rotation logic
│   ├── fuse_fs.rs          # FUSE filesystem impl (Linux/macOS)
│   ├── ninep_fs.rs         # 9P protocol server
│   ├── winfsp_fs.rs        # Windows filesystem impl
│   ├── error.rs            # Error types
│   ├── audit_log.rs        # Audit logging
│   └── [10+ support modules]
├── tests/                  # Integration and e2e tests (50+ files)
├── emacs/                  # NEW: Single-file Emacs mode (v1.0)
│   ├── sss-mode.el         # Transparent decrypt-on-open, re-seal-on-save (354 lines)
│   └── sss-mode.elc        # Compiled bytecode
├── plugins/emacs/          # OLDER: Multi-file implementation
│   ├── sss.el              # Core interface (455 lines)
│   ├── sss-mode.el         # Minor mode & highlighting (214 lines)
│   ├── sss-ui.el           # Transient menus (318 lines)
│   ├── sss-project.el      # Project management (276 lines)
│   ├── sss-utils.el        # Utilities (336 lines)
│   ├── sss-doom.el         # Doom Emacs integration (322 lines)
│   └── README.md           # Comprehensive documentation
├── docs/                   # Documentation
│   ├── architecture.md     # System architecture
│   ├── CRYPTOGRAPHY.md     # Crypto details
│   ├── MARKER_INFERENCE_*.md
│   ├── security-model.md   # Security analysis
│   └── [20+ docs]
├── rpm-build/              # RPM package building
├── debian/                 # Debian package building
├── scripts/                # Utility scripts
├── benches/                # Benchmarks (marker_inference.rs)
├── examples/               # Example code
├── Cargo.toml              # Rust package manifest
├── Cargo.lock              # Dependency lock file
├── build.rs                # Build script
├── LICENCE                 # ISC license
└── README.md               # Main project README
```

## Directory Purposes

**src/ — Rust Implementation:**
- Core application logic
- 70+ modules organized by layer
- Public API exported through `lib.rs`

**src/commands/ — CLI Command Handlers:**
- `init.rs`: Project initialization
- `keys.rs`: Key management (generate, list, rotate)
- `process.rs`: seal/open/render/edit commands
- `mount.rs`: FUSE mount (Linux/macOS)
- `ninep.rs`: 9P server (experimental)
- `project.rs`: Project settings management
- `users.rs`: Project user management
- `settings.rs`: User preferences
- `hooks.rs`: Git hooks management
- `agent.rs`: Agent daemon (experimental)
- `utils.rs`: Shared command utilities
- `mod.rs`: Command export/routing

**src/marker_inference/ — Intelligent Marker Preservation:**
- `mod.rs`: Algorithm overview and public API
- `parser.rs`: Extract markers from source
- `diff.rs`: Compute changes between versions
- `mapper.rs`: Map change positions
- `expander.rs`: Apply 5 expansion rules
- `propagator.rs`: Mark duplicate content
- `reconstructor.rs`: Build output with canonical format
- `validator.rs`: Delimiter pair validation
- `types.rs`: Data structures

**src/fuse/ — FUSE Filesystem Internals:**
- `mod.rs`: FUSE module organization
- `inode_manager.rs`: Inode tracking
- `file_cache.rs`: File content caching
- `virtual_fs.rs`: Virtual file operations

**src/processor/ — Content Transformation:**
- `core.rs`: Main Processor impl (encrypt, decrypt, render, seal, open)
- `marker_parser.rs`: Balanced brace marker detection

**tests/ — Test Suite (50+ files):**
- `marker_inference/`: Marker preservation tests
- `*_integration.rs`: Full command workflows
- `*_edge_cases.rs`: Boundary conditions
- `crypto_*.rs`: Cryptography tests
- `keystore_*.rs`: Key storage tests
- `fuse_*.rs`: FUSE filesystem tests
- Command-specific tests: `command_*.rs`

**emacs/ — Modern Single-File Emacs Mode (v1.0):**
- `sss-mode.el` (354 lines): Complete transparent encryption integration
  - Auto-detect sealed files via magic-mode-alist
  - Decrypt on open via find-file-hook
  - Re-seal on save via write-contents-functions
  - Commands: M-x sss-render-buffer, sss-init, sss-process, sss-keygen, sss-keys-list
  - Keybindings: C-c C-o (open), C-c C-s (seal), C-c C-r (render)
  - Font-lock highlighting: `⊕{...}` and `⊠{...}` markers with distinct faces
  - Disables auto-save and backup automatically
  - Status in modeline: SSS[sealed] or SSS[open]
- `sss-mode.elc`: Compiled bytecode for fast loading

**plugins/emacs/ — Comprehensive Multi-File Implementation (Older):**
- `sss.el` (455 lines): Core interface
  - Interactive region encryption/decryption
  - Auth-source password caching
  - Password cache with configurable timeout
- `sss-mode.el` (214 lines): Minor mode
  - Syntax highlighting
  - Keybinding support
  - Fancy visual mode option
- `sss-ui.el` (318 lines): Transient menus
  - Interactive command menus
  - Completion support
- `sss-project.el` (276 lines): Project management
  - Initialize projects
  - Add/remove users
  - List projects
- `sss-utils.el` (336 lines): Utilities
  - Pattern detection and analysis
  - Buffer analysis helpers
- `sss-doom.el` (322 lines): Doom Emacs integration
  - Evil operator support: `g e` for encrypt
  - Text object: `i s` (inside secret)
  - Leader key bindings: `SPC e` namespace
  - Transient menu integration
- `README.md`: 13.8 KB comprehensive documentation

**docs/ — Documentation (25+ files):**
- Architecture and design docs
- Cryptography details
- Marker specification and implementation
- Security model analysis
- Installation and building guides
- Test coverage reports

**rpm-build/, debian/ — Package Building:**
- Distribution-specific packaging metadata
- Build scripts for RPM and Debian

## Key File Locations

**Entry Points:**
- `src/main.rs` (835 lines): CLI app definition, feature-gated command registration, main() dispatcher
- `src/lib.rs` (164 lines): Public API, module exports, integration tests

**Core Encryption:**
- `src/crypto.rs` (300+ lines): XChaCha20-Poly1305, KeyPair, RepositoryKey, deterministic nonces
- `src/keystore.rs` (400+ lines): Key generation, Argon2id KDF, passphrase protection
- `src/secure_memory.rs`: Memory zeroization utilities

**Content Processing:**
- `src/processor/core.rs` (500+ lines): Processor impl with encrypt/decrypt/render/seal/open methods
- `src/processor/marker_parser.rs` (200+ lines): Balanced brace marker detection
- `src/marker_inference/mod.rs` (8 modules, 1000+ lines total): Smart marker preservation

**Project & Configuration:**
- `src/project.rs` (400+ lines): ProjectConfig structure, user config, ignore patterns
- `src/config.rs` (300+ lines): Config loading and key management
- `src/config_manager.rs` (300+ lines): User settings in ~/.config/sss/

**File Operations:**
- `src/scanner.rs` (200+ lines): FileScanner for recursive pattern finding
- `src/secrets.rs` (300+ lines): Secrets interpolation from secrets file
- `src/filesystem_common.rs`: Shared filesystem detection utilities

**Filesystem Layers:**
- `src/fuse_fs.rs` (800+ lines): FUSE filesystem (Linux/macOS)
- `src/ninep_fs.rs` (600+ lines): 9P protocol server
- `src/winfsp_fs.rs` (300+ lines): Windows filesystem

**Commands:**
- `src/commands/process.rs` (300+ lines): seal/open/render/edit
- `src/commands/mount.rs` (200+ lines): FUSE mount
- `src/commands/keys.rs` (400+ lines): Key management
- `src/commands/project.rs` (300+ lines): Project settings
- `src/commands/init.rs` (200+ lines): Project initialization

**Testing:**
- `tests/marker_inference_tests.rs`: Marker preservation
- `tests/command_integration.rs`: CLI workflows
- `tests/crypto_security_tests.rs`: Encryption validation
- `tests/fuse_integration.rs`: Filesystem operations

## Naming Conventions

**Files:**
- Source modules: `snake_case.rs` (e.g., `marker_inference.rs`, `config_manager.rs`)
- Submodules: `mod.rs` in directory (e.g., `src/marker_inference/mod.rs`)
- Tests: `*_tests.rs` or `*_integration.rs` (e.g., `crypto_security_tests.rs`)
- Binary entries: `[name].rs` in `src/bin/` (e.g., `sss-agent.rs`)

**Directories:**
- Functional grouping: `src/commands/`, `src/fuse/`, `src/marker_inference/`
- Module prefix: `src/bin/` for binaries, `src/fuse/` for submodule
- Package structure: `plugins/[lang]/` (e.g., `plugins/emacs/`)

**Rust Code:**
- Structs/Enums: `PascalCase` (e.g., `Processor`, `ProjectConfig`, `FileScanner`)
- Functions: `snake_case` (e.g., `encrypt_content()`, `infer_markers()`)
- Constants: `UPPER_SNAKE_CASE` (e.g., `MAX_FILE_SIZE`, `TTL`)
- Modules: `snake_case` (e.g., `marker_inference`, `keystore`)
- Private functions: prefix `_` (e.g., `_call_cli()` in emacs-mode.el)

**Emacs Lisp:**
- Functions: `kebab-case` with namespace prefix (e.g., `sss-encrypt-region`, `sss-mode`)
- Variables: `kebab-case` with package prefix (e.g., `sss-executable`, `sss--state`)
- Private variables/functions: double dash `--` (e.g., `sss--sealed-p`, `sss--call-cli`)
- Constants: all caps (e.g., `sss--sealed-marker`)

## Where to Add New Code

**New Feature (Encryption Logic):**
- Primary code: `src/processor/core.rs` (if content transformation) or new module in `src/`
- Tests: `tests/[feature]_tests.rs` (integration) + `src/` internal unit tests
- Documentation: `docs/` for spec, README for user-facing

**New Command:**
- Implementation: `src/commands/[name].rs`
- Handler export: `src/commands/mod.rs` (add use statement and handler signature)
- CLI routing: `src/main.rs` (add subcommand definition and match arm)
- Tests: `tests/command_[name].rs` or append to `tests/command_integration.rs`

**New Marker Inference Rule:**
- Algorithm: `src/marker_inference/expander.rs` (expansion rules)
- Tests: `tests/marker_inference_tests.rs` (with specific rule test case)
- Docs: Update `src/marker_inference/mod.rs` section on expansion rules

**New Filesystem Backend:**
- Implementation: `src/[name]_fs.rs` (e.g., `btrfs_fs.rs`)
- Feature flag: Add to `Cargo.toml` `[features]` section
- CLI integration: `src/commands/mount.rs` (feature-gated)
- Tests: `tests/[name]_integration.rs`

**New Emacs Feature:**
- Modern approach: Add to `emacs/sss-mode.el` (single-file mode, v1.0)
  - Simple features: Add to core functions (encrypt, decrypt, render)
  - Complex features: Create separate defun, bind to keymap
  - Tests: Use Emacs batch mode (see existing mode usage)
- Legacy approach: Extend `plugins/emacs/` modules
  - Core logic: `plugins/emacs/sss.el`
  - UI/menus: `plugins/emacs/sss-ui.el`
  - Project features: `plugins/emacs/sss-project.el`
  - Doom integration: `plugins/emacs/sss-doom.el`
  - Tests: Emacs batch execution

**New Test Suite:**
- Location: `tests/[feature]_tests.rs` (at project root level)
- Structure: Use Rust test framework (see existing tests)
- Integration tests: Reference actual commands, config, filesystem
- Unit tests: Within `src/` module itself

**Utilities & Helpers:**
- Small utilities: `src/[domain]_helpers.rs` (e.g., `error_helpers.rs`)
- Shared constants: `src/constants.rs`
- Shared types: `src/types.rs` or domain-specific module

## Special Directories

**target/ — Build Artifacts:**
- Purpose: Compiled binaries and intermediate objects
- Generated: Yes (cargo build output)
- Committed: No (.gitignore)

**.planning/codebase/ — Codebase Documentation:**
- Purpose: GSD analysis documents (ARCHITECTURE.md, STRUCTURE.md, CONVENTIONS.md, TESTING.md, STACK.md, INTEGRATIONS.md, CONCERNS.md)
- Generated: Yes (by GSD mapping)
- Committed: Yes (reference for future phases)

**vendor/ — Vendored Dependencies:**
- Purpose: Offline dependencies for build
- Generated: No (manually maintained)
- Committed: Yes (rust-9p vendored for ninep feature)

**.sss_backup_*/ — Automatic Backups:**
- Purpose: Automatic project backups (created by sss tool)
- Generated: Yes
- Committed: No (.gitignore)

**docs/ — Developer Documentation:**
- Purpose: Architecture, implementation details, testing guides
- Generated: No (hand-written)
- Committed: Yes

**cross/ — Cross-Compilation Config:**
- Purpose: Platform-specific build configuration
- Generated: No
- Committed: Yes (cross-compile setup for macOS, ARM)

**coordination/, memory/, .hive-mind/, .swarm/ — Agent/Flow Directories:**
- Purpose: Claude-Flow and agent coordination metadata
- Generated: Yes (by Claude-Flow)
- Committed: Mostly no (partial tracking for coordination)

## Emacs Integration Architecture

### New Approach (`emacs/sss-mode.el`)

**Design Philosophy:**
- Single-file implementation
- Transparent decrypt-on-open, re-seal-on-save
- Zero configuration (except sss binary path for daemon mode)
- Auto-detection via magic-mode-alist (checks for sealed marker at buffer start)
- Security-first: auto-save and backup disabled immediately

**Core Flow:**
1. `magic-mode-alist` checks `sss--sealed-p` predicate → activates `sss-mode`
2. `find-file-hook` calls `sss--find-file-hook` → calls `sss open` → decrypts to `⊕{}` markers
3. `write-contents-functions` calls `sss--write-contents` → writes plaintext, then `sss seal --in-place`
4. Keybindings: C-c C-o/C-c C-s/C-c C-r for manual operations

**Key Functions:**
- `sss--call-cli(args, input-file)` — Execute sss binary, return (exit-code stdout stderr)
- `sss--sealed-p()` — Magic-mode predicate (checks UTF-8 marker at buffer start)
- `sss--open-buffer()` — Decrypt via `sss open FILE`, disable auto-save/backup
- `sss--write-contents()` — Write plaintext, seal via `sss seal --in-place`
- `sss-render-buffer()` — Display fully rendered plaintext in read-only buffer
- `sss-init()`, `sss-process()`, `sss-keygen()`, `sss-keys-list()` — Project operations

### Legacy Approach (`plugins/emacs/`)

**Design Philosophy:**
- Feature-rich with interactive region processing
- Multiple independent files for modularity
- Auth-source integration for password caching
- Doom Emacs with Evil operators
- 1,921 lines total across 6 Lisp files

**Organization:**
- `sss.el`: Core (encrypt/decrypt regions, file processing, auth-source)
- `sss-mode.el`: Minor mode with syntax highlighting and auto-processing
- `sss-ui.el`: Transient menus for interactive command selection
- `sss-project.el`: Project/user management workflows
- `sss-utils.el`: Pattern detection, buffer analysis
- `sss-doom.el`: Evil operator bindings (g e for encrypt), text objects, leader keys

**Differences from Modern Mode:**
- Interactive region selection vs transparent file processing
- Password caching with timeout vs prompt per operation
- Fancy visual mode (black bars for encrypted) optional
- More customization points (keybinding prefixes, colors)
- Doom-specific Evil integration

## File Modification Patterns

**When Modifying Core Processor:**
- Update `src/processor/core.rs` → runs all processor tests
- Add marker preservation rules → update `src/marker_inference/expander.rs` → add test to `tests/marker_inference_tests.rs`
- Change encryption algorithm → update `src/crypto.rs` AND document in `docs/CRYPTOGRAPHY.md`

**When Adding Command:**
- Create `src/commands/[name].rs`
- Export in `src/commands/mod.rs`
- Add to CLI in `src/main.rs`
- Add integration test to `tests/command_integration.rs` or create new test file

**When Modifying Emacs Mode:**
- Modern: Edit `emacs/sss-mode.el`, recompile with `emacs -batch -f batch-byte-compile emacs/sss-mode.el`
- Legacy: Edit appropriate `plugins/emacs/[module].el` file

**When Changing Cryptography:**
- Update `src/crypto.rs` implementation
- Update documentation: `docs/CRYPTOGRAPHY.md`
- Update tests: `tests/crypto_security_tests.rs`
- Update marker format docs if marker structure changes

---

*Structure analysis: 2026-02-21*
