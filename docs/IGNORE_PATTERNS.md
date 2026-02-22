# Ignore Patterns in .sss.toml

## Overview

SSS now supports gitignore-style pattern matching to exclude files from secret scanning operations. Patterns are configured in the `.sss.toml` file and support wildcards, directory matching, and negation.

## Configuration

Add the `ignore` field to your `.sss.toml` file:

```toml
version = "1.0"
created = "2025-12-12T15:00:00Z"
ignore = "*.log build/ !important.log"
```

The `ignore` field is optional. If not specified, all files will be scanned (except default ignored directories like `.git`, `node_modules`, `target`).

## Pattern Syntax

### Basic Patterns

- **Wildcard files**: `*.log` - Matches all `.log` files in any directory
- **Specific files**: `Justfile` - Matches files named `Justfile`
- **Prefix wildcards**: `temp*.txt` - Matches `temp1.txt`, `temporary.txt`, etc.
- **Directories**: `build/` - Matches everything in the `build` directory
- **Multiple patterns**: Space or comma separated: `*.log *.tmp` or `*.log,*.tmp`

### Negation Patterns

Use `!` to exclude files from being ignored:

```toml
ignore = "*.db !important.db !session.db"
```

This ignores all `.db` files EXCEPT `important.db` and `session.db`.

### Directory Patterns

Directory patterns automatically match all contents:

```toml
ignore = "build/ node_modules/ .cache/"
```

This is equivalent to `build/** node_modules/** .cache/**`

## CLI Commands

### List Patterns

```bash
sss project ignore list
```

Output:
```
Ignore patterns (in .sss.toml):
================================
  *.log
  build/
  !important.log

Raw: *.log build/ !important.log
```

### Add Pattern

```bash
sss project ignore add "*.tmp"
```

Adds the pattern to the existing ignore list.

### Remove Pattern

```bash
sss project ignore remove "build/"
```

Removes the specified pattern from the ignore list.

## Examples

### Example 1: Typical Development Project

```toml
ignore = "*.log build/ dist/ node_modules/ .git/ *.tmp !important.log"
```

This configuration:
- Ignores all log files except `important.log`
- Ignores build artifacts (`build/`, `dist/`)
- Ignores dependencies (`node_modules/`)
- Ignores version control (`.git/`)
- Ignores temporary files (`*.tmp`)

### Example 2: Rust Project

```toml
ignore = "target/ Cargo.lock *.rlib *.rmeta"
```

### Example 3: Database Files with Exceptions

```toml
ignore = "*.db *.sqlite !production.db !users.db"
```

Ignores all database files except the production and users databases.

## Pattern Matching Behavior

Patterns are matched against:
1. **Relative paths** from the project root
2. **Filenames** for simple patterns

This means:
- `*.log` matches `debug.log` and `logs/app.log`
- `build/` matches everything under `build/` directory
- `logs/*.log` matches log files specifically in the `logs/` directory

## Implementation Details

### Pattern Resolution Order

1. Check if file matches any positive pattern (e.g., `*.log`)
2. If matched, check if file matches any negation pattern (e.g., `!important.log`)
3. If negation matches, file is NOT ignored
4. Otherwise, file is ignored

### Default Ignored Directories

These directories are always ignored, regardless of `.sss.toml` settings:
- `.git`
- `.svn`
- `node_modules`
- `target` (Rust build directory)
- `.cargo`

## Testing

The implementation includes 20 comprehensive tests covering:
- Pattern parsing (simple, complex, directories, wildcards)
- Negation logic (single and multiple negations)
- FileScanner integration
- Real-world scenarios

All tests pass with 100% success rate.

## API Usage

For programmatic use:

```rust
use sss::project::ProjectConfig;
use sss::scanner::FileScanner;

// Load config
let config = ProjectConfig::load_from_file(".sss.toml")?;

// Parse ignore patterns
let (ignore_set, negation_set) = config.parse_ignore_patterns()?;

// Create scanner with patterns
let mut scanner = FileScanner::new();
scanner.set_ignore_patterns(ignore_set, negation_set);

// Scan directory
let results = scanner.scan_directory(".")?;
```

## Troubleshooting

### Pattern Not Working

If a pattern doesn't seem to work:

1. Check the pattern syntax - use `sss project ignore list` to verify
2. Test with simple patterns first (e.g., `*.log`)
3. Remember that directory patterns need trailing slash: `build/` not `build`
4. Use negation patterns (`!file`) to override ignore rules

### Files Still Being Scanned

If files are still being scanned despite ignore patterns:

1. Verify the pattern matches the file path
2. Check for negation patterns that might override the ignore
3. Ensure `.sss.toml` is in the project root
4. Use relative paths from project root in patterns

## Version History

- **v1.1.8**: Initial implementation of ignore patterns
  - Gitignore-style pattern matching
  - Negation support with `!`
  - CLI commands for pattern management
  - 20 comprehensive tests
