# Intelligent Marker Preservation System

A diff-based algorithm for intelligently preserving encryption markers when text files are edited.

## Overview

This module implements the marker inference system as specified in `docs/marker-design.md`. It enables users to edit decrypted content while automatically maintaining encryption markers based on their modifications.

## Features

- **Security-First Design**: Over-marks rather than risking leakage
- **Both Marker Formats**: Accepts `o+{...}` (manual typing) and `⊕{...}` (canonical)
- **5 Expansion Rules**: Intelligent marker placement based on edit patterns
- **Content Propagation**: Automatically marks all instances of sensitive content
- **Delimiter Validation**: Ensures paired delimiters stay together
- **UTF-8 Safe**: Proper handling of multi-byte characters
- **User Markers**: Validates and processes user-inserted markers

## Architecture

```
┌─────────────────────────────────────────┐
│  infer_markers(source, edited)          │
├─────────────────────────────────────────┤
│                                         │
│  Step 1: Parse Markers                  │
│    └─> parser.rs                        │
│                                         │
│  Step 2: Compute Diff                   │
│    └─> diff.rs (using similar crate)   │
│                                         │
│  Step 3: Validate User Markers          │
│    └─> validator.rs                     │
│                                         │
│  Step 4: Map Changes to Source          │
│    └─> mapper.rs                        │
│                                         │
│  Step 5: Apply Expansion Rules          │
│    └─> expander.rs (5 rules)           │
│                                         │
│  Step 6: Propagate Markers              │
│    └─> propagator.rs (Aho-Corasick)    │
│                                         │
│  Step 7: Validate Delimiters            │
│    └─> delimiter.rs                     │
│                                         │
│  Step 8: Reconstruct Output             │
│    └─> reconstructor.rs                 │
│                                         │
└─────────────────────────────────────────┘
```

## Module Structure

```
marker_inference/
├── mod.rs              - Main API and orchestration
├── types.rs            - Data structures
├── error.rs            - Error types
├── parser.rs           - Step 1: Parse markers from source
├── diff.rs             - Step 2: Compute text differences
├── validator.rs        - Step 3: Validate user markers
├── mapper.rs           - Step 4: Map changes to source
├── expander.rs         - Step 5: Apply expansion rules
├── propagator.rs       - Step 6: Propagate to duplicates
├── delimiter.rs        - Step 7: Validate delimiter pairs
└── reconstructor.rs    - Step 8: Build final output
```

## Usage

```rust
use sss::marker_inference::infer_markers;

// Original file with markers
let source = "password: o+{secret123}\napi_key: o+{abc-def}";

// User's edits (markers removed for editing)
let edited = "password: newsecret456\napi_key: xyz-uvw";

// Infer marker placement
let result = infer_markers(source, edited)?;

// Result: "password: ⊕{newsecret456}\napi_key: ⊕{xyz-uvw}"
assert!(result.output.contains("⊕{newsecret456}"));
assert!(result.output.contains("⊕{xyz-uvw}"));

// Check warnings
for warning in &result.warnings {
    eprintln!("Warning: {}", warning);
}
```

## The 5 Expansion Rules

### Rule 1: Replacement of Marked Content
Changes spanning multiple markers → mark entire span
```
Source:   o+{a} middle o+{b}
Edited:   replaced
Result:   ⊕{replaced}
```

### Rule 2: Adjacent Modifications
Change adjacent to single marker → expand that marker
```
Source:   o+{a} b
Edited:   ax b
Result:   ⊕{ax} b
```

### Rule 3: Ambiguous Adjacency (Left-Bias)
Adjacent to multiple markers → merge with left
```
Source:   o+{a}o+{b}
Edited:   axb
Result:   ⊕{ax}⊕{b}
```

### Rule 4: Preservation of Separate Markers
Change affects only one → preserve separation
```
Source:   o+{a}o+{b}
Edited:   axb
Result:   ⊕{ax}⊕{b}
```

### Rule 5: Unmarked Content
No adjacent markers → handled by propagation
```
Source:   o+{secret} public
Edited:   secret and secret
Result:   ⊕{secret} and ⊕{secret}
```

## Content Propagation

If any instance of content is marked, all instances are marked:

```
Source:   o+{password}
Edited:   password appears twice: password
Result:   ⊕{password} appears twice: ⊕{password}
```

## Delimiter Validation

Paired delimiters must both be marked or both be unmarked:

```
Source:   key: "o+{value}"
Edited:   key: "modified"
Result:   key: "⊕{modified}"
```

## Performance

- **Small files (<10KB)**: < 10ms
- **Medium files (<100KB)**: < 50ms
- **Large files (<1MB)**: < 500ms

Optimizations:
- Aho-Corasick for multi-pattern matching
- Single-pass parsing
- Efficient diff algorithm (Myers)

## Testing

Comprehensive test coverage includes:

- **Unit tests**: Each module (parser, diff, validator, etc.)
- **Integration tests**: 24 examples from design document
- **Edge case tests**: 60+ edge cases from specification
- **Property-based tests**: 15 invariant checks with proptest

Run tests:
```bash
cargo test marker_inference
```

Run benchmarks:
```bash
cargo bench marker_inference
```

## Error Handling

### Errors (Fatal)
- `InvalidUtf8`: Input is not valid UTF-8
- `MalformedMarker`: Marker syntax is invalid
- `BinaryContent`: Binary content detected
- `DiffError`: Diff computation failed
- `Internal`: Internal processing error

### Warnings (Non-Fatal)
- Unmatched delimiter pairs
- Escaped invalid markers
- Nested marker escaping

## Integration with FUSE

The module is integrated into the FUSE layer at `src/fuse_fs.rs::write_and_seal()`:

```rust
// Before: Basic marker reconstruction
let reconstructed = crate::merge::smart_reconstruct(...)?;

// After: Intelligent marker inference
let result = crate::marker_inference::infer_markers(source, edited)?;
let reconstructed = result.output;
```

## Security Considerations

1. **Conservative Expansion**: Prefers over-marking to under-marking
2. **No Information Leakage**: All sensitive content instances are marked
3. **DoS Prevention**: Input size limits and bounded operations
4. **UTF-8 Safety**: Proper boundary validation prevents panics
5. **Deterministic**: No randomness, same input → same output

## Design Document

Full specification: `docs/marker-design.md`

Key sections:
- Section 4: Core Algorithm (8 steps)
- Section 5: Marker Expansion Rules (5 rules)
- Section 6: User-Inserted Markers
- Section 7: Content Propagation
- Section 8: Paired Delimiter Handling
- Section 9: Edge Cases
- Section 11: Testing Strategy
- Section 12: Performance Requirements

## Dependencies

- `similar`: Text diffing (Myers algorithm)
- `aho-corasick`: Multi-pattern string matching
- `thiserror`: Error handling macros

## Future Enhancements

Potential improvements:
- Streaming mode for very large files (>10MB)
- Configurable propagation rules
- Performance profiling mode
- Extended marker format support
- Context-aware heuristics (optional)

## Contributing

When modifying this module:
1. Run all tests: `cargo test marker_inference`
2. Run benchmarks: `cargo bench marker_inference`
3. Update documentation
4. Add edge case tests if needed
5. Verify FUSE integration still works

## License

Part of the SSS (Secret Sharing System) project.
See project root for license information.
