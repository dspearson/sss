# Marker Inference Code Review Catalog

**Generated:** 2025-11-04
**Purpose:** Systematic code quality review and refactoring

---

## Source Files Overview

Total: **11 implementation files** (8 modules + mod.rs + parser.rs + types/error)

---

## 1. **types.rs** (90 lines)

**Purpose:** Core data structures

### Structures:
- `Position` (type alias) - Byte offset in text
- `Marker` - Marked region with source/rendered positions
- `ChangeHunk` - Diff-detected change
- `MappedChange` - Change mapped to source coordinates
- `UserMarker` - User-inserted validated marker
- `ValidatedEdit` - User marker validation result
- `MarkerInferenceResult` - Final output result
- `DelimiterPair` - Paired delimiter info

### Functions:
None (all structs)

### Issues to Review:
- [ ] Check if all fields are necessary
- [ ] Consider deriving more traits (Eq, Hash, etc.)
- [ ] Evaluate if Position type alias adds value vs just using usize
- [ ] Review visibility (all pub fields)

---

## 2. **error.rs** (27 lines)

**Purpose:** Error handling

### Enums:
- `MarkerInferenceError` - Error types with thiserror

### Type Aliases:
- `Result<T>` - Standard result type

### Error Variants:
1. `InvalidUtf8(usize)` - Invalid UTF-8 at position
2. `MalformedMarker(Position, String)` - Bad marker syntax
3. `BinaryContent(usize)` - Binary content detected
4. `DiffError(String)` - Diff computation failed
5. `Internal(String)` - Internal processing error

### Issues to Review:
- [ ] Check if all error types are actually used
- [ ] Consider if error messages provide enough context
- [ ] Review if we need source locations for errors

---

## 3. **parser.rs** (190 lines)

**Purpose:** Extract markers from source text (Step 1)

### Public Functions:
1. **`parse_markers(source: &str) -> Result<(String, Vec<Marker>)>`** (81 lines)
   - Extracts o+{...} and ⊕{...} markers from source
   - Returns (rendered_text, markers)
   - Handles escaping, nested markers, unclosed markers

### Private Functions:
2. **`find_unescaped_close(text: &str) -> Option<usize>`** (16 lines)
   - Finds first unescaped closing brace
   - Skips \} escaped braces

### Tests:
- 9 unit tests covering edge cases

### Issues to Review:
- [ ] Large function (81 lines) - consider breaking down
- [ ] UTF-8 handling correctness (char_indices usage)
- [ ] Performance of string operations in loop
- [ ] Escaped marker format consistency (o+\\{ vs ⊕\\{)
- [ ] Consider extracting marker detection to helper function

---

## 4. **diff.rs** (116 lines)

**Purpose:** Compute text differences (Step 2)

### Public Functions:
1. **`compute_diff(rendered: &str, edited: &str) -> Result<Vec<ChangeHunk>>`** (56 lines)
   - Uses similar crate's Myers algorithm
   - Returns vector of changes
   - Merges adjacent insert/delete into replacements

### Issues to Review:
- [ ] current_change mutation pattern - could be cleaner
- [ ] Position tracking correctness
- [ ] Consider using enumerate() for clarity
- [ ] Comment says "edited_pos tracking not needed" - verify this
- [ ] Error handling - what could actually fail?

---

## 5. **validator.rs** (148 lines)

**Purpose:** Validate user-inserted markers (Step 3)

### Public Functions:
1. **`validate_user_markers(edited: &str) -> ValidatedEdit`** (95 lines)
   - Validates user markers in edited text
   - Escapes invalid markers (nested, unclosed)
   - Returns validated text + markers + warnings

### Private Functions:
2. **`find_matching_close(text: &str) -> Option<usize>`** (14 lines)
   - Finds matching closing brace (handles \} escapes)

### Tests:
- 4 unit tests

### Issues to Review:
- [ ] Large function (95 lines) - needs refactoring
- [ ] Code duplication with parser.rs (find_matching_close, marker detection)
- [ ] UTF-8 position tracking
- [ ] Consider extracting marker format handling
- [ ] String manipulation efficiency

---

## 6. **mapper.rs** (114 lines)

**Purpose:** Map changes to source positions (Step 4)

### Public Functions:
1. **`map_changes_to_source(changes: Vec<ChangeHunk>, markers: &[Marker]) -> Vec<MappedChange>`** (43 lines)
   - Converts rendered positions to source positions
   - Identifies overlapping markers

### Private Functions:
2. **`ranges_overlap_or_adjacent(start1: usize, end1: usize, start2: usize, end2: usize) -> bool`** (8 lines)
   - Checks if two ranges overlap or touch

3. **`rendered_to_source_pos(rendered_pos: Position, markers: &[Marker]) -> Position`** (15 lines)
   - Converts single position rendered → source

### Tests:
- 4 unit tests

### Issues to Review:
- [ ] O(n·m) complexity in map_changes_to_source (nested iteration)
- [ ] ranges_overlap_or_adjacent logic could be simplified
- [ ] rendered_to_source_pos recalculates overhead each time
- [ ] Consider caching position mappings
- [ ] Filter predicate could be extracted to helper

---

## 7. **expander.rs** (274 lines)

**Purpose:** Apply 5 expansion rules (Step 5)

### Public Functions:
1. **`apply_expansion_rules(changes: Vec<MappedChange>, original_markers: &[Marker], user_markers: &[UserMarker], edited_text: &str) -> Vec<Marker>`** (127 lines)
   - Implements 5 core expansion rules
   - Merges user markers with original markers
   - Groups changes by overlapping markers
   - Returns new marker set

### Private Functions:
2. **`expand_marker_for_change(marker: &Marker, change: &MappedChange, edited_text: &str) -> Marker`** (24 lines)
   - Expands single marker to cover change
   - **Currently unused - dead code?**

3. **`find_change_boundaries(change: &MappedChange, _edited_text: &str, markers: &[Marker]) -> (usize, usize)`** (23 lines)
   - Finds bounds for multi-marker changes
   - Note: _edited_text parameter unused

4. **`merge_overlapping_markers(markers: Vec<Marker>) -> Vec<Marker>`** (39 lines)
   - Merges overlapping/adjacent markers
   - Handles content concatenation

### Tests:
- 2 unit tests

### Issues to Review:
- [ ] **Very large function** (127 lines) - major refactoring needed
- [ ] **Dead code:** expand_marker_for_change never called
- [ ] Unused parameter _edited_text in find_change_boundaries
- [ ] Complex logic with multiple nested conditions
- [ ] HashMap grouping could be clearer
- [ ] Content extraction has fallback logic - is it needed?
- [ ] merge_overlapping_markers has complex string concatenation logic
- [ ] Consider extracting rule implementations to separate functions
- [ ] Need more comprehensive tests

---

## 8. **propagator.rs** (139 lines)

**Purpose:** Propagate markers to duplicates (Step 6)

### Public Functions:
1. **`propagate_markers(text: &str, markers: &[Marker]) -> Vec<Marker>`** (59 lines)
   - Uses Aho-Corasick for multi-pattern matching
   - Marks all instances of marked content
   - Returns expanded marker set

### Private Functions:
2. **`is_position_marked(start: usize, end: usize, markers: &[Marker]) -> bool`** (6 lines)
   - Checks if range already marked

### Tests:
- 4 unit tests

### Issues to Review:
- [ ] Error handling for AhoCorasick::new - just returns early, good?
- [ ] Performance: rebuilding automaton each call
- [ ] Consider caching automaton between calls
- [ ] Empty content filtering happens inline
- [ ] HashSet for deduplication - is this efficient?
- [ ] Pattern lifetime management (Vec<&str>)

---

## 9. **delimiter.rs** (194 lines)

**Purpose:** Validate paired delimiters (Step 7)

### Public Functions:
1. **`validate_delimiters(text: &str, markers: &mut Vec<Marker>) -> Vec<String>`** (41 lines)
   - Checks 6 delimiter types
   - Ensures pairs are both marked or both unmarked
   - Returns warnings for unmatched pairs

### Private Functions:
2. **`find_delimiter_pairs(text: &str, open: char, close: char) -> Vec<DelimiterPair>`** (51 lines)
   - Finds all delimiter pairs (symmetric and asymmetric)
   - Uses stack for asymmetric, toggle for symmetric

3. **`is_char_marked(pos: usize, markers: &[Marker]) -> bool`** (5 lines)
   - Checks if character position is marked

4. **`expand_marker_to_cover_pair(pair: &DelimiterPair, markers: &mut Vec<Marker>)`** (51 lines)
   - Expands markers to cover delimiter pair
   - Handles overlapping markers

### Tests:
- 3 unit tests

### Issues to Review:
- [ ] find_delimiter_pairs mixes two algorithms (symmetric/asymmetric)
- [ ] Stack-based matching doesn't handle escaping
- [ ] Quote handling is simplistic (no escape sequences)
- [ ] expand_marker_to_cover_pair mutates in complex way
- [ ] Removing markers in reverse - correct but could be clearer
- [ ] Consider splitting symmetric/asymmetric logic
- [ ] Performance: iterates all text for each delimiter type

---

## 10. **reconstructor.rs** (121 lines)

**Purpose:** Build output with markers (Step 8)

### Public Functions:
1. **`reconstruct_with_markers(text: &str, markers: &[Marker]) -> String`** (52 lines)
   - Builds final output with ⊕{...} markers
   - Handles marker sorting
   - Extracts content from text or marker

### Tests:
- 4 unit tests

### Issues to Review:
- [ ] Sorts markers on each call - could be pre-sorted
- [ ] Content extraction has fallback logic
- [ ] String concatenation efficiency (many push_str calls)
- [ ] Consider using String::with_capacity
- [ ] What happens if markers overlap?
- [ ] Boundary checking for text slicing

---

## 11. **mod.rs** (189 lines)

**Purpose:** Main entry point and orchestration

### Public Functions:
1. **`infer_markers(source_text: &str, edited_text: &str) -> Result<MarkerInferenceResult>`** (35 lines)
   - Orchestrates the 8-step algorithm
   - Main entry point for marker inference

### Tests:
- 1 basic integration test

### Issues to Review:
- [ ] Good documentation but could link to algorithm doc
- [ ] Error propagation uses ? operator - good
- [ ] Step 8 comment says "Add warnings" but should say "Collect warnings"
- [ ] Consider if steps could be better pipelined
- [ ] Limited error context at this level

---

## Cross-Cutting Concerns

### Code Duplication:
1. **Marker detection** - parser.rs vs validator.rs
2. **find_*_close functions** - parser.rs vs validator.rs
3. **Position tracking loops** - multiple files
4. **String escaping** - parser.rs vs validator.rs

### Performance:
1. **String allocations** - many throughout
2. **Repeated sorting** - reconstructor.rs
3. **Nested iterations** - mapper.rs O(n·m)
4. **Aho-Corasick rebuilding** - propagator.rs
5. **Delimiter scanning** - delimiter.rs scans 6 times

### Error Handling:
1. **Silent fallbacks** - expander.rs, reconstructor.rs
2. **Error context** - could be improved
3. **Unused error types?** - check error.rs variants

### Testing:
1. **Unit test coverage** - varies by module
2. **Edge case coverage** - good in tests/ but light in modules
3. **Property testing** - only in tests/properties.rs
4. **Performance testing** - only in tests/edge_cases.rs

### UTF-8 Handling:
1. **char_indices() usage** - verify correctness everywhere
2. **Byte offset calculations** - potential bugs
3. **String slicing** - boundary checks

---

## Refactoring Priority

### 🔴 Critical (Must Fix):
1. **expander.rs:apply_expansion_rules** - 127 lines, needs decomposition
2. **validator.rs:validate_user_markers** - 95 lines, needs refactoring
3. **parser.rs:parse_markers** - 81 lines, could be cleaner
4. **Dead code:** expand_marker_for_change in expander.rs

### 🟡 Important (Should Fix):
1. **Code duplication** - extract shared marker parsing logic
2. **Performance issues** - mapper O(n·m), propagator caching
3. **String allocation** - use capacity hints, reduce copies
4. **Error context** - improve error messages

### 🟢 Nice to Have:
1. More comprehensive unit tests in modules
2. Better documentation for complex algorithms
3. Consider builder patterns for complex structures
4. Benchmark suite for performance tracking

---

## Review Workflow

We'll go through each file systematically:

1. ✅ **types.rs** - Review structs
2. ✅ **error.rs** - Review error types
3. ⏳ **parser.rs** - Refactor large function
4. ⏳ **validator.rs** - Deduplicate + refactor
5. ⏳ **diff.rs** - Clean up state management
6. ⏳ **mapper.rs** - Optimize performance
7. ⏳ **expander.rs** - Major refactoring needed
8. ⏳ **propagator.rs** - Performance improvements
9. ⏳ **delimiter.rs** - Split algorithms
10. ⏳ **reconstructor.rs** - Optimize allocation
11. ⏳ **mod.rs** - Minor improvements

---

**Next Steps:** Start with types.rs and error.rs, then move to the larger functions needing refactoring.
