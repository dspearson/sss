# Intelligent Marker Preservation System - Design Document

**Version:** 1.0  
**Date:** 2025-10-26  
**Status:** Final Draft for Implementation

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Overview](#2-system-overview)
3. [Terminology](#3-terminology)
4. [Core Algorithm](#4-core-algorithm)
5. [Marker Expansion Rules](#5-marker-expansion-rules)
6. [User-Inserted Markers](#6-user-inserted-markers)
7. [Content Propagation](#7-content-propagation)
8. [Paired Delimiter Handling](#8-paired-delimiter-handling)
9. [Edge Cases](#9-edge-cases)
10. [Implementation Guide](#10-implementation-guide)
11. [Testing Strategy](#11-testing-strategy)
12. [Performance Requirements](#12-performance-requirements)
13. [Security Considerations](#13-security-considerations)
14. [References](#14-references)
15. [Appendices](#15-appendices)

---

## 1. Executive Summary

### 1.1 Purpose

This document specifies the design and implementation of an intelligent marker preservation system for encrypted content regions in text files. The system enables users to edit decrypted content whilst automatically maintaining encryption markers based on their modifications.

### 1.2 Problem Statement

Configuration files, YAML documents, and other text files often contain sensitive data (passwords, API keys, certificates) that should be encrypted. A FUSE layer can decrypt these files for editing, but when users save changes, the system must intelligently determine which content should remain encrypted.

### 1.3 Solution Approach

The system uses a diff-based algorithm with conservative expansion rules to:
- Preserve encryption markers on modified sensitive content
- Expand markers to cover adjacent modifications
- Propagate markers to duplicate sensitive content
- Handle user-inserted markers correctly
- Maintain security by over-marking rather than leaking

### 1.4 Key Principles

1. **Security-First**: When uncertain, mark content rather than risk leakage
2. **Intent Preservation**: Respect the semantic structure of separately-marked regions
3. **Format-Agnostic**: No file-type-specific intelligence; purely text-based
4. **Predictable**: Conservative, rule-based behaviour without "magic"
5. **User Control**: Allow explicit marker insertion with validation

---

## 2. System Overview

### 2.1 Architecture Context

```
┌─────────────────────────────────────────────────┐
│              User's Editor (vi, etc.)           │
└─────────────────┬───────────────────────────────┘
                  │ Reads/Writes
                  ↓
┌─────────────────────────────────────────────────┐
│            FUSE Filesystem Layer                │
│  ┌───────────────────────────────────────────┐  │
│  │  On Read:  Decrypt ⊠{...} → o+{...}      │  │
│  │            Remove markers for display      │  │
│  └───────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────┐  │
│  │  On Write: Apply Marker Inference         │  │
│  │            (This System)                   │  │
│  │            Encrypt o+{...} → ⊠{...}       │  │
│  └───────────────────────────────────────────┘  │
└─────────────────┬───────────────────────────────┘
                  │ Reads/Writes
                  ↓
┌─────────────────────────────────────────────────┐
│         Underlying Encrypted File Storage       │
│         (Contains ⊠{CIPHERTEXT} markers)        │
└─────────────────────────────────────────────────┘
```

### 2.2 Marker Syntax

| Marker Type | Syntax | Meaning | Notes |
|-------------|--------|---------|-------|
| Plaintext Marker | `o+{content}` or `⊕{content}` | Content to be encrypted | `o+{...}` for manual typing, `⊕{...}` preferred for tool output |
| Ciphertext Marker | `⊠{ciphertext}` | Encrypted content | Not handled by this system |

**Important Notes**:
- Both `o+{...}` and `⊕{...}` are **functionally equivalent** and mark plaintext content for encryption
- The system accepts **both formats** as input when parsing
- The system outputs using `⊕{...}` format (preferred canonical form)
- Users typically type `o+{...}` manually (easier on standard keyboards)
- The FUSE layer handles encryption/decryption between `o+{...}`/`⊕{...}` and `⊠{...}`

### 2.3 Data Flow

```
Input: Source Text (with o+{} markers)
   ↓
Parse & Extract Markers
   ↓
Generate Rendered Text (markers removed)
   ↓
User Edits → Edited Text
   ↓
Validate User-Inserted Markers
   ↓
Compute Diff (Rendered vs Edited)
   ↓
Map Changes to Source Positions
   ↓
Apply Marker Expansion Rules
   ↓
Propagate Markers to Duplicates
   ↓
Validate Paired Delimiters
   ↓
Reconstruct Output (with o+{} markers)
   ↓
Output: Marked Text
```

### 2.4 Use Cases

1. **Configuration Files**: Passwords, API keys in YAML/JSON/TOML
2. **Certificates**: TLS keys, SSH keys with inline encryption
3. **Environment Files**: `.env` files with sensitive values
4. **Infrastructure as Code**: Terraform, Kubernetes manifests with secrets
5. **Documentation**: Technical docs with embedded credentials

---

## 3. Terminology

| Term | Definition | Example |
|------|------------|---------|
| **Source text** | Original file content with `o+{...}` markers | `password: o+{secret123}` |
| **Rendered text** | Source text with markers removed (what user sees) | `password: secret123` |
| **Edited text** | User's modifications to rendered text | `password: newsecret456` |
| **Marked region** | Content enclosed in `o+{...}` markers | `o+{secret123}` |
| **Changed region** | Portion of text that differs between rendered and edited | Position 10-23 changed |
| **Adjoining** | A changed region that touches/overlaps a marked region | Change at position immediately after marker |
| **Boundary** | Unchanged text that separates changed regions | Static text between edits |
| **Paired delimiter** | Matching pairs: `"..."`, `[...]`, `{...}`, etc. | Opening `"` and closing `"` |
| **User marker** | `o+{...}` marker explicitly inserted by user in edited text | User types `o+{new}` |
| **Propagation** | Marking all instances of content that appears in any marker | If `o+{secret}` exists, mark all `secret` |
| **Adjacency** | Two positions with zero characters between them | Positions 5 and 5 are adjacent |
| **Left-bias** | When ambiguous, prefer the leftmost marker | `o+{a}o+{b}` + insert → expand left |

---

## 4. Core Algorithm

### 4.1 Algorithm Overview

```rust
fn infer_markers(source_text: &str, edited_text: &str) 
    -> Result<MarkerInferenceResult, MarkerInferenceError> 
{
    // Step 1: Parse source to extract markers
    let (rendered_text, original_markers) = parse_markers(source_text)?;
    
    // Step 2: Compute diff between rendered and edited
    let changes = compute_diff(&rendered_text, edited_text);
    
    // Step 3: Validate user-inserted markers in edited text
    let validated = validate_user_markers(edited_text);
    
    // Step 4: Map changes back to source positions
    let mapped_changes = map_changes_to_source(changes, &original_markers);
    
    // Step 5: Apply marker expansion rules
    let mut new_markers = apply_expansion_rules(
        mapped_changes,
        original_markers,
        validated.user_markers
    );
    
    // Step 6: Propagate markers to unmarked duplicates
    new_markers = propagate_markers(&validated.text, &new_markers);
    
    // Step 7: Validate paired delimiter integrity
    let mut warnings = validate_delimiters(&validated.text, &mut new_markers);
    
    // Step 8: Add warnings for escaped markers
    warnings.extend(validated.warnings);
    
    // Step 9: Reconstruct output with markers
    let output = reconstruct_with_markers(&validated.text, &new_markers);
    
    Ok(MarkerInferenceResult { output, warnings })
}
```

### 4.2 Data Structures

```rust
/// Position in text (byte offset, UTF-8 aware)
type Position = usize;

/// A marked region in the source text
#[derive(Debug, Clone)]
struct Marker {
    /// Start position in source text
    source_start: Position,
    /// End position in source text (exclusive)
    source_end: Position,
    /// Start position in rendered text
    rendered_start: Position,
    /// End position in rendered text (exclusive)
    rendered_end: Position,
    /// The content within the marker
    content: String,
}

/// A change detected by diff algorithm
#[derive(Debug)]
struct ChangeHunk {
    /// Start position in rendered text
    rendered_start: Position,
    /// End position in rendered text (exclusive)
    rendered_end: Position,
    /// Original content (from rendered text)
    old_content: String,
    /// New content (from edited text)
    new_content: String,
}

/// A change mapped back to source coordinates
#[derive(Debug)]
struct MappedChange {
    /// Start position in source text
    source_start: Position,
    /// End position in source text (exclusive)
    source_end: Position,
    /// Start position in rendered text
    rendered_start: Position,
    /// End position in rendered text (exclusive)
    rendered_end: Position,
    /// New content to insert
    new_content: String,
    /// Indices of markers that overlap this change
    overlapping_markers: Vec<usize>,
}

/// User-inserted marker (validated)
#[derive(Debug)]
struct UserMarker {
    /// Position in edited text where marker starts
    start: Position,
    /// Position in edited text where marker ends (after })
    end: Position,
    /// Content within the marker
    content: String,
}

/// Result of user marker validation
#[derive(Debug)]
struct ValidatedEdit {
    /// Edited text with invalid markers escaped
    text: String,
    /// Valid user-inserted markers
    user_markers: Vec<UserMarker>,
    /// Warnings generated during validation
    warnings: Vec<String>,
}

/// Result of the marker inference process
#[derive(Debug)]
pub struct MarkerInferenceResult {
    /// The text with markers applied
    pub output: String,
    /// List of warnings (e.g., unmatched delimiters)
    pub warnings: Vec<String>,
}

/// Errors that can occur during marker inference
#[derive(Debug, thiserror::Error)]
pub enum MarkerInferenceError {
    #[error("Invalid UTF-8 in input")]
    InvalidUtf8,
    
    #[error("Malformed marker at position {0}")]
    MalformedMarker(Position),
    
    #[error("Binary content detected (text-only supported)")]
    BinaryContent,
    
    #[error("Diff computation failed: {0}")]
    DiffError(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
}
```

### 4.3 Step 1: Parse Markers

**Purpose**: Extract all `o+{...}` markers from source text and generate rendered version.

**Algorithm**:

```rust
fn parse_markers(source: &str) -> Result<(String, Vec<Marker>), ParseError> {
    let mut markers = Vec::new();
    let mut rendered = String::new();
    let mut source_pos = 0;
    let mut rendered_pos = 0;
    
    while source_pos < source.len() {
        // Check for escaped markers (both formats)
        if source[source_pos..].starts_with("o+\\{") {
            // Escaped o+{ format
            rendered.push_str("o+\\{");
            source_pos += 4;
            rendered_pos += 4;
        } else if source[source_pos..].starts_with("⊕\\{") {
            // Escaped ⊕{ format
            rendered.push_str("⊕\\{");
            source_pos += "⊕\\{".len();
            rendered_pos += "⊕\\{".len();
        } else if source[source_pos..].starts_with("o+{") || source[source_pos..].starts_with("⊕{") {
            // Potential marker start (either format)
            let is_oplus = source[source_pos..].starts_with("o+{");
            let marker_start = source_pos;
            let prefix_len = if is_oplus { 3 } else { "⊕{".len() };
            let content_start = source_pos + prefix_len;
            
            // Find matching }
            if let Some(close_pos) = find_unescaped_close(&source[content_start..]) {
                let abs_close = content_start + close_pos;
                let content = &source[content_start..abs_close];
                
                // Check for nested markers (both formats)
                if content.contains("o+{") || content.contains("⊕{") {
                    // Nested markers not allowed - escape the outer marker
                    if is_oplus {
                        rendered.push_str("o+\\{");
                        source_pos += 3;
                        rendered_pos += 4;
                    } else {
                        rendered.push_str("⊕\\{");
                        source_pos += "⊕{".len();
                        rendered_pos += "⊕\\{".len();
                    }
                } else {
                    // Valid marker
                    markers.push(Marker {
                        source_start: marker_start,
                        source_end: abs_close + 1,
                        rendered_start: rendered_pos,
                        rendered_end: rendered_pos + content.len(),
                        content: content.to_string(),
                    });
                    rendered.push_str(content);
                    rendered_pos += content.len();
                   4: Map Changes to Source Positions

**Purpose**: Map the changed regions (in rendered text coordinates) back to source text coordinates, accounting for marker syntax overhead.

**Input**:
- Change hunks (in rendered coordinates)
- Original markers (with both source and rendered positions)

**Output**: Vector of `MappedChange` structs

**Algorithm**:

```rust
fn map_changes_to_source(
    changes: Vec<ChangeHunk>,
    markers: &[Marker],
) -> Vec<MappedChange> {
    let mut mapped = Vec::new();
    
    for change in changes {
        // Find all markers that overlap or are adjacent to this change
        let overlapping: Vec<usize> = markers
            .iter()
            .enumerate()
            .filter(|(_, m)| {
                // Check if marker overlaps or is adjacent to change
                ranges_overlap_or_adjacent(
                    m.rendered_start, m.rendered_end,
                    change.rendered_start, change.rendered_end
                )
            })
            .map(|(idx, _)| idx)
            .collect();
        
        // Convert rendered positions to source positions
        let source_start = rendered_to_source_pos(
            change.rendered_start, 
            markers
        );
        let source_end = rendered_to_source_pos(
            change.rendered_end,
            markers
        );
        
        mapped.push(MappedChange {
            source_start,
            source_end,
            rendered_start: change.rendered_start,
            rendered_end: change.rendered_end,
            new_content: change.new_content,
            overlapping_markers: overlapping,
        });
    }
    
    mapped
}

fn ranges_overlap_or_adjacent(
    start1: usize, end1: usize,
    start2: usize, end2: usize,
) -> bool {
    // Overlap: [start1, end1) and [start2, end2) share any positions
    // Adjacent: end1 == start2 or end2 == start1
    !(end1 < start2 || end2 < start1) || end1 == start2 || end2 == start1
}

fn rendered_to_source_pos(rendered_pos: usize, markers: &[Marker]) -> usize {
    let mut source_pos = rendered_pos;
    
    // Add marker syntax overhead for all markers before this position
    for marker in markers {
        if marker.rendered_start < rendered_pos {
            // This marker comes before our position
            // Add the overhead: "o+{" (3 bytes) or "⊕{" + "}" (1 byte)
            // Simplified: assume 4 bytes overhead per marker
            let marker_overhead = (marker.source_end - marker.source_start) 
                                - (marker.rendered_end - marker.rendered_start);
            source_pos += marker_overhead;
        }
    }
    
    source_pos
}
```

**Note on Adjacency**:
- Two regions are adjacent if `end1 == start2` (zero bytes between them)
- Punctuation and whitespace do NOT automatically break adjacency within a change
- However, for expansion rules, punctuation breaks adjacency between separate markers

### 4.7 Step 5: Apply Marker Expansion Rules

**Purpose**: Determine which content should be marked based on what changed and where.

This is the core intelligence of the system. See [Section 5: Marker Expansion Rules](#5-marker-expansion-rules) for detailed rules.

**High-level algorithm**:

```rust
fn apply_expansion_rules(
    changes: Vec<MappedChange>,
    original_markers: Vec<Marker>,
    user_markers: Vec<UserMarker>,
) -> Vec<Marker> {
    // Convert user markers to standard Marker format
    let mut all_markers = original_markers.clone();
    all_markers.extend(user_markers_to_markers(user_markers));
    
    let mut new_markers = Vec::new();
    
    for change in changes {
        if change.overlapping_markers.is_empty() {
            // Rule 5: Unmarked content modification
            // Will be handled by propagation if content matches any marker
            continue;
        } else if change.overlapping_markers.len() == 1 {
            // Rule 2 or 4: Adjacent to single marker
            let marker_idx = change.overlapping_markers[0];
            let marker = &all_markers[marker_idx];
            
            // Expand marker to cover change
            new_markers.push(expand_marker_for_change(marker, &change));
        } else {
            // Rule 1: Multiple markers involved
            // Determine boundaries and mark entire changed span
            let boundaries = find_unchanged_boundaries(&change, edited_text);
            new_markers.push(create_marker_for_span(
                boundaries.start,
                boundaries.end,
                &change.new_content
            ));
        }
    }
    
    // Merge overlapping markers
    new_markers = merge_adjacent_markers(new_markers);
    
    new_markers
}
```

### 4.8 Step 6: Propagate Markers to Duplicates

**Purpose**: Find all instances of marked content elsewhere in the file and mark them too.

**Rationale**: If content is sensitive enough to mark once, all instances should be protected.

**Algorithm**:

```rust
fn propagate_markers(text: &str, markers: &[Marker]) -> Vec<Marker> {
    let mut result = markers.to_vec();
    let mut seen_content = std::collections::HashSet::new();
    
    // Collect all unique marked content
    for marker in markers {
        seen_content.insert(marker.content.clone());
    }
    
    // For each unique marked content, find all occurrences
    for content in seen_content {
        let mut search_pos = 0;
        
        while let Some(found_pos) = text[search_pos..].find(&content) {
            let abs_pos = search_pos + found_pos;
            let end_pos = abs_pos + content.len();
            
            // Check if this position is already marked
            if !is_position_marked(abs_pos, end_pos, &result) {
                result.push(Marker {
                    source_start: abs_pos,
                    source_end: end_pos,
                    rendered_start: abs_pos,
                    rendered_end: end_pos,
                    content: content.clone(),
                });
            }
            
            search_pos = abs_pos + 1;
        }
    }
    
    // Sort markers by position
    result.sort_by_key(|m| m.source_start);
    
    result
}

fn is_position_marked(start: usize, end: usize, markers: &[Marker]) -> bool {
    markers.iter().any(|m| {
        // Check if [start, end) is fully contained within marker
        m.source_start <= start && end <= m.source_end
    })
}
```

**Match Criteria**:
- Exact string match (case-sensitive)
- No substring matching: `o+{password}` does NOT mark `pass`
- No whitespace normalisation: `secret  value` ≠ `secret value`
- Escape regex special characters when using search algorithms

**Performance Note**: For files with many markers or large content, consider using Aho-Corasick algorithm for multi-pattern matching.

### 4.9 Step 7: Validate Paired Delimiters

**Purpose**: Ensure opening and closing delimiters are both marked or both unmarked.

**Paired delimiters**: `"..."`, `'...'`, `[...]`, `{...}`, `(...)`, `<...>`

**Algorithm**:

```rust
fn validate_delimiters(text: &str, markers: &mut Vec<Marker>) -> Vec<String> {
    let mut warnings = Vec::new();
    let pairs = vec![
        ('\"', '\"'),
        ('\'', '\''),
        ('[', ']'),
        ('{', '}'),
        ('(', ')'),
        ('<', '>'),
    ];
    
    for (open, close) in pairs {
        let delimiter_pairs = find_delimiter_pairs(text, open, close);
        
        for pair in delimiter_pairs {
            let open_marked = is_char_marked(pair.open_pos, markers);
            let close_marked = is_char_marked(pair.close_pos, markers);
            
            if open_marked != close_marked {
                // Expand marker to cover both delimiters (conservative)
                expand_marker_to_cover_pair(&pair, markers);
                warnings.push(format!(
                    "Unmatched delimiter pair '{}' at positions {}-{}, expanded marker",
                    open, pair.open_pos, pair.close_pos
                ));
            }
        }
    }
    
    warnings
}

#[derive(Debug)]
struct DelimiterPair {
    open_pos: usize,
    close_pos: usize,
    open_char: char,
    close_char: char,
}

fn find_delimiter_pairs(
    text: &str, 
    open: char, 
    close: char
) -> Vec<DelimiterPair> {
    let mut pairs = Vec::new();
    let mut stack = Vec::new();
    
    for (pos, ch) in text.char_indices() {
        if ch == open {
            stack.push(pos);
        } else if ch == close {
            if let Some(open_pos) = stack.pop() {
                pairs.push(DelimiterPair {
                    open_pos,
                    close_pos: pos,
                    open_char: open,
                    close_char: close,
                });
            }
        }
    }
    
    // Process innermost pairs first
    pairs.sort_by_key(|p| p.close_pos - p.open_pos);
    
    pairs
}

fn is_char_marked(pos: usize, markers: &[Marker]) -> bool {
    markers.iter().any(|m| m.source_start <= pos && pos < m.source_end)
}

fn expand_marker_to_cover_pair(pair: &DelimiterPair, markers: &mut Vec<Marker>) {
    // Find markers that overlap the pair
    let overlapping: Vec<usize> = markers
        .iter()
        .enumerate()
        .filter(|(_, m)| {
            (m.source_start <= pair.open_pos && pair.open_pos < m.source_end) ||
            (m.source_start <= pair.close_pos && pair.close_pos < m.source_end)
        })
        .map(|(idx, _)| idx)
        .collect();
    
    if overlapping.is_empty() {
        // No existing marker, create one covering the pair
        markers.push(Marker {
            source_start: pair.open_pos,
            source_end: pair.close_pos + 1,
            rendered_start: pair.open_pos,
            rendered_end: pair.close_pos + 1,
            content: String::new(), // Will be filled later
        });
    } else {
        // Expand existing marker(s) to cover both delimiters
        let min_start = overlapping.iter()
            .map(|&idx| markers[idx].source_start)
            .min()
            .unwrap()
            .min(pair.open_pos);
        let max_end = overlapping.iter()
            .map(|&idx| markers[idx].source_end)
            .max()
            .unwrap()
            .max(pair.close_pos + 1);
        
        // Remove old markers
        let mut idx = 0;
        markers.retain(|_| {
            let keep = !overlapping.contains(&idx);
            idx += 1;
            keep
        });
        
        // Add expanded marker
        markers.push(Marker {
            source_start: min_start,
            source_end: max_end,
            rendered_start: min_start,
            rendered_end: max_end,
            content: String::new(), // Will be filled later
        });
    }
}
```

### 4.10 Step 8: Reconstruct Output

**Purpose**: Generate final text with markers in the canonical `⊕{...}` format.

**Algorithm**:

```rust
fn reconstruct_with_markers(text: &str, markers: &[Marker]) -> String {
    let mut output = String::new();
    let mut pos = 0;
    
    // Sort markers by position
    let mut sorted_markers = markers.to_vec();
    sorted_markers.sort_by_key(|m| m.source_start);
    
    for marker in sorted_markers {
        // Add any text before this marker
        if pos < marker.source_start {
            output.push_str(&text[pos..marker.source_start]);
        }
        
        // Add marker in canonical format (⊕{...})
        output.push_str("⊕{");
        output.push_str(&marker.content);
        output.push('}');
        
        pos = marker.source_end;
    }
    
    // Add any remaining text after last marker
    if pos < text.len() {
        output.push_str(&text[pos..]);
    }
    
    output
}
```

**Note**: The output always uses `⊕{...}` format (canonical form), even if input contained `o+{...}`.

---

## 5. Marker Expansion Rules

This section details the five core rules that determine when and how markers are expanded.

### 5.1 Rule 1: Replacement of Marked Content

**Condition**: Changed region overlaps one or more marked regions.

**Action**: Expand markers to encompass the entire changed region, bounded by unchanged text or file edges.

**Examples**:

```
Source:   o+{a} middle o+{b}
Rendered: a middle b
Edited:   replaced
Result:   ⊕{replaced}
Reason:   Change spans both markers, no boundaries
```

```
Source:   prefix o+{a} middle o+{b} suffix
Rendered: prefix a middle b suffix
Edited:   prefix replaced suffix  
Result:   prefix ⊕{replaced} suffix
Reason:   Change bounded by unchanged "prefix" and "suffix"
```

```
Source:   o+{a} middle o+{b}
Rendered: a middle b
Edited:   start replaced end
Result:   ⊕{start replaced end}
Reason:   Change extends beyond original markers, no boundaries
```

```
Source:   o+{SECRET_KEY_HERE}
Rendered: SECRET_KEY_HERE
Edited:   COMPLETELY_NEW_KEY
Result:   ⊕{COMPLETELY_NEW_KEY}
Reason:   Entire marked region replaced, no context to limit expansion
```

### 5.2 Rule 2: Adjacent Modifications

**Condition**: Changed region is adjacent to exactly one marked region and does not overlap any other markers.

**Action**: Expand the adjacent marker to include the change.

**Examples**:

```
Source:   o+{a} b
Rendered: a b
Edited:   ax b
Result:   ⊕{ax} b
Reason:   "x" added adjacent to o+{a}
```

```
Source:   a o+{b}
Rendered: a b
Edited:   a bx
Result:   a ⊕{bx}
Reason:   "x" added adjacent to o+{b}
```

```
Source:   o+{value}
Rendered: value
Edited:   valuemore
Result:   ⊕{valuemore}
Reason:   "more" added adjacent to marker
```

### 5.3 Rule 3: Ambiguous Adjacency (Left-Bias)

**Condition**: Changed region is adjacent to multiple marked regions (no separator between markers).

**Action**: Merge with the leftmost marker.

**Rationale**: Preserves separate marker semantics whilst providing predictable behaviour.

**Examples**:

```
Source:   o+{a}o+{b}
Rendered: ab
Edited:   axb
Result:   ⊕{ax}⊕{b}
Reason:   "x" touches both markers, left-bias applies
```

```
Source:   o+{a}o+{b}
Rendered: ab
Edited:   abc
Result:   ⊕{ab}⊕{c}
Reason:   "c" added at boundary, left-bias applies
```

### 5.4 Rule 4: Preservation of Separate Markers

**Condition**: Multiple adjacent markers exist, but change only affects one.

**Action**: Do not merge markers; preserve semantic separation.

**Rationale**: Separate markers were intentionally separated, indicating different semantic regions.

**Examples**:

```
Source:   o+{a}o+{b}
Rendered: ab
Edited:   axb
Result:   ⊕{ax}⊕{b}
Reason:   Change only affects "a", preserve separate o+{b}
```

```
Source:   o+{a}o+{b}
Rendered: ab
Edited:   replaced
Result:   ⊕{replaced}
Reason:   Change spans both markers entirely, merge them
```

**Key distinction**: If change only modifies part of the marked regions → preserve separation. If change replaces all of them → merge.

### 5.5 Rule 5: Unmarked Content Modifications

**Condition**: Changed region does not overlap or adjoin any markers.

**Action**: Leave unmarked initially (will be handled by propagation pass if content matches any marker).

**Examples**:

```
Source:   o+{a} middle o+{b}
Rendered: a middle b
Edited:   a modified b
Result:   ⊕{a} modified ⊕{b}
Reason:   Change to "middle" doesn't touch markers, stays unmarked
```

```
Source:   o+{secret} public
Rendered: secret public
Edited:   secret public
Result:   ⊕{secret} public
Reason:   No change, markers preserved as-is
```

### 5.6 Adjacency and Boundary Detection

**Adjacency Rules**:
- Two positions are adjacent if there are zero bytes between them
- Within a marked region: whitespace does NOT break adjacency
- Between regions: punctuation and delimiters DO break adjacency

**Examples**:

```
Source:   o+{a},o+{b}
Change:   Add comma between "," and "b"
Result:   ⊕{a},⊕{,b}
Reason:   The added "," is adjacent to o+{b}, the existing "," breaks adjacency to left
```

```
Source:   o+{hello} world
Change:   Modify "hello" to "hellox"
Result:   ⊕{hellox} world
Reason:   Space doesn't break adjacency within the marked content
```

**Boundary Detection**:

Boundaries are portions of unchanged text that separate changed regions. When a change spans multiple markers:

1. Find the leftmost unchanged text before the change (or start of file)
2. Find the rightmost unchanged text after the change (or end of file)
3. Mark everything between these boundaries

---

## 6. User-Inserted Markers

### 6.1 Overview

Users can explicitly insert markers (`o+{...}` or `⊕{...}`) in their edited text. The system must validate these and handle various edge cases.

### 6.2 Validation Rules

| Input | Handling | Result |
|-------|----------|--------|
| Valid marker: `o+{secret}` | Preserve | `⊕{secret}` |
| Valid marker: `⊕{secret}` | Preserve | `⊕{secret}` |
| Unclosed: `o+{secret` | Escape | `o+\{secret` |
| Nested: `o+{outer o+{inner}}` | Escape inner | `⊕{outer o+\{inner}}` |
| Already escaped: `o+\{literal}` | Preserve | `o+\{literal}` |
| Escaped close: `o+{text \} more}` | Valid marker with `}` in content | `⊕{text } more}` |

### 6.3 Examples

#### Example 1: Valid User Marker

```
Source:   text to edit about that
Rendered: text to edit about that
Edited:   text to edit o+{how about that}
Result:   text to edit ⊕{how about that}
```

#### Example 2: Unclosed Marker

```
Source:   text to edit about that
Rendered: text to edit about that
Edited:   text to edit o+{how about that
Result:   text to edit o+\{how about that
Warning:  "Escaped unclosed marker at position 13"
```

#### Example 3: Nested Markers

```
Source:   text about more text
Rendered: text about more text  
Edited:   text o+{and o+{more text}}
Result:   text ⊕{and o+\{more text}}
Warning:  "Escaped nested marker at position 12"
```

#### Example 4: User Marker + Propagation

```
Source:   public secret public
Rendered: public secret public
Edited:   public o+{secret} secret
Result:   public ⊕{secret} ⊕{secret}
Reason:   User marked first "secret", propagation marked second
```

#### Example 5: Mixed Formats

```
Source:   old: o+{secret1}
Rendered: old: secret1
Edited:   old: ⊕{secret1} new: o+{secret2}
Result:   old: ⊕{secret1} new: ⊕{secret2}
Reason:   Both formats accepted, output uses canonical ⊕{...}
```

### 6.4 Integration with Expansion Rules

User-inserted markers are treated as "already marked" regions when applying expansion rules. This means:

1. They are included in the `overlapping_markers` calculation
2. Adjacent changes get merged with them per Rule 2
3. They participate in propagation like any other marker
4. They are converted to canonical `⊕{...}` format in output

---

## 7. Content Propagation

### 7.1 Purpose

Ensure that sensitive content is consistently marked throughout the file. If any instance of content is marked, all instances must be marked.

### 7.2 Algorithm Details

```rust
fn propagate_markers(text: &str, markers: &[Marker]) -> Vec<Marker> {
    let mut result = markers.to_vec();
    let mut seen = std::collections::HashSet::new();
    
    // Collect all unique marked content
    for marker in markers {
        seen.insert(marker.content.clone());
    }
    
    // Search for each unique content
    for content in seen {
        if content.is_empty() {
            continue; // Skip empty markers
        }
        
        // Use efficient string search
        let mut pos = 0;
        while pos < text.len() {
            if let Some(found) = text[pos..].find(&content) {
                let abs_pos = pos + found;
                let end_pos = abs_pos + content.len();
                
                if !is_position_marked(abs_pos, end_pos, &result) {
                    result.push(Marker {
                        source_start: abs_pos,
                        source_end: end_pos,
                        rendered_start: abs_pos,
                        rendered_end: end_pos,
                        content: content.clone(),
                    });
                }
                
                pos = abs_pos + 1;
            } else {
                break;
            }
        }
    }
    
    result.sort_by_key(|m| m.source_start);
    result
}
```

### 7.3 Match Criteria

- **Exact match**: Byte-for-byte identical
- **Case-sensitive**: `Secret` ≠ `secret`
- **No normalisation**: `hello  world` ≠ `hello world`
- **No substring**: `password123` does not match `password`

### 7.4 Performance Optimisation

For files with many markers or large content:

**Option 1**: Use Aho-Corasick for multi-pattern matching
```rust
use aho_corasick::AhoCorasick;

let patterns: Vec<&str> = seen.iter().map(|s| s.as_str()).collect();
let ac = AhoCorasick::new(&patterns).unwrap();

for mat in ac.find_iter(text) {
    let content = &patterns[mat.pattern()];
    let start = mat.start();
    let end = mat.end();
    
    if !is_position_marked(start, end, &result) {
        // Add marker
    }
}
```

**Option 2**: Use interval trees for O(log n) overlap checking
```rust
// Check if position is marked using interval tree
// instead of linear scan through all markers
```

---

## 8. Paired Delimiter Handling

### 8.1 Delimiter Pairs

The system recognises these paired delimiters:
- Double quotes: `"..."`
- Single quotes: `'...'`
- Square brackets: `[...]`
- Curly braces: `{...}`
- Parentheses: `(...)`
- Angle brackets: `<...>`

### 8.2 Rule

Opening and closing delimiters must both be marked or both be unmarked. If only one is marked, expand the marker to cover both.

**Rationale**: Breaking delimiter pairs creates invalid syntax in most file formats.

### 8.3 Examples

#### Example 1: Consistent Marking

```
Source:   key: "o+{value}"
Edited:   key: "newvalue"
Result:   key: "⊕{newvalue}"
Reason:   Both quotes outside marker, content inside marked
```

#### Example 2: Unmatched Delimiters

```
Source:   key: "o+{value}"
Edited:   key: "value
Result:   key: "⊕{value}
Reason:   Closing quote missing, mark anyway (security over syntax)
Warning:  "Unmatched delimiter pair at positions X-Y"
```

#### Example 3: Nested Delimiters

```
Source:   outer: "inner: 'o+{secret}'"
Edited:   outer: "inner: 'modified'"
Result:   outer: "inner: '⊕{modified}'"
Reason:   Inner pair (single quotes) processed first, stays together
```

### 8.4 Algorithm Notes

- Process innermost pairs first (shortest span)
- Use stack-based matching for nested pairs
- Handle escaped delimiters: `\"` and `\'` are not delimiters
- Same delimiter for open/close (quotes): track depth carefully

---

## 9. Edge Cases

This section documents all identified edge cases and their handling.

### 9.1 Marker Syntax Edge Cases

| Scenario | Input | Output | Notes |
|----------|-------|--------|-------|
| Empty marker | `o+{}` | `⊕{}` | Valid, preserved |
| Whitespace only | `o+{   }` | `⊕{   }` | Valid, whitespace can be sensitive |
| Newlines in marker | `o+{line1\nline2}` | `⊕{line1\nline2}` | Valid, multi-line content |
| Unicode in marker | `o+{日本語}` | `⊕{日本語}` | Valid, UTF-8 supported |
| Escaped close brace | `o+{text \} more}` | `⊕{text } more}` | Valid, `\}` is literal `}` |
| Already escaped | `o+\{literal}` | `o+\{literal}` | Preserved as-is |
| Double escape | `o+\\{text}` | `o+\\{text}` | Preserved as-is |

### 9.2 Nesting and Recursion

| Scenario | Input | Output | Reason |
|----------|-------|--------|--------|
| Simple nesting | `o+{a o+{b}}` | `⊕{a o+\{b}}` | Inner marker escaped |
| Deep nesting | `o+{a o+{b o+{c}}}` | `⊕{a o+\{b o+\{c}}}` | All inner markers escaped |
| Mixed formats | `o+{a ⊕{b}}` | `⊕{a ⊕\{b}}` | Inner marker escaped regardless of format |

### 9.3 Deletion Edge Cases

| Scenario | Input → Edited | Output | Notes |
|----------|----------------|--------|-------|
| Delete marked content | `o+{secret} text` → `text` | `text` | Marker removed |
| Delete around marker | `prefix o+{keep} suffix` → `o+{keep}` | `⊕{keep}` | Marker preserved |
| Delete everything except marker | `lots o+{keep} text` → `keep` | `⊕{keep}` | Marker preserved |
| Delete part of marker | `o+{longtext}` → `long` | `⊕{long}` | Marker adjusted |

### 9.4 Adjacent Marker Edge Cases

| Scenario | Input | Edited | Output | Reason |
|----------|-------|--------|--------|--------|
| Insert between adjacent | `o+{a}o+{b}` | `axb` | `⊕{ax}⊕{b}` | Left-bias |
| Insert at boundary | `o+{a}o+{b}` | `abc` | `⊕{ab}⊕{c}` | Left-bias |
| Replace both | `o+{a}o+{b}` | `replaced` | `⊕{replaced}` | Spans both |
| Modify first only | `o+{a}o+{b}` | `axb` | `⊕{ax}⊕{b}` | Preserve separation |
| Modify second only | `o+{a}o+{b}` | `axb` | `⊕{a}⊕{xb}` | Preserve separation |

### 9.5 Delimiter Edge Cases

| Scenario | Input | Output | Notes |
|----------|-------|--------|-------|
| Unmatched open | `"o+{text}` | `"⊕{text}` | Mark anyway, log warning |
| Unmatched close | `o+{text}"` | `⊕{text}"` | Mark anyway, log warning |
| Escaped delimiter | `"o+{text \"}` | `"⊕{text "}` | Escaped `\"` not a delimiter |
| Empty pair | `""` | `""` | Valid, no marking needed |
| Nested same type | `"outer "inner" outer"` | Handled by stack | Process innermost first |

### 9.6 Propagation Edge Cases

| Scenario | Handling | Notes |
|----------|----------|-------|
| Partial match | `o+{password}` + `pass` | No propagation | Exact match only |
| Case difference | `o+{Secret}` + `secret` | No propagation | Case-sensitive |
| Whitespace difference | `o+{a  b}` + `a b` | No propagation | Exact match |
| Empty content | `o+{}` | No propagation | Skip empty markers |
| Very long content | Use efficient search | See performance section |

### 9.7 File-Level Edge Cases

| Scenario | Handling | Notes |
|----------|----------|-------|
| Empty file | Empty output | No markers |
| File is entirely marked | `o+{entire file}` | Valid |
| No markers in source | Changes stay unmarked | Unless user adds markers |
| Only whitespace | Preserved | Whitespace can be sensitive |
| Binary content | Error | Text-only supported |
| Invalid UTF-8 | Error | UTF-8 required |
| Mixed line endings | Normalise to `\n`, preserve in output | Prevent diff issues |

### 9.8 Boundary Detection Edge Cases

| Scenario | Input → Edited | Output | Reason |
|----------|----------------|--------|--------|
| No boundaries (entire file) | `o+{all}` → `new all` | `⊕{new all}` | No boundary to stop expansion |
| Boundary at start | `prefix o+{a} o+{b}` → `prefix new` | `prefix ⊕{new}` | "prefix" is boundary |
| Boundary at end | `o+{a} o+{b} suffix` → `new suffix` | `⊕{new} suffix` | "suffix" is boundary |
| Multiple changes | `o+{a} x o+{b} y o+{c}` → `a new1 b new2 c` | `⊕{a} ⊕{new1} ⊕{b} ⊕{new2} ⊕{c}` | Each change independent |

---

## 10. Implementation Guide

### 10.1 Recommended Technology Stack

**Language**: Rust

**Crates**:
- `similar` (v0.3+) or `diff` - Diff algorithm
- `aho-corasick` - Efficient multi-pattern string search (for propagation)
- `thiserror` - Error handling
- `regex` (optional) - For complex parsing if needed
- `criterion` - Benchmarking
- `proptest` - Property-based testing

### 10.2 Project Structure

```
marker-inference/
├── Cargo.toml
├── src/
│   ├── lib.rs           # Public API
│   ├── parser.rs        # Marker parsing (Step 1)
│   ├── diff.rs          # Diff computation (Step 2)
│   ├── validator.rs     # User marker validation (Step 3)
│   ├── mapper.rs        # Change mapping (Step 4)
│   ├── expander.rs      # Expansion rules (Step 5)
│   ├── propagator.rs    # Content propagation (Step 6)
│   ├── delimiter.rs     # Delimiter handling (Step 7)
│   ├── reconstructor.rs # Output reconstruction (Step 8)
│   ├── types.rs         # Data structures
│   └── error.rs         # Error types
├── tests/
│   ├── integration.rs   # Integration tests
│   ├── edge_cases.rs    # Edge case tests
│   └── fixtures/        # Test data files
└── benches/
    └── performance.rs   # Performance benchmarks
```

### 10.3 Module Responsibilities

#### lib.rs
```rust
pub fn infer_markers(
    source_text: &str,
    edited_text: &str,
) -> Result<MarkerInferenceResult, MarkerInferenceError>;

pub struct MarkerInferenceResult {
    pub output: String,
    pub warnings: Vec<String>,
}
```

#### types.rs
```rust
pub type Position = usize;

pub struct Marker { /* ... */ }
pub struct ChangeHunk { /* ... */ }
pub struct MappedChange { /* ... */ }
pub struct UserMarker { /* ... */ }
pub struct ValidatedEdit { /* ... */ }
```

#### parser.rs
```rust
pub fn parse_markers(source: &str) 
    -> Result<(String, Vec<Marker>), ParseError>;
```

#### validator.rs
```rust
pub fn validate_user_markers(edited: &str) -> ValidatedEdit;
```

### 10.4 Development Phases

**Phase 1: Core Implementation** (Week 1-2)
- [ ] Define data structures
- [ ] Implement marker parser
- [ ] Integrate diff library
- [ ] Implement change mapper
- [ ] Basic expansion rules (Rules 1-2)

**Phase 2: Full Rules** (Week 3)
- [ ] Complete expansion rules (Rules 3-5)
- [ ] Content propagation
- [ ] Delimiter validation
- [ ] Output reconstruction

**Phase 3: User Markers** (Week 4)
- [ ] User marker validation
- [ ] Escaping logic
- [ ] Integration with main flow

**Phase 4: Testing** (Week 5-6)
- [ ] Unit tests (>80% coverage)
- [ ] Integration tests
- [ ] Edge case tests
- [ ] Property-based tests
- [ ] Fuzzing

**Phase 5: Optimisation** (Week 7)
- [ ] Performance benchmarking
- [ ] Optimise hot paths
- [ ] Large file handling
- [ ] Memory profiling

**Phase 6: Documentation** (Week 8)
- [ ] API documentation
- [ ] Usage examples
- [ ] Integration guide
- [ ] Performance guide

### 10.5 UTF-8 Handling

**Critical**: All positions are **byte offsets**, not character indices.

```rust
// CORRECT: Iterate with char_indices()
for (byte_pos, ch) in text.char_indices() {
    // byte_pos is valid UTF-8 boundary
}

// WRONG: Direct byte indexing
let ch = text[pos]; // May panic or give invalid UTF-8
```

**Best practices**:
- Use `str::char_indices()` for iteration
- Use `str::chars().count()` for character count
- Use `str::len()` for byte length
- Validate UTF-8 boundaries when inserting markers
- Handle multi-byte characters correctly (é, 日, 🔒, etc.)

### 10.6 Error Handling Strategy

```rust
#[derive(Debug, thiserror::Error)]
pub enum MarkerInferenceError {
    #[error("Invalid UTF-8 in input at byte {0}")]
    InvalidUtf8(usize),
    
    #[error("Malformed marker at position {0}: {1}")]
    MalformedMarker(Position, String),
    
    #[error("Binary content detected at byte {0}")]
    BinaryContent(usize),
    
    #[error("Diff computation failed: {0}")]
    DiffError(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, MarkerInferenceError>;
```

**Error handling principles**:
- Validate UTF-8 early (use `str` not `[u8]`)
- Provide position information in errors
- Log warnings for non-fatal issues
- Never panic in production code
- Use `Result` for recoverable errors

### 10.7 Logging and Debugging

Add logging using `log` crate:

```rust
use log::{debug, info, warn};

pub fn infer_markers(...) -> Result<...> {
    debug!("Starting marker inference");
    debug!("Source length: {}, Edited length: {}", source.len(), edited.len());
    
    let (rendered, markers) = parse_markers(source)?;
    info!("Found {} markers in source", markers.len());
    
    // ...
    
    if validated.warnings.len() > 0 {
        warn!("Generated {} warnings during validation", validated.warnings.len());
        for warning in &validated.warnings {
            warn!("  {}", warning);
        }
    }
    
    Ok(result)
}
```

**Log levels**:
- `trace`: Detailed position/content information
- `debug`: Algorithm steps and intermediate results
- `info`: High-level progress (markers found, changes detected)
- `warn`: Non-fatal issues (escaped markers, unmatched delimiters)
- `error`: Fatal errors before returning `Err`

---

## 11. Testing Strategy

### 11.1 Test Pyramid

```
           /\
          /  \      E2E Tests (5%)
         /____\
        /      \    Integration Tests (15%)
       /________\
      /          \  Unit Tests (80%)
     /____________\
```

### 11.2 Unit Tests

Each module should have comprehensive unit tests:

**parser.rs**:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_simple_marker() {
        let (rendered, markers) = parse_markers("text o+{secret} more").unwrap();
        assert_eq!(rendered, "text secret more");
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].content, "secret");
    }
    
    #[test]
    fn test_parse_escaped_marker() {
        let (rendered, markers) = parse_markers("text o+\\{literal}").unwrap();
        assert_eq!(rendered, "text o+\\{literal}");
        assert_eq!(markers.len(), 0);
    }
    
    #[test]
    fn test_parse_unclosed_marker() {
        let (rendered, markers) = parse_markers("text o+{unclosed").unwrap();
        assert_eq!(rendered, "text o+\\{unclosed");
        assert_eq!(markers.len(), 0);
    }
    
    #[test]
    fn test_parse_nested_marker() {
        let (rendered, markers) = parse_markers("o+{outer o+{inner}}").unwrap();
        assert_eq!(rendered, "o+\\{outer o+{inner}}");
        // Outer escaped, inner becomes valid
    }
    
    #[test]
    fn test_parse_both_formats() {
        let (rendered, markers) = parse_markers("o+{a} ⊕{b}").unwrap();
        assert_eq!(rendered, "a b");
        assert_eq!(markers.len(), 2);
    }
    
    #[test]
    fn test_parse_empty_marker() {
        let (rendered, markers) = parse_markers("o+{}").unwrap();
        assert_eq!(rendered, "");
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].content, "");
    }
    
    #[test]
    fn test_parse_unicode() {
        let (rendered, markers) = parse_markers("o+{日本語}").unwrap();
        assert_eq!(rendered, "日本語");
        assert_eq!(markers[0].content, "日本語");
    }
}
```

### 11.3 Integration Tests

Test the full pipeline with realistic scenarios:

**tests/integration.rs**:
```rust
use marker_inference::infer_markers;

#[test]
fn test_simple_modification() {
    let source = "A o+{strange day} for a o+{walk}";
    let edited = "A nasty day for a stroll outside";
    
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "A ⊕{nasty day} for a ⊕{stroll outside}");
    assert_eq!(result.warnings.len(), 0);
}

#[test]
fn test_content_movement() {
    let source = "Here's a o+{secret}. And other stuff.";
    let edited = "Other stuff. Here's a secret.";
    
    let result = infer_markers(source, edited).unwrap();
    assert!(result.output.contains("⊕{secret}"));
}

#[test]
fn test_multiple_region_replacement() {
    let source = "o+{a} middle o+{b}";
    let edited = "replaced";
    
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "⊕{replaced}");
}

#[test]
fn test_adjacent_markers() {
    let source = "o+{a}o+{b}";
    let edited = "axb";
    
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "⊕{ax}⊕{b}");
}

#[test]
fn test_content_propagation() {
    let source = "o+{secret} and public";
    let edited = "secret and secret";
    
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "⊕{secret} and ⊕{secret}");
}

#[test]
fn test_delimiter_handling() {
    let source = "key: \"o+{value}\"";
    let edited = "key: \"modified\"";
    
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "key: \"⊕{modified}\"");
}

#[test]
fn test_complete_rewrite() {
    let source = "o+{SSH KEY CONTENT}";
    let edited = "COMPLETELY NEW KEY";
    
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "⊕{COMPLETELY NEW KEY}");
}

#[test]
fn test_user_inserted_marker() {
    let source = "public text";
    let edited = "public o+{new secret}";
    
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "public ⊕{new secret}");
}

#[test]
fn test_unclosed_user_marker() {
    let source = "public text";
    let edited = "public o+{unclosed";
    
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "public o+\\{unclosed");
    assert_eq!(result.warnings.len(), 1);
}
```

### 11.4 Edge Case Tests

Create a dedicated test suite for all edge cases:

**tests/edge_cases.rs**:
```rust
// Test all scenarios from Section 9
#[test] fn test_empty_marker() { /* ... */ }
#[test] fn test_whitespace_only_marker() { /* ... */ }
#[test] fn test_unicode_marker() { /* ... */ }
#[test] fn test_escaped_close_brace() { /* ... */ }
// ... (one test per edge case)
```

### 11.5 Property-Based Tests

Use `proptest` to verify invariants:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_idempotence(source in ".*", edited in ".*") {
        // Applying inference twice should give same result
        if let Ok(result1) = infer_markers(&source, &edited) {
            if let Ok(result2) = infer_markers(&result1.output, &edited) {
                assert_eq!(result1.output, result2.output);
            }
        }
    }
    
    #[test]
    fn test_content_preservation(source in ".*", edited in ".*") {
        // Rendered output after marking should match edited text
        if let Ok(result) = infer_markers(&source, &edited) {
            let (rendered, _) = parse_markers(&result.output).unwrap();
            assert_eq!(rendered, edited);
        }
    }
    
    #[test]
    fn test_marker_validity(source in ".*", edited in ".*") {
        // All markers in output should be well-formed
        if let Ok(result) = infer_markers(&source, &edited) {
            assert!(all_markers_valid(&result.output));
        }
    }
    
    #[test]
    fn test_no_marker_loss(
        content in "[a-z]+",
        filler in "[a-z ]+"
    ) {
        // If source has marker, output has marker
        let source = format!("o+{{{}}} {}", content, filler);
        let edited = format!("{} {}", content, filler);
        
        let result = infer_markers(&source, &edited).unwrap();
        assert!(result.output.contains("⊕{"));
    }
}
```

### 11.6 Fuzzing

Use `cargo-fuzz` for fuzzing:

```rust
// fuzz/fuzz_targets/fuzz_infer.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use marker_inference::infer_markers;

fuzz_target!(|data: &[u8]| {
    if let Ok(source) = std::str::from_utf8(data) {
        if let Ok(edited) = std::str::from_utf8(data) {
            let _ = infer_markers(source, edited);
        }
    }
});
```

Run fuzzing:
```bash
cargo fuzz run fuzz_infer -- -max_total_time=3600
```

### 11.7 Test Coverage Goals

- **Unit tests**: >90% line coverage
- **Integration tests**: All critical paths covered
- **Edge cases**: 100% of documented edge cases tested
- **Property tests**: All invariants verified
- **Fuzzing**: No crashes after 1 hour

---

## 12. Performance Requirements

### 12.1 Performance Targets

| File Size | Target Latency | Max Memory |
|-----------|----------------|------------|
| < 1 KB | < 1ms | < 1 MB |
| < 10 KB | < 10ms | < 5 MB |
| < 100 KB | < 50ms | < 20 MB |
| < 1 MB | < 500ms | < 100 MB |
| < 10 MB | < 5s | < 500 MB |

### 12.2 Complexity Analysis

| Operation | Complexity | Notes |
|-----------|------------|-------|
| Parse markers | O(n) | Linear scan through source |
| Compute diff | O(ND) | Myers diff, N+M = input sizes, D = edit distance |
| Map changes | O(m · log k) | m changes, k markers, binary search |
| Apply rules | O(m · k) | m changes, k markers |
| Propagation | O(n · k) | n = text length, k = unique marked content |
| Delimiter validation | O(n) | Single pass with stack |
| Reconstruct | O(n + k) | Linear with markers sorted |

**Overall**: O(n · k + ND) where:
- n = file size
- k = number of markers
- D = edit distance

### 12.3 Optimisation Strategies

**For large files**:
1. Use streaming diff algorithms
2. Process file in chunks if > 10 MB
3. Use memory-mapped files for very large inputs

**For many markers**:
1. Use interval trees for overlap queries
2. Sort markers once, binary search for queries
3. Use hash set for O(1) duplicate detection

**For propagation**:
1. Use Aho-Corasick multi-pattern matching
2. Skip propagation if no duplicates expected (heuristic)
3. Limit max search iterations (safety cutoff)

**Memory management**:
1. Reuse allocations where possible
2. Use `String::with_capacity` for known sizes
3. Stream output instead of building full string in memory

### 12.4 Benchmarking

Use `criterion` for benchmarking:

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use marker_inference::infer_markers;

fn bench_small_file(c: &mut Criterion) {
    let source = "password: o+{secret123}";
    let edited = "password: newsecret456";
    
    c.bench_function("infer_small", |b| {
        b.iter(|| infer_markers(black_box(source), black_box(edited)))
    });
}

fn bench_large_file(c: &mut Criterion) {
    let source = include_str!("../fixtures/large_file.txt");
    let edited = include_str!("../fixtures/large_file_edited.txt");
    
    c.bench_function("infer_large", |b| {
        b.iter(|| infer_markers(black_box(source), black_box(edited)))
    });
}

criterion_group!(benches, bench_small_file, bench_large_file);
criterion_main!(benches);
```

Run benchmarks:
```bash
cargo bench
```

---

## 13. Security Considerations

### 13.1 Threat Model

**Primary Threat**: Sensitive data leakage through incorrect marker inference.

**Attack Scenarios**:
1. Craft edits to trick algorithm into unmarking sensitive content
2. Exploit delimiter handling to break markers
3. Cause excessive memory usage (DoS) via large diffs
4. Timing attacks to infer marker positions

**Mitigations**:
1. Conservative expansion rules (prefer over-marking)
2. Paired delimiter validation ensures syntax preservation
3. Memory limits and streaming for large files
4. Constant-time operations where possible (not critical for this use case)

### 13.2 Security Principles

1. **Fail Secure**: On error or ambiguity, mark content rather than leak
2. **Defense in Depth**: Multiple layers (expansion rules, propagation, delimiters)
3. **Least Privilege**: Only mark what's necessary, but err on side of caution
4. **Audit Logging**: Log all marker expansions for security-sensitive deployments

### 13.3 Audit Logging

For high-security environments:

```rust
pub struct AuditLog {
    pub timestamp: SystemTime,
    pub source_markers: Vec<Marker>,
    pub result_markers: Vec<Marker>,
    pub expansions: Vec<MarkerExpansion>,
    pub propagations: Vec<Propagation>,
    pub warnings: Vec<String>,
}

pub struct MarkerExpansion {
    pub original: Marker,
    pub expanded: Marker,
    pub reason: String,
}

pub struct Propagation {
    pub content: String,
    pub positions: Vec<(usize, usize)>,
}
```

Enable auditing:
```rust
let (result, audit_log) = infer_markers_with_audit(source, edited)?;
log::info!("Audit: {}", serde_json::to_string(&audit_log)?);
```

### 13.4 Input Validation

Validate inputs before processing:

```rust
fn validate_input(text: &str) -> Result<()> {
    // Check valid UTF-8 (already guaranteed by &str type)
    
    // Check for null bytes
    if text.contains('\0') {
        return Err(MarkerInferenceError::BinaryContent(
            text.find('\0').unwrap()
        ));
    }
    
    // Check reasonable size (prevent DoS)
    const MAX_SIZE: usize = 100 * 1024 * 1024; // 100 MB
    if text.len() > MAX_SIZE {
        return Err(MarkerInferenceError::Internal(
            format!("Input too large: {} bytes", text.len())
        ));
    }
    
    Ok(())
}
```

### 13.5 Secrets in Memory

**Note**: This system operates on plaintext content. The FUSE layer must:
- Use secure memory (e.g., `zeroize` crate) for sensitive content
- Clear buffers after use
- Prevent secrets from being swapped to disk (mlock)
- Avoid logging sensitive content

---

## 14. References

### 14.1 Academic Papers

1. Myers, Eugene W. "An O(ND) difference algorithm and its variations." *Algorithmica* 1.1-4 (1986): 251-266.
2. Hunt, James W., and M. Douglas McIlroy. "An algorithm for differential file comparison." *Computing Science Technical Report* 41 (1976).
3. Aho, Alfred V., and Margaret J. Corasick. "Efficient string matching: an aid to bibliographic search." *Communications of the ACM* 18.6 (1975): 333-340.

### 14.2 Rust Crates

- `similar`: https://docs.rs/similar/
- `diff`: https://docs.rs/diff/
- `aho-corasick`: https://docs.rs/aho-corasick/
- `thiserror`: https://docs.rs/thiserror/
- `proptest`: https://docs.rs/proptest/
- `criterion`: https://docs.rs/criterion/

### 14.3 Related Work

- **git diff**: Standard diff algorithms and implementations
- **Operational Transform**: For collaborative editing (different problem space)
- **CRDT**: Conflict-free replicated data types (different problem space)

---

## 15. Appendices

### Appendix A: Complete Algorithm Pseudocode

```python
def infer_markers(source_text: str, edited_text: str) -> tuple[str, list[str]]:
    """
    Main algorithm for marker inference.
    Returns (output_text, warnings)
    """
    # Step 1: Parse source to extract markers
    rendered_text, original_markers = parse_markers(source_text)
    
    # Step 2: Compute diff
    changes = compute_diff(rendered_text, edited_text)
    
    # Step 3: Validate user-inserted markers
    validated = validate_user_markers(edited_text)
    edited_text = validated.text
    user_markers = validated.user_markers
    warnings = validated.warnings
    
    # Step 4: Map changes to source positions
    mapped_changes = []
    for change in changes:
        overlapping = find_overlapping_markers(change, original_markers)
        source_start = rendered_to_source_pos(change.start, original_markers)
        source_end = rendered_to_source_pos(change.end, original_markers)
        mapped_changes.append(MappedChange(
            source_start, source_end,
            change.start, change.end,
            change.new_content,
            overlapping
        ))
    
    # Step 5: Apply expansion rules
    new_markers = []
    for change in mapped_changes:
        if len(change.overlapping) == 0:
            # Rule 5: Unmarked content, skip
            continue
        elif len(change.overlapping) == 1:
            # Rule 2: Adjacent to one marker
            marker = original_markers[change.overlapping[0]]
            expanded = expand_marker(marker, change)
            new_markers.append(expanded)
        else:
            # Rule 1: Multiple markers
            boundaries = find_boundaries(change, edited_text)
            new_marker = create_marker_for_span(
                boundaries.start, boundaries.end,
                edited_text[boundaries.start:boundaries.end]
            )
            new_markers.append(new_marker)
    
    # Add user-inserted markers
    new_markers.extend(convert_user_markers(user_markers))
    
    # Step 6: Propagate to duplicates
    new_markers = propagate_markers(edited_text, new_markers)
    
    # Step 7: Validate delimiters
    delimiter_warnings = validate_delimiters(edited_text, new_markers)
    warnings.extend(delimiter_warnings)
    
    # Step 8: Reconstruct output with canonical format
    output = reconstruct_with_markers(edited_text, new_markers, format="⊕{}")
    
    return output, warnings


def parse_markers(source: str) -> tuple[str, list[Marker]]:
    """Parse markers from source, return (rendered, markers)"""
    markers = []
    rendered = ""
    pos = 0
    
    while pos < len(source):
        if source[pos:pos+4] == "o+\\{" or source[pos:pos+len("⊕\\{")] == "⊕\\{":
            # Escaped marker
            if source[pos] == 'o':
                rendered += "o+\\{"
                pos += 4
            else:
                rendered += "⊕\\{"
                pos += len("⊕\\{")
        elif source[pos:pos+3] == "o+{" or source[pos:pos+len("⊕{")] == "⊕{":
            # Potential marker
            is_oplus = (source[pos] == 'o')
            prefix_len = 3 if is_oplus else len("⊕{")
            
            close_pos = find_unescaped_close(source[pos+prefix_len:])
            if close_pos is None:
                # Unclosed, escape
                if is_oplus:
                    rendered += "o+\\{"
                    pos += 3
                else:
                    rendered += "⊕\\{"
                    pos += len("⊕{")
            else:
                content = source[pos+prefix_len:pos+prefix_len+close_pos]
                if "o+{" in content or "⊕{" in content:
                    # Nested, escape outer
                    if is_oplus:
                        rendered += "o+\\{"
                        pos += 3
                    else:
                        rendered += "⊕\\{"
                        pos += len("⊕{")
                else:
                    # Valid marker
                    markers.append(Marker(
                        source_start=pos,
                        source_end=pos+prefix_len+close_pos+1,
                        rendered_start=len(rendered),
                        rendered_end=len(rendered)+len(content),
                        content=content
                    ))
                    rendered += content
                    pos += prefix_len + close_pos + 1
        else:
            rendered += source[pos]
            pos += 1
    
    return rendered, markers


def find_unescaped_close(text: str) -> int | None:
    """Find first unescaped } in text"""
    pos = 0
    while pos < len(text):
        if text[pos:pos+2] == "\\}":
            pos += 2
        elif text[pos] == '}':
            return pos
        else:
            pos += 1
    return None


def validate_user_markers(edited: str) -> ValidatedEdit:
    """Validate and escape invalid user-inserted markers"""
    validated = ""
    user_markers = []
    warnings = []
    pos = 0
    
    while pos < len(edited):
        # Check for escaped markers
        if edited[pos:pos+4] == "o+\\{":
            validated += "o+\\{"
            pos += 4
            continue
        elif edited[pos:pos+len("⊕\\{")] == "⊕\\{":
            validated += "⊕\\{"
            pos += len("⊕\\{")
            continue
        
        # Check for marker start
        is_oplus = edited[pos:pos+3] == "o+{"
        is_circled = edited[pos:pos+len("⊕{")] == "⊕{"
        
        if is_oplus or is_circled:
            marker_start = pos
            prefix_len = 3 if is_oplus else len("⊕{")
            
            close_pos = find_matching_close(edited[pos+prefix_len:])
            if close_pos is None:
                # Unclosed, escape
                if is_oplus:
                    validated += "o+\\{"
                    pos += 3
                else:
                    validated += "⊕\\{"
                    pos += len("⊕{")
                warnings.append(f"Escaped unclosed marker at {marker_start}")
            else:
                content = edited[pos+prefix_len:pos+prefix_len+close_pos]
                if "o+{" in content or "⊕{" in content:
                    # Nested, escape inner
                    escaped_content = content.replace("o+{", "o+\\{").replace("⊕{", "⊕\\{")
                    if is_oplus:
                        validated += "o+{"
                    else:
                        validated += "⊕{"
                    validated += escaped_content + "}"
                    pos += prefix_len + close_pos + 1
                    warnings.append(f"Escaped nested marker at {pos+prefix_len}")
                else:
                    # Valid marker
                    user_markers.append(UserMarker(
                        start=marker_start,
                        end=pos+prefix_len+close_pos+1,
                        content=content
                    ))
                    validated += edited[marker_start:pos+prefix_len+close_pos+1]
                    pos += prefix_len + close_pos + 1
        else:
            validated += edited[pos]
            pos += 1
    
    return ValidatedEdit(validated, user_markers, warnings)


def propagate_markers(text: str, markers: list[Marker]) -> list[Marker]:
    """Find all unmarked instances of marked content and mark them"""
    result = markers.copy()
    seen = set(m.content for m in markers if m.content)
    
    for content in seen:
        pos = 0
        while True:
            found = text.find(content, pos)
            if found == -1:
                break
            
            if not is_position_marked(found, found + len(content), result):
                result.append(Marker(
                    source_start=found,
                    source_end=found + len(content),
                    rendered_start=found,
                    rendered_end=found + len(content),
                    content=content
                ))
            
            pos = found + 1
    
    result.sort(key=lambda m: m.source_start)
    return result


def reconstruct_with_markers(text: str, markers: list[Marker], format: str = "⊕{}") -> str:
    """Reconstruct text with markers in canonical format"""
    output = ""
    pos = 0
    
    markers = sorted(markers, key=lambda m: m.source_start)
    
    for marker in markers:
        # Add text before marker
        output += text[pos:marker.source_start]
        
        # Add marker with canonical format
        output += f"⊕{{{marker.content}}}"
        
        pos = marker.source_end
    
    # Add remaining text
    output += text[pos:]
    
    return output
```

### Appendix B: Test Data Examples

**Simple modification**:
```
Source:   A o+{strange day} for a o+{walk}
Edited:   A nasty day for a stroll outside
Expected: A ⊕{nasty day} for a ⊕{stroll outside}
```

**Content movement**:
```
Source:   Here's a o+{secret}. And other stuff.
Edited:   Other stuff. Here's a secret.
Expected: Other stuff. Here's a ⊕{secret}.
```

**Multiple region replacement**:
```
Source:   o+{a} middle o+{b}
Edited:   replaced
Expected: ⊕{replaced}
```

**Adjacent markers**:
```
Source:   o+{a}o+{b}
Edited:   axb
Expected: ⊕{ax}⊕{b}
```

**Content propagation**:
```
Source:   o+{secret} and public
Edited:   secret and secret
Expected: ⊕{secret} and ⊕{secret}
```

**Delimiter handling**:
```
Source:   key: "o+{value}"
Edited:   key: "modified"
Expected: key: "⊕{modified}"
```

**Complete rewrite**:
```
Source:   o+{SSH KEY CONTENT}
Edited:   COMPLETELY NEW KEY
Expected: ⊕{COMPLETELY NEW KEY}
```

**User-inserted marker**:
```
Source:   public text
Edited:   public o+{new secret}
Expected: public ⊕{new secret}
```

**Unclosed user marker**:
```
Source:   public text
Edited:   public o+{unclosed
Expected: public o+\{unclosed
Warning:  "Escaped unclosed marker at position 7"
```

**Nested user marker**:
```
Source:   text
Edited:   o+{outer o+{inner}}
Expected: ⊕{outer o+\{inner}}
Warning:  "Escaped nested marker at position 11"
```

### Appendix C: Benchmark Data

Create realistic test files for benchmarking:

**small.txt** (1 KB):
```
password: o+{secret123}
api_key: o+{abc-def-ghi}
database: localhost
```

**medium.txt** (100 KB):
```yaml
# 100 KB YAML configuration with 50 marked secrets
services:
  api:
    password: o+{prod-secret-1}
    token: o+{bearer-token-xyz}
  # ... (many more entries)
```

**large.txt** (1 MB):
```
# 1 MB file with 500 marked secrets
# Realistic infrastructure-as-code file
```

**huge.txt** (10 MB):
```
# 10 MB file with 5000 marked secrets
# Stress test for large files
```

### Appendix D: FAQ

**Q: Why use `⊕{...}` instead of `o+{...}` for output?**

A: `⊕{...}` is the canonical format that's easier to visually distinguish and less prone to confusion with mathematical operators. `o+{...}` is accepted for ease of manual typing.

**Q: What happens if the diff algorithm produces overlapping changes?**

A: The system should merge overlapping changes into a single change region before processing. Most diff libraries (like `similar`) don't produce overlapping changes.

**Q: Can markers span multiple lines?**

A: Yes, markers can contain newlines. Example: `o+{line1\nline2\nline3}`

**Q: What if the file encoding is not UTF-8?**

A: The system requires UTF-8 input. If needed, convert files to UTF-8 before processing.

**Q: How are line endings handled?**

A: Line endings are normalised to `\n` before diffing, then preserved in the output. This prevents diff issues between CRLF and LF.

**Q: Can I disable propagation?**

A: Not in the default implementation, but you could add a configuration flag. Propagation is a security feature to prevent leakage.

**Q: What's the maximum marker nesting depth?**

A: Nesting is not allowed. Any nested markers are escaped.

**Q: How do I handle very large files (>100 MB)?**

A: Consider processing in chunks, using streaming algorithms, or implementing a chunked version of the algorithm.

**Q: Can this be used for non-text files?**

A: No, the system is designed for text files only (UTF-8 encoded).

---

## Document Changelog

**Version 1.0 (2025-10-26)**:
- Initial comprehensive design document
- All core algorithms specified
- Complete edge case coverage
- Testing strategy defined
- Performance targets set
- Security considerations documented

---

**End of Design Document**

This document provides complete specifications for implementing the Intelligent Marker Preservation System. All edge cases, algorithms, and implementation details have been thoroughly documented for engineering team reference.
