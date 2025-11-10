# Known Test Failures

## Marker Inference Integration Tests

The following marker inference tests are currently failing. These tests were added in commit `7c19b72` based on the marker-design.md specification, but the implementation does not yet fully match the spec for these edge cases.

**Status**: Actively being fixed
**Impact**: Core functionality works (all 249 library tests pass)
**Scope**: Edge cases in marker inference system
**Progress**: 1 of 14 tests fixed (empty marker handling)

### Failing Tests (13 remaining, 1 fixed)

#### Edge Cases Module
1. ✅ `test_empty_marker` - **FIXED**: Empty markers are now removed entirely
2. `test_whitespace_only_marker` - Whitespace-only markers should be preserved
3. `test_delete_around_marker` - Content deletion around markers
4. `test_delete_marked_content` - Deletion of marked content
5. `test_case_difference_no_propagation` - Case changes shouldn't propagate markers
6. `test_marker_with_special_chars` - Special characters in markers
7. `test_partial_match_no_propagation` - Partial matches shouldn't propagate
8. `test_replace_both_adjacent` - Replacing adjacent marked regions
9. `test_whitespace_difference_no_propagation` - Whitespace changes shouldn't propagate

#### Integration Module
10. `test_mixed_marker_formats` - Mixed ASCII (o+{}) and Unicode (⊕{}) formats
11. `test_multiple_region_replacement` - Multiple region replacements
12. `test_user_inserted_marker` - User-inserted markers

#### Properties Module (Proptest)
13. `prop_content_preservation` - Property test for content preservation
14. `prop_propagation` - Property test for marker propagation

### Next Steps

To fully implement these features:
1. Review marker-design.md specification for expected behavior
2. Update marker inference implementation to handle edge cases
3. Or adjust test expectations if spec interpretation differs

### Improvements Made

**Commit 9ef26e9** (this commit):
- ✅ Fixed empty marker handling in reconstructor (test_empty_marker now passes)
- ⚙️  Added deletion validation in expander (markers with invalid positions are not created)
- ⚙️  Added content existence checks for preserved markers
- 📊 Progress: 146/159 tests passing (1 more test fixed)

**Remaining Issues:**
- Coordinate transformation after deletions needs refinement
- User-inserted marker handling needs improvement
- Whitespace-only marker preservation
- Case-sensitive propagation validation
- Special character escaping
- Adjacent marker merging rules

### Test Results Summary

- **Library Tests**: ✅ 249/249 passing
- **Integration Tests**: ⚠️  146/159 passing (13 failing, 1 fixed)
- **Overall**: Core functionality intact, edge cases being systematically addressed
