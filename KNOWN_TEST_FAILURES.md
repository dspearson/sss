# Known Test Failures

## Marker Inference Integration Tests

The following marker inference tests are currently failing. These tests were added in commit `7c19b72` based on the marker-design.md specification, but the implementation does not yet fully match the spec for these edge cases.

**Status**: Pre-existing failures (not introduced by recent refactoring)
**Impact**: Core functionality works (all 249 library tests pass)
**Scope**: Edge cases in marker inference system

### Failing Tests (14 total)

#### Edge Cases Module
1. `test_empty_marker` - Empty markers should be removed entirely
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

### Test Results Summary

- **Library Tests**: ✅ 249/249 passing
- **Integration Tests**: ⚠️  145/159 passing (14 failing)
- **Overall**: Core functionality intact, edge cases need work
