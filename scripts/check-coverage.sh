#!/bin/bash
# Simple test coverage analyzer for SSS
# Usage: ./scripts/check-coverage.sh

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║          SSS Test Coverage Analysis                        ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Count tests
unit_tests=$(find src -name "*.rs" -exec grep -c "^\s*#\[test\]" {} \; 2>/dev/null | awk '{s+=$1} END {print s}')
integration_tests=$(find tests -name "*.rs" -exec grep -c "^\s*#\[test\]" {} \; 2>/dev/null | awk '{s+=$1} END {print s}')
total_tests=$((unit_tests + integration_tests))

# Count files
total_src=$(find src -name "*.rs" -not -path "*/bin/*" | wc -l)
tested_src=$(find src -name "*.rs" -not -path "*/bin/*" -exec grep -l "^#\[cfg(test)\]" {} \; 2>/dev/null | wc -l)

coverage_pct=$((tested_src * 100 / total_src))

echo "📊 Test Statistics:"
echo "   Unit tests:        $unit_tests"
echo "   Integration tests: $integration_tests"
echo "   Total tests:       $total_tests"
echo ""
echo "📁 File Coverage:"
echo "   Source files:      $total_src"
echo "   With tests:        $tested_src"
echo "   Coverage:          $coverage_pct%"
echo ""

# Coverage by category
echo "📚 Coverage by Category:"
echo ""

check_category() {
    local name=$1
    local pattern=$2
    local files=$(find src -name "*.rs" | grep -E "$pattern" | wc -l)
    local tested=$(find src -name "*.rs" | grep -E "$pattern" -exec grep -l "^#\[cfg(test)\]" {} \; 2>/dev/null | wc -l)
    local pct=0
    if [ "$files" -gt 0 ]; then
        pct=$((tested * 100 / files))
    fi

    local icon="✗"
    if [ "$pct" -eq 100 ]; then icon="✅"
    elif [ "$pct" -ge 70 ]; then icon="⚠️"
    fi

    printf "   %-20s %2d/%2d files  %3d%%  %s\n" "$name" "$tested" "$files" "$pct" "$icon"
}

check_category "Core Crypto" "crypto\.rs|kdf\.rs|keystore\.rs|keyring"
check_category "Commands" "commands/"
check_category "Processing" "processor\.rs|merge\.rs|scanner\.rs"
check_category "Config/Project" "config|project\.rs"
check_category "Filesystems" "fuse_fs\.rs|ninep_fs\.rs"
check_category "Security" "secure_memory\.rs|validation\.rs|rate_limiter\.rs"

echo ""
echo "⚠️  Critical Files Without Tests:"
echo ""

find src/commands -name "*.rs" | while read file; do
    if ! grep -q "^#\[cfg(test)\]" "$file" 2>/dev/null; then
        lines=$(wc -l < "$file")
        if [ "$lines" -gt 100 ]; then
            printf "   • %-40s (%4d lines)\n" "$(basename $file)" "$lines"
        fi
    fi
done

# Check for FUSE
if [ -f "src/fuse_fs.rs" ]; then
    if ! grep -q "^#\[cfg(test)\]" "src/fuse_fs.rs" 2>/dev/null; then
        lines=$(wc -l < "src/fuse_fs.rs")
        printf "   • %-40s (%4d lines) ⚠️ LARGEST FILE\n" "fuse_fs.rs" "$lines"
    fi
fi

echo ""
echo "💡 Recommendations:"
if [ "$coverage_pct" -lt 60 ]; then
    echo "   Priority: Add tests for command modules (currently 0% coverage)"
elif [ "$coverage_pct" -lt 80 ]; then
    echo "   Priority: Improve coverage for filesystem modules"
else
    echo "   Good coverage! Focus on edge cases and error paths"
fi

echo ""
echo "Run tests:     cargo test"
echo "With coverage: cargo llvm-cov --html  (requires: cargo install cargo-llvm-cov)"
echo ""
