#!/bin/bash
# MACFlow - Run all test suites
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
TOTAL_PASS=0
TOTAL_FAIL=0

run_suite() {
  local name="$1"
  local script="$2"
  echo ""
  echo "###############################################"
  echo "  Running: $name"
  echo "###############################################"
  if bash "$script"; then
    echo "  >>> $name: PASSED"
    TOTAL_PASS=$((TOTAL_PASS+1))
  else
    echo "  >>> $name: FAILED (exit=$?)"
    TOTAL_FAIL=$((TOTAL_FAIL+1))
  fi
}

echo "============================================="
echo "  MACFlow Full Test Suite"
echo "  $(date)"
echo "============================================="

run_suite "Splitting Test"    "$DIR/test-splitting.sh"
run_suite "Captive Unresolved" "$DIR/test-captive-unresolved.sh"
run_suite "Whitelist Test"    "$DIR/test-whitelist.sh"
run_suite "Stability Test"    "$DIR/test-stability.sh"
run_suite "Concurrency Test"  "$DIR/test-concurrency.sh"
run_suite "Final Check"       "$DIR/final-check.sh"

if [ "${MACFLOW_LONG_TESTS:-0}" = "1" ]; then
  run_suite "DNS Fail-Close Test" "$DIR/test-dns-failclose.sh"
else
  echo ""
  echo "(skip) DNS Fail-Close Test: set MACFLOW_LONG_TESTS=1 to enable"
fi

echo ""
echo "============================================="
echo "  SUITES PASSED: $TOTAL_PASS"
echo "  SUITES FAILED: $TOTAL_FAIL"
echo "============================================="

if [ "$TOTAL_FAIL" -eq 0 ]; then
  echo "  ALL TEST SUITES PASSED"
  exit 0
else
  echo "  SOME TEST SUITES FAILED"
  exit 1
fi
