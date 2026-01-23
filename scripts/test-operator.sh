#!/bin/bash
#
# Unified Test Runner for Vulnerable K8s Operator
# Provides multiple test execution modes for different use cases
#
# This script wraps verify-remediation-cycle.sh with additional test tier options
# and provides a unified interface for running operator tests.
#
# Test Tiers:
#   Tier 1: Programmatic API Verification (fast, accurate, no scanner dependencies)
#   Tier 2: Scanner Baseline Differencing (filters noise, verifies scanner detectability)
#   Tier 3: Representative Sampling (6 tests, quick smoke test)
#
# Usage:
#   ./test-operator.sh [OPTIONS]
#
# Options:
#   --tier [1|2|3|all]     Which tier(s) to run (default: 1)
#   --category [K01-K08]   Filter by vulnerability category
#   --representative       Run quick mode (6 representative tests)
#   --full                 Run all 22 tests
#   --verbose              Enable verbose output
#   --dry-run              Show test plan without executing
#   --help                 Show this help message
#
# Examples:
#   ./test-operator.sh --tier 1 --representative    # Quick programmatic smoke test (6 tests)
#   ./test-operator.sh --tier 1 --full              # All tests with programmatic verification
#   ./test-operator.sh --tier 2 --category K01      # Scanner-based K01 tests only
#   ./test-operator.sh --tier all --verbose         # Run all tiers with verbose output
#

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VERIFY_SCRIPT="${SCRIPT_DIR}/verify-remediation-cycle.sh"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Default options
TIER="1"
CATEGORY=""
REPRESENTATIVE=false
FULL=false
VERBOSE=false
DRY_RUN=false

# =============================================================================
# Utility Functions
# =============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_section() {
    echo
    echo -e "${CYAN}${BOLD}=== $1 ===${NC}"
    echo
}

show_help() {
    cat << EOF
${BOLD}Unified Test Runner for Vulnerable K8s Operator${NC}

This script provides a unified interface for running operator tests across multiple tiers.

${BOLD}USAGE:${NC}
    ./test-operator.sh [OPTIONS]

${BOLD}OPTIONS:${NC}
    --tier [1|2|3|all]     Which tier(s) to run (default: 1)
                           1: Programmatic API Verification (fast, no scanner)
                           2: Scanner Baseline Differencing (with scanners)
                           3: Representative Sampling (6 quick tests)
                           all: Run all tiers sequentially

    --category [K01-K08]   Filter by vulnerability category (K01, K02, K03, K06, K07, K08)
                           Cannot be used with --representative

    --representative       Run quick mode with 6 representative tests
                           Covers all categories: K01:0, K02:2, K03:0, K06:0, K07:2, K08:0
                           Cannot be used with --category

    --full                 Run all 22 tests (default if neither --representative nor --category specified)

    --verbose              Enable verbose output from underlying test script

    --dry-run              Show test plan without executing

    --help, -h             Show this help message

${BOLD}TEST TIERS:${NC}

${BOLD}Tier 1: Programmatic API Verification${NC}
  - Fast execution (~2-3 min for all 22 tests)
  - Uses kubectl + jq for direct Kubernetes API checks
  - No scanner dependencies (kubescape, trivy, etc.)
  - 100% coverage of all vulnerabilities
  - No false positives
  - Best for: CI/CD pipelines, quick validation, environments without scanners

${BOLD}Tier 2: Scanner Baseline Differencing${NC}
  - Medium execution (~5-10 min for all 22 tests)
  - Uses security scanners (kubescape, trivy) with baseline differencing
  - Filters infrastructure noise via kubescape-exceptions.json
  - Verifies scanner detectability of vulnerabilities
  - Best for: Integration testing, scanner validation, comprehensive security testing

${BOLD}Tier 3: Representative Sampling${NC}
  - Very fast execution (~1 min for 6 tests)
  - Runs 6 carefully selected representative tests
  - Covers all vulnerability categories
  - Best for: Quick smoke tests, pre-commit hooks, rapid iteration

${BOLD}EXAMPLES:${NC}

    # Quick smoke test with programmatic verification (recommended for CI)
    ./test-operator.sh --tier 1 --representative

    # Full test suite with programmatic verification
    ./test-operator.sh --tier 1 --full

    # Test specific category with scanner baseline differencing
    ./test-operator.sh --tier 2 --category K01

    # Run all tiers sequentially with verbose output
    ./test-operator.sh --tier all --full --verbose

    # Show test plan without executing
    ./test-operator.sh --tier 1 --representative --dry-run

    # Representative smoke test with all tiers
    ./test-operator.sh --tier all --representative

${BOLD}VULNERABILITY CATEGORIES:${NC}
    K01 - Insecure Workload Configurations (3 tests)
    K02 - Supply Chain Vulnerabilities (5 tests)
    K03 - Overly Permissive RBAC (3 tests)
    K06 - Broken Authentication (5 tests)
    K07 - Missing Network Segmentation (4 tests)
    K08 - Secrets Management Failures (3 tests)

    Total: 22 vulnerabilities across 6 categories

${BOLD}EXIT CODES:${NC}
    0 - All tests passed
    1 - One or more tests failed
    2 - Invalid arguments or configuration error

EOF
}

# =============================================================================
# Test Tier Functions
# =============================================================================

run_tier1() {
    log_section "Running Tier 1: Programmatic API Verification"

    local args=("--programmatic-only")

    if [ "$REPRESENTATIVE" = true ]; then
        args+=("--representative")
    elif [ -n "$CATEGORY" ]; then
        args+=("--category" "$CATEGORY")
    fi

    if [ "$VERBOSE" = true ]; then
        args+=("--verbose")
    fi

    if [ "$DRY_RUN" = true ]; then
        args+=("--dry-run")
    fi

    log_info "Executing: ${VERIFY_SCRIPT} ${args[*]}"

    if "$VERIFY_SCRIPT" "${args[@]}"; then
        log_success "Tier 1 tests passed"
        return 0
    else
        log_error "Tier 1 tests failed"
        return 1
    fi
}

run_tier2() {
    log_section "Running Tier 2: Scanner Baseline Differencing"

    local args=()

    if [ "$REPRESENTATIVE" = true ]; then
        args+=("--representative")
    elif [ -n "$CATEGORY" ]; then
        args+=("--category" "$CATEGORY")
    fi

    if [ "$VERBOSE" = true ]; then
        args+=("--verbose")
    fi

    if [ "$DRY_RUN" = true ]; then
        args+=("--dry-run")
    fi

    log_info "Executing: ${VERIFY_SCRIPT} ${args[*]}"
    log_warning "Scanner baseline differencing requires kubescape and trivy to be installed"

    if "$VERIFY_SCRIPT" "${args[@]}"; then
        log_success "Tier 2 tests passed"
        return 0
    else
        log_error "Tier 2 tests failed"
        return 1
    fi
}

run_tier3() {
    log_section "Running Tier 3: Representative Sampling"

    local args=("--representative")

    if [ "$VERBOSE" = true ]; then
        args+=("--verbose")
    fi

    if [ "$DRY_RUN" = true ]; then
        args+=("--dry-run")
    fi

    log_info "Executing: ${VERIFY_SCRIPT} ${args[*]}"
    log_info "Running 6 representative tests covering all vulnerability categories"

    if "$VERIFY_SCRIPT" "${args[@]}"; then
        log_success "Tier 3 tests passed"
        return 0
    else
        log_error "Tier 3 tests failed"
        return 1
    fi
}

# =============================================================================
# Argument Parsing
# =============================================================================

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --tier)
                TIER="$2"
                shift 2
                ;;
            --category)
                CATEGORY="$2"
                shift 2
                ;;
            --representative|-r)
                REPRESENTATIVE=true
                shift
                ;;
            --full|-f)
                FULL=true
                shift
                ;;
            --verbose|-v)
                VERBOSE=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 2
                ;;
        esac
    done
}

# =============================================================================
# Validation
# =============================================================================

validate_arguments() {
    # Validate tier
    if [[ ! "$TIER" =~ ^(1|2|3|all)$ ]]; then
        log_error "Invalid tier: $TIER. Must be 1, 2, 3, or all"
        exit 2
    fi

    # Validate category
    if [ -n "$CATEGORY" ] && [[ ! "$CATEGORY" =~ ^K0[12368]$ ]]; then
        log_error "Invalid category: $CATEGORY. Must be K01, K02, K03, K06, K07, or K08"
        exit 2
    fi

    # Validate mutually exclusive options
    if [ "$REPRESENTATIVE" = true ] && [ -n "$CATEGORY" ]; then
        log_error "Cannot use --representative with --category (mutually exclusive)"
        exit 2
    fi

    if [ "$REPRESENTATIVE" = true ] && [ "$FULL" = true ]; then
        log_error "Cannot use --representative with --full (mutually exclusive)"
        exit 2
    fi

    # Check if verify script exists
    if [ ! -f "$VERIFY_SCRIPT" ]; then
        log_error "Verification script not found: $VERIFY_SCRIPT"
        exit 2
    fi

    if [ ! -x "$VERIFY_SCRIPT" ]; then
        log_error "Verification script is not executable: $VERIFY_SCRIPT"
        exit 2
    fi
}

# =============================================================================
# Main Execution
# =============================================================================

main() {
    parse_arguments "$@"
    validate_arguments

    # Print banner
    echo
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║        Vulnerable K8s Operator - Test Runner                ║${NC}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo

    log_info "Tier: $TIER"
    if [ "$REPRESENTATIVE" = true ]; then
        log_info "Mode: Representative (6 tests)"
    elif [ -n "$CATEGORY" ]; then
        log_info "Mode: Category filter ($CATEGORY)"
    else
        log_info "Mode: Full (22 tests)"
    fi
    log_info "Verbose: $VERBOSE"
    log_info "Dry run: $DRY_RUN"
    echo

    # Execute tests based on tier
    local exit_code=0

    case "$TIER" in
        1)
            run_tier1 || exit_code=$?
            ;;
        2)
            run_tier2 || exit_code=$?
            ;;
        3)
            run_tier3 || exit_code=$?
            ;;
        all)
            local tier1_result=0
            local tier2_result=0
            local tier3_result=0

            run_tier1 || tier1_result=$?
            run_tier2 || tier2_result=$?
            run_tier3 || tier3_result=$?

            if [ $tier1_result -ne 0 ] || [ $tier2_result -ne 0 ] || [ $tier3_result -ne 0 ]; then
                exit_code=1
            fi

            log_section "Overall Results"
            [ $tier1_result -eq 0 ] && log_success "Tier 1: PASSED" || log_error "Tier 1: FAILED"
            [ $tier2_result -eq 0 ] && log_success "Tier 2: PASSED" || log_error "Tier 2: FAILED"
            [ $tier3_result -eq 0 ] && log_success "Tier 3: PASSED" || log_error "Tier 3: FAILED"
            ;;
    esac

    echo
    if [ $exit_code -eq 0 ]; then
        log_success "All tests passed!"
    else
        log_error "Some tests failed"
    fi
    echo

    exit $exit_code
}

# Run main function with all arguments
main "$@"
