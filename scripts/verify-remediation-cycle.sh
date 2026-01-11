#!/bin/bash
#
# Comprehensive Remediation Cycle Verification Script
# Tests all 24 sub-issues across 6 OWASP K8s Top 10 vulnerability categories
#
# State machine flow: Initialized -> Vulnerable -> Remediated -> (reset) -> Vulnerable (new)
# Controller checks remediation every 30 seconds
#
# Categories tested:
#   K01 - Insecure Workload Configurations (3 sub-issues)
#   K02 - Supply Chain Vulnerabilities (5 sub-issues)
#   K03 - Overly Permissive RBAC (3 sub-issues)
#   K06 - Broken Authentication (6 sub-issues)
#   K07 - Missing Network Segmentation (4 sub-issues)
#   K08 - Secrets Management (3 sub-issues)
#
# Usage:
#   ./verify-remediation-cycle.sh                    # Run all 24 tests
#   ./verify-remediation-cycle.sh --category K01    # Run only K01 tests (3 tests)
#   ./verify-remediation-cycle.sh --verbose         # Run with verbose output
#   ./verify-remediation-cycle.sh --dry-run         # Show test plan without executing
#   ./verify-remediation-cycle.sh --help            # Show help message

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

NAMESPACE="test-lab"
LAB_NAME="test-lab"
EXAMPLES_DIR="$(cd "$(dirname "$0")/../examples" && pwd)"
TIMEOUT_VULNERABLE=180      # Time to wait for Vulnerable state (seconds)
TIMEOUT_REMEDIATED=120      # Time to wait for Remediated state (seconds)
TIMEOUT_RESET=180           # Time to wait for reset to new Vulnerable state (seconds)
POLL_INTERVAL=5             # Time between state checks (seconds)

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Counters for test results
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# Options
VERBOSE=false
CATEGORY_FILTER=""
DRY_RUN=false

# Arrays for tracking results
declare -a PASSED_TESTS=()
declare -a FAILED_TESTS=()
declare -a SKIPPED_TESTS=()

# Secure image versions for K02 remediation
declare -A SECURE_IMAGES=(
    ["api"]="node:22-alpine"
    ["webapp"]="nginx:1.29.1-alpine"
    ["user-service"]="python:3.13-alpine"
    ["payment-service"]="ruby:3.3-alpine"
    ["grafana"]="grafana/grafana:12.2.0"
)

# K03 RBAC resource names (namespace-scoped, based on subissue)
declare -A K03_ROLE_NAMES=(
    [0]="${NAMESPACE}-overpermissive"
    [1]="${NAMESPACE}-default-permissions"
    [2]="${NAMESPACE}-secrets-reader"
)

declare -A K03_BINDING_NAMES=(
    [0]="${NAMESPACE}-overpermissive-binding"
    [1]="${NAMESPACE}-default-binding"
    [2]="${NAMESPACE}-secrets-binding"
)

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

log_verbose() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${CYAN}[DEBUG]${NC} $1"
    fi
}

log_header() {
    echo ""
    echo -e "${BOLD}==========================================${NC}"
    echo -e "${BOLD} $1${NC}"
    echo -e "${BOLD}==========================================${NC}"
}

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Comprehensive verification of remediation cycles for all vulnerability types
in the vulnerable-k8s-operator. Tests the complete state machine flow:
Initialized -> Vulnerable -> Remediated -> (reset) -> Vulnerable (new)

OPTIONS:
    -c, --category CATEGORY  Run tests for specific category only
                             Valid: K01, K02, K03, K06, K07, K08
    -v, --verbose            Enable verbose/debug output
    -d, --dry-run            Show test plan without executing tests
    -h, --help               Show this help message

EXAMPLES:
    $(basename "$0")                     # Run all 24 tests
    $(basename "$0") -c K01              # Run only K01 tests (3 tests)
    $(basename "$0") -c K02 -v           # Run K02 tests with verbose output
    $(basename "$0") --dry-run           # Show what would be tested

VULNERABILITY CATEGORIES:
    K01 - Insecure Workload Configurations (3 sub-issues)
          0: Privileged container
          1: Running as root
          2: Dangerous capabilities (SYS_ADMIN, NET_ADMIN)

    K02 - Supply Chain Vulnerabilities (5 sub-issues)
          0: API vulnerable image (node:10-alpine)
          1: Webapp vulnerable image (nginx:1.15-alpine)
          2: User-service vulnerable image (python:3.5-alpine)
          3: Payment-service vulnerable image (ruby:2.6-alpine)
          4: Grafana vulnerable image (grafana:9.0.0)

    K03 - Overly Permissive RBAC (3 sub-issues)
          0: Overpermissive RBAC role
          1: Default service account permissions
          2: Excessive secrets access

    K06 - Broken Authentication (6 sub-issues)
          0: Default service account usage
          1: Token annotation
          2: Account annotation
          3: Missing fsGroup
          4: Root user
          5: Privileged container

    K07 - Missing Network Segmentation (4 sub-issues)
          0: Network policy disabled annotation
          1: Network isolation disabled annotation
          2: Postgres NodePort exposure
          3: Service exposure annotation

    K08 - Secrets Management (3 sub-issues)
          0: Secrets in ConfigMap
          1: Hardcoded secrets annotation
          2: Insecure volume permissions annotation

REQUIREMENTS:
    - kubectl configured with cluster access
    - VulnerableLab CRD must be installed
    - Operator must be running in the cluster

EOF
    exit 0
}

# =============================================================================
# Core Functions
# =============================================================================

cleanup_lab() {
    log_verbose "Cleaning up existing lab resources..."

    # Delete the VulnerableLab CR if it exists
    kubectl delete vulnerablelab "$LAB_NAME" --ignore-not-found=true 2>/dev/null || true

    # Wait for lab CR to be deleted
    local max_wait=30
    local waited=0
    while kubectl get vulnerablelab "$LAB_NAME" &>/dev/null && [[ $waited -lt $max_wait ]]; do
        log_verbose "Waiting for VulnerableLab CR deletion... ($waited/$max_wait)"
        sleep 2
        waited=$((waited + 2))
    done

    # Force cleanup of namespace-scoped resources if namespace exists
    if kubectl get namespace "$NAMESPACE" &>/dev/null; then
        log_verbose "Cleaning up namespace resources in $NAMESPACE..."

        # Delete deployments first
        kubectl delete deployment --all -n "$NAMESPACE" --ignore-not-found=true 2>/dev/null || true

        # Delete services
        kubectl delete service --all -n "$NAMESPACE" --ignore-not-found=true 2>/dev/null || true

        # Delete configmaps (except kube-root-ca.crt)
        kubectl delete configmap --all -n "$NAMESPACE" --ignore-not-found=true 2>/dev/null || true

        # Delete secrets (except default service account token)
        kubectl delete secret --all -n "$NAMESPACE" --ignore-not-found=true 2>/dev/null || true

        # Delete RBAC resources
        kubectl delete role --all -n "$NAMESPACE" --ignore-not-found=true 2>/dev/null || true
        kubectl delete rolebinding --all -n "$NAMESPACE" --ignore-not-found=true 2>/dev/null || true

        # Delete service accounts (except default)
        local sas
        sas=$(kubectl get serviceaccount -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
        for sa in $sas; do
            if [[ "$sa" != "default" ]]; then
                kubectl delete serviceaccount "$sa" -n "$NAMESPACE" --ignore-not-found=true 2>/dev/null || true
            fi
        done

        # Wait for cleanup to complete
        sleep 3
    fi

    log_verbose "Cleanup complete"
}

apply_lab() {
    local example_file="$1"
    local full_path="$EXAMPLES_DIR/$example_file"

    if [[ ! -f "$full_path" ]]; then
        log_error "Example file not found: $full_path"
        return 1
    fi

    log_verbose "Applying lab from: $example_file"
    kubectl apply -f "$full_path"
}

wait_for_state() {
    local expected_state="$1"
    local timeout="$2"
    local start_time
    start_time=$(date +%s)

    log_verbose "Waiting for state: $expected_state (timeout: ${timeout}s)"

    while true; do
        local current_state
        current_state=$(kubectl get vulnerablelab "$LAB_NAME" -o jsonpath='{.status.state}' 2>/dev/null || echo "")

        if [[ "$current_state" == "$expected_state" ]]; then
            log_verbose "Reached state: $expected_state"
            return 0
        fi

        local elapsed
        elapsed=$(($(date +%s) - start_time))
        if [[ $elapsed -ge $timeout ]]; then
            log_error "Timeout waiting for state: $expected_state (current: $current_state)"
            return 1
        fi

        log_verbose "Current state: '$current_state', waiting for: '$expected_state' (${elapsed}s/${timeout}s)"
        sleep "$POLL_INTERVAL"
    done
}

get_target_resource() {
    kubectl get vulnerablelab "$LAB_NAME" -o jsonpath='{.status.targetResource}' 2>/dev/null || echo ""
}

get_current_state() {
    kubectl get vulnerablelab "$LAB_NAME" -o jsonpath='{.status.state}' 2>/dev/null || echo ""
}

get_chosen_vulnerability() {
    kubectl get vulnerablelab "$LAB_NAME" -o jsonpath='{.status.chosenVulnerability}' 2>/dev/null || echo ""
}

# =============================================================================
# Scanner Verification Functions
# =============================================================================

# Verify that at least one scanner detects the vulnerability
# Uses cascading approach: kubescape -> kube-bench -> kube-score
# For K02 (image vulnerabilities), uses trivy k8s mode
verify_scanner_detection() {
    local category="$1"
    local target="$2"

    log_verbose "Running scanner verification for $category on $target"

    # For K02 (image vulnerabilities): Use trivy k8s mode
    if [[ "$category" == "K02" ]]; then
        log_verbose "Using trivy for K02 image vulnerability detection"
        if command -v trivy &>/dev/null; then
            if trivy k8s --include-namespaces "$NAMESPACE" --severity CRITICAL,HIGH --quiet 2>/dev/null | grep -qE "(CRITICAL|HIGH)"; then
                log_verbose "trivy detected vulnerability"
                return 0
            fi
        else
            log_warning "trivy not installed, skipping K02 scanner verification"
            return 0  # Don't fail if scanner not installed
        fi
        log_warning "trivy did not detect K02 vulnerability"
        return 1
    fi

    # For all other categories: Try kubescape first, then fallbacks
    # Try kubescape (primary)
    if command -v kubescape &>/dev/null; then
        log_verbose "Trying kubescape scan..."
        if kubescape scan --include-namespaces "$NAMESPACE" --format json 2>/dev/null | grep -q '"status":"failed"'; then
            log_verbose "kubescape detected vulnerability"
            return 0
        fi
    else
        log_verbose "kubescape not installed, trying fallback scanners"
    fi

    # Try kube-bench (fallback 1)
    if command -v kube-bench &>/dev/null; then
        log_verbose "Trying kube-bench scan..."
        if kube-bench run --targets node 2>/dev/null | grep -q "FAIL"; then
            log_verbose "kube-bench detected vulnerability"
            return 0
        fi
    else
        log_verbose "kube-bench not installed"
    fi

    # Try kube-score (fallback 2)
    if command -v kube-score &>/dev/null; then
        log_verbose "Trying kube-score scan..."
        local deploy_yaml
        deploy_yaml=$(kubectl get deployment "$target" -n "$NAMESPACE" -o yaml 2>/dev/null)
        if [[ -n "$deploy_yaml" ]] && echo "$deploy_yaml" | kube-score score - 2>/dev/null | grep -qE "(CRITICAL|WARNING)"; then
            log_verbose "kube-score detected vulnerability"
            return 0
        fi
    else
        log_verbose "kube-score not installed"
    fi

    # Check if any scanner was available
    if ! command -v kubescape &>/dev/null && ! command -v kube-bench &>/dev/null && ! command -v kube-score &>/dev/null; then
        log_warning "No scanners installed (kubescape, kube-bench, kube-score). Skipping scanner verification."
        return 0  # Don't fail if no scanners installed
    fi

    log_warning "No scanner detected the vulnerability for $category"
    return 1
}

# Verify that the remediation message appears in the status
verify_remediation_message() {
    local expected_message="Vulnerability fixed! Preparing next challenge..."
    local actual_message

    actual_message=$(kubectl get vulnerablelab "$LAB_NAME" -o jsonpath='{.status.message}' 2>/dev/null || echo "")

    if [[ "$actual_message" == *"Vulnerability fixed"* ]]; then
        log_verbose "Remediation message verified: $actual_message"
        return 0
    else
        log_warning "Expected remediation message not found. Got: '$actual_message'"
        return 1
    fi
}

# =============================================================================
# Remediation Functions - K01 (Insecure Workload Configurations)
# =============================================================================

remediate_k01_privileged() {
    local target="$1"
    log_verbose "Remediating K01-0 (privileged container) on $target"

    # Try to remove privileged flag first, fall back to setting it to false
    kubectl patch deployment "$target" -n "$NAMESPACE" --type='json' -p='[
        {"op": "remove", "path": "/spec/template/spec/containers/0/securityContext/privileged"}
    ]' 2>/dev/null || \
    kubectl patch deployment "$target" -n "$NAMESPACE" --type='json' -p='[
        {"op": "replace", "path": "/spec/template/spec/containers/0/securityContext/privileged", "value": false}
    ]'
}

remediate_k01_root() {
    local target="$1"
    log_verbose "Remediating K01-1 (running as root) on $target"

    kubectl patch deployment "$target" -n "$NAMESPACE" --type='json' -p='[
        {"op": "replace", "path": "/spec/template/spec/containers/0/securityContext/runAsUser", "value": 1000}
    ]'
}

remediate_k01_capabilities() {
    local target="$1"
    log_verbose "Remediating K01-2 (dangerous capabilities) on $target"

    # Try to remove capabilities.add, fall back to setting it to empty array
    kubectl patch deployment "$target" -n "$NAMESPACE" --type='json' -p='[
        {"op": "remove", "path": "/spec/template/spec/containers/0/securityContext/capabilities/add"}
    ]' 2>/dev/null || \
    kubectl patch deployment "$target" -n "$NAMESPACE" --type='json' -p='[
        {"op": "replace", "path": "/spec/template/spec/containers/0/securityContext/capabilities/add", "value": []}
    ]'
}

# =============================================================================
# Remediation Functions - K02 (Supply Chain Vulnerabilities)
# =============================================================================

remediate_k02() {
    local target="$1"
    local subissue="$2"

    # Map subissue to deployment and secure image
    local containers=(
        "api"
        "webapp"
        "user-service"
        "payment-service"
        "grafana"
    )

    local container="${containers[$subissue]}"
    local secure_image="${SECURE_IMAGES[$container]}"

    log_verbose "Remediating K02-$subissue on $target: updating image to $secure_image"

    # Use kubectl set image to update the container image
    kubectl set image deployment/"$target" -n "$NAMESPACE" "$container=$secure_image"
}

# =============================================================================
# Remediation Functions - K03 (Overly Permissive RBAC)
# =============================================================================

remediate_k03() {
    local subissue="$1"

    local role="${K03_ROLE_NAMES[$subissue]}"
    local binding="${K03_BINDING_NAMES[$subissue]}"

    log_verbose "Remediating K03-$subissue: deleting role '$role' and binding '$binding'"

    # Both role AND rolebinding must be deleted for remediation to be detected
    kubectl delete rolebinding "$binding" -n "$NAMESPACE" --ignore-not-found=true
    kubectl delete role "$role" -n "$NAMESPACE" --ignore-not-found=true
}

# =============================================================================
# Remediation Functions - K06 (Broken Authentication)
# =============================================================================

remediate_k06_default_account() {
    local target="$1"
    log_verbose "Remediating K06-0 (default service account) on $target"

    kubectl patch deployment "$target" -n "$NAMESPACE" --type='json' -p='[
        {"op": "add", "path": "/spec/template/spec/serviceAccountName", "value": "restricted-sa"}
    ]'
}

remediate_k06_token_annotation() {
    local target="$1"
    log_verbose "Remediating K06-1 (token annotation) on $target"

    # Remove the token annotation using JSON path escaping for '/'
    kubectl patch deployment "$target" -n "$NAMESPACE" --type='json' -p='[
        {"op": "remove", "path": "/spec/template/metadata/annotations/kubernetes.io~1service-account.token"}
    ]'
}

remediate_k06_account_annotation() {
    local target="$1"
    log_verbose "Remediating K06-2 (account annotation) on $target"

    # Remove the default-account annotation
    kubectl patch deployment "$target" -n "$NAMESPACE" --type='json' -p='[
        {"op": "remove", "path": "/spec/template/metadata/annotations/auth.kubernetes.io~1default-account"}
    ]'
}

remediate_k06_missing_fsgroup() {
    local target="$1"
    log_verbose "Remediating K06-3 (missing fsGroup) on $target"

    # Add fsGroup to the pod security context
    kubectl patch deployment "$target" -n "$NAMESPACE" --type='json' -p='[
        {"op": "add", "path": "/spec/template/spec/securityContext/fsGroup", "value": 1000}
    ]'
}

remediate_k06_root_user() {
    local target="$1"
    log_verbose "Remediating K06-4 (root user) on $target"

    kubectl patch deployment "$target" -n "$NAMESPACE" --type='json' -p='[
        {"op": "replace", "path": "/spec/template/spec/containers/0/securityContext/runAsUser", "value": 1000}
    ]'
}

remediate_k06_privileged() {
    local target="$1"
    log_verbose "Remediating K06-5 (privileged) on $target"

    kubectl patch deployment "$target" -n "$NAMESPACE" --type='json' -p='[
        {"op": "replace", "path": "/spec/template/spec/containers/0/securityContext/privileged", "value": false}
    ]'
}

# =============================================================================
# Remediation Functions - K07 (Missing Network Segmentation)
# =============================================================================

remediate_k07_no_netpol() {
    local target="$1"
    log_verbose "Remediating K07-0 (network policy disabled annotation) on $target"

    kubectl patch deployment "$target" -n "$NAMESPACE" --type='json' -p='[
        {"op": "remove", "path": "/spec/template/metadata/annotations/networking.kubernetes.io~1network-policy"}
    ]'
}

remediate_k07_no_isolation() {
    local target="$1"
    log_verbose "Remediating K07-1 (network isolation disabled annotation) on $target"

    kubectl patch deployment "$target" -n "$NAMESPACE" --type='json' -p='[
        {"op": "remove", "path": "/spec/template/metadata/annotations/networking.kubernetes.io~1isolation"}
    ]'
}

remediate_k07_db_exposure() {
    local target="$1"
    log_verbose "Remediating K07-2 (postgres NodePort exposure) on service: $target"

    # Get the service name from VulnerableLab status (or use target)
    # For K07, the target might be a deployment, so we need to get the associated service
    # We'll use postgres-service as the service name for now, but this should be dynamic
    local service_name="postgres-service"

    # Try to find service associated with the target deployment if target is set
    if [[ -n "$target" ]]; then
        # Look for a service with the same name or ending in -service
        if kubectl get service "$target" -n "$NAMESPACE" &>/dev/null; then
            service_name="$target"
        elif kubectl get service "${target}-service" -n "$NAMESPACE" &>/dev/null; then
            service_name="${target}-service"
        fi
    fi

    log_verbose "Using service: $service_name"

    # Change service type from NodePort to ClusterIP
    kubectl patch service "$service_name" -n "$NAMESPACE" --type='json' -p='[
        {"op": "replace", "path": "/spec/type", "value": "ClusterIP"}
    ]'

    # Remove nodePort from ports (if present)
    kubectl patch service "$service_name" -n "$NAMESPACE" --type='json' -p='[
        {"op": "remove", "path": "/spec/ports/0/nodePort"}
    ]' 2>/dev/null || true
}

remediate_k07_service_exposure() {
    local target="$1"
    log_verbose "Remediating K07-3 (service exposure annotation) on service: $target"

    # Get the service name from VulnerableLab status (or use target)
    # For K07, the target might be a deployment, so we need to get the associated service
    # We'll use postgres-service as the service name for now, but this should be dynamic
    local service_name="postgres-service"

    # Try to find service associated with the target deployment if target is set
    if [[ -n "$target" ]]; then
        # Look for a service with the same name or ending in -service
        if kubectl get service "$target" -n "$NAMESPACE" &>/dev/null; then
            service_name="$target"
        elif kubectl get service "${target}-service" -n "$NAMESPACE" &>/dev/null; then
            service_name="${target}-service"
        fi
    fi

    log_verbose "Using service: $service_name"

    kubectl patch service "$service_name" -n "$NAMESPACE" --type='json' -p='[
        {"op": "remove", "path": "/metadata/annotations/networking.kubernetes.io~1exposure"}
    ]'
}

# =============================================================================
# Remediation Functions - K08 (Secrets Management)
# =============================================================================

remediate_k08_secrets_configmap() {
    local target="$1"
    log_verbose "Remediating K08-0 (secrets in ConfigMap) for $target"

    # Delete the ConfigMap containing secrets
    kubectl delete configmap "${target}-config" -n "$NAMESPACE" --ignore-not-found=true
}

remediate_k08_hardcoded_annotation() {
    local target="$1"
    log_verbose "Remediating K08-1 (hardcoded secrets annotation) on $target"

    kubectl patch deployment "$target" -n "$NAMESPACE" --type='json' -p='[
        {"op": "remove", "path": "/spec/template/metadata/annotations/config.kubernetes.io~1hardcoded-secrets"}
    ]'
}

remediate_k08_volume_annotation() {
    local target="$1"
    log_verbose "Remediating K08-2 (insecure volume annotation) on $target"

    kubectl patch deployment "$target" -n "$NAMESPACE" --type='json' -p='[
        {"op": "remove", "path": "/spec/template/metadata/annotations/security.kubernetes.io~1volume-permissions"}
    ]'
}

# =============================================================================
# Test Execution Functions
# =============================================================================

# Generic test runner for tests that need target resource
run_test() {
    local test_name="$1"
    local example_file="$2"
    local remediation_func="$3"
    shift 3
    local remediation_args=("$@")

    log_info "Testing: $test_name"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "  [DRY RUN] Would apply: $example_file"
        log_info "  [DRY RUN] Would remediate using: $remediation_func ${remediation_args[*]:-<target>}"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        SKIPPED_TESTS+=("$test_name (dry run)")
        return 0
    fi

    # Step 1: Cleanup any existing lab
    cleanup_lab

    # Step 2: Apply the example YAML
    if ! apply_lab "$example_file"; then
        log_error "$test_name: Failed to apply lab"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$test_name (apply failed)")
        return 1
    fi

    # Step 3: Wait for Vulnerable state
    if ! wait_for_state "Vulnerable" "$TIMEOUT_VULNERABLE"; then
        log_error "$test_name: Did not reach Vulnerable state"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$test_name (not vulnerable)")
        return 1
    fi

    # Step 4: Get target resource from status
    local target
    target=$(get_target_resource)
    if [[ -z "$target" ]]; then
        log_error "$test_name: Could not get target resource"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$test_name (no target)")
        return 1
    fi
    log_verbose "Target resource: $target"

    # Step 4b: Verify scanner detects vulnerability
    local category
    category=$(echo "$test_name" | grep -oE "^K[0-9]+" || echo "")
    if [[ -n "$category" ]]; then
        if ! verify_scanner_detection "$category" "$target"; then
            log_warning "$test_name: Scanner verification warning (continuing test)"
        else
            log_verbose "$test_name: Scanner detected vulnerability"
        fi
    fi

    # Step 5: Apply specific remediation
    log_verbose "Applying remediation..."
    if ! "$remediation_func" "${remediation_args[@]:-$target}"; then
        log_error "$test_name: Remediation command failed"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$test_name (remediation failed)")
        return 1
    fi

    # Step 6: Wait for Remediated state
    if ! wait_for_state "Remediated" "$TIMEOUT_REMEDIATED"; then
        log_error "$test_name: Did not reach Remediated state"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$test_name (not remediated)")
        return 1
    fi

    # Step 6b: Verify remediation message appears
    if ! verify_remediation_message; then
        log_warning "$test_name: Remediation message verification warning (continuing test)"
    else
        log_verbose "$test_name: Remediation message verified"
    fi

    # Step 7: Wait for reset to new Vulnerable state (confirms cycle works)
    if ! wait_for_state "Vulnerable" "$TIMEOUT_RESET"; then
        log_error "$test_name: Did not reset to new Vulnerable state"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$test_name (no reset)")
        return 1
    fi

    log_success "$test_name: Full remediation cycle verified"
    PASS_COUNT=$((PASS_COUNT + 1))
    PASSED_TESTS+=("$test_name")
    return 0
}

# Test runner for K02 tests that need subissue index
run_k02_test() {
    local test_name="$1"
    local example_file="$2"
    local subissue="$3"

    log_info "Testing: $test_name"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "  [DRY RUN] Would apply: $example_file"
        log_info "  [DRY RUN] Would remediate K02 subissue $subissue"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        SKIPPED_TESTS+=("$test_name (dry run)")
        return 0
    fi

    # Step 1: Cleanup
    cleanup_lab

    # Step 2: Apply lab
    if ! apply_lab "$example_file"; then
        log_error "$test_name: Failed to apply lab"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$test_name (apply failed)")
        return 1
    fi

    # Step 3: Wait for Vulnerable state
    if ! wait_for_state "Vulnerable" "$TIMEOUT_VULNERABLE"; then
        log_error "$test_name: Did not reach Vulnerable state"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$test_name (not vulnerable)")
        return 1
    fi

    # Step 4: Get target resource
    local target
    target=$(get_target_resource)
    if [[ -z "$target" ]]; then
        log_error "$test_name: Could not get target resource"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$test_name (no target)")
        return 1
    fi
    log_verbose "Target resource: $target"

    # Step 4b: Verify scanner detects vulnerability (K02 uses trivy)
    if ! verify_scanner_detection "K02" "$target"; then
        log_warning "$test_name: Scanner verification warning (continuing test)"
    else
        log_verbose "$test_name: Scanner detected vulnerability"
    fi

    # Step 5: Apply remediation
    log_verbose "Applying remediation..."
    if ! remediate_k02 "$target" "$subissue"; then
        log_error "$test_name: Remediation command failed"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$test_name (remediation failed)")
        return 1
    fi

    # Step 6: Wait for Remediated state
    if ! wait_for_state "Remediated" "$TIMEOUT_REMEDIATED"; then
        log_error "$test_name: Did not reach Remediated state"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$test_name (not remediated)")
        return 1
    fi

    # Step 6b: Verify remediation message appears
    if ! verify_remediation_message; then
        log_warning "$test_name: Remediation message verification warning (continuing test)"
    else
        log_verbose "$test_name: Remediation message verified"
    fi

    # Step 7: Wait for reset to new Vulnerable state
    if ! wait_for_state "Vulnerable" "$TIMEOUT_RESET"; then
        log_error "$test_name: Did not reset to new Vulnerable state"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$test_name (no reset)")
        return 1
    fi

    log_success "$test_name: Full remediation cycle verified"
    PASS_COUNT=$((PASS_COUNT + 1))
    PASSED_TESTS+=("$test_name")
    return 0
}

# Test runner for K03 tests (RBAC deletion doesn't need target)
run_k03_test() {
    local test_name="$1"
    local example_file="$2"
    local subissue="$3"

    log_info "Testing: $test_name"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "  [DRY RUN] Would apply: $example_file"
        log_info "  [DRY RUN] Would remediate K03 subissue $subissue"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        SKIPPED_TESTS+=("$test_name (dry run)")
        return 0
    fi

    # Step 1: Cleanup
    cleanup_lab

    # Step 2: Apply lab
    if ! apply_lab "$example_file"; then
        log_error "$test_name: Failed to apply lab"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$test_name (apply failed)")
        return 1
    fi

    # Step 3: Wait for Vulnerable state
    if ! wait_for_state "Vulnerable" "$TIMEOUT_VULNERABLE"; then
        log_error "$test_name: Did not reach Vulnerable state"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$test_name (not vulnerable)")
        return 1
    fi

    # Step 3b: Verify scanner detects vulnerability (K03 RBAC issues)
    if ! verify_scanner_detection "K03" ""; then
        log_warning "$test_name: Scanner verification warning (continuing test)"
    else
        log_verbose "$test_name: Scanner detected vulnerability"
    fi

    # Step 4: Apply remediation (K03 doesn't need target for RBAC deletion)
    log_verbose "Applying remediation..."
    if ! remediate_k03 "$subissue"; then
        log_error "$test_name: Remediation command failed"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$test_name (remediation failed)")
        return 1
    fi

    # Step 5: Wait for Remediated state
    if ! wait_for_state "Remediated" "$TIMEOUT_REMEDIATED"; then
        log_error "$test_name: Did not reach Remediated state"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$test_name (not remediated)")
        return 1
    fi

    # Step 5b: Verify remediation message appears
    if ! verify_remediation_message; then
        log_warning "$test_name: Remediation message verification warning (continuing test)"
    else
        log_verbose "$test_name: Remediation message verified"
    fi

    # Step 6: Wait for reset to new Vulnerable state
    if ! wait_for_state "Vulnerable" "$TIMEOUT_RESET"; then
        log_error "$test_name: Did not reset to new Vulnerable state"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$test_name (no reset)")
        return 1
    fi

    log_success "$test_name: Full remediation cycle verified"
    PASS_COUNT=$((PASS_COUNT + 1))
    PASSED_TESTS+=("$test_name")
    return 0
}

# Test runner for K07 service tests (remediation on service, not deployment)
run_k07_service_test() {
    local test_name="$1"
    local example_file="$2"
    local remediation_func="$3"

    log_info "Testing: $test_name"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "  [DRY RUN] Would apply: $example_file"
        log_info "  [DRY RUN] Would remediate using: $remediation_func"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        SKIPPED_TESTS+=("$test_name (dry run)")
        return 0
    fi

    # Step 1: Cleanup
    cleanup_lab

    # Step 2: Apply lab
    if ! apply_lab "$example_file"; then
        log_error "$test_name: Failed to apply lab"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$test_name (apply failed)")
        return 1
    fi

    # Step 3: Wait for Vulnerable state
    if ! wait_for_state "Vulnerable" "$TIMEOUT_VULNERABLE"; then
        log_error "$test_name: Did not reach Vulnerable state"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$test_name (not vulnerable)")
        return 1
    fi

    # Step 3b: Get target resource from status
    local target
    target=$(get_target_resource)
    if [[ -z "$target" ]]; then
        log_error "$test_name: Could not get target resource"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$test_name (no target)")
        return 1
    fi
    log_verbose "Target resource: $target"

    # Step 3c: Verify scanner detects vulnerability (K07 network issues)
    if ! verify_scanner_detection "K07" "$target"; then
        log_warning "$test_name: Scanner verification warning (continuing test)"
    else
        log_verbose "$test_name: Scanner detected vulnerability"
    fi

    # Step 4: Apply remediation (pass target for dynamic service lookup)
    log_verbose "Applying remediation..."
    if ! "$remediation_func" "$target"; then
        log_error "$test_name: Remediation command failed"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$test_name (remediation failed)")
        return 1
    fi

    # Step 5: Wait for Remediated state
    if ! wait_for_state "Remediated" "$TIMEOUT_REMEDIATED"; then
        log_error "$test_name: Did not reach Remediated state"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$test_name (not remediated)")
        return 1
    fi

    # Step 5b: Verify remediation message appears
    if ! verify_remediation_message; then
        log_warning "$test_name: Remediation message verification warning (continuing test)"
    else
        log_verbose "$test_name: Remediation message verified"
    fi

    # Step 6: Wait for reset to new Vulnerable state
    if ! wait_for_state "Vulnerable" "$TIMEOUT_RESET"; then
        log_error "$test_name: Did not reset to new Vulnerable state"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$test_name (no reset)")
        return 1
    fi

    log_success "$test_name: Full remediation cycle verified"
    PASS_COUNT=$((PASS_COUNT + 1))
    PASSED_TESTS+=("$test_name")
    return 0
}

# =============================================================================
# Test Suite Functions
# =============================================================================

run_k01_tests() {
    log_header "K01 - Insecure Workload Configurations (3 sub-issues)"

    run_test "K01-0: Privileged Container" \
        "k01-privileged.yaml" \
        remediate_k01_privileged

    run_test "K01-1: Running as Root" \
        "k01-root.yaml" \
        remediate_k01_root

    run_test "K01-2: Dangerous Capabilities" \
        "k01-capabilities.yaml" \
        remediate_k01_capabilities
}

run_k02_tests() {
    log_header "K02 - Supply Chain Vulnerabilities (5 sub-issues)"

    run_k02_test "K02-0: API (node:10-alpine -> node:22-alpine)" \
        "k02-api.yaml" 0

    run_k02_test "K02-1: Webapp (nginx:1.15-alpine -> nginx:1.29.1-alpine)" \
        "k02-webapp.yaml" 1

    run_k02_test "K02-2: User Service (python:3.5-alpine -> python:3.13-alpine)" \
        "k02-user-service.yaml" 2

    run_k02_test "K02-3: Payment Service (ruby:2.6-alpine -> ruby:3.3-alpine)" \
        "k02-payment-service.yaml" 3

    run_k02_test "K02-4: Grafana (grafana:9.0.0 -> grafana:12.2.0)" \
        "k02-grafana.yaml" 4
}

run_k03_tests() {
    log_header "K03 - Overly Permissive RBAC (3 sub-issues)"

    run_k03_test "K03-0: Overpermissive RBAC" \
        "k03-overpermissive-rbac.yaml" 0

    run_k03_test "K03-1: Default Service Account Permissions" \
        "k03-default-service-account.yaml" 1

    run_k03_test "K03-2: Excessive Secrets Access" \
        "k03-excessive-secrets.yaml" 2
}

run_k06_tests() {
    log_header "K06 - Broken Authentication (6 sub-issues)"

    run_test "K06-0: Default Service Account" \
        "k06-default-account.yaml" \
        remediate_k06_default_account

    run_test "K06-1: Token Annotation" \
        "k06-token-annotation.yaml" \
        remediate_k06_token_annotation

    run_test "K06-2: Account Annotation" \
        "k06-account-annotation.yaml" \
        remediate_k06_account_annotation

    run_test "K06-3: Missing fsGroup" \
        "k06-missing-fsgroup.yaml" \
        remediate_k06_missing_fsgroup

    run_test "K06-4: Root User" \
        "k06-root-user.yaml" \
        remediate_k06_root_user

    run_test "K06-5: Privileged Container" \
        "k06-privileged.yaml" \
        remediate_k06_privileged
}

run_k07_tests() {
    log_header "K07 - Missing Network Segmentation (4 sub-issues)"

    run_test "K07-0: Network Policy Disabled" \
        "k07-no-netpol.yaml" \
        remediate_k07_no_netpol

    run_test "K07-1: Network Isolation Disabled" \
        "k07-no-isolation.yaml" \
        remediate_k07_no_isolation

    run_k07_service_test "K07-2: Database Exposure (NodePort)" \
        "k07-db-exposure.yaml" \
        remediate_k07_db_exposure

    run_k07_service_test "K07-3: Service Exposure Annotation" \
        "k07-service-exposure.yaml" \
        remediate_k07_service_exposure
}

run_k08_tests() {
    log_header "K08 - Secrets Management (3 sub-issues)"

    run_test "K08-0: Secrets in ConfigMap" \
        "k08-secrets-configmap.yaml" \
        remediate_k08_secrets_configmap

    run_test "K08-1: Hardcoded Secrets Annotation" \
        "k08-hardcoded-annotation.yaml" \
        remediate_k08_hardcoded_annotation

    run_test "K08-2: Insecure Volume Annotation" \
        "k08-insecure-volumes.yaml" \
        remediate_k08_volume_annotation
}

# =============================================================================
# Summary and Main
# =============================================================================

print_summary() {
    echo ""
    log_header "TEST RESULTS SUMMARY"
    echo ""

    local total=$((PASS_COUNT + FAIL_COUNT + SKIP_COUNT))

    echo -e "Total Tests:   ${BOLD}$total${NC}"
    echo -e "Passed:        ${GREEN}$PASS_COUNT${NC}"
    echo -e "Failed:        ${RED}$FAIL_COUNT${NC}"
    echo -e "Skipped:       ${YELLOW}$SKIP_COUNT${NC}"
    echo ""

    if [[ ${#PASSED_TESTS[@]} -gt 0 ]]; then
        echo -e "${GREEN}Passed Tests:${NC}"
        for test in "${PASSED_TESTS[@]}"; do
            echo "  + $test"
        done
        echo ""
    fi

    if [[ ${#FAILED_TESTS[@]} -gt 0 ]]; then
        echo -e "${RED}Failed Tests:${NC}"
        for test in "${FAILED_TESTS[@]}"; do
            echo "  - $test"
        done
        echo ""
    fi

    if [[ ${#SKIPPED_TESTS[@]} -gt 0 ]]; then
        echo -e "${YELLOW}Skipped Tests:${NC}"
        for test in "${SKIPPED_TESTS[@]}"; do
            echo "  ~ $test"
        done
        echo ""
    fi

    # Calculate and display pass rate
    local executed=$((PASS_COUNT + FAIL_COUNT))
    if [[ $executed -gt 0 ]]; then
        local pass_rate
        pass_rate=$(awk "BEGIN {printf \"%.1f\", ($PASS_COUNT / $executed) * 100}")
        echo "Pass Rate: ${pass_rate}% ($PASS_COUNT/$executed)"
    fi

    echo ""
    if [[ $FAIL_COUNT -eq 0 && $SKIP_COUNT -eq 0 && $total -gt 0 ]]; then
        echo -e "${GREEN}${BOLD}All tests passed!${NC}"
    elif [[ $FAIL_COUNT -eq 0 && $total -gt 0 ]]; then
        echo -e "${YELLOW}All executed tests passed (some skipped)${NC}"
    elif [[ $total -eq 0 ]]; then
        echo -e "${YELLOW}No tests were run${NC}"
    else
        echo -e "${RED}${BOLD}Some tests failed${NC}"
    fi
}

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is required but not installed"
        exit 1
    fi

    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi

    # Check if VulnerableLab CRD exists
    if ! kubectl get crd vulnerablelabs.lab.security.lab &> /dev/null; then
        log_error "VulnerableLab CRD not found. Is the operator installed?"
        exit 1
    fi

    # Check if examples directory exists
    if [[ ! -d "$EXAMPLES_DIR" ]]; then
        log_error "Examples directory not found: $EXAMPLES_DIR"
        exit 1
    fi

    log_success "Prerequisites check passed"
}

main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--category)
                CATEGORY_FILTER="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -h|--help)
                usage
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                ;;
        esac
    done

    # Validate category filter if specified
    if [[ -n "$CATEGORY_FILTER" ]]; then
        case "$CATEGORY_FILTER" in
            K01|K02|K03|K06|K07|K08)
                log_info "Category filter: $CATEGORY_FILTER"
                ;;
            *)
                log_error "Invalid category: $CATEGORY_FILTER"
                log_error "Valid categories: K01, K02, K03, K06, K07, K08"
                exit 1
                ;;
        esac
    fi

    # Print banner
    echo ""
    echo -e "${BOLD}============================================${NC}"
    echo -e "${BOLD} Vulnerable K8s Operator                   ${NC}"
    echo -e "${BOLD} Remediation Cycle Verification Script     ${NC}"
    echo -e "${BOLD}============================================${NC}"
    echo ""
    echo "Namespace:       $NAMESPACE"
    echo "Examples Dir:    $EXAMPLES_DIR"
    echo "Verbose Mode:    $VERBOSE"
    echo "Dry Run Mode:    $DRY_RUN"
    if [[ -n "$CATEGORY_FILTER" ]]; then
        echo "Category Filter: $CATEGORY_FILTER"
    else
        echo "Category Filter: (all categories)"
    fi
    echo ""

    # Check prerequisites (unless dry run)
    if [[ "$DRY_RUN" != "true" ]]; then
        check_prerequisites
    fi

    # Record start time
    local start_time
    start_time=$(date +%s)

    # Run tests based on category filter
    if [[ -z "$CATEGORY_FILTER" ]]; then
        # Run all tests (24 total)
        run_k01_tests
        run_k02_tests
        run_k03_tests
        run_k06_tests
        run_k07_tests
        run_k08_tests
    else
        # Run specific category
        case "$CATEGORY_FILTER" in
            K01) run_k01_tests ;;
            K02) run_k02_tests ;;
            K03) run_k03_tests ;;
            K06) run_k06_tests ;;
            K07) run_k07_tests ;;
            K08) run_k08_tests ;;
        esac
    fi

    # Final cleanup
    if [[ "$DRY_RUN" != "true" ]]; then
        log_info "Performing final cleanup..."
        cleanup_lab
    fi

    # Calculate duration
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))

    # Print summary
    print_summary
    echo ""
    echo "Total Duration: ${duration} seconds"
    echo ""

    # Exit with appropriate code
    if [[ $FAIL_COUNT -gt 0 ]]; then
        exit 1
    fi
    exit 0
}

main "$@"
