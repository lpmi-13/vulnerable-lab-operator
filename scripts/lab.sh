#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

MODE="host"
CMD="up"
SEED_DEFAULT=1

usage() {
  cat <<'USAGE'
Usage:
  scripts/lab.sh [command] [--mode host|vm-rootfs] [--no-seed]

Commands:
  up        Clean, install CRD, seed default CR, run operator (default)
  reset     Clean lab state only
  down      Alias for reset

Options:
  --mode        host (default) or vm-rootfs
  --no-seed     Skip creating the default VulnerableLab CR
  -h, --help    Show this help
USAGE
}

require_kubectl_ready() {
  if ! kubectl get --raw=/readyz >/dev/null 2>&1; then
    echo "kubectl is not ready; check your kubeconfig and cluster" >&2
    exit 1
  fi
}

cleanup_lab() {
  # Cleanup RBAC resources
  kubectl delete clusterrole test-lab-secret-reader test-lab-node-reader --ignore-not-found
  kubectl delete clusterrolebinding test-lab-cluster-access test-lab-secret-access test-lab-node-access --ignore-not-found
  kubectl delete role test-lab-system-access -n kube-system --ignore-not-found
  kubectl delete rolebinding test-lab-system-binding -n kube-system --ignore-not-found

  # Delete the VulnerableLab resource first
  kubectl delete vulnerablelab test-lab --ignore-not-found --timeout=30s

  # Force-delete all pods to avoid Terminating state
  echo "Force-deleting pods in test-lab..."
  kubectl delete pods --all -n test-lab --grace-period=0 --force --ignore-not-found 2>/dev/null || true

  # Fast namespace deletion with aggressive cleanup
  echo "Deleting test-lab namespace..."
  # Namespace deletion can legitimately time out while finalizers drain.
  kubectl delete ns test-lab --ignore-not-found --timeout=15s || true

  # If still exists, force finalize via raw API
  if kubectl get ns test-lab >/dev/null 2>&1; then
    echo "Force finalizing stuck namespace..."
    kubectl get ns test-lab -o json | jq '.spec.finalizers = []' | kubectl replace --raw /api/v1/namespaces/test-lab/finalize -f - >/dev/null 2>&1 || true
  fi

  # Final verification
  if kubectl get ns test-lab >/dev/null 2>&1; then
    echo "Warning: Namespace test-lab still exists"
  else
    echo "Namespace cleanup complete"
  fi

  # Clean up operator deployment (if it exists from a previous 'make deploy')
  echo "Cleaning up operator system namespace..."
  kubectl delete namespace vulnerable-k8s-operator-system --ignore-not-found --timeout=10s

  # If still exists, force finalize via raw API
  if kubectl get ns vulnerable-k8s-operator-system >/dev/null 2>&1; then
    echo "Force finalizing operator namespace..."
    kubectl get ns vulnerable-k8s-operator-system -o json | jq '.spec.finalizers = []' | kubectl replace --raw /api/v1/namespaces/vulnerable-k8s-operator-system/finalize -f - >/dev/null 2>&1 || true
  fi

  # Clean up any lingering operator RBAC resources
  kubectl delete clusterrole vulnerable-k8s-operator-manager-role vulnerable-k8s-operator-metrics-reader vulnerable-k8s-operator-proxy-role --ignore-not-found
  kubectl delete clusterrolebinding vulnerable-k8s-operator-manager-rolebinding vulnerable-k8s-operator-proxy-rolebinding --ignore-not-found
}

install_crds() {
  echo "Generating CRD manifests..."
  (cd "${REPO_ROOT}" && make manifests)

  echo "Installing CRDs only (no operator pod)..."
  (cd "${REPO_ROOT}" && make install)
}

seed_default_cr() {
  kubectl apply -f - <<'YAML'
apiVersion: lab.security.lab/v1alpha1
kind: VulnerableLab
metadata:
  name: test-lab
spec: {}
YAML
}

run_operator_foreground() {
  echo "Starting operator locally (foreground)..."
  echo "The operator will run on your host machine (not as a pod)."
  echo "Notifications are available at http://localhost:8888"
  (cd "${REPO_ROOT}" && make run)
}

run_vm_rootfs() {
  "${REPO_ROOT}/hack/build-rootfs-image.sh"
  "${REPO_ROOT}/hack/run-rootfs-vm.sh"
}

if [[ $# -gt 0 ]]; then
  case "$1" in
    up|reset|down)
      CMD="$1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
  esac
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="$2"
      shift 2
      ;;
    --no-seed)
      SEED_DEFAULT=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

case "${CMD}" in
  reset|down)
    require_kubectl_ready
    cleanup_lab
    exit 0
    ;;
  up)
    if [[ "${MODE}" == "vm-rootfs" ]]; then
      run_vm_rootfs
      exit 0
    fi

    if [[ "${MODE}" != "host" ]]; then
      echo "Unsupported mode: ${MODE}" >&2
      exit 1
    fi

    require_kubectl_ready
    cleanup_lab
    install_crds
    if [[ "${SEED_DEFAULT}" -eq 1 ]]; then
      echo "Seeding default VulnerableLab CR..."
      seed_default_cr
    fi
    run_operator_foreground
    ;;
  *)
    echo "Unknown command: ${CMD}" >&2
    usage >&2
    exit 1
    ;;
esac
