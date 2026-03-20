#!/usr/bin/env bash
set -euo pipefail

CRD_NAME="vulnerablelabs.lab.security.lab"
LAB_RESOURCE="vulnerablelabs.lab.security.lab"
DEFAULT_LAB_NAME="test-lab"
OPERATOR_NAMESPACE="vulnerable-k8s-operator-system"
DELETE_CRD=1
FAILURES=0

declare -A SEEN_LAB_NAMES=()
LAB_NAMES=()

OPERATOR_CLUSTER_ROLES=(
  "vulnerable-k8s-operator-manager-role"
  "vulnerable-k8s-operator-metrics-auth-role"
  "vulnerable-k8s-operator-metrics-reader"
  "vulnerable-k8s-operator-vulnerablelab-admin-role"
  "vulnerable-k8s-operator-vulnerablelab-editor-role"
  "vulnerable-k8s-operator-vulnerablelab-viewer-role"
  "vulnerable-k8s-operator-proxy-role"
)

OPERATOR_CLUSTER_ROLE_BINDINGS=(
  "vulnerable-k8s-operator-manager-rolebinding"
  "vulnerable-k8s-operator-metrics-auth-rolebinding"
  "vulnerable-k8s-operator-proxy-rolebinding"
)

usage() {
  cat <<'USAGE'
Usage:
  scripts/cleanup-k3s-resources.sh [--lab-name NAME] [--keep-crd]

Options:
  --lab-name NAME  Additional lab name/namespace to clean. May be repeated.
  --keep-crd       Keep the VulnerableLab CRD installed for faster reruns.
  -h, --help       Show this help.

This removes:
- VulnerableLab custom resources
- RBAC labeled rbac.k8s.lab/managed-by=vulnerable-lab
- Known legacy lab RBAC names for each lab namespace
- The discovered lab namespaces (defaults to test-lab)
- Operator deployment resources in vulnerable-k8s-operator-system
- The VulnerableLab CRD, unless --keep-crd is set
USAGE
}

append_lab_name() {
  local lab_name="${1:-}"

  if [[ -z "${lab_name}" ]]; then
    return
  fi

  if [[ -n "${SEEN_LAB_NAMES[${lab_name}]+x}" ]]; then
    return
  fi

  SEEN_LAB_NAMES["${lab_name}"]=1
  LAB_NAMES+=("${lab_name}")
}

require_command() {
  local command_name="$1"

  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "Missing required command: ${command_name}" >&2
    exit 1
  fi
}

require_kubectl_ready() {
  if ! kubectl get --raw=/readyz >/dev/null 2>&1; then
    echo "kubectl is not ready; check your kubeconfig and cluster" >&2
    exit 1
  fi
}

discover_lab_names() {
  local lab_name

  append_lab_name "${DEFAULT_LAB_NAME}"

  if ! kubectl get crd "${CRD_NAME}" >/dev/null 2>&1; then
    return
  fi

  while IFS= read -r lab_name; do
    append_lab_name "${lab_name}"
  done < <(
    kubectl get "${LAB_RESOURCE}" --all-namespaces \
      -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true
  )
}

delete_vulnerablelabs() {
  local lab_namespace
  local lab_name

  if ! kubectl get crd "${CRD_NAME}" >/dev/null 2>&1; then
    return
  fi

  echo "Deleting VulnerableLab custom resources..."

  while IFS=$'\t' read -r lab_namespace lab_name; do
    if [[ -z "${lab_namespace}" || -z "${lab_name}" ]]; then
      continue
    fi

    kubectl delete "${LAB_RESOURCE}" "${lab_name}" \
      -n "${lab_namespace}" \
      --ignore-not-found \
      --timeout=30s >/dev/null 2>&1 || true
  done < <(
    kubectl get "${LAB_RESOURCE}" --all-namespaces \
      -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\n"}{end}' 2>/dev/null || true
  )
}

delete_labeled_rbac() {
  echo "Deleting lab-managed RBAC objects..."

  kubectl delete role,rolebinding \
    --all-namespaces \
    -l rbac.k8s.lab/managed-by=vulnerable-lab \
    --ignore-not-found >/dev/null 2>&1 || true

  kubectl delete clusterrole,clusterrolebinding \
    -l rbac.k8s.lab/managed-by=vulnerable-lab \
    --ignore-not-found >/dev/null 2>&1 || true
}

delete_legacy_lab_rbac() {
  local lab_name="$1"

  echo "Deleting fallback RBAC objects for ${lab_name}..."

  kubectl delete role \
    "${lab_name}-secrets-access-role" \
    "${lab_name}-pod-create-role" \
    "${lab_name}-delete-role" \
    "${lab_name}-portforward-role" \
    "${lab_name}-exec-role" \
    -n "${lab_name}" \
    --ignore-not-found >/dev/null 2>&1 || true

  kubectl delete rolebinding \
    "${lab_name}-secrets-access-binding" \
    "${lab_name}-pod-create-binding" \
    "${lab_name}-delete-binding" \
    "${lab_name}-portforward-binding" \
    "${lab_name}-exec-binding" \
    -n "${lab_name}" \
    --ignore-not-found >/dev/null 2>&1 || true

  kubectl delete clusterrole \
    "${lab_name}-secret-reader" \
    "${lab_name}-node-reader" \
    "${lab_name}-cluster-role" \
    --ignore-not-found >/dev/null 2>&1 || true

  kubectl delete clusterrolebinding \
    "${lab_name}-cluster-access" \
    "${lab_name}-secret-access" \
    "${lab_name}-node-access" \
    "${lab_name}-cluster-binding" \
    --ignore-not-found >/dev/null 2>&1 || true

  kubectl delete role \
    "${lab_name}-system-access" \
    -n kube-system \
    --ignore-not-found >/dev/null 2>&1 || true

  kubectl delete rolebinding \
    "${lab_name}-system-binding" \
    -n kube-system \
    --ignore-not-found >/dev/null 2>&1 || true
}

force_finalize_namespace() {
  local namespace="$1"

  if ! kubectl get namespace "${namespace}" >/dev/null 2>&1; then
    return
  fi

  if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required to force finalize namespace ${namespace}" >&2
    FAILURES=1
    return
  fi

  echo "Force finalizing namespace ${namespace}..."
  kubectl get namespace "${namespace}" -o json \
    | jq '.spec.finalizers = []' \
    | kubectl replace --raw "/api/v1/namespaces/${namespace}/finalize" -f - >/dev/null 2>&1 || true
}

delete_namespace() {
  local namespace="$1"

  if ! kubectl get namespace "${namespace}" >/dev/null 2>&1; then
    return
  fi

  echo "Deleting namespace ${namespace}..."
  kubectl delete pods --all -n "${namespace}" \
    --grace-period=0 \
    --force \
    --ignore-not-found >/dev/null 2>&1 || true

  kubectl delete namespace "${namespace}" \
    --ignore-not-found \
    --timeout=20s >/dev/null 2>&1 || true

  if kubectl get namespace "${namespace}" >/dev/null 2>&1; then
    force_finalize_namespace "${namespace}"
  fi

  if kubectl get namespace "${namespace}" >/dev/null 2>&1; then
    echo "Warning: namespace ${namespace} still exists" >&2
    FAILURES=1
  fi
}

delete_operator_resources() {
  echo "Deleting operator deployment resources..."

  kubectl delete clusterrole "${OPERATOR_CLUSTER_ROLES[@]}" \
    --ignore-not-found >/dev/null 2>&1 || true

  kubectl delete clusterrolebinding "${OPERATOR_CLUSTER_ROLE_BINDINGS[@]}" \
    --ignore-not-found >/dev/null 2>&1 || true

  delete_namespace "${OPERATOR_NAMESPACE}"
}

delete_crd() {
  if [[ "${DELETE_CRD}" -ne 1 ]]; then
    return
  fi

  if ! kubectl get crd "${CRD_NAME}" >/dev/null 2>&1; then
    return
  fi

  echo "Deleting CRD ${CRD_NAME}..."
  kubectl delete crd "${CRD_NAME}" --ignore-not-found --timeout=30s >/dev/null 2>&1 || true

  if kubectl get crd "${CRD_NAME}" >/dev/null 2>&1; then
    echo "Warning: CRD ${CRD_NAME} still exists" >&2
    FAILURES=1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --lab-name)
      if [[ $# -lt 2 ]]; then
        echo "--lab-name requires a value" >&2
        usage >&2
        exit 1
      fi
      append_lab_name "$2"
      shift 2
      ;;
    --keep-crd)
      DELETE_CRD=0
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

require_command kubectl
require_kubectl_ready
discover_lab_names

delete_vulnerablelabs
delete_labeled_rbac

for lab_name in "${LAB_NAMES[@]}"; do
  delete_legacy_lab_rbac "${lab_name}"
done

for lab_name in "${LAB_NAMES[@]}"; do
  delete_namespace "${lab_name}"
done

delete_operator_resources
delete_crd

if [[ "${FAILURES}" -ne 0 ]]; then
  echo "Cleanup finished with warnings." >&2
  exit 1
fi

echo "Cleanup complete."
