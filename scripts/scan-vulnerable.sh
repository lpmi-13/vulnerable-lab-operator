#!/usr/bin/env bash
set -euo pipefail

LAB_NAME="${1:-test-lab}"

echo "==> Getting vulnerable deployment target..."
TARGET=$(kubectl get vulnerablelab "$LAB_NAME" -o jsonpath='{.status.targetResource}' 2>/dev/null || echo "")
VULN=$(kubectl get vulnerablelab "$LAB_NAME" -o jsonpath='{.status.chosenVulnerability}' 2>/dev/null || echo "")

if [ -z "$TARGET" ]; then
  echo "Error: No target deployment found. Is the lab vulnerable?"
  echo "Check status with: kubectl get vulnerablelab $LAB_NAME -o yaml"
  exit 1
fi

echo "==> Vulnerability: $VULN"
echo "==> Target: deployment/$TARGET"
echo ""

if [ "$VULN" = "K02" ]; then
  echo "==> Running Trivy scan on deployment/$TARGET..."
  trivy k8s deployment/"$TARGET" -n "$LAB_NAME" --report summary
else
  echo "==> This vulnerability requires different scanning tools:"
  echo "    K01: kubescape scan workload Deployment/$TARGET --include-namespaces $LAB_NAME"
  echo "    K03: kubectl get roles,rolebindings -n $LAB_NAME"
  echo "    K06: kubectl get serviceaccounts,secrets -n $LAB_NAME"
  echo "    K07: kubectl get networkpolicies -n $LAB_NAME"
  echo "    K08: kubectl get secrets,configmaps -n $LAB_NAME"
fi
