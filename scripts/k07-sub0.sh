#!/usr/bin/env bash
set -euo pipefail

VULN="K07"
SUB_ISSUE=0
LAB_NAME="test-lab"

echo "==> Cleaning up existing VulnerableLab..."
kubectl delete vulnerablelab "$LAB_NAME" --ignore-not-found --wait=true

echo "==> Waiting for namespace resources to be cleaned up..."
sleep 5

echo "==> Applying $VULN sub-issue $SUB_ISSUE..."
kubectl apply -f - <<EOF
apiVersion: lab.security.lab/v1alpha1
kind: VulnerableLab
metadata:
  name: $LAB_NAME
spec:
  vulnerability: "$VULN"
  subIssue: $SUB_ISSUE
EOF

echo "==> Waiting for lab to become vulnerable..."
kubectl wait vulnerablelab "$LAB_NAME" \
  --for=jsonpath='{.status.state}'=Vulnerable \
  --timeout=120s

echo "==> $VULN sub-issue $SUB_ISSUE is now active."
kubectl get vulnerablelab "$LAB_NAME" -o yaml | grep -A5 status:
