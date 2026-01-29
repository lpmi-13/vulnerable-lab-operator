#!/bin/bash

# Cleanup RBAC resources
kubectl delete clusterrole test-lab-secret-reader test-lab-node-reader --ignore-not-found
kubectl delete clusterrolebinding test-lab-cluster-access test-lab-secret-access test-lab-node-access --ignore-not-found
kubectl delete role test-lab-system-access -n kube-system --ignore-not-found
kubectl delete rolebinding test-lab-system-binding -n kube-system --ignore-not-found

# Delete the VulnerableLab resource first
kubectl delete vulnerablelab test-lab --ignore-not-found --timeout=30s

# Fast namespace deletion with aggressive cleanup
echo "Deleting test-lab namespace..."
kubectl delete ns test-lab --ignore-not-found --timeout=3s

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

# Uninstall CRDs to ensure clean state
echo "Uninstalling CRDs..."
make uninstall 2>/dev/null || true

# Setup for local development mode
echo "Setting up local development mode..."
echo "- Generating CRD manifests..."
make manifests

echo "- Installing CRDs only (no operator pod)..."
make install

echo ""
echo "Setup complete! Starting operator locally..."
echo "The operator will run on your host machine (not as a pod)."
echo "Terminal notifications are handled directly by the operator."
echo ""

make run
