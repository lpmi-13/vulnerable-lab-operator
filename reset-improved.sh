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

# Continue with operator setup
make manifests
make install
make run
