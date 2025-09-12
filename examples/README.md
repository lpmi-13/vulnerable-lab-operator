# VulnerableLab Sub-Issue Examples

This directory contains example YAML files for testing each specific sub-issue within vulnerability categories.

## Usage

Apply any example file to trigger that specific misconfiguration:

```bash
kubectl apply -f k01-privileged.yaml
```

Check the status to see which vulnerability and sub-issue was applied:

```bash
kubectl get vulnerablelab k01-privileged -o yaml
```

## Sub-Issue Index Reference

### K01 - Insecure Workload Configurations
- `0`: Privileged container (`privileged: true`)
- `1`: Running as root (`runAsUser: 0`)
- `2`: Dangerous capabilities (`SYS_ADMIN`, `NET_ADMIN`)

### K02 - Supply Chain Vulnerabilities
- `0`: API vulnerable image (`node:16-alpine`)
- `1`: Webapp vulnerable image (`nginx:1.20-alpine`)
- `2`: User-service vulnerable image (`python:3.9-alpine`)
- `3`: Payment-service vulnerable image (`ruby:3.0-alpine`)
- `4`: Grafana vulnerable image (`grafana/grafana:9.0.0`)

### K03 - Overly Permissive RBAC
- `0`: Cluster Admin Access (grants `cluster-admin` permissions)
- `1`: Secret Access (grants broad secret access across cluster)
- `2`: Cross-Namespace Access (grants access to `kube-system` namespace)
- `3`: Node Access (grants access to node resources and metrics)

### K06 - Broken Authentication
- `0`: Default service account usage (removes explicit serviceAccountName)
- `1`: Service account token annotation (adds token requirement annotation)
- `2`: Default service account annotation (adds temporary account annotation)
- `3`: Missing fsGroup in PodSecurityContext (creates PodSecurityContext without fsGroup)
- `4`: Root user with volume access (sets runAsUser: 0)
- `5`: Privileged container with volume access (sets privileged: true)

### K07 - Missing Network Segmentation
- `0`: Unrestricted pod-to-pod communication (network policy disabled annotation)
- `1`: Network isolation disabled (isolation disabled annotation)
- `2`: Database exposure (changes PostgreSQL service to NodePort)
- `3`: Service exposure annotation (adds external database access annotation)

### K08 - Secrets Management Failures
- `0`: Secret data in ConfigMaps (stores sensitive data in ConfigMap instead of Secret)
- `1`: Hardcoded secrets annotation (adds development mode annotation)
- `2`: Insecure volume permissions (adds debugging enabled annotation)

## Scanner Testing

For comprehensive scanner testing, you can systematically test each sub-issue:

```bash
# Test all K01 sub-issues
kubectl apply -f k01-privileged.yaml
kubectl apply -f k01-root.yaml  
kubectl apply -f k01-capabilities.yaml

# Test all K06 sub-issues (authentication issues)
kubectl apply -f k06-default-account.yaml
kubectl apply -f k06-token-annotation.yaml
kubectl apply -f k06-account-annotation.yaml
kubectl apply -f k06-missing-fsgroup.yaml
kubectl apply -f k06-root-user.yaml
kubectl apply -f k06-privileged.yaml

# etc...
```

Each example creates a lab environment with exactly one specific misconfiguration, allowing you to verify that your security scanners detect each individual issue.