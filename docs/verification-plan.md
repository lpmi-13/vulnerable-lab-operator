# Comprehensive Verification Plan

## Objective
Verify the vulnerable-k8s-operator implementation is complete, vulnerabilities are detectable by scanners, and remediation triggers user notification via `wall` utility.

**Target Environment:** k3s (lightweight Kubernetes cluster for local development)

---

## Phase 0: k3s Cluster Readiness

Before running any verification tests, ensure k3s is running locally.

### 0.1 Check k3s Status

```bash
# Check if k3s is installed and running
sudo systemctl status k3s
```

**Expected**: Service is `active (running)`

**Alternative check** (if systemd not available):
```bash
# Check if k3s process is running
pgrep -f k3s
# Check if kubectl can connect
sudo k3s kubectl get nodes
```

### 0.2 Start k3s (if not running)

If k3s is not running, start it with:

```bash
# Start k3s service
sudo systemctl start k3s

# Wait for k3s to be ready (may take 30-60 seconds)
sudo k3s kubectl wait --for=condition=Ready node --all --timeout=120s
```

### 0.3 Configure kubectl for k3s

```bash
# Set up kubeconfig for k3s
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $USER:$USER ~/.kube/config
export KUBECONFIG=~/.kube/config

# Verify connectivity
kubectl get nodes
```

**Expected**: Node status shows `Ready`

### 0.4 Install k3s (if not installed)

If k3s is not installed on your system:

```bash
# Install k3s (lightweight Kubernetes)
curl -sfL https://get.k3s.io | sh -

# Check installation
sudo systemctl status k3s

# Configure kubectl access
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $USER:$USER ~/.kube/config

# Verify
kubectl get nodes
```

**Note**: k3s runs as a systemd service and requires sudo for most operations unless kubeconfig is properly configured.

### 0.5 Reset k3s Cluster (if needed)

If the k3s cluster is in a bad state or you need to start fresh:

```bash
# Reset the k3s cluster to a clean state
./reset-improved.sh
```

**Purpose**: This script resets the k3s cluster to a known good state, cleaning up any existing resources and preparing the cluster for testing.

**When to use**:
- Before starting a fresh verification run
- When the cluster has leftover resources from previous tests
- When troubleshooting issues and you need a clean slate

---

## Phase 1: Code Quality Verification

### 1.1 Run Linter
```bash
make lint
```
**Expected**: No errors (per CLAUDE.md requirement)

### 1.2 Run Unit Tests
```bash
go test ./internal/breaker/ -v
```
**Expected**: All tests pass for vulnerability application logic

---

## Phase 2: Vulnerability Implementation Verification

Verify all 6 OWASP categories are properly implemented with their sub-issues:

| Category | Sub-issues | Scanner Detection | Key Files |
|----------|------------|-------------------|-----------|
| K01 | 3 (privileged, root, capabilities) | kubescape | `breaker.go:122-193` |
| K02 | 5 (vulnerable images) | trivy | `breaker.go:196-246` |
| K03 | 3 (RBAC roles/bindings) | kubescape | `breaker.go:249-475` |
| K06 | 6 (auth misconfigs) | kubescape | `breaker.go:478-539` |
| K07 | 4 (network segmentation) | kubescape | `breaker.go:542-645` |
| K08 | 3 (secrets in configmaps) | kubescape, trivy | `breaker.go:648-776` |

### 2.1 Code Review Checklist
- [ ] Each category has correct number of sub-issues
- [ ] Each category validates subIssue range
- [ ] Each category creates detectable resources (not just annotations)

---

## Phase 3: Scanner Detection Verification

**Note:** All scanner commands below work with k3s clusters. Ensure your kubeconfig is properly configured (see Phase 0.3) before running scans.

### 3.1 Deploy and Scan Each Vulnerability Type

```bash
# K01 - Insecure Workload (kubescape should detect privileged/root/capabilities)
kubescape scan --include-namespaces test-lab

# K02 - Supply Chain (trivy should detect CVEs in old images)
trivy k8s --include-namespaces test-lab --report summary

# K03 - RBAC (kubescape should detect overly permissive roles)
kubescape scan --include-namespaces test-lab

# K06 - Auth Issues (check for service account misconfigs)
kubescape scan --include-namespaces test-lab

# K07 - Network Segmentation (check for exposed services)
kubescape scan --include-namespaces test-lab

# K08 - Secrets Management (check for secrets in configmaps)
kubescape scan --include-namespaces test-lab
```

### 3.2 Expected Scanner Findings

| Vulnerability | Scanner | Expected Finding |
|--------------|---------|------------------|
| K01:0 | kubescape | Privileged container |
| K01:1 | kubescape | Running as root |
| K01:2 | kubescape | Dangerous capabilities (SYS_ADMIN, NET_ADMIN) |
| K02:* | trivy | Critical CVEs in old images |
| K03:* | kubescape | Overpermissive RBAC |
| K07:2 | any | NodePort on postgres (30432) |
| K08:0 | any | Secrets in ConfigMap |

---

## Phase 4: Remediation Cycle Verification

### 4.1 State Machine Flow

```
Initialized → Vulnerable → Remediated → (reset) → Initialized → Vulnerable (new)
```

**Key timing:**
- Controller checks remediation every 30 seconds
- Allow 60-120 seconds for state transitions

**Key code**: `vulnerablelab_controller.go:62-86`

### 4.2 K01 Smoke Test (Run First)

Before running the full 24-vulnerability verification suite, run a smoke test with K01 vulnerabilities only:

```bash
./scripts/verify-remediation-cycle.sh --category K01 --verbose
```

**K01 Smoke Test Checks:**
- [ ] K01:0 (privileged container) - Creates, detected, remediated, resets
- [ ] K01:1 (running as root) - Creates, detected, remediated, resets
- [ ] K01:2 (dangerous capabilities) - Creates, detected, remediated, resets
- [ ] `wall` notification appears when vulnerability is remediated
- [ ] Status file `/tmp/cluster-status` updated correctly

**Why K01 First:**
- K01 vulnerabilities are the simplest to verify visually
- Quick feedback loop (3 tests vs 24)
- Tests core state machine + remediation detection + notification
- If K01 passes, proceed with full suite

### 4.3 All 24 Sub-Issues: Tables and Remediation Commands

#### General Verification Pattern

```bash
# 1. Deploy vulnerability
kubectl apply -f examples/<example-file>.yaml

# 2. Wait for Vulnerable state
kubectl wait --for=jsonpath='{.status.state}'=Vulnerable vulnerablelab/test-lab --timeout=120s

# 3. Get target resource
TARGET=$(kubectl get vulnerablelab test-lab -o jsonpath='{.status.targetResource}')

# 4. Apply remediation (specific to vulnerability type)
kubectl patch deployment $TARGET -n test-lab --type='json' -p='[...]'

# 5. Wait for Remediated state
kubectl wait --for=jsonpath='{.status.state}'=Remediated vulnerablelab/test-lab --timeout=60s

# 6. Wait for new Vulnerable state (confirms reset cycle)
kubectl wait --for=jsonpath='{.status.state}'=Vulnerable vulnerablelab/test-lab --timeout=120s
```

---

#### K01 - Insecure Workload Configurations (3 sub-issues)

| SubIssue | Vulnerability | Remediation Action |
|----------|---------------|-------------------|
| 0 | Privileged container (`privileged: true`) | Remove privileged flag or set to false |
| 1 | Running as root (`runAsUser: 0`) | Change runAsUser to non-zero value |
| 2 | Dangerous capabilities (SYS_ADMIN, NET_ADMIN) | Remove capabilities.add |

**K01-0: Privileged Container**
```bash
kubectl patch deployment $TARGET -n test-lab --type='json' -p='[
  {"op": "remove", "path": "/spec/template/spec/containers/0/securityContext/privileged"}
]'
```

**K01-1: Running as Root**
```bash
kubectl patch deployment $TARGET -n test-lab --type='json' -p='[
  {"op": "replace", "path": "/spec/template/spec/containers/0/securityContext/runAsUser", "value": 1000}
]'
```

**K01-2: Dangerous Capabilities**
```bash
kubectl patch deployment $TARGET -n test-lab --type='json' -p='[
  {"op": "remove", "path": "/spec/template/spec/containers/0/securityContext/capabilities/add"}
]'
```

---

#### K02 - Supply Chain Vulnerabilities (5 sub-issues)

| SubIssue | Vulnerable Image | Secure Image | Target |
|----------|------------------|--------------|--------|
| 0 | node:10-alpine | node:22-alpine | api |
| 1 | nginx:1.15-alpine | nginx:1.29.1-alpine | webapp |
| 2 | python:3.5-alpine | python:3.13-alpine | user-service |
| 3 | ruby:2.6-alpine | ruby:3.3-alpine | payment-service |
| 4 | grafana/grafana:9.0.0 | grafana/grafana:12.2.0 | grafana |

**K02-*: Update to Secure Image**
```bash
kubectl set image deployment/$TARGET -n test-lab <container-name>=<secure-image>
```

---

#### K03 - Overly Permissive RBAC (3 sub-issues)

| SubIssue | Resources Created | Remediation |
|----------|------------------|-------------|
| 0 | Role: `test-lab-overpermissive`, RoleBinding: `test-lab-overpermissive-binding` | Delete both |
| 1 | Role: `test-lab-default-permissions`, RoleBinding: `test-lab-default-binding` | Delete both |
| 2 | Role: `test-lab-secrets-reader`, RoleBinding: `test-lab-secrets-binding` | Delete both |

**K03-*: Delete RBAC Resources**
```bash
kubectl delete role <role-name> -n test-lab
kubectl delete rolebinding <binding-name> -n test-lab
```

**Note:** Both Role AND RoleBinding must be deleted for remediation to be detected. The `cleanupOrphanedK03Resources()` function handles partial deletions.

---

#### K06 - Broken Authentication (6 sub-issues)

| SubIssue | Vulnerability | Remediation |
|----------|---------------|-------------|
| 0 | Empty serviceAccountName | Set serviceAccountName to "restricted-sa" |
| 1 | Token annotation (`kubernetes.io/service-account.token`) | Remove annotation |
| 2 | Default account annotation (`auth.kubernetes.io/default-account`) | Remove annotation |
| 3 | Missing fsGroup in PodSecurityContext | Add fsGroup value |
| 4 | Root user (`runAsUser: 0`) | Change to non-zero |
| 5 | Privileged container | Set privileged to false |

**K06-0: Default Service Account**
```bash
kubectl patch deployment $TARGET -n test-lab --type='json' -p='[
  {"op": "add", "path": "/spec/template/spec/serviceAccountName", "value": "restricted-sa"}
]'
```

**K06-3: Missing fsGroup**
```bash
kubectl patch deployment $TARGET -n test-lab --type='json' -p='[
  {"op": "add", "path": "/spec/template/spec/securityContext/fsGroup", "value": 1000}
]'
```

---

#### K07 - Missing Network Segmentation (4 sub-issues)

| SubIssue | Vulnerability | Remediation |
|----------|---------------|-------------|
| 0 | Network policy disabled annotation | Remove annotation |
| 1 | Network isolation disabled annotation | Remove annotation |
| 2 | Postgres service as NodePort | Change to ClusterIP |
| 3 | Service exposure annotation | Remove annotation |

**K07-2: Postgres NodePort**
```bash
kubectl patch service postgres-service -n test-lab --type='json' -p='[
  {"op": "replace", "path": "/spec/type", "value": "ClusterIP"}
]'
```

---

#### K08 - Secrets Management (3 sub-issues)

| SubIssue | Vulnerability | Remediation |
|----------|---------------|-------------|
| 0 | Secrets in ConfigMap (`{target}-config`) | Delete the ConfigMap |
| 1 | Hardcoded secrets annotation | Remove annotation |
| 2 | Insecure volume permissions annotation | Remove annotation |

**K08-0: Secrets in ConfigMap**
```bash
kubectl delete configmap ${TARGET}-config -n test-lab
```

---

### 4.4 Special Cases

**Alternative Remediation:**
- Deleting the deployment entirely always works for K01, K02, K06, K07, K08
- This is a valid remediation approach

**Timing:**
- Controller requeues every 30 seconds when in `Vulnerable` state
- Tests should allow 60-120 seconds for state transitions

### 4.5 Full Suite Verification

After K01 smoke test passes:

```bash
./scripts/verify-remediation-cycle.sh --verbose
```

This runs all 24 tests across 6 categories.

---

## Phase 5: User Notification

### 5.1 Status File Verification

Verify `/tmp/cluster-status` file is written with correct messages:

| State | Expected Message |
|-------|------------------|
| After init | "Ready for scanning" |
| After fix detected | "Vulnerability fixed! Preparing next challenge..." |
| During reset | "Resetting cluster" |

### 5.2 Wall Notification

The operator broadcasts status changes to all terminals via `wall`.

**Implementation** (in `vulnerablelab_controller.go:324-340`):
```go
func (r *VulnerableLabReconciler) writeClusterStatus(status string) {
    // Write to file for programmatic access
    err := os.WriteFile("/tmp/cluster-status", []byte(status), 0644)
    if err != nil {
        ctrl.Log.WithName("status-file").Error(err, "Failed to write cluster status file")
    }

    // Broadcast to all terminals via wall for immediate user notification
    cmd := exec.Command("wall", status)
    if err := cmd.Run(); err != nil {
        ctrl.Log.WithName("wall").Error(err, "Failed to broadcast status via wall")
    }
}
```

### 5.3 Notification Strategy Analysis

| Option | Pros | Cons |
|--------|------|------|
| **wall** (RECOMMENDED) | Works in any terminal, broadcasts to all users, no dependencies | Can be noisy, requires permissions |
| Terminal Bell | Simple (`\a`) | Often disabled, easy to miss |
| File-based | Non-intrusive | Requires watch script |
| Log output | Already implemented | Requires active monitoring |

**Recommendation:** Use `wall` for Iximiuz Labs ephemeral environments where users benefit from immediate, unmissable notifications.

---

## Phase 6: Critical Files & Checklists

### 6.1 Critical Files

| File | Purpose | Key Functions |
|------|---------|---------------|
| `internal/controller/vulnerablelab_controller.go` | State machine, reconciliation | `Reconcile`, `checkRemediation`, `resetLab`, `writeClusterStatus` |
| `internal/breaker/breaker.go` | Vulnerability injection | `BreakCluster`, `applyK*ToStack` |
| `internal/breaker/remediate.go` | Fix detection | `CheckRemediation`, `checkK*` |
| `internal/baseline/baseline.go` | Secure baseline stack | `GetAppStack` |
| `examples/*.yaml` | Example VulnerableLab manifests | Per sub-issue examples |

### 6.2 Master Verification Checklist

**Code Quality:**
- [ ] `make lint` passes
- [ ] Unit tests pass

**Implementation:**
- [ ] Each K category creates at least one scannable vulnerability
- [ ] K01 vulnerabilities detected by kubescape
- [ ] K02 vulnerabilities (CVEs) detected by trivy
- [ ] K03 RBAC issues detected by kubescape
- [ ] K08 secrets-in-configmap detected by scanners

**Remediation Cycle (per vulnerability, 24 total):**
- [ ] VulnerableLab created with specific vulnerability/subIssue
- [ ] Operator reaches `Vulnerable` state
- [ ] Target resource has vulnerability applied
- [ ] After remediation, operator reaches `Remediated` state
- [ ] Operator resets and reaches new `Vulnerable` state
- [ ] Previous resources cleaned up

**User Notification:**
- [ ] `/tmp/cluster-status` file written on state changes
- [ ] **`wall` notification broadcasts to all terminals on remediation** (CRITICAL)
